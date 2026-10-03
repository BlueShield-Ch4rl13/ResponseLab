<#
.SYNOPSIS
  Active response de ResponseLab para agentes Wazuh en Windows.

.DESCRIPTION
  Lo invocan los lanzadores responselab-<accion>.cmd de active-response\bin
  cuando el motor pide una accion (PUT /active-response con
  "!responselab-<accion>.cmd"). Windows PowerShell 5.1, sin modulos externos.

  Protocolo de Wazuh 4.2+: execd escribe una linea JSON en stdin
  ({"command":"add","parameters":{"alert":{"data":{"responselab":{...}}}}}),
  el script contesta check_keys y lee continue/abort. execd ESPERA a que el
  script termine: el triage forense se lanza en segundo plano.

  El acuse vuelve por el propio Wazuh: una linea JSON en
  active-response\active-responses.log ({"responselab_ar": {...}}) que el
  agente ya envia al manager. No hace falta ningun secreto en el equipo y el
  acuse llega aunque el equipo este aislado.

  Cada accion comprueba su objetivo antes de tocar nada y guarda lo necesario
  para deshacerla en C:\ProgramData\ResponseLab (solo SYSTEM y
  Administradores).

  RL_AR_SIMULACION=1 registra las ordenes en vez de ejecutarlas (pruebas).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)] [string] $Accion,
    [string] $ArgumentosFondo = ''
)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$Aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
$Wazuh = if ($env:RL_WAZUH_DIR) { $env:RL_WAZUH_DIR } else { Split-Path -Parent (Split-Path -Parent $Aqui) }
$Estado = if ($env:RL_ESTADO_DIR) { $env:RL_ESTADO_DIR } else { Join-Path $env:ProgramData 'ResponseLab' }
$Custodia = Join-Path $Estado 'custodia'
$Registro = Join-Path $Wazuh 'active-response\active-responses.log'
$Configuraciones = @((Join-Path $Wazuh 'shared\responselab.conf'), (Join-Path $Wazuh 'responselab.conf'))
$Simulacion = ($env:RL_AR_SIMULACION -eq '1')
$GrupoReglas = 'ResponseLab'
$ReSistema = '(?i)^(?:[a-z]:\\windows\\|\\\\\?\\[a-z]:\\windows\\|%systemroot%|%windir%)'
$ProcesosCriticos = @('system', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'lsaiso', 'svchost',
                      'fontdrvhost', 'dwm', 'wazuh-agent', 'ossec-agent', 'msmpeng', 'mssense', 'sensecncproxy')
$script:Ordenes = New-Object System.Collections.ArrayList

class Fallo : System.Exception {
    Fallo([string] $Mensaje) : base($Mensaje) {}
}

# === Utilidades ==============================================================

function Ahora { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Leer-Campo($Objeto, [string] $Ruta) {
    $actual = $Objeto
    foreach ($parte in $Ruta.Split('.')) {
        if ($null -eq $actual) { return $null }
        if ($actual -is [System.Collections.IDictionary]) {
            if (-not $actual.Contains($parte)) { return $null }
            $actual = $actual[$parte]
        } else {
            $propiedad = $actual.PSObject.Properties[$parte]
            if ($null -eq $propiedad) { return $null }
            $actual = $propiedad.Value
        }
    }
    return $actual
}

function Texto($Valor) { if ($null -eq $Valor) { return '' } return [string] $Valor }

function A-Json($Objeto, [int] $Profundidad = 6) {
    $json = ConvertTo-Json -InputObject $Objeto -Compress -Depth $Profundidad
    # Solo ASCII en el log: lo no ASCII como \uXXXX
    return [regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
}

function Escribir-Acuse([string] $Nombre, [string] $EstadoAcuse, [string] $Detalle, [string] $Ejecucion, $Datos) {
    if ($Detalle.Length -gt 500) { $Detalle = $Detalle.Substring(0, 500) }
    $cuerpo = [ordered]@{ v = 1; accion = $Nombre; estado = $EstadoAcuse; ejecucion_id = $Ejecucion;
                          detalle = $Detalle; equipo = $env:COMPUTERNAME }
    if ($null -ne $Datos) {
        $texto = A-Json $Datos
        if ($texto.Length -gt 6000) { $texto = '{"recortado":true}' }
        $cuerpo['datos'] = $texto
    }
    $linea = A-Json ([ordered]@{ responselab_ar = $cuerpo }) 4
    $carpeta = Split-Path -Parent $Registro
    if (-not (Test-Path -LiteralPath $carpeta)) { New-Item -ItemType Directory -Path $carpeta -Force | Out-Null }
    for ($i = 0; $i -lt 5; $i++) {
        try { [System.IO.File]::AppendAllText($Registro, $linea + "`n", [System.Text.Encoding]::ASCII); break }
        catch { Start-Sleep -Milliseconds 200 }      # el agente puede tener el fichero abierto un instante
    }
}

function Configuracion {
    foreach ($ruta in $Configuraciones) {
        if (Test-Path -LiteralPath $ruta) {
            try { return (Get-Content -LiteralPath $ruta -Raw | ConvertFrom-Json) } catch { }
        }
    }
    return $null
}

function Orden([string] $Descripcion, [scriptblock] $Bloque) {
    # Toda orden que cambia el equipo pasa por aqui: se registra y, en simulacion, no se ejecuta.
    # No devuelve nada: lo que escribiera el bloque no debe colarse en el resultado de la accion.
    [void] $script:Ordenes.Add($Descripcion)
    if (-not $Simulacion) { $null = & $Bloque }
}

function Guardar([string] $Nombre, $Datos) {
    if (-not (Test-Path -LiteralPath $Estado)) {
        New-Item -ItemType Directory -Path $Estado -Force | Out-Null
        Proteger-Carpeta $Estado
    }
    Set-Content -LiteralPath (Join-Path $Estado $Nombre) -Value (ConvertTo-Json -InputObject $Datos -Depth 6) -Encoding UTF8
}

function Leer-Estado([string] $Nombre) {
    $ruta = Join-Path $Estado $Nombre
    if (-not (Test-Path -LiteralPath $ruta)) { return $null }
    try { return (Get-Content -LiteralPath $ruta -Raw | ConvertFrom-Json) } catch { return $null }
}

function Proteger-Carpeta([string] $Ruta) {
    # Solo SYSTEM y Administradores: la custodia no la lee un usuario del equipo
    if ($Simulacion) { return }
    & icacls.exe $Ruta /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}

function Hash-Fichero([string] $Ruta, [string] $Algoritmo = 'SHA256') {
    return (Get-FileHash -LiteralPath $Ruta -Algorithm $Algoritmo).Hash.ToLowerInvariant()
}

function Es-RutaSistema([string] $Ruta) {
    # Normalizar antes de comparar: C:/Windows/..., C:\\Windows\\... y rutas con
    # .. llegan igual de lejos que C:\Windows\...
    $r = ($Ruta.Trim().Trim('"')) -replace '/', '\'
    if ($r -match '^[a-zA-Z]:\\') {
        $r = $r.Substring(0, 2) + ($r.Substring(2) -replace '\\{2,}', '\')
        if ($env:OS -eq 'Windows_NT') { try { $r = [IO.Path]::GetFullPath($r) } catch { } }
    }
    if ([regex]::IsMatch($r, $ReSistema)) { return $true }
    if ($r -match '(?i)^[a-z]:\\window~\d') { return $true }      # nombre corto 8.3
    try {
        # Un enlace simbolico o una union que apunta al sistema tambien es del sistema
        $item = Get-Item -LiteralPath $r -Force -ErrorAction Stop
        if ($item.LinkType) {
            foreach ($t in @($item.Target)) { if ([regex]::IsMatch(([string] $t) -replace '/', '\', $ReSistema)) { return $true } }
        }
    } catch { }
    return $false
}

function IPs-Validas($Valores) {
    $salida = @()
    foreach ($v in @($Valores)) {
        $ip = $null
        if ($null -ne $v -and [System.Net.IPAddress]::TryParse(([string] $v).Trim(), [ref] $ip)) { $salida += $ip.ToString() }
    }
    return @($salida | Sort-Object -Unique)
}

function Resolver([string] $Nombre) {
    try { return @([System.Net.Dns]::GetHostAddresses($Nombre) | ForEach-Object { $_.ToString() } | Sort-Object -Unique) }
    catch { return @() }
}

function Managers-Del-Agente {
    $conf = Join-Path $Wazuh 'ossec.conf'
    if (-not (Test-Path -LiteralPath $conf)) { return @() }
    $ips = @()
    foreach ($m in [regex]::Matches((Get-Content -LiteralPath $conf -Raw), '<address>\s*([^<\s]+)\s*</address>')) {
        $d = $m.Groups[1].Value
        $validas = @(IPs-Validas @($d))
        if ($validas.Count) { $ips += $validas } else { $ips += Resolver $d }
    }
    return @($ips | Sort-Object -Unique)
}

function Momento-Utc([string] $Valor) {
    $estilos = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $resultado = [datetime]::MinValue
    if ([datetime]::TryParse($Valor.Replace('T', ' ').TrimEnd('Z'), [System.Globalization.CultureInfo]::InvariantCulture, $estilos, [ref] $resultado)) {
        return $resultado
    }
    throw [Fallo]::new("hora de arranque del proceso ilegible: $Valor")
}

# === Aislamiento de red ======================================================

function IPv4-ANumero([string] $Ip) {
    $b = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes(); [Array]::Reverse($b)
    return [uint64] [BitConverter]::ToUInt32($b, 0)
}

function Numero-AIPv4([uint64] $N) {
    $b = [BitConverter]::GetBytes([uint32] $N); [Array]::Reverse($b)
    return ([System.Net.IPAddress]::new($b)).ToString()
}

function Complemento-IPv4([string[]] $Ips) {
    # Windows Firewall da prioridad a las reglas de bloqueo sobre las de permitir:
    # "todo menos el manager" se expresa bloqueando los rangos que lo rodean.
    $numeros = @($Ips | ForEach-Object { IPv4-ANumero $_ } | Sort-Object -Unique)
    $rangos = @()
    [uint64] $desde = 0
    foreach ($n in $numeros) {
        if ($n -gt $desde) { $rangos += '{0}-{1}' -f (Numero-AIPv4 $desde), (Numero-AIPv4 ($n - 1)) }
        $desde = $n + 1
    }
    if ($desde -le 4294967295) { $rangos += '{0}-255.255.255.255' -f (Numero-AIPv4 $desde) }
    return $rangos
}

function Aislar($P) {
    $permitidos = @(@(IPs-Validas (Leer-Campo $P 'permitidos')) + @(Managers-Del-Agente) | Sort-Object -Unique)
    if ($permitidos.Count -eq 0) { throw [Fallo]::new('sin IPs permitidas (manager y motor): el equipo perderia Wazuh y no se podria deshacer') }
    $v6 = @($permitidos | Where-Object { $_.Contains(':') })
    if ($v6.Count) { throw [Fallo]::new("hay direcciones IPv6 permitidas ($($v6 -join ', ')): el aislamiento en Windows solo garantiza IPv4; requiere una persona") }
    if (-not $Simulacion) {
        foreach ($perfil in Get-NetFirewallProfile -PolicyStore ActiveStore) {
            if ([string] $perfil.AllowLocalFirewallRules -eq 'False') {
                throw [Fallo]::new("la GPO ignora las reglas locales del cortafuegos (perfil $($perfil.Name)): el aislamiento no tendria efecto")
            }
        }
    }
    New-Item -ItemType Directory -Path $Estado -Force | Out-Null
    $copia = Join-Path $Estado ('cortafuegos-antes-{0}.wfw' -f (Get-Date -Format 'yyyyMMddTHHmmss'))
    Orden "netsh advfirewall export $copia" { & netsh.exe advfirewall export $copia | Out-Null }
    $perfiles = @()
    if (-not $Simulacion) {
        $perfiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object { @{ nombre = [string] $_.Name; activo = [string] $_.Enabled } })
    }
    $rangos = @(Complemento-IPv4 $permitidos) + @('::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
    Orden 'Quitar reglas de aislamiento previas' { Get-NetFirewallRule -Group $GrupoReglas -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'ResponseLab aislamiento*' } | Remove-NetFirewallRule }
    Orden 'Activar el cortafuegos en todos los perfiles' { Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True }
    Orden "Bloquear entrada salvo $($permitidos -join ', ')" { New-NetFirewallRule -DisplayName 'ResponseLab aislamiento (entrada)' -Group $GrupoReglas -Direction Inbound -Action Block -RemoteAddress $rangos -Profile Any | Out-Null }
    Orden "Bloquear salida salvo $($permitidos -join ', ')" { New-NetFirewallRule -DisplayName 'ResponseLab aislamiento (salida)' -Group $GrupoReglas -Direction Outbound -Action Block -RemoteAddress $rangos -Profile Any | Out-Null }
    Guardar 'aislamiento.json' @{ permitidos = $permitidos; perfiles = $perfiles; copia = $copia; desde = (Ahora); ejecucion = (Texto (Leer-Campo $P 'ejecucion_id')) }
    return @("equipo aislado con el cortafuegos de Windows; solo habla con $($permitidos -join ', ')", @{ permitidos = $permitidos; copia = $copia })
}

function Liberar($P) {
    $previo = Leer-Estado 'aislamiento.json'
    Orden 'Quitar las reglas de aislamiento' { Get-NetFirewallRule -Group $GrupoReglas -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'ResponseLab aislamiento*' } | Remove-NetFirewallRule }
    if ($null -ne $previo -and $null -ne (Leer-Campo $previo 'perfiles')) {
        foreach ($perfil in @($previo.perfiles)) {
            if ((Texto $perfil.activo) -eq 'False') {
                $nombre = Texto $perfil.nombre
                Orden "Devolver el perfil $nombre a desactivado" { Set-NetFirewallProfile -Profile $nombre -Enabled False }
            }
        }
    }
    $ruta = Join-Path $Estado 'aislamiento.json'
    if (Test-Path -LiteralPath $ruta) { Remove-Item -LiteralPath $ruta -Force }
    return @('aislamiento levantado', @{ previo = $previo })
}

# === Procesos ================================================================

function Matar($P) {
    $idTexto = Texto (Leer-Campo $P 'pid')
    $id = 0
    if (-not [int]::TryParse($idTexto, [ref] $id) -or $id -le 4) { throw [Fallo]::new("PID no valido o protegido: $idTexto") }
    $proceso = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue
    if ($null -eq $proceso) { throw [Fallo]::new("el proceso $id ya no existe") }
    $nombre = [System.IO.Path]::GetFileNameWithoutExtension([string] $proceso.Name).ToLowerInvariant()
    if ($ProcesosCriticos -contains $nombre) { throw [Fallo]::new("$($proceso.Name) es un proceso critico del sistema o del propio agente: no se mata") }
    $real = ([datetime] $proceso.CreationDate).ToUniversalTime()
    $esperado = Momento-Utc (Texto (Leer-Campo $P 'inicio'))
    $diferencia = [Math]::Abs(($real - $esperado).TotalSeconds)
    if ($diferencia -gt 2) { throw [Fallo]::new("el PID $id se ha reutilizado: arranco con $([int] $diferencia) s de diferencia con la alerta; no se mata") }
    $imagen = Texto (Leer-Campo $P 'imagen')
    $ruta = Texto $proceso.ExecutablePath
    if ($imagen -and $ruta -and ((Split-Path -Leaf $imagen) -ne (Split-Path -Leaf $ruta))) {
        throw [Fallo]::new("el PID $id es $ruta, no $imagen; no se mata")
    }
    $datos = @{ pid = $id; imagen = $ruta; linea = (Texto $proceso.CommandLine) }
    if ($ruta -and (Test-Path -LiteralPath $ruta)) { $datos['sha256'] = Hash-Fichero $ruta }
    Orden "Stop-Process -Id $id -Force" { Stop-Process -Id $id -Force }
    return @("proceso $id ($ruta) terminado", $datos)
}

# === Ficheros ================================================================

function Fichero-Objetivo([string] $Ruta, [string] $ShaEsperado) {
    if (-not $Ruta) { throw [Fallo]::new('sin ruta de fichero') }
    if (Es-RutaSistema $Ruta) { throw [Fallo]::new("$Ruta es del sistema operativo: no se toca sin una persona") }
    if (-not (Test-Path -LiteralPath $Ruta -PathType Leaf)) { throw [Fallo]::new("$Ruta no existe o no es un fichero") }
    $sha = Hash-Fichero $Ruta
    if ($ShaEsperado -and $sha -ne $ShaEsperado.ToLowerInvariant()) {
        throw [Fallo]::new("el contenido de $Ruta ha cambiado desde la alerta (sha256 $($sha.Substring(0, 16)))")
    }
    return $sha
}

function Carpeta-Custodia([string] $Sha, [string] $Ruta) {
    # Hash del contenido y de la ruta, y nunca una carpeta que ya guarde algo:
    # dos copias identicas en dos rutas no se pisan.
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Ruta.ToLowerInvariant())) } finally { $h.Dispose() }
    $base = "$Sha-" + (($bytes[0..5] | ForEach-Object { $_.ToString('x2') }) -join '')
    $destino = Join-Path $Custodia $base
    $n = 1
    while (Test-Path -LiteralPath (Join-Path $destino 'fichero')) { $n++; $destino = Join-Path $Custodia "$base-$n" }
    return $destino
}

function Cuarentena($P) {
    $ruta = Texto (Leer-Campo $P 'ruta')
    $sha = Fichero-Objetivo $ruta (Texto (Leer-Campo $P 'sha256'))
    $item = Get-Item -LiteralPath $ruta
    $destino = Carpeta-Custodia $sha $ruta
    New-Item -ItemType Directory -Path $destino -Force | Out-Null
    Proteger-Carpeta $Custodia
    $sddl = ''
    if (-not $Simulacion) { $sddl = (Get-Acl -LiteralPath $ruta).Sddl }
    $meta = [ordered]@{ ruta = $ruta; sha256 = $sha; md5 = (Hash-Fichero $ruta 'MD5'); tamano = $item.Length; sddl = $sddl
                        atributos = [string] $item.Attributes; creado = $item.CreationTimeUtc.ToString('o')
                        modificado = $item.LastWriteTimeUtc.ToString('o'); cuarentena = (Ahora)
                        ejecucion = (Texto (Leer-Campo $P 'ejecucion_id')); caso = (Texto (Leer-Campo $P 'caso')) }
    try { Move-Item -LiteralPath $ruta -Destination (Join-Path $destino 'fichero') -Force }
    catch { throw [Fallo]::new("no se pudo mover $ruta (en uso?): mata antes el proceso o usa el EDR. $($_.Exception.Message)") }
    Set-Content -LiteralPath (Join-Path $destino 'meta.json') -Value (ConvertTo-Json -InputObject $meta -Depth 3) -Encoding UTF8
    return @("$ruta en cuarentena (sha256 $($sha.Substring(0, 16)))", @{ custodia = $destino; sha256 = $sha; ruta = $ruta })
}

function Restaurar($P) {
    $sha = (Texto (Leer-Campo $P 'sha256')).ToLowerInvariant()
    $buscada = Texto (Leer-Campo $P 'ruta')
    if (-not $sha -and -not $buscada) { throw [Fallo]::new('sin sha256 ni ruta que restaurar') }
    $carpetas = @(); $rutas = @{}
    foreach ($d in @(Get-ChildItem -LiteralPath $Custodia -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $metaRuta = Join-Path $d.FullName 'meta.json'
        if (-not (Test-Path -LiteralPath (Join-Path $d.FullName 'fichero')) -or -not (Test-Path -LiteralPath $metaRuta)) { continue }
        try { $m = Get-Content -LiteralPath $metaRuta -Raw | ConvertFrom-Json } catch { continue }
        if ($sha -and $m.sha256 -ne $sha) { continue }
        if ($buscada -and $m.ruta -ne $buscada) { continue }
        $carpetas += $d.FullName; $rutas[([string] $m.ruta).ToLowerInvariant()] = $true
    }
    if ($rutas.Count -gt 1) { throw [Fallo]::new("el sha256 $sha esta en custodia desde varias rutas: indica la ruta a restaurar") }
    foreach ($carpeta in @($carpetas | Select-Object -Last 1)) {
        $fichero = Join-Path $carpeta 'fichero'
        if (-not (Test-Path -LiteralPath $fichero)) { continue }
        $meta = Get-Content -LiteralPath (Join-Path $carpeta 'meta.json') -Raw | ConvertFrom-Json
        if (Test-Path -LiteralPath $meta.ruta) { throw [Fallo]::new("ya hay un fichero en $($meta.ruta): no se sobrescribe") }
        $padre = Split-Path -Parent $meta.ruta
        if (-not (Test-Path -LiteralPath $padre)) { New-Item -ItemType Directory -Path $padre -Force | Out-Null }
        Move-Item -LiteralPath $fichero -Destination $meta.ruta
        if ((Texto (Leer-Campo $meta 'sddl')) -and -not $Simulacion) {
            $acl = Get-Acl -LiteralPath $meta.ruta
            $acl.SetSecurityDescriptorSddlForm($meta.sddl)
            Set-Acl -LiteralPath $meta.ruta -AclObject $acl
        }
        return @("$($meta.ruta) restaurado desde la custodia", @{ ruta = $meta.ruta; sha256 = $meta.sha256 })
    }
    throw [Fallo]::new("no hay nada en custodia para $(if ($sha) { $sha } else { Texto (Leer-Campo $P 'ruta') })")
}

function Conservar($P) {
    $ruta = Texto (Leer-Campo $P 'ruta')
    if (-not $ruta -or -not (Test-Path -LiteralPath $ruta -PathType Leaf)) { throw [Fallo]::new("no hay fichero que conservar en $ruta") }
    if ($ruta -match '(?i)^[a-z]:\\windows\\(system32\\config\\(sam|security|system)|ntds\\ntds\.dit)$') {
        throw [Fallo]::new("$ruta es un almacen de credenciales: no se copia a custodia")
    }
    $sha = Hash-Fichero $ruta
    $destino = Join-Path (Join-Path $Custodia 'conservados') $sha
    New-Item -ItemType Directory -Path $destino -Force | Out-Null
    Copy-Item -LiteralPath $ruta -Destination (Join-Path $destino 'fichero') -Force
    $meta = [ordered]@{ ruta = $ruta; sha256 = $sha; md5 = (Hash-Fichero $ruta 'MD5'); copiado = (Ahora)
                        ejecucion = (Texto (Leer-Campo $P 'ejecucion_id')); caso = (Texto (Leer-Campo $P 'caso')) }
    Set-Content -LiteralPath (Join-Path $destino 'meta.json') -Value (ConvertTo-Json -InputObject $meta) -Encoding UTF8
    return @("copia de $ruta conservada (sha256 $($sha.Substring(0, 16)))", @{ custodia = $destino; sha256 = $sha })
}

# === Persistencia ============================================================

function Clave-Persistencia([string] $Texto) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Texto.ToLowerInvariant()))
    return (-join ($bytes[0..11] | ForEach-Object { $_.ToString('x2') }))
}

function Tipo-Persistencia([string] $Tipo, [string] $Nombre, [string] $Ruta) {
    $t = $Tipo.ToLowerInvariant()
    if ($t -match 'tarea|task') { return 'tarea' }
    if ($t -match 'registro|registry|run') { return 'registro' }
    if ($t -match 'servicio|service') { return 'servicio' }
    if ($t -match 'fichero|file|inicio|startup') { return 'fichero' }
    if ($Ruta -match '^(?i)(HKLM|HKCU|HKU|HKEY_|\\REGISTRY\\)') { return 'registro' }
    if ($Nombre.StartsWith('\')) { return 'tarea' }
    if ($Ruta -and (Test-Path -LiteralPath $Ruta -PathType Leaf)) { return 'fichero' }
    if ($Nombre -and (Get-Service -Name $Nombre -ErrorAction SilentlyContinue)) { return 'servicio' }
    throw [Fallo]::new("no se reconoce el tipo de persistencia (tipo=$Tipo, nombre=$Nombre, ruta=$Ruta)")
}

function Ruta-Registro([string] $Ruta) {
    $r = $Ruta -replace '^(?i)\\REGISTRY\\MACHINE\\', 'HKLM\' -replace '^(?i)\\REGISTRY\\USER\\', 'HKU\'
    $r = $r -replace '^(?i)HKEY_LOCAL_MACHINE\\', 'HKLM\' -replace '^(?i)HKEY_CURRENT_USER\\', 'HKCU\' -replace '^(?i)HKEY_USERS\\', 'HKU\'
    if ($r -match '^(?i)HKU\\') { $r = 'Registry::HKEY_USERS\' + $r.Substring(4) } else { $r = $r -replace '^(HKLM|HKCU)\\', '$1:\' }
    return $r
}

function Persistencia($P) {
    $tipoTexto = Texto (Leer-Campo $P 'tipo'); $nombre = Texto (Leer-Campo $P 'nombre'); $ruta = Texto (Leer-Campo $P 'ruta')
    $tipo = Tipo-Persistencia $tipoTexto $nombre $ruta
    $destino = Join-Path (Join-Path $Custodia 'persistencia') (Clave-Persistencia "$tipo|$nombre|$ruta")
    New-Item -ItemType Directory -Path $destino -Force | Out-Null
    $meta = [ordered]@{ tipo = $tipo; nombre = $nombre; ruta = $ruta; momento = (Ahora); ejecucion = (Texto (Leer-Campo $P 'ejecucion_id')) }
    switch ($tipo) {
        'tarea' {
            $tarea = if ($nombre) { $nombre } else { $ruta }
            Orden "schtasks /query /tn $tarea /xml" { & schtasks.exe /query /tn $tarea /xml | Set-Content -LiteralPath (Join-Path $destino 'tarea.xml') -Encoding Unicode }
            Orden "schtasks /change /tn $tarea /disable" {
                & schtasks.exe /change /tn $tarea /disable | Out-Null
                if ($LASTEXITCODE -ne 0) { throw [Fallo]::new("schtasks no pudo deshabilitar $tarea") }
            }
            $detalle = "tarea programada $tarea deshabilitada (definicion guardada)"
        }
        'registro' {
            $clave = $ruta; $valor = $nombre
            if (-not $valor) { $valor = Split-Path -Leaf $ruta; $clave = Split-Path -Parent $ruta }
            $rutaPs = Ruta-Registro $clave
            $meta['clave'] = $rutaPs; $meta['valor'] = $valor
            if (-not $Simulacion) {
                $item = Get-Item -LiteralPath $rutaPs
                $meta['datos'] = $item.GetValue($valor, $null, 'DoNotExpandEnvironmentNames')
                $meta['tipo_valor'] = [string] $item.GetValueKind($valor)
                if ($null -eq $meta['datos']) { throw [Fallo]::new("el valor $valor no existe en $clave") }
            }
            Orden "Remove-ItemProperty $rutaPs $valor" { Remove-ItemProperty -LiteralPath $rutaPs -Name $valor }
            $detalle = "valor de arranque $valor retirado de $clave (datos guardados)"
        }
        'servicio' {
            if (-not $Simulacion) {
                $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($nombre.Replace("'", ''))'"
                if ($null -eq $svc) { throw [Fallo]::new("el servicio $nombre no existe") }
                $meta['inicio'] = [string] $svc.StartMode; $meta['binario'] = [string] $svc.PathName
            }
            Orden "Stop-Service $nombre; Set-Service $nombre -StartupType Disabled" {
                Stop-Service -Name $nombre -Force -ErrorAction SilentlyContinue
                Set-Service -Name $nombre -StartupType Disabled
            }
            $detalle = "servicio $nombre parado y deshabilitado (configuracion guardada)"
        }
        'fichero' {
            if (Es-RutaSistema $ruta) { throw [Fallo]::new("$ruta es del sistema operativo: no se toca sin una persona") }
            $meta['sha256'] = Hash-Fichero $ruta
            Move-Item -LiteralPath $ruta -Destination (Join-Path $destino 'fichero') -Force
            $detalle = "$ruta retirado (copia en custodia)"
        }
    }
    Set-Content -LiteralPath (Join-Path $destino 'meta.json') -Value (ConvertTo-Json -InputObject $meta -Depth 3) -Encoding UTF8
    return @($detalle, @{ tipo = $tipo; custodia = $destino })
}

function Persistencia-Restaurar($P) {
    $tipoTexto = Texto (Leer-Campo $P 'tipo'); $nombre = Texto (Leer-Campo $P 'nombre'); $ruta = Texto (Leer-Campo $P 'ruta')
    $encontrado = $null
    foreach ($tipo in @('tarea', 'registro', 'servicio', 'fichero')) {
        $carpeta = Join-Path (Join-Path $Custodia 'persistencia') (Clave-Persistencia "$tipo|$nombre|$ruta")
        if (Test-Path -LiteralPath (Join-Path $carpeta 'meta.json')) { $encontrado = $carpeta; break }
    }
    if (-not $encontrado) { throw [Fallo]::new("no hay copia en custodia de esa persistencia ($tipoTexto $nombre $ruta)") }
    $meta = Get-Content -LiteralPath (Join-Path $encontrado 'meta.json') -Raw | ConvertFrom-Json
    switch ($meta.tipo) {
        'tarea' {
            $tarea = if ($meta.nombre) { $meta.nombre } else { $meta.ruta }
            Orden "schtasks /change /tn $tarea /enable" { & schtasks.exe /change /tn $tarea /enable | Out-Null }
            $detalle = "tarea $tarea habilitada de nuevo"
        }
        'registro' {
            $clave = Texto (Leer-Campo $meta 'clave'); $valor = Texto (Leer-Campo $meta 'valor')
            Orden "New-ItemProperty $clave $valor" { New-ItemProperty -LiteralPath $clave -Name $valor -Value $meta.datos -PropertyType $meta.tipo_valor -Force | Out-Null }
            $detalle = "valor $valor devuelto a $clave"
        }
        'servicio' {
            $modo = switch (Texto (Leer-Campo $meta 'inicio')) { 'Auto' { 'Automatic' } default { 'Manual' } }
            Orden "Set-Service $($meta.nombre) -StartupType $modo" { Set-Service -Name $meta.nombre -StartupType $modo }
            $detalle = "servicio $($meta.nombre) devuelto a inicio $modo (no se arranca: decide la persona)"
        }
        'fichero' {
            if (Test-Path -LiteralPath $meta.ruta) { throw [Fallo]::new("ya existe $($meta.ruta): no se sobrescribe") }
            Move-Item -LiteralPath (Join-Path $encontrado 'fichero') -Destination $meta.ruta
            $detalle = "$($meta.ruta) restaurado"
        }
    }
    return @($detalle, @{ tipo = $meta.tipo })
}

# === Bloqueo de destinos en este equipo ======================================

function IPs-Destino($P) {
    $destino = Texto (Leer-Campo $P 'destino')
    if ($destino -notmatch '^[A-Za-z0-9.:_-]{1,253}$') { throw [Fallo]::new("destino no valido: $destino") }
    $ips = @(IPs-Validas @($destino))
    if (-not $ips.Count) { $ips = @(Resolver $destino) }
    if (-not $ips.Count) { throw [Fallo]::new("$destino no resuelve a ninguna IP") }
    $publicas = @($ips | Where-Object { -not (Es-IP-Interna $_) })
    if (-not $publicas.Count) { throw [Fallo]::new("$destino solo resuelve a IPs internas ($($ips -join ', ')): bloquearlas en el equipo necesita una persona") }
    return @($destino, $publicas)
}

function Es-IP-Interna([string] $Ip) {
    $d = [System.Net.IPAddress]::Parse($Ip)
    if ([System.Net.IPAddress]::IsLoopback($d)) { return $true }
    if ($d.AddressFamily -eq 'InterNetworkV6') { return ($d.IsIPv6LinkLocal -or $d.IsIPv6SiteLocal -or $Ip.ToLowerInvariant().StartsWith('fc') -or $Ip.ToLowerInvariant().StartsWith('fd')) }
    $b = $d.GetAddressBytes()
    return ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or
            ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or $b[0] -eq 0)
}

function Bloquear-Destino($P) {
    $destino, $ips = IPs-Destino $P
    $nombre = "ResponseLab destino $destino"
    Orden "Bloquear salida a $destino ($($ips -join ', '))" {
        Get-NetFirewallRule -DisplayName $nombre -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $nombre -Group $GrupoReglas -Direction Outbound -Action Block -RemoteAddress $ips -Profile Any | Out-Null
    }
    return @("salida bloqueada hacia $destino ($($ips -join ', '))", @{ ips = $ips })
}

function Desbloquear-Destino($P) {
    $destino = Texto (Leer-Campo $P 'destino')
    $nombre = "ResponseLab destino $destino"
    Orden "Quitar el bloqueo de $destino" {
        $reglas = @(Get-NetFirewallRule -DisplayName $nombre -ErrorAction SilentlyContinue)
        if (-not $reglas.Count) { throw [Fallo]::new("no consta ningun bloqueo de $destino en este equipo") }
        $reglas | Remove-NetFirewallRule
    }
    return @("salida hacia $destino desbloqueada", $null)
}

# === Claves SSH (OpenSSH para Windows) =======================================

function Fichero-AuthorizedKeys($P) {
    $ruta = Texto (Leer-Campo $P 'ruta')
    if ($ruta) { return $ruta }
    $usuario = Texto (Leer-Campo $P 'usuario')
    $admin = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $perfil = Join-Path (Join-Path (Split-Path -Parent $env:PUBLIC) $usuario) '.ssh\authorized_keys'
    if ($usuario -and (Test-Path -LiteralPath $perfil)) { return $perfil }
    if (Test-Path -LiteralPath $admin) { return $admin }
    throw [Fallo]::new("no se encuentra authorized_keys para $usuario")
}

function Ssh-Clave($P) {
    $ruta = Fichero-AuthorizedKeys $P
    $partes = (Texto (Leer-Campo $P 'clave')).Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
    $material = if ($partes.Count -gt 1) { $partes[1] } elseif ($partes.Count) { $partes[0] } else { '' }
    if ($material.Length -lt 40) { throw [Fallo]::new('clave SSH no identificada sin ambiguedad') }
    $lineas = @(Get-Content -LiteralPath $ruta)
    $quitadas = @($lineas | Where-Object { $_.Contains($material) })
    if (-not $quitadas.Count) { throw [Fallo]::new("la clave no esta en $ruta") }
    $destino = Join-Path (Join-Path $Custodia 'ssh') (Clave-Persistencia $ruta)
    New-Item -ItemType Directory -Path $destino -Force | Out-Null
    Add-Content -LiteralPath (Join-Path $destino 'quitadas.txt') -Value $quitadas -Encoding UTF8
    Set-Content -LiteralPath $ruta -Value @($lineas | Where-Object { -not $_.Contains($material) }) -Encoding UTF8
    return @("$($quitadas.Count) clave(s) retiradas de $ruta", @{ ruta = $ruta })
}

function Ssh-Clave-Restaurar($P) {
    $ruta = Fichero-AuthorizedKeys $P
    $copia = Join-Path (Join-Path (Join-Path $Custodia 'ssh') (Clave-Persistencia $ruta)) 'quitadas.txt'
    if (-not (Test-Path -LiteralPath $copia)) { throw [Fallo]::new("no hay claves retiradas de $ruta") }
    $lineas = @(Get-Content -LiteralPath $copia)
    Add-Content -LiteralPath $ruta -Value $lineas -Encoding UTF8
    Remove-Item -LiteralPath $copia -Force
    return @("$($lineas.Count) clave(s) devueltas a $ruta", @{ ruta = $ruta })
}

# === Instantanea de un objeto de Active Directory ============================

function Instantanea-AD($P) {
    $dn = Texto (Leer-Campo $P 'dn')
    if (-not $dn) { throw [Fallo]::new('sin DN del objeto de directorio') }
    if (-not $Simulacion) {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { throw [Fallo]::new('falta el modulo ActiveDirectory (RSAT) en este equipo') }
        Import-Module ActiveDirectory
    }
    $destino = Join-Path (Join-Path $Custodia 'ad') (Get-Date -Format 'yyyyMMddTHHmmss')
    New-Item -ItemType Directory -Path $destino -Force | Out-Null
    $fichero = Join-Path $destino 'objeto.json'
    Orden "Get-ADObject $dn -Properties *" {
        Get-ADObject -Identity $dn -Properties * | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $fichero -Encoding UTF8
    }
    $sha = if (Test-Path -LiteralPath $fichero) { Hash-Fichero $fichero } else { '' }
    return @("estado de $dn guardado antes de tocar nada", @{ fichero = $fichero; sha256 = $sha })
}

# === Triage forense (FtriageDFIR), en segundo plano =========================

function Triage($P) {
    $conf = Configuracion
    $script = Texto (Leer-Campo $conf 'ftriage'); if (-not $script) { $script = 'C:\Program Files\ftriage\triage.py' }
    $python = Texto (Leer-Campo $conf 'python_ftriage')
    if (-not $python) { $py = Get-Command py.exe -ErrorAction SilentlyContinue; if ($py) { $python = $py.Source } else { $python = 'python.exe' } }
    if (-not (Test-Path -LiteralPath $script)) { throw [Fallo]::new("FtriageDFIR no esta instalado en $script (clave 'ftriage' de responselab.conf)") }
    $caso = ((Texto (Leer-Campo $P 'caso')) -replace '[^A-Za-z0-9_.-]', '_'); if (-not $caso) { $caso = 'responselab' }
    $salida = Join-Path (Join-Path $Estado 'triage') ('{0}_{1}' -f $caso, (Get-Date -Format 'yyyyMMddTHHmmss'))
    New-Item -ItemType Directory -Path (Split-Path -Parent $salida) -Force | Out-Null
    $argumentos = A-Json @{ python = $python; script = $script; salida = $salida; caso = $caso; ejecucion_id = (Texto (Leer-Campo $P 'ejecucion_id')) }
    $codificado = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($argumentos))
    $yo = $PSCommandPath
    Orden "Lanzar el triage en segundo plano ($salida)" {
        Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -WindowStyle Hidden -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $yo),
            '-Accion', '_triage_en_segundo_plano', '-ArgumentosFondo', $codificado) | Out-Null
    }
    return @("triage forense lanzado en segundo plano ($salida)", @{ salida = $salida; estado = 'en_curso' })
}

function Resumen-Ftriage($Informe) {
    $ev = Leer-Campo $Informe 'assessment'
    $tecnicas = @(@(Leer-Campo $ev 'attack_techniques') | Where-Object { $_ } | Select-Object -First 20 | ForEach-Object { @{ attack = $_.attack; tactic = $_.tactic } })
    $iocs = @(@(Leer-Campo $Informe 'iocs') | Where-Object { $_ -and -not $_.private } | Select-Object -First 30 | ForEach-Object { @{ type = $_.type; value = $_.value; defanged = $_.defanged } })
    $criticos = @(@(Leer-Campo $Informe 'findings') | Where-Object { $_ -and $_.level -eq 'crit' } | Select-Object -First 10 | ForEach-Object { @{ level = 'crit'; text = (Texto $_.text) } })
    return @{
        host = @{ hostname = (Texto (Leer-Campo $Informe 'host.hostname')) }
        case = @{ name = (Texto (Leer-Campo $Informe 'case.name')) }
        assessment = @{ verdict = (Leer-Campo $ev 'verdict'); verdict_key = (Leer-Campo $ev 'verdict_key')
                        risk_score = (Leer-Campo $ev 'risk_score'); confidence = (Leer-Campo $ev 'confidence'); attack_techniques = $tecnicas }
        iocs = $iocs; findings = $criticos
    }
}

function Triage-EnSegundoPlano([string] $Codificado) {
    $a = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Codificado)) | ConvertFrom-Json
    try {
        $argumentos = @()
        if ([System.IO.Path]::GetFileName($a.python) -ieq 'py.exe') { $argumentos += '-3' }
        $argumentos += @($a.script, 'triage', '--case', $a.caso, '--examiner', 'ResponseLab', '--output', $a.salida)
        & $a.python @argumentos *> ($a.salida + '.log')
        $informeRuta = Join-Path $a.salida 'report.json'
        if (-not (Test-Path -LiteralPath $informeRuta)) { throw [Fallo]::new("ftriage termino sin report.json (codigo $LASTEXITCODE)") }
        $informe = Get-Content -LiteralPath $informeRuta -Raw | ConvertFrom-Json
        $datos = @{ salida = $a.salida; sha256_informe = (Hash-Fichero $informeRuta); informe_ftriage = (Resumen-Ftriage $informe) }
        $conf = Configuracion
        $motor = Texto (Leer-Campo $conf 'motor'); $token = Texto (Leer-Campo $conf 'token_agentes'); $cliente = Texto (Leer-Campo $conf 'cliente')
        if ($motor -and $token -and $cliente) {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-RestMethod -Method Post -Uri ($motor.TrimEnd('/') + "/v1/$cliente/evidencias/ftriage") -ContentType 'application/json' `
                    -Headers @{ Authorization = "Bearer $token" } -Body ([System.IO.File]::ReadAllBytes($informeRuta)) -TimeoutSec 120 | Out-Null
                $datos['subido'] = $true; $datos.Remove('informe_ftriage')
            } catch { $datos['subido'] = $false; $datos['error_subida'] = $_.Exception.Message }
        }
        Escribir-Acuse 'triage' 'aplicada' ("triage terminado: {0}" -f (Texto (Leer-Campo $informe 'assessment.verdict'))) (Texto $a.ejecucion_id) $datos
    } catch {
        Escribir-Acuse 'triage' 'fallida' ("el triage no termino: {0}" -f $_.Exception.Message) (Texto $a.ejecucion_id) @{ salida = $a.salida }
    }
}

# === Protocolo de Wazuh ======================================================

$Acciones = @{
    'aislar' = ${function:Aislar}; 'liberar' = ${function:Liberar}; 'matar' = ${function:Matar}
    'cuarentena' = ${function:Cuarentena}; 'restaurar' = ${function:Restaurar}; 'conservar' = ${function:Conservar}
    'persistencia' = ${function:Persistencia}; 'persistencia-restaurar' = ${function:Persistencia-Restaurar}
    'bloquear-destino' = ${function:Bloquear-Destino}; 'desbloquear-destino' = ${function:Desbloquear-Destino}
    'ssh-clave' = ${function:Ssh-Clave}; 'ssh-clave-restaurar' = ${function:Ssh-Clave-Restaurar}
    'instantanea-ad' = ${function:Instantanea-AD}; 'triage' = ${function:Triage}
}

if ($Accion -eq '_triage_en_segundo_plano') { Triage-EnSegundoPlano $ArgumentosFondo; exit 0 }

$ejecucion = ''
try {
    if (-not $Acciones.ContainsKey($Accion)) { throw [Fallo]::new("accion desconocida: $Accion") }
    $linea = [Console]::In.ReadLine()
    if (-not $linea) { throw [Fallo]::new('execd no envio nada por stdin') }
    $mensaje = $linea | ConvertFrom-Json
    $comando = Texto (Leer-Campo $mensaje 'command')
    if ($comando -ne 'add' -and $comando -ne 'delete') { throw [Fallo]::new("comando de execd no reconocido: $comando") }
    $p = Leer-Campo $mensaje 'parameters.alert.data.responselab'
    if ($null -eq $p) { throw [Fallo]::new('parametros de ResponseLab ausentes en la orden') }
    $ejecucion = Texto (Leer-Campo $p 'ejecucion_id')
    if ($comando -eq 'delete') { exit 0 }      # ResponseLab deshace con su accion inversa, no con timeouts
    $clave = if ($ejecucion) { $ejecucion } else { $Accion }
    $pedido = A-Json ([ordered]@{ version = 1; origin = [ordered]@{ name = "responselab-$Accion"; module = 'active-response' }
                                  command = 'check_keys'; parameters = @{ keys = @($clave) } }) 4
    [Console]::Out.WriteLine($pedido); [Console]::Out.Flush()
    $respuesta = [Console]::In.ReadLine()
    if ($respuesta -and (Texto (Leer-Campo ($respuesta | ConvertFrom-Json) 'command')) -eq 'abort') {
        Escribir-Acuse $Accion 'rechazada' 'execd aborto la orden (repetida)' $ejecucion $null
        exit 0
    }
    $resultado = @(& $Acciones[$Accion] $p)
    # La accion devuelve (detalle, datos) al final de su salida
    $detalle = [string] $resultado[-2]; $datos = $resultado[-1]
    $estadoFinal = 'aplicada'
    if ($datos -is [System.Collections.IDictionary] -and $datos.Contains('estado')) { $estadoFinal = $datos['estado']; $datos.Remove('estado') }
    if ($Simulacion -and $datos -is [System.Collections.IDictionary]) { $datos['ordenes'] = @($script:Ordenes) }
    Escribir-Acuse $Accion $estadoFinal $detalle $ejecucion $datos
    exit 0
} catch {
    $mensajeError = $_.Exception.Message
    if (-not ($_.Exception -is [Fallo])) { $mensajeError = "error inesperado: $mensajeError" }
    Escribir-Acuse $Accion 'fallida' $mensajeError $ejecucion $null
    exit 1
}
