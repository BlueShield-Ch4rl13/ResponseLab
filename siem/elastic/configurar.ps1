<#
.SYNOPSIS
  Conecta Elastic Security con el motor de ResponseLab.

.DESCRIPTION
  1. Crea (o reutiliza) un conector Webhook "ResponseLab" en Kibana que envia
     las alertas a /v1/<cliente>/alertas/elastic. La autenticacion es Basic con
     el token de ingesta como contrasena: Kibana la guarda cifrada en "secrets";
     una cabecera Authorization escrita a mano quedaria en claro en "config".
  2. Anade la accion del conector a las reglas de deteccion cuyo nombre esta en
     reglas-responselab.json (las de DetectionLab, con o sin el prefijo "DL - "),
     en bloque con la API _bulk_action.

  La accion envia {"rule": {...}, "alerts": [...]} con {{{context.alerts.asJSON}}}:
  el motor separa cada alerta y descarta las repetidas por su id.
  Requiere Kibana 8.8 o posterior (frecuencia por accion y arrays .asJSON).

.EXAMPLE
  $token = Read-Host -AsSecureString 'Token de ingesta'
  ./configurar.ps1 -Kibana https://kibana:5601 -Usuario elastic -Motor https://10.0.30.20:8443 -Cliente lab -TokenIngesta $token

.EXAMPLE
  ./configurar.ps1 -Kibana https://kibana:5601 -Usuario elastic -Motor https://motor:8443 -Cliente lab -TokenIngesta $token -SoloConector
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)] [string] $Kibana,
    [Parameter(Mandatory = $true)] [string] $Usuario,
    [Parameter(Mandatory = $true)] [string] $Motor,
    [Parameter(Mandatory = $true)] [string] $Cliente,
    [Parameter(Mandatory = $true)] [securestring] $TokenIngesta,
    [securestring] $Clave,
    [string] $Espacio = 'default',
    [switch] $SoloConector,
    [switch] $SinVerificarTls
)
$ErrorActionPreference = 'Stop'

function Texto-Plano([securestring] $Seguro) {
    $puntero = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Seguro)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($puntero) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($puntero) }
}

if (-not $Clave) { $Clave = Read-Host -AsSecureString "Contrasena de $Usuario en Kibana" }
$par = '{0}:{1}' -f $Usuario, (Texto-Plano $Clave)
$cabeceras = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($par)); 'kbn-xsrf' = 'true' }
$base = $Kibana.TrimEnd('/') + $(if ($Espacio -ne 'default') { "/s/$Espacio" } else { '' })
$extra = @{}
if ($SinVerificarTls) {
    if ($PSVersionTable.PSVersion.Major -ge 6) { $extra['SkipCertificateCheck'] = $true }
    else { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Kibana([string] $Metodo, [string] $Ruta, $Cuerpo) {
    $p = @{ Method = $Metodo; Uri = $base + $Ruta; Headers = $cabeceras; ContentType = 'application/json' } + $extra
    if ($null -ne $Cuerpo) { $p['Body'] = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Cuerpo -Depth 10 -Compress)) }
    return Invoke-RestMethod @p
}

# -- 1. Conector --------------------------------------------------------------
$url = '{0}/v1/{1}/alertas/elastic' -f $Motor.TrimEnd('/'), $Cliente
$conector = @(Kibana GET '/api/actions/connectors' $null) | Where-Object { $_.name -eq 'ResponseLab' -and $_.connector_type_id -eq '.webhook' } | Select-Object -First 1
if ($conector) {
    Write-Host "Conector ResponseLab ya existe ($($conector.id)): se actualiza la URL y el token"
    if ($PSCmdlet.ShouldProcess('conector ResponseLab', 'actualizar')) {
        $conector = Kibana PUT "/api/actions/connector/$($conector.id)" @{
            name = 'ResponseLab'
            config = @{ url = $url; method = 'post'; headers = @{ 'Content-Type' = 'application/json' }; hasAuth = $true }
            secrets = @{ user = $Cliente; password = (Texto-Plano $TokenIngesta) } }
    }
} elseif ($PSCmdlet.ShouldProcess('conector ResponseLab', 'crear')) {
    $conector = Kibana POST '/api/actions/connector' @{
        name = 'ResponseLab'; connector_type_id = '.webhook'
        config = @{ url = $url; method = 'post'; headers = @{ 'Content-Type' = 'application/json' }; hasAuth = $true }
        secrets = @{ user = $Cliente; password = (Texto-Plano $TokenIngesta) } }
    Write-Host "Conector ResponseLab creado ($($conector.id)) -> $url"
}
if ($SoloConector) { return }

# -- 2. Accion en las reglas de DetectionLab ---------------------------------
$lista = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'reglas-responselab.json') -Raw | ConvertFrom-Json
$titulos = @{}
foreach ($t in $lista.titulos) { $titulos[$t.ToLowerInvariant()] = $true }

$reglas = @(); $pagina = 1
do {
    $r = Kibana GET "/api/detection_engine/rules/_find?page=$pagina&per_page=500" $null
    $reglas += @($r.data); $pagina++
} while ($reglas.Count -lt $r.total -and @($r.data).Count -gt 0)

$ids = @()
foreach ($regla in $reglas) {
    $nombre = ([string] $regla.name).Trim() -replace '^(?i)(dl|rl|responselab)\s*-\s*', ''
    if (-not $titulos.ContainsKey($nombre.ToLowerInvariant())) { continue }
    $ya = @($regla.actions | Where-Object { $_.id -eq $conector.id })
    if ($ya.Count -eq 0) { $ids += $regla.id }
}
Write-Host ("Reglas de Kibana: {0}; de DetectionLab sin la accion: {1}" -f $reglas.Count, $ids.Count)
if ($ids.Count -eq 0) { return }

$cuerpoAccion = '{"rule":{"id":"{{context.rule.id}}","name":"{{context.rule.name}}"},"alerts":{{{context.alerts.asJSON}}} }'
for ($i = 0; $i -lt $ids.Count; $i += 100) {
    $lote = $ids[$i..([Math]::Min($i + 99, $ids.Count - 1))]
    if ($PSCmdlet.ShouldProcess("$($lote.Count) reglas", 'anadir la accion ResponseLab')) {
        $resultado = Kibana POST '/api/detection_engine/rules/_bulk_action' @{
            action = 'edit'; ids = @($lote)
            edit = @(@{ type = 'add_rule_actions'; value = @{ actions = @(@{
                id = $conector.id; group = 'default'; params = @{ body = $cuerpoAccion }
                frequency = @{ summary = $true; notifyWhen = 'onActiveAlert'; throttle = $null } }) } }) }
        Write-Host ("  lote {0}: {1} actualizadas, {2} con error" -f ($i / 100 + 1), $resultado.attributes.summary.succeeded, $resultado.attributes.summary.failed)
    }
}
