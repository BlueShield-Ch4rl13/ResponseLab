<#
.SYNOPSIS
  Instala los scripts de active response de ResponseLab en un agente Windows de Wazuh 4.x.

.DESCRIPTION
  1. Copia responselab_ar.ps1 y los lanzadores responselab-<accion>.cmd a
     active-response\bin del agente.
  2. Deja esa carpeta y C:\ProgramData\ResponseLab solo para SYSTEM y
     Administradores: los scripts se ejecutan como SYSTEM y un usuario que
     pudiera editarlos tendria una escalada de privilegios servida.
  3. Comprueba que el agente envia active-response\active-responses.log al
     manager (por ahi vuelven los acuses) y, si no, lo anade a ossec.conf y
     reinicia el servicio.

  Ejecutar como administrador:
    powershell -ExecutionPolicy Bypass -File siem\wazuh\instalar-agente-windows.ps1

  Para muchos equipos: el mismo script desde una GPO de inicio o Intune.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $Agente = "${env:ProgramFiles(x86)}\ossec-agent"
)
$ErrorActionPreference = 'Stop'

$identidad = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identidad.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Ejecutar como administrador' }
$bin = Join-Path $Agente 'active-response\bin'
if (-not (Test-Path -LiteralPath $bin)) { throw "No hay agente de Wazuh en $Agente (parametro -Agente)" }
$origen = Join-Path $PSScriptRoot 'active-response\windows'

$ficheros = @(Get-ChildItem -LiteralPath $origen -Filter 'responselab*')
foreach ($f in $ficheros) {
    if ($PSCmdlet.ShouldProcess($f.Name, "copiar a $bin")) { Copy-Item -LiteralPath $f.FullName -Destination $bin -Force }
}
Write-Host ("{0} ficheros copiados a {1}" -f $ficheros.Count, $bin)

$estado = Join-Path $env:ProgramData 'ResponseLab'
foreach ($carpeta in @($estado)) {
    if (-not (Test-Path -LiteralPath $carpeta)) { New-Item -ItemType Directory -Path $carpeta -Force | Out-Null }
    if ($PSCmdlet.ShouldProcess($carpeta, 'permisos solo SYSTEM y Administradores')) {
        & icacls.exe $carpeta /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    }
}
foreach ($f in Get-ChildItem -LiteralPath $bin -Filter 'responselab*') {
    if ($PSCmdlet.ShouldProcess($f.Name, 'permisos solo SYSTEM y Administradores')) {
        & icacls.exe $f.FullName /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    }
}

$conf = Join-Path $Agente 'ossec.conf'
$texto = Get-Content -LiteralPath $conf -Raw
if ($texto -notmatch 'active-responses\.log') {
    if ($PSCmdlet.ShouldProcess($conf, 'anadir active-responses.log y reiniciar WazuhSvc')) {
        Copy-Item -LiteralPath $conf -Destination "$conf.antes-responselab" -Force
        Add-Content -LiteralPath $conf -Encoding ASCII -Value @(
            '<ossec_config>', '  <localfile>', '    <location>active-response\active-responses.log</location>',
            '    <log_format>syslog</log_format>', '  </localfile>', '</ossec_config>')
        Restart-Service -Name WazuhSvc
        Write-Host 'Anadido active-responses.log a ossec.conf y reiniciado el agente'
    }
}
$managers = [regex]::Matches($texto, '<address>\s*([^<\s]+)\s*</address>') | ForEach-Object { $_.Groups[1].Value }
Write-Host ("Manager(es) que nunca se bloquean al aislar: {0}" -f ($managers -join ', '))
if (@($managers | Where-Object { $_ -notmatch '^[0-9.]+$' }).Count) {
    Write-Warning 'El manager esta por nombre: durante el aislamiento no hay DNS. Pon su IP en ossec.conf o anade los DNS a "permitidos".'
}
