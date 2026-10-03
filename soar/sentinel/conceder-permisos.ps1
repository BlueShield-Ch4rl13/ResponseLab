<#
.SYNOPSIS
  Concede a los playbooks de ResponseLab los permisos que necesitan.

.DESCRIPTION
  Generado por ResponseLab (tools/compilar.py). No editar: se regenera.

  1. Rol "Microsoft Sentinel Responder" a la identidad de cada playbook sobre
     el grupo de recursos del workspace: comentar y crear tareas en incidentes.
  2. Permisos de aplicacion en Defender for Endpoint (WindowsDefenderATP) y en
     Microsoft Graph: a cada playbook solo los que usa.
  3. Rol "Microsoft Sentinel Automation Contributor" a "Azure Security
     Insights" sobre el grupo de los playbooks, para que la regla de
     automatizacion pueda ejecutarlos.

  Requiere: Az.Accounts, Az.Resources y Microsoft.Graph.Applications, y ser
  Owner (o User Access Administrator) de los dos grupos de recursos y poder
  conceder permisos de aplicacion (Privileged Role Administrator).
  Se puede ejecutar varias veces: lo que ya esta concedido se salta.

.EXAMPLE
  ./conceder-permisos.ps1 -GrupoPlaybooks rg-soar -GrupoWorkspace rg-sentinel
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $GrupoPlaybooks,
    [Parameter(Mandatory)] [string] $GrupoWorkspace,
    [string] $Suscripcion
)
$ErrorActionPreference = 'Stop'

$Permisos = @{
    'RL-Aislar-equipo' = @{ mde = @('Machine.Read.All', 'Machine.Isolate'); graph = @() }
    'RL-Confirmar-compromiso' = @{ mde = @(); graph = @('IdentityRiskyUser.ReadWrite.All') }
    'RL-Cuarentena-fichero' = @{ mde = @('Machine.Read.All', 'Machine.StopAndQuarantine'); graph = @() }
    'RL-Descartar-riesgo' = @{ mde = @(); graph = @('IdentityRiskyUser.ReadWrite.All') }
    'RL-Liberar-equipo' = @{ mde = @('Machine.Read.All', 'Machine.Isolate'); graph = @() }
    'RL-Paquete-investigacion' = @{ mde = @('Machine.Read.All', 'Machine.CollectForensics'); graph = @() }
    'RL-Reenviar-al-motor' = @{ mde = @(); graph = @() }
    'RL-Respuesta' = @{ mde = @('Machine.Read.All', 'Machine.Isolate', 'Machine.StopAndQuarantine', 'Machine.CollectForensics'); graph = @('User.RevokeSessions.All', 'IdentityRiskyUser.ReadWrite.All') }
    'RL-Revocar-sesiones' = @{ mde = @(); graph = @('User.RevokeSessions.All') }
}
$AppMde = 'fc780465-2017-40d4-a0c5-307022471b92'     # WindowsDefenderATP
$AppGraph = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph

if ($Suscripcion) { Set-AzContext -Subscription $Suscripcion | Out-Null }
$ctx = Get-AzContext
if (-not $ctx) { throw 'Ejecuta Connect-AzAccount antes.' }
Connect-MgGraph -TenantId $ctx.Tenant.Id -Scopes 'AppRoleAssignment.ReadWrite.All', 'Application.Read.All' -NoWelcome

$spMde = Get-MgServicePrincipal -Filter "appId eq '$AppMde'" -ErrorAction SilentlyContinue
$spGraph = Get-MgServicePrincipal -Filter "appId eq '$AppGraph'"
if (-not $spMde) { Write-Warning 'Defender for Endpoint no esta en el tenant: se omiten sus permisos.' }
$rgWorkspace = (Get-AzResourceGroup -Name $GrupoWorkspace).ResourceId
$rgPlaybooks = (Get-AzResourceGroup -Name $GrupoPlaybooks).ResourceId

function Conceder-Rol($objeto, $rol, $ambito, $quien) {
    $ya = Get-AzRoleAssignment -ObjectId $objeto -RoleDefinitionName $rol -Scope $ambito -ErrorAction SilentlyContinue
    if ($ya) { Write-Host "  = $rol ya concedido a $quien"; return }
    New-AzRoleAssignment -ObjectId $objeto -RoleDefinitionName $rol -Scope $ambito | Out-Null
    Write-Host "  + $rol a $quien"
}

function Conceder-Api($objeto, $sp, $valores, $quien) {
    if (-not $sp) { return }
    $ya = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $objeto -All |
          Where-Object { $_.ResourceId -eq $sp.Id } | ForEach-Object { $_.AppRoleId }
    foreach ($v in $valores) {
        $rol = $sp.AppRoles | Where-Object { $_.Value -eq $v -and $_.AllowedMemberTypes -contains 'Application' }
        if (-not $rol) { Write-Warning "  ! $($sp.DisplayName) no tiene el permiso $v"; continue }
        if ($ya -contains $rol.Id) { Write-Host "  = $v ya concedido a $quien"; continue }
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $objeto -PrincipalId $objeto `
            -ResourceId $sp.Id -AppRoleId $rol.Id | Out-Null
        Write-Host "  + $v a $quien"
    }
}

foreach ($nombre in $Permisos.Keys | Sort-Object) {
    $wf = Get-AzResource -ResourceGroupName $GrupoPlaybooks -ResourceType 'Microsoft.Logic/workflows' -Name $nombre -ErrorAction SilentlyContinue
    if (-not $wf) { Write-Host "- $nombre no esta desplegado: se omite"; continue }
    $objeto = $wf.Identity.PrincipalId
    if (-not $objeto) { Write-Warning "$nombre no tiene identidad administrada"; continue }
    Write-Host $nombre
    Conceder-Rol $objeto 'Microsoft Sentinel Responder' $rgWorkspace $nombre
    Conceder-Api $objeto $spMde $Permisos[$nombre].mde $nombre
    Conceder-Api $objeto $spGraph $Permisos[$nombre].graph $nombre
}

$asi = Get-AzADServicePrincipal -DisplayName 'Azure Security Insights' | Select-Object -First 1
if ($asi) {
    Write-Host 'Azure Security Insights'
    Conceder-Rol $asi.Id 'Microsoft Sentinel Automation Contributor' $rgPlaybooks 'Azure Security Insights'
} else {
    Write-Warning 'No se encontro Azure Security Insights: concede el permiso desde Sentinel > Configuracion > Permisos de playbooks.'
}
Write-Host 'Listo. Los permisos de API pueden tardar unos minutos en aplicarse.'
