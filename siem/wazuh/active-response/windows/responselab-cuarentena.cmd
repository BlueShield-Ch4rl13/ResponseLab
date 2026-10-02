@echo off
rem Lanzador de ResponseLab para el active response de Wazuh (agente Windows).
rem El nombre del fichero es la accion: responselab-aislar.cmd -> aislar.
rem Todos los lanzadores son iguales; la logica esta en responselab_ar.ps1.
rem El agente de Wazuh es de 32 bits: Sysnative da la PowerShell de 64 bits,
rem sin la cual el registro (claves Run) y el cortafuegos se ven redirigidos.
setlocal
set "ACCION=%~n0"
set "ACCION=%ACCION:responselab-=%"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0responselab_ar.ps1" -Accion %ACCION%
exit /b %ERRORLEVEL%
