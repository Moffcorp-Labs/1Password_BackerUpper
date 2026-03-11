#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates a Windows Scheduled Task for daily 1Password BCDR backups.

.DESCRIPTION
    Registers a scheduled task that runs Backup-1Password.ps1 daily at the
    configured time. The task runs under the specified user account (which
    must match the user who ran Initialize-Credential.ps1 for DPAPI decryption).

.PARAMETER TaskTime
    Time to run the backup daily (24h format). Default: "02:00".

.PARAMETER RunAsUser
    Windows user account the task runs under. Default: current user.

.PARAMETER ScriptPath
    Path to Backup-1Password.ps1. Default: auto-detected from this script's location.

.PARAMETER ConfigPath
    Path to backup-config.json. Default: auto-detected from this script's location.

.PARAMETER Uninstall
    Removes the scheduled task instead of creating it.

.EXAMPLE
    .\Install-ScheduledTask.ps1
    .\Install-ScheduledTask.ps1 -TaskTime "03:30" -RunAsUser "DOMAIN\svc_backup"
    .\Install-ScheduledTask.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$TaskTime = '02:00',

    [Parameter()]
    [string]$RunAsUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,

    [Parameter()]
    [string]$ScriptPath,

    [Parameter()]
    [string]$ConfigPath,

    [Parameter()]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName = '1Password BCDR Backup'
$TaskPath = '\BCDR\'

# ─── Uninstall ─────────────────────────────────────────────────────────────────

if ($Uninstall) {
    $existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-Host "Scheduled task '$TaskPath$TaskName' removed." -ForegroundColor Green
    }
    else {
        Write-Host "Task '$TaskPath$TaskName' not found." -ForegroundColor Yellow
    }
    exit 0
}

# ─── Resolve Paths ─────────────────────────────────────────────────────────────

if (-not $ScriptPath) {
    $ScriptPath = Join-Path $PSScriptRoot 'Backup-1Password.ps1'
}
if (-not (Test-Path $ScriptPath)) {
    throw "Backup script not found: $ScriptPath"
}
$ScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $PSScriptRoot '..\config\backup-config.json'
}
if (Test-Path $ConfigPath) {
    $ConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)
}
else {
    Write-Host "WARNING: Config file not found at $ConfigPath. Task will be created but may fail at runtime." -ForegroundColor Yellow
}

# ─── PowerShell Executable ────────────────────────────────────────────────────

# All scripts target PowerShell 5.1 -- always use Windows PowerShell
$psExecutable = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
Write-Host "Using Windows PowerShell 5.1: $psExecutable"

# ─── Build Task Definition ─────────────────────────────────────────────────────

$arguments = "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File `"$ScriptPath`" -ConfigPath `"$ConfigPath`""

$action = New-ScheduledTaskAction `
    -Execute $psExecutable `
    -Argument $arguments `
    -WorkingDirectory (Split-Path $ScriptPath)

$trigger = New-ScheduledTaskTrigger -Daily -At $TaskTime

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 15)

$principal = New-ScheduledTaskPrincipal `
    -UserId $RunAsUser `
    -LogonType S4U `
    -RunLevel Highest

# ─── Register Task ─────────────────────────────────────────────────────────────

$existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Updating existing task '$TaskPath$TaskName'..." -ForegroundColor Yellow
    Set-ScheduledTask `
        -TaskName $TaskName `
        -TaskPath $TaskPath `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal | Out-Null
}
else {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -TaskPath $TaskPath `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description 'Daily backup of all 1Password Business vaults to CMS-encrypted archive (PKCS#7/EnvelopedCms).' | Out-Null
}

Write-Host "`nScheduled task configured:" -ForegroundColor Green
Write-Host "  Name     : $TaskPath$TaskName"
Write-Host "  Schedule : Daily at $TaskTime"
Write-Host "  User     : $RunAsUser"
Write-Host "  Script   : $ScriptPath"
Write-Host "  Config   : $ConfigPath"
Write-Host "  Retries  : 2 (15 min interval)"
Write-Host "  Timeout  : 2 hours"

Write-Host ""
Write-Host "NOTE: S4U logon does not support network resource access." -ForegroundColor Yellow
Write-Host "If BackupPath is a UNC/network share, re-register with -LogonType Password." -ForegroundColor Yellow

Write-Host "`nTo test manually:" -ForegroundColor Cyan
Write-Host "  Start-ScheduledTask -TaskName '$TaskName' -TaskPath '$TaskPath'"
Write-Host ""
