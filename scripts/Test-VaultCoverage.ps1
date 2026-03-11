#Requires -Version 5.1
<#
.SYNOPSIS
    Audits which 1Password vaults the backup service account can access.

.DESCRIPTION
    Lists all vaults accessible to the configured service account and
    reports item counts per vault. Since service accounts cannot enumerate
    vaults they lack access to, this script provides visibility into what
    IS covered -- admins should compare this against the full vault list in
    the 1Password admin console.

    Run periodically (or after creating new vaults) to catch access gaps.

.PARAMETER ConfigPath
    Path to backup-config.json (for consistent credential loading).

.EXAMPLE
    .\Test-VaultCoverage.ps1
    .\Test-VaultCoverage.ps1 | Out-File vault-audit.txt
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── op CLI helper ─────────────────────────────────────────────────────────────

function Invoke-OpCli {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'op'
    $escaped = $Arguments | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"{0}"' -f ($_ -replace '"', '\"')
        } else { $_ }
    }
    $psi.Arguments = $escaped -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        $exitCode = $proc.ExitCode
    }
    finally {
        $proc.Dispose()
    }

    return [PSCustomObject]@{
        Output   = $stdout
        Error    = $stderr
        ExitCode = $exitCode
    }
}

function ConvertFrom-JsonArray {
    param([Parameter(Mandatory)][string]$Json)
    $parsed = $Json | ConvertFrom-Json
    if ($null -eq $parsed) { return ,@() }
    if ($parsed -is [Array]) { return ,$parsed }
    return ,@($parsed)
}

# ─── Main ──────────────────────────────────────────────────────────────────────

try {
    # ─── Authentication ────────────────────────────────────────────────────────

    if (-not $env:OP_SERVICE_ACCOUNT_TOKEN) {
        $credPath = Join-Path $env:USERPROFILE '.1pw-backup-cred.xml'
        if (-not (Test-Path $credPath)) {
            throw "No service account token. Set OP_SERVICE_ACCOUNT_TOKEN or run Initialize-Credential.ps1."
        }
        $cred = Import-Clixml $credPath
        $env:OP_SERVICE_ACCOUNT_TOKEN = $cred.GetNetworkCredential().Password
    }

    # ─── Verify Authentication ─────────────────────────────────────────────────

    $whoamiResult = Invoke-OpCli @('whoami', '--format', 'json')
    if ($whoamiResult.ExitCode -ne 0) {
        throw "op CLI authentication failed: $($whoamiResult.Error)"
    }
    # op whoami returns duplicate keys differing only by case (url/URL,
    # user_type/ServiceAccountType). PS 5.1 ConvertFrom-Json is case-insensitive
    # and rejects these. Extract the values we need via regex instead.
    $whoamiJson = $whoamiResult.Output
    $acctUrl  = if ($whoamiJson -match '"url"\s*:\s*"([^"]+)"') { $Matches[1] } else { 'unknown' }
    $acctUuid = if ($whoamiJson -match '"account_uuid"\s*:\s*"([^"]+)"') { $Matches[1] } else { 'unknown' }

    # ─── Enumerate Vaults ──────────────────────────────────────────────────────

    Write-Host "`n1Password Vault Coverage Audit" -ForegroundColor Cyan
    Write-Host ("=" * 60)
    Write-Host "Account  : $acctUrl"
    Write-Host "Auth     : Service Account ($acctUuid)"
    Write-Host "Date     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ("=" * 60)

    $vaultResult = Invoke-OpCli @('vault', 'list', '--format', 'json')
    if ($vaultResult.ExitCode -ne 0) {
        throw "Failed to list vaults: $($vaultResult.Error)"
    }
    $vaults = ConvertFrom-JsonArray -Json $vaultResult.Output

    if ($vaults.Count -eq 0) {
        Write-Host "`nWARNING: No vaults accessible!" -ForegroundColor Red
        Write-Host "Grant vault access to the service account in the 1Password admin console."
        exit 1
    }

    $totalItems = 0
    $results = foreach ($vault in $vaults) {
        $itemResult = Invoke-OpCli @('item', 'list', '--vault', $vault.id, '--format', 'json')
        $items = @()
        if ($itemResult.ExitCode -eq 0) {
            $items = ConvertFrom-JsonArray -Json $itemResult.Output
        }
        $totalItems += $items.Count

        [PSCustomObject]@{
            VaultName = $vault.name
            VaultId   = $vault.id
            ItemCount = $items.Count
        }
    }

    Write-Host ""
    $results | Format-Table -AutoSize

    Write-Host ("-" * 60)
    Write-Host "Accessible vaults : $($vaults.Count)" -ForegroundColor Green
    Write-Host "Total items       : $totalItems"
    Write-Host ("-" * 60)

    Write-Host "`nAction required:" -ForegroundColor Yellow
    Write-Host "  Compare the vault list above against ALL vaults in your 1Password"
    Write-Host "  admin console (https://start.1password.com). Any vault NOT listed"
    Write-Host "  above is NOT being backed up."
    Write-Host ""
    Write-Host "  To grant access: Admin Console > Service Accounts > Select account > Add Vault"
    Write-Host ""
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
}
