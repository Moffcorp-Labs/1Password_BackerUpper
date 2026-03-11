#Requires -Version 5.1
<#
.SYNOPSIS
    Detects vaults missing from the backup service account and recreates it with full coverage.

.DESCRIPTION
    1Password service accounts cannot be granted access to new vaults after creation.
    This script compares all organization vaults (visible to the signed-in admin) with
    the vaults accessible to the current backup service account. If gaps are found, it
    creates a NEW service account with access to all eligible vaults and stores the
    new token in DPAPI-encrypted storage.

    Requires: interactive admin/owner sign-in via 'op signin' before running.

    After this script runs, the OLD service account should be deleted (or left to expire)
    from the 1Password admin console. The CLI does not support deleting service accounts.

    Vault types excluded from sync (cannot be granted to service accounts):
    - Personal vaults
    - Employee vaults
    - The default "Everyone" shared vault

.PARAMETER ServiceAccountName
    Name for the new service account. Defaults to 'BCDR-Backup'.

.PARAMETER ExpiresIn
    Token expiry duration (e.g., '8760h' for 1 year). Omit for no expiry.

.PARAMETER CredentialPath
    Path for DPAPI-encrypted token file. Defaults to ~\.1pw-backup-cred.xml.

.PARAMETER Account
    1Password account shorthand or URL, for multi-account setups. Passed to op CLI.

.EXAMPLE
    # Check for vault gaps without making changes
    .\Sync-VaultAccess.ps1 -WhatIf

    # Create new service account with full vault access
    .\Sync-VaultAccess.ps1

    # Specify token expiry and custom SA name
    .\Sync-VaultAccess.ps1 -ServiceAccountName 'BCDR-Backup' -ExpiresIn '8760h'
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string]$ServiceAccountName = 'BCDR-Backup',

    [Parameter()]
    [string]$ExpiresIn,

    [Parameter()]
    [string]$CredentialPath = (Join-Path $env:USERPROFILE '.1pw-backup-cred.xml'),

    [Parameter()]
    [string]$Account
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Helpers (shared patterns from other scripts) --------------------------------

function Invoke-OpCli {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'op'
    $psi.Arguments = $Arguments -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    # Do NOT touch $psi.EnvironmentVariables -- on .NET Framework, accessing it
    # copies the entire environment into a case-insensitive StringDictionary which
    # can throw on duplicate env var names and corrupt the ProcessStartInfo.

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    return [PSCustomObject]@{
        Output   = $stdout
        Error    = $stderr
        ExitCode = $proc.ExitCode
    }
}

function ConvertFrom-JsonArray {
    param([Parameter(Mandatory)][string]$Json)
    $parsed = $Json | ConvertFrom-Json
    if ($null -eq $parsed) { return ,@() }
    if ($parsed -is [Array]) { return ,$parsed }
    return ,@($parsed)
}

# Vault types that cannot be granted to service accounts.
# 1Password rejects: Personal, Employee, and the default "Everyone" shared vault.
$script:ExcludedVaultTypes = @('PERSONAL', 'PRIVATE', 'EVERYONE', 'EMPLOYEE', 'USER_CREATED_PERSONAL')

# ---- Functions -------------------------------------------------------------------

function Test-OpCliVersion {
    <#
    .SYNOPSIS
        Verifies op CLI is v2.26.0+ (minimum for service-account create).
    #>
    $result = Invoke-OpCli @('--version')
    if ($result.ExitCode -ne 0) {
        throw "1Password CLI (op) not found or failed. Install: https://1password.com/downloads/command-line/"
    }
    $versionStr = $result.Output.Trim()
    Write-Host "op CLI: $versionStr"

    if ($versionStr -match '(\d+)\.(\d+)\.(\d+)') {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -lt 2 -or ($major -eq 2 -and $minor -lt 26)) {
            throw "op CLI v2.26.0+ required for 'service-account create'. Current: $versionStr. Update: winget upgrade AgileBits.1Password.CLI"
        }
    }
}

function Test-AdminSession {
    <#
    .SYNOPSIS
        Verifies the admin is signed in (interactive session, NOT service account).
    #>
    if ($env:OP_SERVICE_ACCOUNT_TOKEN) {
        throw "OP_SERVICE_ACCOUNT_TOKEN is set. This script requires interactive admin auth, not a service account. Clear the variable and run 'op signin'."
    }

    $args_ = @('whoami', '--format', 'json')
    if ($Account) { $args_ += @('--account', $Account) }

    $result = Invoke-OpCli $args_
    if ($result.ExitCode -ne 0) {
        throw "Not signed in as admin. Run 'op signin' first, then re-run this script.`nop stderr: $($result.Error)"
    }

    # Extract admin info via regex (op whoami returns duplicate keys that break
    # PS 5.1 ConvertFrom-Json -- url/URL, user_type/ServiceAccountType).
    $json = $result.Output
    $email = if ($json -match '"email"\s*:\s*"([^"]+)"') { $Matches[1] } else { 'unknown' }
    $url   = if ($json -match '"url"\s*:\s*"([^"]+)"')   { $Matches[1] } else { 'unknown' }

    # Reject if this is actually a service account session
    if ($json -match '"user_type"\s*:\s*"SERVICE_ACCOUNT"') {
        throw "Signed in as a service account, not an admin. Run 'op signin' with your admin credentials."
    }

    Write-Host "Admin session : $email ($url)"
    return @{ Email = $email; Url = $url }
}

function Get-AllOrgVaults {
    <#
    .SYNOPSIS
        Lists all vaults visible to the admin, excluding non-grantable types.
    .DESCRIPTION
        op vault list does not return a type field. This function calls
        op vault get for each vault to resolve the actual type, then filters
        out types that cannot be granted to service accounts (Personal,
        Private, Employee, Everyone).
    #>
    $args_ = @('vault', 'list', '--format', 'json')
    if ($Account) { $args_ += @('--account', $Account) }

    $result = Invoke-OpCli $args_
    if ($result.ExitCode -ne 0) {
        throw "Failed to list organization vaults: $($result.Error)"
    }

    $allVaults = ConvertFrom-JsonArray -Json $result.Output

    # op vault list doesn't return type. Probe each vault with op vault get.
    Write-Host "`nResolving vault types ($($allVaults.Count) vaults)..." -ForegroundColor Cyan
    foreach ($v in $allVaults) {
        $vType = 'UNKNOWN'

        # Check if type is already present (future CLI versions may include it)
        if ($v.PSObject.Properties['type'] -and $v.type) {
            $vType = $v.type
        }
        else {
            # Fetch vault detail to get the type field
            $detailArgs = @('vault', 'get', $v.id, '--format', 'json')
            if ($Account) { $detailArgs += @('--account', $Account) }
            $detail = Invoke-OpCli $detailArgs
            if ($detail.ExitCode -eq 0) {
                # Use regex to extract type (avoids ConvertFrom-Json issues)
                if ($detail.Output -match '"type"\s*:\s*"([^"]+)"') {
                    $vType = $Matches[1]
                }
            }
        }

        # Attach resolved type to the vault object
        $v | Add-Member -NotePropertyName '_resolvedType' -NotePropertyValue $vType -Force
    }

    # Separate grantable from excluded
    $grantable = @()
    $excluded  = @()
    foreach ($v in $allVaults) {
        if ($script:ExcludedVaultTypes -contains $v._resolvedType) {
            $excluded += $v
        }
        else {
            $grantable += $v
        }
    }

    Write-Host "`nAll organization vaults ($($allVaults.Count) total):" -ForegroundColor Cyan
    foreach ($v in $allVaults) {
        $marker = if ($script:ExcludedVaultTypes -contains $v._resolvedType) { 'SKIP' } else { ' OK ' }
        $color  = if ($marker -eq 'SKIP') { 'DarkGray' } else { 'White' }
        Write-Host "  [$marker] $($v.name) (type: $($v._resolvedType))" -ForegroundColor $color
    }

    if ($excluded.Count -gt 0) {
        Write-Host "`n  Skipped $($excluded.Count) non-grantable vault(s)" -ForegroundColor DarkGray
    }

    return ,@($grantable)
}

function Get-ServiceAccountVaults {
    <#
    .SYNOPSIS
        Lists vaults accessible to the current backup service account.
        Returns empty array if no credential file exists (first-time setup).
    #>
    if (-not (Test-Path $CredentialPath)) {
        Write-Host "No existing SA credential found at $CredentialPath (first-time setup)" -ForegroundColor Yellow
        return ,@()
    }

    try {
        $cred = Import-Clixml $CredentialPath
        $env:OP_SERVICE_ACCOUNT_TOKEN = $cred.GetNetworkCredential().Password
    }
    catch {
        Write-Host "WARNING: Could not decrypt SA credential file. Running as first-time setup." -ForegroundColor Yellow
        return ,@()
    }

    try {
        $result = Invoke-OpCli @('vault', 'list', '--format', 'json')
        if ($result.ExitCode -ne 0) {
            Write-Host "WARNING: SA authentication failed (token may be expired). Running as first-time setup." -ForegroundColor Yellow
            return ,@()
        }
        return ConvertFrom-JsonArray -Json $result.Output
    }
    finally {
        $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    }
}

function Show-GapAnalysis {
    <#
    .SYNOPSIS
        Compares admin-visible vaults with SA-accessible vaults and displays the gap.
    #>
    param(
        [Parameter(Mandatory)][object[]]$OrgVaults,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$SaVaults
    )

    $saVaultIds = @($SaVaults | ForEach-Object { $_.id })
    $missing = @($OrgVaults | Where-Object { $saVaultIds -notcontains $_.id })

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  Vault Coverage Analysis" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Organization vaults (grantable) : $($OrgVaults.Count)" -ForegroundColor White
    Write-Host "  SA-accessible vaults            : $($SaVaults.Count)" -ForegroundColor White
    Write-Host "  Missing from SA                 : $($missing.Count)" -ForegroundColor $(if ($missing.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""

    if ($SaVaults.Count -gt 0) {
        Write-Host "  Covered vaults:" -ForegroundColor Green
        foreach ($v in $SaVaults) {
            Write-Host "    [OK] $($v.name)" -ForegroundColor Green
        }
        Write-Host ""
    }

    if ($missing.Count -gt 0) {
        Write-Host "  Missing vaults (not backed up):" -ForegroundColor Red
        foreach ($v in $missing) {
            Write-Host "    [!!] $($v.name) ($($v.id))" -ForegroundColor Red
        }
        Write-Host ""
    }

    Write-Host ("=" * 60) -ForegroundColor Cyan

    return ,@($missing)
}

function New-BackupServiceAccount {
    <#
    .SYNOPSIS
        Creates a new service account with read_items access to all provided vaults.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Vaults,
        [Parameter(Mandatory)][string]$Name
    )

    # Build vault arguments: --vault "vault_id:read_items" for each vault
    # Quote the name in case it contains spaces
    $createArgs = @('service-account', 'create', "`"$Name`"")
    foreach ($v in $Vaults) {
        $createArgs += '--vault'
        $createArgs += "$($v.id):read_items"
    }
    if ($ExpiresIn) {
        $createArgs += '--expires-in'
        $createArgs += $ExpiresIn
    }
    if ($Account) {
        $createArgs += '--account'
        $createArgs += $Account
    }

    Write-Host "`nCreating service account '$Name' with $($Vaults.Count) vault(s)..." -ForegroundColor Cyan

    $result = Invoke-OpCli $createArgs
    if ($result.ExitCode -ne 0) {
        throw "Failed to create service account: $($result.Error)"
    }

    # Token is emitted to stdout (plain text, starts with ops_)
    $output = $result.Output.Trim()

    # Extract the token line (in case of extra output)
    $token = $null
    foreach ($line in $output -split "`n") {
        $line = $line.Trim()
        if ($line -match '^ops_') {
            $token = $line
            break
        }
    }

    if (-not $token) {
        # Fallback: entire output might be the token
        if ($output -match 'ops_') {
            $token = $output
        }
        else {
            throw "Service account created but could not extract token from output. Check the 1Password admin console."
        }
    }

    Write-Host "Service account created successfully." -ForegroundColor Green

    return $token
}

function Save-ServiceAccountToken {
    <#
    .SYNOPSIS
        Stores the SA token as a DPAPI-encrypted credential file.
        Reuses the same pattern as Initialize-Credential.ps1.
    #>
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$Path
    )

    $secureToken = ConvertTo-SecureString $Token -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential('1pw-service-account', $secureToken)
    $cred | Export-Clixml -Path $Path

    # Lock down file permissions (same as Initialize-Credential.ps1)
    try {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser,
            'FullControl',
            'Allow'
        )
        $acl.AddAccessRule($rule)
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM',
            'FullControl',
            'Allow'
        )
        $acl.AddAccessRule($systemRule)
        Set-Acl -Path $Path -AclObject $acl
    }
    catch {
        Write-Host "WARNING: Could not restrict file permissions on $Path. Verify ACLs manually." -ForegroundColor Yellow
    }

    Write-Host "Token stored (DPAPI encrypted): $Path" -ForegroundColor Green
}

function Confirm-NewServiceAccount {
    <#
    .SYNOPSIS
        Verifies the new SA can authenticate and access the expected vaults.
    #>
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][int]$ExpectedVaultCount
    )

    $env:OP_SERVICE_ACCOUNT_TOKEN = $Token
    try {
        $whoami = Invoke-OpCli @('whoami', '--format', 'json')
        if ($whoami.ExitCode -ne 0) {
            throw "New SA authentication failed: $($whoami.Error)"
        }

        $vaultResult = Invoke-OpCli @('vault', 'list', '--format', 'json')
        if ($vaultResult.ExitCode -ne 0) {
            throw "New SA cannot list vaults: $($vaultResult.Error)"
        }
        $vaults = ConvertFrom-JsonArray -Json $vaultResult.Output

        Write-Host "`nVerification:" -ForegroundColor Cyan
        Write-Host "  Expected vaults : $ExpectedVaultCount"
        Write-Host "  Actual vaults   : $($vaults.Count)"

        if ($vaults.Count -lt $ExpectedVaultCount) {
            $diff = $ExpectedVaultCount - $vaults.Count
            Write-Host "  WARNING: $diff vault(s) were not granted (likely non-grantable types)" -ForegroundColor Yellow
        }
        elseif ($vaults.Count -eq $ExpectedVaultCount) {
            Write-Host "  All vaults verified" -ForegroundColor Green
        }

        return $vaults.Count
    }
    finally {
        $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    }
}

# ---- Main ------------------------------------------------------------------------

$newToken = $null
try {
    Write-Host "`n1Password BCDR -- Vault Access Sync" -ForegroundColor Cyan
    Write-Host ("=" * 50)
    Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""

    # Prerequisites
    Test-OpCliVersion
    $adminInfo = Test-AdminSession

    # Gather vault data from both contexts
    Write-Host "`nScanning organization vaults (admin context)..." -ForegroundColor Cyan
    $orgVaults = Get-AllOrgVaults

    if ($orgVaults.Count -eq 0) {
        throw "No grantable vaults found in the organization. Verify admin access and vault types."
    }

    Write-Host "`nScanning service account vaults..." -ForegroundColor Cyan
    $saVaults = Get-ServiceAccountVaults

    # Gap analysis
    $missing = Show-GapAnalysis -OrgVaults $orgVaults -SaVaults $saVaults

    if ($missing.Count -eq 0) {
        Write-Host "`nNo action needed -- all grantable vaults are covered." -ForegroundColor Green
        Write-Host ""
        exit 0
    }

    # Prompt for SA recreation
    Write-Host ""
    Write-Host "To fix the $($missing.Count) missing vault(s), a NEW service account will be created" -ForegroundColor Yellow
    Write-Host "with read_items access to all $($orgVaults.Count) grantable vault(s)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "After this completes:" -ForegroundColor Yellow
    Write-Host "  1. The new token is stored automatically in DPAPI" -ForegroundColor Yellow
    Write-Host "  2. The next scheduled backup will use the new token" -ForegroundColor Yellow
    Write-Host "  3. Delete the OLD '$ServiceAccountName' SA from the 1Password admin console" -ForegroundColor Yellow
    Write-Host ""

    $saDisplayName = "$ServiceAccountName-$(Get-Date -Format 'yyyy-MM-dd')"

    if ($PSCmdlet.ShouldProcess(
        "Service account '$saDisplayName' with $($orgVaults.Count) vaults",
        "Create new 1Password service account and store DPAPI token"
    )) {
        # Create new SA
        $newToken = New-BackupServiceAccount -Vaults $orgVaults -Name $saDisplayName

        # Store token via DPAPI
        Save-ServiceAccountToken -Token $newToken -Path $CredentialPath

        # Verify
        $verifiedCount = Confirm-NewServiceAccount -Token $newToken -ExpectedVaultCount $orgVaults.Count

        # Summary
        Write-Host "`n" -NoNewline
        Write-Host ("=" * 60) -ForegroundColor Green
        Write-Host "  Sync Complete" -ForegroundColor Green
        Write-Host ("=" * 60) -ForegroundColor Green
        Write-Host ""
        Write-Host "  New SA        : $saDisplayName" -ForegroundColor White
        Write-Host "  Vaults granted: $verifiedCount" -ForegroundColor White
        Write-Host "  Token stored  : $CredentialPath" -ForegroundColor White
        Write-Host ""
        Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
        Write-Host "  1. Verify: .\scripts\Backup-1Password.ps1 -DryRun -Verbose" -ForegroundColor White
        Write-Host "  2. Delete the old service account from the 1Password admin console:" -ForegroundColor White
        Write-Host "     https://start.1password.com > Settings > Service Accounts" -ForegroundColor DarkGray
        Write-Host ""
    }
}
catch {
    Write-Host "`nFATAL: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    exit 1
}
finally {
    # Always clean up sensitive data from environment and variables
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    if ($newToken) {
        $newToken = $null
    }
}
