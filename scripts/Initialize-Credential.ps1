#Requires -Version 5.1
<#
.SYNOPSIS
    Stores the 1Password service account token in DPAPI-encrypted storage.

.DESCRIPTION
    Prompts for the service account token and saves it as a DPAPI-encrypted
    credential file. The file can only be decrypted by the same Windows user
    on the same machine -- ensuring the token is protected at rest.

    Run this once during initial setup, or again to rotate the token.

.PARAMETER CredentialPath
    Path for the encrypted credential file. Defaults to ~\.1pw-backup-cred.xml.

.EXAMPLE
    .\Initialize-Credential.ps1
    .\Initialize-Credential.ps1 -CredentialPath "C:\SecureStore\1pw-cred.xml"
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$CredentialPath = (Join-Path $env:USERPROFILE '.1pw-backup-cred.xml')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "`n1Password BCDR -- Credential Initialization" -ForegroundColor Cyan
Write-Host ("=" * 50)

# Warn if overwriting
if (Test-Path $CredentialPath) {
    Write-Host "`nExisting credential file found at: $CredentialPath" -ForegroundColor Yellow
    $confirm = Read-Host "Overwrite? (y/N)"
    if ($confirm -ne 'y') {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

# Prompt for token
Write-Host "`nEnter the 1Password Service Account token."
Write-Host "This is the token that starts with 'ops_' from your service account setup." -ForegroundColor Gray
$secureToken = Read-Host -AsSecureString "Service Account Token"

# Validate non-empty
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
try {
    $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ([string]::IsNullOrWhiteSpace($plainToken)) {
        throw "Token cannot be empty."
    }
    if ($plainToken -notmatch '^ops_') {
        Write-Host "WARNING: Token does not start with 'ops_'. Verify this is a valid service account token." -ForegroundColor Yellow
    }
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $plainToken = $null
}

# Store as DPAPI-encrypted credential
$cred = New-Object System.Management.Automation.PSCredential('1pw-service-account', $secureToken)
$cred | Export-Clixml -Path $CredentialPath

# Lock down file permissions (Windows ACL)
try {
    $acl = Get-Acl $CredentialPath
    $acl.SetAccessRuleProtection($true, $false)
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $currentUser,
        'FullControl',
        'Allow'
    )
    $acl.AddAccessRule($rule)
    # Allow SYSTEM access (required for backup agents, AV scanning, indexing)
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM',
        'FullControl',
        'Allow'
    )
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path $CredentialPath -AclObject $acl
    Write-Host "`nFile permissions locked to current user: $currentUser" -ForegroundColor Green
}
catch {
    Write-Host "`nWARNING: Could not restrict file permissions. Manually verify ACLs on: $CredentialPath" -ForegroundColor Yellow
}

# Verify round-trip (check SecureString length without exposing plaintext)
try {
    $testCred = Import-Clixml $CredentialPath
    if ($testCred.Password.Length -gt 0) {
        Write-Host "`nCredential stored and verified successfully." -ForegroundColor Green
        Write-Host "Path: $CredentialPath"
        Write-Host "Encrypted with: DPAPI (current user context)"
    }
    $testCred = $null
}
catch {
    throw "Credential verification failed: $_"
}

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Run .\Backup-1Password.ps1 -DryRun to validate the full configuration"
Write-Host "  2. Run .\Install-ScheduledTask.ps1 to set up automated daily backups"
Write-Host ""
