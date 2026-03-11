#Requires -Version 5.1
<#
.SYNOPSIS
    Generates the encryption certificate for 1Password BCDR backups.

.DESCRIPTION
    Creates a self-signed Document Encryption certificate, exports the
    private key (.pfx) for physical safe storage, and leaves only the
    public key in the certificate store for backup encryption.

    Run this ONCE during initial setup.

.PARAMETER Subject
    Certificate subject name. Default: "CN=1PW BCDR Backup Encryption".

.PARAMETER ValidYears
    Certificate validity in years. Default: 10.

.PARAMETER KeyLength
    RSA key length. Default: 4096.

.PARAMETER ExportPath
    Directory to export .pfx and .cer files. Default: current directory.

.PARAMETER CertStoreLocation
    Certificate store. Default: Cert:\CurrentUser\My.

.EXAMPLE
    .\New-BackupCertificate.ps1
    .\New-BackupCertificate.ps1 -ExportPath "C:\CertExport" -ValidYears 5
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$Subject = 'CN=1PW BCDR Backup Encryption',

    [Parameter()]
    [int]$ValidYears = 10,

    [Parameter()]
    [int]$KeyLength = 4096,

    [Parameter()]
    [string]$ExportPath = (Get-Location).Path,

    [Parameter()]
    [string]$CertStoreLocation = 'Cert:\CurrentUser\My'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "`n1Password BCDR -- Certificate Generation" -ForegroundColor Cyan
Write-Host ("=" * 55)

$cert = $null
$thumbprint = $null

try {
    # ─── Generate Certificate ──────────────────────────────────────────────────

    Write-Host "`nGenerating $KeyLength-bit RSA Document Encryption certificate..."

    $certParams = @{
        Subject           = $Subject
        Type              = 'DocumentEncryptionCert'
        KeyUsage          = 'KeyEncipherment', 'DataEncipherment'
        KeyAlgorithm      = 'RSA'
        KeyLength         = $KeyLength
        HashAlgorithm     = 'SHA256'
        NotAfter          = (Get-Date).AddYears($ValidYears)
        CertStoreLocation = $CertStoreLocation
    }

    $cert = New-SelfSignedCertificate @certParams
    $thumbprint = $cert.Thumbprint

    Write-Host "Certificate created." -ForegroundColor Green
    Write-Host "  Subject    : $($cert.Subject)"
    Write-Host "  Thumbprint : $thumbprint"
    Write-Host "  Expires    : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
    Write-Host "  Key Size   : $KeyLength bit"

    # ─── Export Private Key (.pfx) ─────────────────────────────────────────────

    $pfxPath = Join-Path $ExportPath "BCDR_1PW_Backup_Key.pfx"
    $cerPath = Join-Path $ExportPath "BCDR_1PW_Backup_Cert.cer"

    Write-Host "`nExporting private key (.pfx)..." -ForegroundColor Yellow
    Write-Host "Choose a strong password. You will need this password + the .pfx file to restore backups."
    $pfxPassword = Read-Host -AsSecureString "PFX Password"
    $pfxPasswordConfirm = Read-Host -AsSecureString "Confirm PFX Password"

    # Verify passwords match
    $bstr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pfxPassword)
    $bstr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pfxPasswordConfirm)
    try {
        $plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
        $plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
        if ($plain1 -ne $plain2) { throw "Passwords do not match." }
        if ($plain1.Length -lt 12) { throw "Password must be at least 12 characters." }
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
        $plain1 = $null
        $plain2 = $null
    }

    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword | Out-Null
    Write-Host "  Exported: $pfxPath" -ForegroundColor Green

    # Dispose SecureStrings
    $pfxPassword.Dispose()
    $pfxPasswordConfirm.Dispose()

    # ─── Export Public Certificate (.cer) ──────────────────────────────────────

    Write-Host "Exporting public certificate (.cer)..."
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Write-Host "  Exported: $cerPath" -ForegroundColor Green

    # ─── Remove Private Key from Store ─────────────────────────────────────────

    Write-Host "`nRemoving private key from certificate store..."
    Remove-Item "$CertStoreLocation\$thumbprint" -Force

    # Re-import public cert only (no private key)
    Import-Certificate -FilePath $cerPath -CertStoreLocation $CertStoreLocation | Out-Null
    Write-Host "  Public-only certificate re-imported to store." -ForegroundColor Green

    # Verify no private key
    $reimported = Get-Item "$CertStoreLocation\$thumbprint"
    if ($reimported.HasPrivateKey) {
        Write-Host "  WARNING: Private key still present in store!" -ForegroundColor Red
    }
    else {
        Write-Host "  Confirmed: No private key in store." -ForegroundColor Green
    }

    # ─── Summary ───────────────────────────────────────────────────────────────

    Write-Host ("`n" + ("=" * 55)) -ForegroundColor Cyan
    Write-Host "Certificate Thumbprint (for backup-config.json):" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  $thumbprint" -ForegroundColor White
    Write-Host ""
    Write-Host ("=" * 55) -ForegroundColor Cyan

    Write-Host "`nAction items:" -ForegroundColor Yellow
    Write-Host "  1. PRINT the .pfx file and its password, store in physical safe"
    Write-Host "     File: $pfxPath"
    Write-Host ""
    Write-Host "  2. KEEP the .cer file as a backup (public key only, safe to store digitally)"
    Write-Host "     File: $cerPath"
    Write-Host ""
    Write-Host "  3. DELETE the .pfx from this machine after printing/storing:"
    Write-Host "     Remove-Item '$pfxPath' -Force" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  4. ADD the thumbprint to config/backup-config.json:"
    Write-Host "     `"CertificateThumbprint`": `"$thumbprint`"" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  5. RUN a dry-run to validate:"
    Write-Host "     .\Backup-1Password.ps1 -DryRun -Verbose" -ForegroundColor Gray
    Write-Host ""
}
catch {
    # Clean up cert from store on any failure
    if ($thumbprint) {
        Remove-Item "$CertStoreLocation\$thumbprint" -Force -ErrorAction SilentlyContinue
    }
    throw
}
