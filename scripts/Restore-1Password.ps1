#Requires -Version 5.1
<#
.SYNOPSIS
    Restores 1Password items from a CMS-encrypted BCDR backup archive.

.DESCRIPTION
    Decrypts a hybrid-encrypted backup archive (AES-256-CBC + CMS key envelope)
    using the recovery certificate (.pfx), then optionally restores items to
    1Password vaults via the op CLI.

    This script supports two modes:
    - Extract only: Decrypt and extract for manual review (default).
    - Restore: Recreate items in 1Password (requires -Restore flag).

    IMPORTANT: The .pfx file and its password must be retrieved from the
    physical safe before running this script.

.PARAMETER ArchivePath
    Path to the .zip.cms encrypted backup file.

.PARAMETER PfxPath
    Path to the .pfx certificate file (private key, from physical safe).

.PARAMETER PfxPassword
    Password for the .pfx file. If not provided, you will be prompted interactively.

.PARAMETER OutputPath
    Directory to extract backup contents into. Default: .\restore_<timestamp>

.PARAMETER Restore
    Actually restore items to 1Password. Without this flag, only extracts.

.PARAMETER TargetVault
    Restore all items into a specific vault (useful for DR scenarios).
    If not specified, items restore to their original vaults.

.PARAMETER Force
    Skip interactive confirmation prompt (required for non-interactive/automated restores).

.EXAMPLE
    # Extract and review only (safe)
    .\Restore-1Password.ps1 -ArchivePath "C:\Backups\BCDR_1PW_20260309.zip.cms" -PfxPath ".\backup-key.pfx"

    # Full restore to original vaults
    .\Restore-1Password.ps1 -ArchivePath "C:\Backups\BCDR_1PW_20260309.zip.cms" -PfxPath ".\backup-key.pfx" -Restore

    # Restore to a single recovery vault, non-interactive
    .\Restore-1Password.ps1 -ArchivePath "..." -PfxPath "..." -Restore -TargetVault "DR-Recovery" -Force
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$ArchivePath,

    [Parameter(Mandatory)]
    [string]$PfxPath,

    [Parameter()]
    [securestring]$PfxPassword,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$Restore,

    [Parameter()]
    [string]$TargetVault,

    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

# ─── Script state ──────────────────────────────────────────────────────────────

$script:RestoreTempDir = $null
$script:LogPath = $null
$script:CertImported = $false
$script:CertThumbprint = $null

# ─── Logging ───────────────────────────────────────────────────────────────────

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$timestamp [$Level] $Message"

    if ($script:LogPath) {
        try { Add-Content -Path $script:LogPath -Value $entry -ErrorAction Stop }
        catch { Write-Warning "Log write failed: $_" }
    }

    switch ($Level) {
        'ERROR' { Write-Warning "[ERROR] $Message" }
        'WARN'  { Write-Warning $Message }
        default { Write-Verbose $entry }
    }
}

# ─── op CLI helper ─────────────────────────────────────────────────────────────

function Invoke-OpCli {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'op'
    $psi.Arguments = $Arguments -join ' '
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

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

# ─── JSON Transform for op item create ─────────────────────────────────────────

function ConvertTo-CreateTemplate {
    <#
    .SYNOPSIS
        Transforms an op item get export into a format compatible with op item create.
        Strips server-generated read-only fields that op rejects.
    #>
    param([string]$ItemJson)

    $item = $ItemJson | ConvertFrom-Json

    # Fields that op item create rejects (server-generated / read-only)
    $readOnlyProps = @('id', 'created_at', 'updated_at', 'last_edited_by',
                       'version', 'vault', 'additional_information')

    # Build a clean object
    $clean = [ordered]@{}
    foreach ($prop in $item.PSObject.Properties) {
        if ($readOnlyProps -contains $prop.Name) { continue }

        if ($prop.Name -eq 'fields' -and $prop.Value) {
            # Strip read-only field properties
            $cleanFields = @()
            foreach ($field in $prop.Value) {
                $cleanField = [ordered]@{}
                foreach ($fp in $field.PSObject.Properties) {
                    if (@('id', 'reference') -contains $fp.Name) { continue }
                    $cleanField[$fp.Name] = $fp.Value
                }
                $cleanFields += $cleanField
            }
            $clean['fields'] = $cleanFields
        }
        else {
            $clean[$prop.Name] = $prop.Value
        }
    }

    return ($clean | ConvertTo-Json -Depth 20)
}

# ─── Validation ────────────────────────────────────────────────────────────────

if (-not (Test-Path $ArchivePath)) {
    throw "Archive not found: $ArchivePath"
}
if (-not (Test-Path $PfxPath)) {
    throw "PFX certificate not found: $PfxPath"
}

# Prompt for PFX password if not provided
if (-not $PfxPassword) {
    if (-not [Environment]::UserInteractive) {
        throw "PfxPassword is required in non-interactive mode."
    }
    $PfxPassword = Read-Host -AsSecureString "PFX Password"
}

if (-not $OutputPath) {
    $OutputPath = Join-Path (Get-Location) "restore_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# Set up restore log
$script:LogPath = Join-Path $OutputPath "restore_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create a secure temp directory for intermediate files
$script:RestoreTempDir = Join-Path ([System.IO.Path]::GetTempPath()) "1pw_restore_$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $script:RestoreTempDir -Force | Out-Null

$exitCode = 0
try {
    # ─── Load Certificate ──────────────────────────────────────────────────────

    Write-Host "`n1Password BCDR -- Restore" -ForegroundColor Cyan
    Write-Host ("=" * 50)
    Write-Log "=== 1Password BCDR Restore Started ==="

    Write-Host "Loading certificate from PFX..."
    $pfxFullPath = [System.IO.Path]::GetFullPath($PfxPath)
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $pfxFullPath,
            $PfxPassword,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )
    }
    catch {
        throw "Failed to load PFX. Check the file and password. Error: $_"
    }
    Write-Host "  Certificate: $($cert.Subject)" -ForegroundColor Green
    Write-Host "  Thumbprint : $($cert.Thumbprint)"
    Write-Log "Certificate loaded: $($cert.Subject) ($($cert.Thumbprint))"

    # .NET Framework's EnvelopedCms.Decrypt() uses the legacy CAPI layer which
    # cannot access private keys loaded directly from PFX into memory. The cert
    # must be in a Windows certificate store for CAPI to find the private key.
    # Import temporarily; cleaned up in the finally block.
    $script:CertThumbprint = $cert.Thumbprint
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
    try {
        $store.Open('ReadWrite')
        $store.Add($cert)
        $script:CertImported = $true
        Write-Log "Certificate temporarily imported to CurrentUser\My for CAPI decryption"
    }
    finally {
        $store.Close()
    }

    # ─── Decrypt (hybrid AES+CMS) ─────────────────────────────────────────────

    $zipPath = Join-Path $script:RestoreTempDir "backup.zip"

    Write-Host "Decrypting archive..."
    Write-Log "Decrypting: $ArchivePath"

    $fsIn = $null
    $fsOut = $null
    $cs = $null
    $aes = $null
    $decryptor = $null
    $keyMaterial = $null
    $aesKey = $null
    $aesIV = $null
    try {
        $fsIn = [System.IO.File]::OpenRead([System.IO.Path]::GetFullPath($ArchivePath))

        # Read CMS envelope length
        $lenBytes = New-Object byte[] 4
        $null = $fsIn.Read($lenBytes, 0, 4)
        $envelopeLen = [BitConverter]::ToInt32($lenBytes, 0)

        if ($envelopeLen -le 0 -or $envelopeLen -gt 10MB) {
            throw "Invalid envelope length: $envelopeLen. File may be corrupt or not a BCDR archive."
        }

        # Read and decrypt CMS envelope to recover AES key+IV
        $envelopeBytes = New-Object byte[] $envelopeLen
        $null = $fsIn.Read($envelopeBytes, 0, $envelopeLen)

        $cms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
        $cms.Decode($envelopeBytes)
        $certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $certCollection.Add($cert) | Out-Null
        $cms.Decrypt($certCollection)

        $keyMaterial = $cms.ContentInfo.Content
        if ($keyMaterial.Length -ne 48) {
            throw "Invalid key material length: $($keyMaterial.Length). Expected 48 bytes."
        }

        $aesKey = New-Object byte[] 32
        $aesIV = New-Object byte[] 16
        [Array]::Copy($keyMaterial, 0, $aesKey, 0, 32)
        [Array]::Copy($keyMaterial, 32, $aesIV, 0, 16)

        # Stream-decrypt the AES ciphertext
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.KeySize = 256
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV = $aesIV

        $decryptor = $aes.CreateDecryptor()
        $cs = New-Object System.Security.Cryptography.CryptoStream($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $fsOut = [System.IO.File]::Create($zipPath)

        $buffer = New-Object byte[] 81920
        while ($true) {
            $read = $cs.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $fsOut.Write($buffer, 0, $read)
        }

        Write-Host "  Decryption successful." -ForegroundColor Green
        Write-Log "Decryption successful"
    }
    finally {
        if ($fsOut) { $fsOut.Dispose() }
        if ($cs) { $cs.Dispose() }
        if ($fsIn) { $fsIn.Dispose() }
        if ($decryptor) { $decryptor.Dispose() }
        if ($aes) { $aes.Dispose() }
        # Zero key material
        if ($keyMaterial) { [Array]::Clear($keyMaterial, 0, $keyMaterial.Length) }
        if ($aesKey) { [Array]::Clear($aesKey, 0, $aesKey.Length) }
        if ($aesIV) { [Array]::Clear($aesIV, 0, $aesIV.Length) }
    }

    # ─── Extract ───────────────────────────────────────────────────────────────

    Write-Host "Extracting to: $OutputPath"
    Write-Log "Extracting to: $OutputPath"
    Expand-Archive -Path $zipPath -DestinationPath $OutputPath -Force
    # Zip is inside RestoreTempDir -- cleaned up in outer finally

    # ─── Read Manifest ─────────────────────────────────────────────────────────

    $manifestPath = Join-Path $OutputPath 'manifest.json'
    if (-not (Test-Path $manifestPath)) {
        throw "Manifest not found in backup. Archive may be corrupt."
    }

    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

    Write-Host "`nBackup Details:" -ForegroundColor Green
    Write-Host "  Timestamp : $($manifest.BackupTimestamp)"
    Write-Host "  Source    : $($manifest.HostName)"
    Write-Host "  Vaults    : $($manifest.VaultCount)"
    Write-Host "  Items     : $($manifest.TotalItems)"
    Write-Host "  Documents : $($manifest.TotalDocuments)"
    Write-Host ""
    Write-Log "Backup: $($manifest.BackupTimestamp) from $($manifest.HostName) -- $($manifest.VaultCount) vaults, $($manifest.TotalItems) items"

    foreach ($v in $manifest.Vaults) {
        Write-Host "  [$($v.Name)] $($v.ItemCount) items, $($v.DocumentCount) documents"
    }

    # ─── Extract Only Mode ─────────────────────────────────────────────────────

    if (-not $Restore) {
        Write-Host "`nExtraction complete. Files available at:" -ForegroundColor Green
        Write-Host "  $OutputPath"
        Write-Host "`nTo restore items to 1Password, re-run with -Restore flag."
        Write-Host "Review the extracted JSON files first to verify backup integrity."
        Write-Log "Extract-only mode complete"
        # Fall through to finally for cleanup
    }

    # ─── Restore Mode ─────────────────────────────────────────────────────────

    if ($Restore) {
        Write-Host "`nRESTORE MODE" -ForegroundColor Red
        Write-Host "This will create items in 1Password." -ForegroundColor Red

        $opCmd = Get-Command 'op' -ErrorAction SilentlyContinue
        if (-not $opCmd) {
            throw "1Password CLI (op) not found. Required for restore."
        }

        # Verify authentication
        $whoami = Invoke-OpCli @('whoami')
        if ($whoami.ExitCode -ne 0) {
            throw "op CLI not authenticated. Sign in first: op signin"
        }

        # Confirm
        if (-not $Force) {
            if (-not [Environment]::UserInteractive) {
                throw "Cannot prompt for confirmation in non-interactive mode. Use -Force."
            }
            $confirm = Read-Host "`nProceed with restore? (type YES to confirm)"
            if ($confirm -ne 'YES') {
                Write-Host "Restore cancelled." -ForegroundColor Yellow
                Write-Log "Restore cancelled by user"
                # Fall through to finally
                $Restore = $false
            }
        }
    }

    if ($Restore) {
        # Cache vault list (one API call instead of N)
        $vaultListResult = Invoke-OpCli @('vault', 'list', '--format', 'json')
        $existingVaults = @()
        if ($vaultListResult.ExitCode -eq 0) {
            $existingVaults = ConvertFrom-JsonArray -Json $vaultListResult.Output
        }

        $vaultsDir = Join-Path $OutputPath 'vaults'
        $restored = 0
        $failed = 0

        foreach ($vaultDir in (Get-ChildItem -Path $vaultsDir -Directory)) {
            $vaultMeta = Get-Content (Join-Path $vaultDir.FullName 'vault.json') -Raw | ConvertFrom-Json
            $vaultTarget = $vaultMeta.name
            if ($TargetVault) { $vaultTarget = $TargetVault }

            Write-Host "`nRestoring vault: $($vaultMeta.name) -> $vaultTarget" -ForegroundColor Cyan
            Write-Log "Restoring vault: $($vaultMeta.name) -> $vaultTarget"

            # Check if target vault exists (from cache)
            $matchedVault = $existingVaults | Where-Object { $_.name -eq $vaultTarget }

            if (-not $matchedVault) {
                Write-Host "  Creating vault: $vaultTarget"
                $createResult = Invoke-OpCli @('vault', 'create', $vaultTarget, '--format', 'json')
                if ($createResult.ExitCode -ne 0) {
                    Write-Host "  ERROR: Failed to create vault '$vaultTarget'. Skipping." -ForegroundColor Red
                    Write-Log "ERROR: Failed to create vault '$vaultTarget': $($createResult.Error)" -Level ERROR
                    $failed++
                    continue
                }
                # Add to cache
                $existingVaults += ConvertFrom-JsonArray -Json $createResult.Output
            }

            # Restore items
            $itemsDir = Join-Path $vaultDir.FullName 'items'
            if (-not (Test-Path $itemsDir)) { continue }

            foreach ($itemFile in (Get-ChildItem -Path $itemsDir -Filter '*.json')) {
                $templateFile = $null
                try {
                    $itemJson = Get-Content $itemFile.FullName -Raw
                    $item = $itemJson | ConvertFrom-Json

                    # Documents need special handling
                    if ($item.category -eq 'DOCUMENT') {
                        $docDir = Join-Path $vaultDir.FullName "documents\$($item.id)"
                        if (Test-Path $docDir) {
                            $docFile = Get-ChildItem -Path $docDir -File | Select-Object -First 1
                            if ($docFile) {
                                $docResult = Invoke-OpCli @('document', 'create', $docFile.FullName, '--vault', $vaultTarget, '--title', $item.title)
                                if ($docResult.ExitCode -eq 0) {
                                    $restored++
                                    Write-Host "  + [DOC] $($item.title)" -ForegroundColor Gray
                                    Write-Log "Restored: [DOC] $($item.title)"
                                }
                                else {
                                    Write-Host "  ! [DOC] $($item.title) -- failed" -ForegroundColor Yellow
                                    Write-Log "FAILED: [DOC] $($item.title): $($docResult.Error)" -Level WARN
                                    $failed++
                                }
                            }
                        }
                        continue
                    }

                    # Transform export JSON to create-compatible template
                    $cleanJson = ConvertTo-CreateTemplate -ItemJson $itemJson
                    $templateFile = Join-Path $script:RestoreTempDir "item_$([guid]::NewGuid().ToString('N')).json"
                    $cleanJson | Set-Content $templateFile -Encoding UTF8

                    $createResult = Invoke-OpCli @('item', 'create', '--vault', $vaultTarget, '--template', $templateFile)
                    if ($createResult.ExitCode -eq 0) {
                        $restored++
                        Write-Host "  + [$($item.category)] $($item.title)" -ForegroundColor Gray
                        Write-Log "Restored: [$($item.category)] $($item.title)"
                    }
                    else {
                        Write-Host "  ! [$($item.category)] $($item.title) -- failed" -ForegroundColor Yellow
                        Write-Log "FAILED: [$($item.category)] $($item.title): $($createResult.Error)" -Level WARN
                        $failed++
                    }
                }
                catch {
                    Write-Host "  ! Error restoring $($itemFile.Name): $_" -ForegroundColor Yellow
                    Write-Log "FAILED: $($itemFile.Name): $_" -Level WARN
                    $failed++
                }
                finally {
                    if ($templateFile -and (Test-Path $templateFile -ErrorAction SilentlyContinue)) {
                        Remove-Item $templateFile -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }

        # Summary
        Write-Host ""
        Write-Host ("=" * 50) -ForegroundColor Cyan
        Write-Host "Restore Complete" -ForegroundColor Green
        Write-Host "  Restored : $restored"
        Write-Host "  Failed   : $failed"
        Write-Host "  Source   : $ArchivePath"
        Write-Host "  Log      : $($script:LogPath)"
        Write-Host ""
        Write-Log "=== Restore Complete: $restored restored, $failed failed ==="

        if ($failed -gt 0) {
            Write-Host "Some items failed to restore. Review the log and manually" -ForegroundColor Yellow
            Write-Host "import failed items from the extracted JSON in: $OutputPath" -ForegroundColor Yellow
            $exitCode = 1
        }
    }

    Write-Host "`nIMPORTANT: Securely delete the extracted backup and PFX when done:" -ForegroundColor Red
    Write-Host "  Remove-Item -Path '$OutputPath' -Recurse -Force"
    Write-Host ""
}
catch {
    $exitCode = 1
    Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # Remove temporarily imported certificate from the user store
    if ($script:CertImported -and $script:CertThumbprint) {
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
            $store.Open('ReadWrite')
            $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $script:CertThumbprint }
            if ($found) {
                foreach ($c in $found) { $store.Remove($c) }
                Write-Log "Removed temporary certificate from CurrentUser\My store"
            }
            $store.Close()
        }
        catch {
            Write-Warning "Could not remove temporary certificate from store. Manually remove thumbprint $($script:CertThumbprint) from Cert:\CurrentUser\My"
        }
    }

    # Clean up secure temp directory (contains decrypted zip + any template files)
    if ($script:RestoreTempDir -and (Test-Path $script:RestoreTempDir -ErrorAction SilentlyContinue)) {
        Remove-Item -Path $script:RestoreTempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
