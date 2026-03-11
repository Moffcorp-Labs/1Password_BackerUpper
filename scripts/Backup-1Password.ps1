#Requires -Version 5.1
<#
.SYNOPSIS
    Backs up all accessible 1Password vaults to an encrypted archive.

.DESCRIPTION
    Exports all items and documents from 1Password vaults accessible by the
    configured service account, creates a CMS-encrypted zip archive using a
    certificate, and manages backup retention.

    Requires: 1Password CLI (op), Document Encryption certificate (public key only).
    Authentication: Service account token from DPAPI-encrypted credential file.

    Encryption uses a hybrid approach: AES-256-CBC for the archive data (streaming,
    constant memory) and CMS/PKCS#7 for the AES key envelope. No third-party tools.

.PARAMETER ConfigPath
    Path to backup-config.json. Defaults to ..\config\backup-config.json.

.PARAMETER DryRun
    Validates configuration and prerequisites without performing backup.

.EXAMPLE
    .\Backup-1Password.ps1
    .\Backup-1Password.ps1 -ConfigPath "C:\Config\backup-config.json"
    .\Backup-1Password.ps1 -DryRun -Verbose
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigPath,

    [Parameter()]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

# ─── Script-scoped state ───────────────────────────────────────────────────────

$script:Config    = $null
$script:LogPath   = $null
$script:TempPath  = $null
$script:Mutex     = $null
$script:StartTime = Get-Date
$script:DryRunCompleted = $false

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
    <#
    .SYNOPSIS
        Runs an op CLI command, separating stdout from stderr to avoid JSON corruption.
    #>
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
    # Service account token is inherited from the parent process environment
    # (set by Set-ServiceAccountToken). Do NOT touch $psi.EnvironmentVariables
    # -- on .NET Framework, accessing it copies the entire environment into a
    # case-insensitive StringDictionary which can throw on duplicate env var
    # names (common on Windows) and corrupt the ProcessStartInfo.

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($stderr) {
        Write-Log "op stderr: $stderr" -Level WARN
    }

    return [PSCustomObject]@{
        Output   = $stdout
        Error    = $stderr
        ExitCode = $proc.ExitCode
    }
}

function ConvertFrom-JsonArray {
    <#
    .SYNOPSIS
        Parses JSON and always returns a flat array.
        Works around PS 5.1 ConvertFrom-Json which outputs a JSON array as a
        single pipeline object instead of enumerating elements.
    #>
    param([Parameter(Mandatory)][string]$Json)

    $parsed = $Json | ConvertFrom-Json
    if ($null -eq $parsed) { return ,@() }
    if ($parsed -is [Array]) { return ,$parsed }
    return ,@($parsed)
}

# ─── Configuration ─────────────────────────────────────────────────────────────

function Initialize-Configuration {
    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $PSScriptRoot '..\config\backup-config.json'
    }
    $ConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)

    if (-not (Test-Path $ConfigPath)) {
        throw "Config file not found: $ConfigPath. Copy backup-config.example.json and fill in values."
    }

    $script:Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

    # Validate required fields
    foreach ($field in @('BackupPath', 'CertificateThumbprint')) {
        if (-not $script:Config.$field) {
            throw "Missing required config field: $field"
        }
    }

    # RetentionDays must be a positive integer
    if (-not $script:Config.RetentionDays -or $script:Config.RetentionDays -lt 1) {
        throw "RetentionDays must be at least 1. Current value: $($script:Config.RetentionDays)"
    }

    # Validate thumbprint format (40 hex chars)
    if ($script:Config.CertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
        throw "Invalid CertificateThumbprint format. Expected: 40 hex characters."
    }

    # Ensure backup directory exists
    if (-not (Test-Path $script:Config.BackupPath)) {
        New-Item -ItemType Directory -Path $script:Config.BackupPath -Force | Out-Null
    }

    # Set up log file
    $logDir = Join-Path $script:Config.BackupPath 'logs'
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    $script:LogPath = Join-Path $logDir "backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

    # Create temp working directory with subdirectories
    $script:TempPath = Join-Path ([System.IO.Path]::GetTempPath()) "1pw_backup_$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path (Join-Path $script:TempPath 'export') -Force | Out-Null

    Write-Log "Configuration loaded from $ConfigPath"
    Write-Log "Backup destination: $($script:Config.BackupPath)"
    Write-Log "Retention: $($script:Config.RetentionDays) days"
}

# ─── Concurrency Guard ─────────────────────────────────────────────────────────

function Enter-BackupMutex {
    $script:Mutex = New-Object System.Threading.Mutex($false, 'Global\BCDR_1PW_Backup')
    if (-not $script:Mutex.WaitOne(0)) {
        throw "Another backup is already running. Exiting."
    }
    Write-Log "Acquired backup mutex"
}

# ─── Authentication ────────────────────────────────────────────────────────────

function Set-ServiceAccountToken {
    # Check if already set (e.g., by Task Scheduler environment)
    if ($env:OP_SERVICE_ACCOUNT_TOKEN) {
        Write-Log "Service account token found in environment"
        return
    }

    # Load from DPAPI-encrypted credential file
    $credPath = Join-Path $env:USERPROFILE '.1pw-backup-cred.xml'
    if (-not (Test-Path $credPath)) {
        throw "Service account credential not found at $credPath. Run Initialize-Credential.ps1 first."
    }

    try {
        $cred = Import-Clixml $credPath
        $env:OP_SERVICE_ACCOUNT_TOKEN = $cred.GetNetworkCredential().Password
        Write-Log "Service account token loaded from DPAPI credential store"
    }
    catch {
        throw "Failed to decrypt credential file. Ensure you are running as the same user who created it. Error: $_"
    }
}

# ─── Prerequisites ─────────────────────────────────────────────────────────────

function Test-Prerequisites {
    # Check op CLI
    $opCmd = Get-Command 'op' -ErrorAction SilentlyContinue
    if (-not $opCmd) {
        throw "1Password CLI (op) not found in PATH. Install: https://1password.com/downloads/command-line/"
    }
    $opVersion = Invoke-OpCli @('--version')
    Write-Log "op CLI version: $($opVersion.Output.Trim())"

    # Check encryption certificate
    $thumbprint = $script:Config.CertificateThumbprint
    $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $thumbprint } |
        Select-Object -First 1

    if (-not $cert) {
        throw "Encryption certificate not found (thumbprint: $thumbprint). Run New-BackupCertificate.ps1 or import the .cer file."
    }

    if ($cert.NotAfter -lt (Get-Date)) {
        throw "Encryption certificate has expired ($($cert.NotAfter.ToString('yyyy-MM-dd'))). Generate a new certificate."
    }

    if ($cert.NotAfter -lt (Get-Date).AddDays(90)) {
        Write-Log "Certificate expires in less than 90 days ($($cert.NotAfter.ToString('yyyy-MM-dd')))" -Level WARN
    }

    Write-Log "Encryption certificate: $($cert.Subject) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"

    # Verify op authentication
    $whoami = Invoke-OpCli @('whoami', '--format', 'json')
    if ($whoami.ExitCode -ne 0) {
        throw "op CLI authentication failed. Check service account token. stderr: $($whoami.Error)"
    }
    # op whoami returns duplicate keys differing only by case (url/URL,
    # user_type/ServiceAccountType). PS 5.1 ConvertFrom-Json is case-insensitive
    # and rejects these. Extract the values we need via regex instead.
    $whoamiJson = $whoami.Output
    $acctUrl  = if ($whoamiJson -match '"url"\s*:\s*"([^"]+)"') { $Matches[1] } else { 'unknown' }
    $acctUuid = if ($whoamiJson -match '"account_uuid"\s*:\s*"([^"]+)"') { $Matches[1] } else { 'unknown' }
    Write-Log "Authenticated as: $acctUrl (account: $acctUuid)"

    Write-Log "All prerequisites validated"
}

# ─── Filename Sanitization ─────────────────────────────────────────────────────

function Get-SafeFileName {
    param([string]$Name)

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    $safe = ($Name.ToCharArray() | ForEach-Object {
        if ($invalidChars -contains $_) { '_' } else { $_ }
    }) -join ''
    $safe = $safe.TrimEnd('. ')
    if ($safe -match '^(CON|PRN|AUX|NUL|COM\d|LPT\d)$') { $safe = "_$safe" }
    if ($safe.Length -gt 200) { $safe = $safe.Substring(0, 200) }
    if (-not $safe) { $safe = '_unnamed' }
    return $safe
}

# ─── Vault Export ──────────────────────────────────────────────────────────────

function Export-AllVaults {
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    Write-Log "Retrieving vault list..."
    $result = Invoke-OpCli @('vault', 'list', '--format', 'json')
    if ($result.ExitCode -ne 0) {
        throw "Failed to list vaults (exit $($result.ExitCode)): $($result.Error)"
    }
    $vaults = ConvertFrom-JsonArray -Json $result.Output

    if ($vaults.Count -eq 0) {
        throw "No vaults accessible. Check service account vault permissions."
    }

    Write-Log "Found $($vaults.Count) accessible vault(s)"

    $delayMs = 100
    if ($script:Config.RateLimitDelayMs) { $delayMs = $script:Config.RateLimitDelayMs }

    $manifest = [ordered]@{
        BackupTimestamp  = (Get-Date -Format 'o')
        OpCliVersion     = (Invoke-OpCli @('--version')).Output.Trim()
        HostName         = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
        VaultCount       = $vaults.Count
        TotalItems       = 0
        TotalDocuments   = 0
        Vaults           = @()
    }

    foreach ($vault in $vaults) {
        Write-Log "--- Vault: $($vault.name) ($($vault.id)) ---"

        $vaultDir = Join-Path $OutputPath "vaults\$($vault.id)"
        $itemsDir = Join-Path $vaultDir 'items'
        $docsDir  = Join-Path $vaultDir 'documents'
        New-Item -ItemType Directory -Path $itemsDir -Force | Out-Null
        New-Item -ItemType Directory -Path $docsDir -Force | Out-Null

        # Save vault metadata
        $vault | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $vaultDir 'vault.json') -Encoding UTF8

        # List all items in vault
        $itemResult = Invoke-OpCli @('item', 'list', '--vault', $vault.id, '--format', 'json')
        if ($itemResult.ExitCode -ne 0) {
            Write-Log "  WARN: Failed to list items in vault $($vault.name): $($itemResult.Error)" -Level WARN
            continue
        }
        $items = ConvertFrom-JsonArray -Json $itemResult.Output

        Write-Log "  Items: $($items.Count)"

        $itemCount = 0
        $docCount  = 0

        foreach ($item in $items) {
            try {
                # Get full item details
                $fullResult = Invoke-OpCli @('item', 'get', $item.id, '--vault', $vault.id, '--format', 'json')
                if ($fullResult.ExitCode -ne 0) {
                    Write-Log "  WARN: Failed to get item '$($item.title)': $($fullResult.Error)" -Level WARN
                    continue
                }
                $fullResult.Output | Set-Content (Join-Path $itemsDir "$($item.id).json") -Encoding UTF8
                $itemCount++

                # Download document files
                if ($item.category -eq 'DOCUMENT') {
                    $docItemDir = Join-Path $docsDir $item.id
                    New-Item -ItemType Directory -Path $docItemDir -Force | Out-Null

                    $safeTitle = Get-SafeFileName -Name $item.title
                    $docFile = Join-Path $docItemDir $safeTitle

                    $docResult = Invoke-OpCli @('document', 'get', $item.id, '--vault', $vault.id, '--out-file', $docFile)
                    if ($docResult.ExitCode -eq 0) {
                        $docCount++
                    }
                    else {
                        Write-Log "  WARN: Failed to download document '$($item.title)'" -Level WARN
                    }
                }
            }
            catch {
                Write-Log "  WARN: Failed to export item '$($item.title)' ($($item.id)): $_" -Level WARN
            }

            Start-Sleep -Milliseconds $delayMs
        }

        $manifest.Vaults += [ordered]@{
            Id            = $vault.id
            Name          = $vault.name
            ItemCount     = $itemCount
            DocumentCount = $docCount
        }
        $manifest.TotalItems     += $itemCount
        $manifest.TotalDocuments += $docCount

        Write-Log "  Exported: $itemCount items, $docCount documents"
    }

    # Write manifest
    $manifest | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $OutputPath 'manifest.json') -Encoding UTF8
    Write-Log "Manifest written with $($manifest.TotalItems) total items across $($manifest.VaultCount) vaults"

    return $manifest
}

# ─── Hybrid Encryption (AES-256 streaming + CMS key envelope) ─────────────────

function New-EncryptedArchive {
    <#
    .SYNOPSIS
        Compresses and encrypts the export using hybrid AES+CMS encryption.

    .DESCRIPTION
        1. Compress-Archive creates a .zip inside the secure temp directory.
        2. A random AES-256 key + IV is generated.
        3. The zip is encrypted with AES-256-CBC using CryptoStream (constant memory).
        4. The AES key+IV is CMS-encrypted with the certificate (tiny payload).
        5. Output format: [4-byte envelope length][CMS envelope][AES ciphertext]
        6. A SHA-256 hash sidecar (.sha256) is written for integrity verification.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ExportPath,

        [Parameter(Mandatory)]
        [string]$DestinationDir,

        [Parameter(Mandatory)]
        [string]$CertificateThumbprint
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    # Intermediate zip lives inside the secure temp directory (wiped on cleanup)
    $zipPath = Join-Path $script:TempPath "archive_$timestamp.zip"
    $encPath = Join-Path $DestinationDir "BCDR_1PW_$timestamp.zip.cms"

    if (-not (Test-Path $DestinationDir)) {
        New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
    }

    # Create zip archive
    Write-Log "Creating zip archive..."
    Compress-Archive -Path (Join-Path $ExportPath '*') -DestinationPath $zipPath -CompressionLevel Optimal
    $zipSize = (Get-Item $zipPath).Length
    Write-Log "Archive size: $([math]::Round($zipSize / 1MB, 2)) MB (unencrypted)"

    # Load encryption certificate (public key only)
    $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $CertificateThumbprint } |
        Select-Object -First 1

    if (-not $cert) {
        throw "Encryption certificate not found: $CertificateThumbprint"
    }

    Write-Log "Encrypting archive (hybrid AES-256-CBC + CMS envelope)..."
    $aes = $null
    $encryptor = $null
    $fsIn = $null
    $fsOut = $null
    $cs = $null
    try {
        # Generate random AES-256 key and IV
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.KeySize = 256
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateKey()
        $aes.GenerateIV()

        # CMS-encrypt the AES key material (48 bytes: 32 key + 16 IV)
        $keyMaterial = New-Object byte[] 48
        [Array]::Copy($aes.Key, 0, $keyMaterial, 0, 32)
        [Array]::Copy($aes.IV, 0, $keyMaterial, 32, 16)

        $contentInfo = New-Object System.Security.Cryptography.Pkcs.ContentInfo(, $keyMaterial)
        $cms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms($contentInfo)
        $recipient = New-Object System.Security.Cryptography.Pkcs.CmsRecipient($cert)
        $cms.Encrypt($recipient)
        $envelope = $cms.Encode()

        # Write output: [4-byte envelope length][envelope][AES ciphertext]
        $fsOut = [System.IO.File]::Create($encPath)
        $envelopeLenBytes = [BitConverter]::GetBytes([int]$envelope.Length)
        $fsOut.Write($envelopeLenBytes, 0, 4)
        $fsOut.Write($envelope, 0, $envelope.Length)

        # Stream-encrypt the zip with AES
        $encryptor = $aes.CreateEncryptor()
        $cs = New-Object System.Security.Cryptography.CryptoStream($fsOut, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $fsIn = [System.IO.File]::OpenRead($zipPath)

        $buffer = New-Object byte[] 81920
        while ($true) {
            $read = $fsIn.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $cs.Write($buffer, 0, $read)
        }
        $cs.FlushFinalBlock()
    }
    finally {
        if ($cs) { $cs.Dispose() }
        if ($fsIn) { $fsIn.Dispose() }
        if ($fsOut) { $fsOut.Dispose() }
        if ($encryptor) { $encryptor.Dispose() }

        # Zero key material from memory
        if ($keyMaterial) { [Array]::Clear($keyMaterial, 0, $keyMaterial.Length) }
        if ($aes) {
            if ($aes.Key) { [Array]::Clear($aes.Key, 0, $aes.Key.Length) }
            $aes.Dispose()
        }
    }

    # Remove unencrypted zip
    Remove-Item $zipPath -Force

    $encSize = (Get-Item $encPath).Length
    Write-Log "Encrypted archive: $encPath ($([math]::Round($encSize / 1MB, 2)) MB)"

    # Write SHA-256 hash sidecar for integrity verification
    $hash = Get-FileHash -Path $encPath -Algorithm SHA256
    "$($hash.Hash)  $(Split-Path $encPath -Leaf)" |
        Set-Content "$encPath.sha256" -Encoding UTF8
    Write-Log "SHA-256: $($hash.Hash)"

    # Verify CMS envelope can be decoded (structure check, not decryption)
    try {
        $verifyBytes = New-Object byte[] 4
        $verifyFs = [System.IO.File]::OpenRead($encPath)
        $null = $verifyFs.Read($verifyBytes, 0, 4)
        $verifyLen = [BitConverter]::ToInt32($verifyBytes, 0)
        $verifyEnvelope = New-Object byte[] $verifyLen
        $null = $verifyFs.Read($verifyEnvelope, 0, $verifyLen)
        $verifyFs.Dispose()

        $verifyCms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
        $verifyCms.Decode($verifyEnvelope)
        Write-Log "Archive integrity: CMS envelope verified"
    }
    catch {
        Write-Log "Archive integrity: CMS envelope verification FAILED -- $_" -Level ERROR
        throw "Encrypted archive failed integrity check. Backup may be corrupt."
    }

    return $encPath
}

# ─── Retention ─────────────────────────────────────────────────────────────────

function Remove-ExpiredBackups {
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath,

        [Parameter(Mandatory)]
        [int]$RetentionDays
    )

    $cutoff = (Get-Date).AddDays(-$RetentionDays)

    # Prune backup archives by filename timestamp (not filesystem CreationTime)
    $archives = @(Get-ChildItem -Path $BackupPath -Filter 'BCDR_1PW_*.zip.cms' -File -ErrorAction SilentlyContinue)

    if ($archives.Count -eq 0) {
        Write-Log "No existing backups to evaluate for retention"
        return
    }

    $removed = 0
    foreach ($archive in $archives) {
        if ($archive.Name -match 'BCDR_1PW_(\d{8}_\d{6})\.zip\.cms$') {
            try {
                $backupDate = [datetime]::ParseExact($Matches[1], 'yyyyMMdd_HHmmss', $null)
                if ($backupDate -lt $cutoff) {
                    Remove-Item $archive.FullName -Force
                    # Remove SHA-256 sidecar if present
                    $sha256Path = "$($archive.FullName).sha256"
                    if (Test-Path $sha256Path) { Remove-Item $sha256Path -Force }
                    Write-Log "Pruned: $($archive.Name) (from $($backupDate.ToString('yyyy-MM-dd')))"
                    $removed++
                }
            }
            catch {
                Write-Log "WARN: Could not parse date from $($archive.Name), skipping" -Level WARN
            }
        }
    }

    # Prune old log files with the same retention window
    $logDir = Join-Path $BackupPath 'logs'
    if (Test-Path $logDir) {
        $oldLogs = @(Get-ChildItem -Path $logDir -Filter 'backup_*.log' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -lt $cutoff })
        foreach ($log in $oldLogs) {
            Remove-Item $log.FullName -Force
        }
        if ($oldLogs.Count -gt 0) { Write-Log "Pruned $($oldLogs.Count) old log file(s)" }
    }

    $remaining = ($archives.Count - $removed)
    Write-Log "Retention: pruned $removed archive(s), keeping $remaining"
}

# ─── Secure Cleanup ───────────────────────────────────────────────────────────

function Remove-SecureTemp {
    <#
    .NOTES
        Overwrites file contents with random data before deletion. On SSDs this
        is best-effort due to wear-leveling -- the real security boundary is the
        CMS encryption. The temp directory is the last line of defense.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) { return }

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                if ($_.Length -gt 0) {
                    $bytes = [byte[]]::new($_.Length)
                    $rng.GetBytes($bytes)
                    [System.IO.File]::WriteAllBytes($_.FullName, $bytes)
                    [Array]::Clear($bytes, 0, $bytes.Length)
                }
            }
            catch {
                # Best-effort wipe -- continue even if individual file fails
            }
        }
    }
    finally {
        $rng.Dispose()
    }

    Remove-Item -Path $Path -Recurse -Force
    Write-Log "Temp directory securely wiped: $Path"
}

# ─── Main ──────────────────────────────────────────────────────────────────────

$exitCode = 0
try {
    Initialize-Configuration
    Enter-BackupMutex
    Write-Log "=== 1Password BCDR Backup Started ==="

    if ($DryRun) {
        Write-Log "DRY RUN -- validating configuration and prerequisites only" -Level WARN
    }

    Set-ServiceAccountToken
    Test-Prerequisites

    if ($DryRun) {
        Write-Log "Dry run complete. Configuration and prerequisites are valid."
        Write-Log "=== Dry Run Finished ==="
        $script:DryRunCompleted = $true
        # Fall through to finally block (do not use 'exit' inside try -- PS 5.1 skips finally)
    }

    if (-not $script:DryRunCompleted) {
        # Export vaults into the secure temp subdirectory
        $exportPath = Join-Path $script:TempPath 'export'
        $manifest = Export-AllVaults -OutputPath $exportPath

        if ($manifest.TotalItems -eq 0) {
            Write-Log "WARNING: Backup contains zero items. Verify service account vault access." -Level WARN
        }

        # Encrypt archive
        $archivePath = New-EncryptedArchive `
            -ExportPath $exportPath `
            -DestinationDir $script:Config.BackupPath `
            -CertificateThumbprint $script:Config.CertificateThumbprint

        # Prune old backups
        Remove-ExpiredBackups `
            -BackupPath $script:Config.BackupPath `
            -RetentionDays $script:Config.RetentionDays

        # Summary
        $elapsed = (Get-Date) - $script:StartTime
        Write-Log "=== Backup Complete ==="
        Write-Log "Archive : $archivePath"
        Write-Log "Vaults  : $($manifest.VaultCount)"
        Write-Log "Items   : $($manifest.TotalItems)"
        Write-Log "Docs    : $($manifest.TotalDocuments)"
        Write-Log "Duration: $($elapsed.ToString('hh\:mm\:ss'))"
    }
}
catch {
    $exitCode = 1
    Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack: $($_.ScriptStackTrace)" -Level ERROR
}
finally {
    # Always clean up temp files
    if ($script:TempPath -and (Test-Path $script:TempPath -ErrorAction SilentlyContinue)) {
        Remove-SecureTemp -Path $script:TempPath
    }

    # Clear sensitive environment variable
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null

    # Release mutex
    if ($script:Mutex) {
        try { $script:Mutex.ReleaseMutex() } catch {}
        $script:Mutex.Dispose()
    }
}

exit $exitCode
