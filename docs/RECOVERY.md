# Recovery Runbook -- 1Password BCDR Restore

## When to Use This

- 1Password account compromise or lockout
- Accidental vault or item deletion
- Compliance/audit data retrieval
- Migration to a new 1Password account
- Disaster recovery testing

## What You Need

1. **Encrypted backup file**: `BCDR_1PW_<timestamp>.zip.cms` from the backup location
2. **PFX certificate file**: `BCDR_1PW_Backup_Key.pfx` retrieved from physical safe
3. **PFX password**: Stored alongside the .pfx in the physical safe
4. **A Windows machine with**: PowerShell 5.1+ and `op` CLI (for full restore), or just PowerShell (for extract-only)

## Option A: Extract and Review (No 1Password Needed)

Use this to inspect backup contents without restoring to 1Password.

```powershell
# 1. Copy the .pfx from physical safe to the machine

# 2. Decrypt and extract (will prompt for PFX password)
.\scripts\Restore-1Password.ps1 `
    -ArchivePath "C:\Backups\1Password\BCDR_1PW_20260309_020000.zip.cms" `
    -PfxPath ".\BCDR_1PW_Backup_Key.pfx"

# 3. Browse extracted data
#    restore_<timestamp>/
#      manifest.json          -- backup metadata
#      vaults/<id>/
#        vault.json           -- vault metadata
#        items/<id>.json      -- individual items (full JSON)
#        documents/<id>/      -- binary document files

# 4. Securely delete PFX and extracted data when done
Remove-Item .\BCDR_1PW_Backup_Key.pfx -Force
Remove-Item restore_* -Recurse -Force
```

## Option B: Full Restore to 1Password

Use this in a DR scenario to recreate items in 1Password.

```powershell
# 1. Copy the .pfx from physical safe to the machine

# 2. Authenticate to 1Password (interactive sign-in, NOT service account)
op signin

# 3. Restore to original vaults (will prompt for PFX password)
.\scripts\Restore-1Password.ps1 `
    -ArchivePath "C:\Backups\1Password\BCDR_1PW_20260309_020000.zip.cms" `
    -PfxPath ".\BCDR_1PW_Backup_Key.pfx" `
    -Restore

# 4. Or restore everything into a single recovery vault
.\scripts\Restore-1Password.ps1 `
    -ArchivePath "C:\Backups\1Password\BCDR_1PW_20260309_020000.zip.cms" `
    -PfxPath ".\BCDR_1PW_Backup_Key.pfx" `
    -Restore `
    -TargetVault "DR-Recovery"

# 5. Securely clean up
Remove-Item .\BCDR_1PW_Backup_Key.pfx -Force
Remove-Item restore_* -Recurse -Force
```

## Manual Decrypt (Without Scripts)

If the restore script is unavailable, you can decrypt with raw PowerShell.
The archive uses hybrid encryption: AES-256-CBC for data, CMS/PKCS#7 for the key.

```powershell
Add-Type -AssemblyName System.Security

# Load PFX
$pfxPassword = Read-Host -AsSecureString "PFX Password"
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    "C:\path\to\BCDR_1PW_Backup_Key.pfx",
    $pfxPassword,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
)
# .NET Framework requires the cert in a store for CMS decryption (CAPI layer)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','CurrentUser')
$store.Open('ReadWrite'); $store.Add($cert); $store.Close()

$archivePath = "C:\Backups\BCDR_1PW_20260309_020000.zip.cms"
$zipPath = "C:\temp\backup.zip"

# Open archive and read CMS key envelope
$fsIn = [System.IO.File]::OpenRead($archivePath)
$lenBytes = New-Object byte[] 4
$null = $fsIn.Read($lenBytes, 0, 4)
$envLen = [BitConverter]::ToInt32($lenBytes, 0)
$envBytes = New-Object byte[] $envLen
$null = $fsIn.Read($envBytes, 0, $envLen)

# Decrypt CMS envelope to get AES key+IV
$cms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
$cms.Decode($envBytes)
$certs = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$certs.Add($cert) | Out-Null
$cms.Decrypt($certs)
$km = $cms.ContentInfo.Content  # 48 bytes: 32 key + 16 IV

# Stream-decrypt AES data to zip
$aes = New-Object System.Security.Cryptography.AesManaged
$aes.Key = $km[0..31]
$aes.IV = $km[32..47]
$dec = $aes.CreateDecryptor()
$cs = New-Object System.Security.Cryptography.CryptoStream($fsIn, $dec, 'Read')
$fsOut = [System.IO.File]::Create($zipPath)
$cs.CopyTo($fsOut)
$fsOut.Dispose(); $cs.Dispose(); $fsIn.Dispose(); $aes.Dispose()

# Extract
Expand-Archive -Path $zipPath -DestinationPath "C:\temp\restored"

# Browse JSON
Get-ChildItem "C:\temp\restored\vaults" -Recurse

# Clean up: remove cert from store when done
$store.Open('ReadWrite'); $store.Remove($cert); $store.Close()
```

## Backup Contents Structure

```
manifest.json
├── BackupTimestamp    -- ISO 8601 timestamp
├── OpCliVersion      -- op CLI version used
├── HostName          -- machine that ran the backup
├── VaultCount        -- number of vaults
├── TotalItems        -- total items across all vaults
├── TotalDocuments    -- total document files
└── Vaults[]          -- per-vault breakdown

vaults/<vault-id>/
├── vault.json        -- vault name, ID, metadata
├── items/
│   └── <item-id>.json  -- full item export (all fields, passwords, notes)
└── documents/
    └── <item-id>/
        └── <filename>  -- binary document file
```

## Post-Restore Verification

After restoring, verify:

- [ ] Expected number of vaults present
- [ ] Spot-check critical items (admin credentials, API keys)
- [ ] Document files open correctly
- [ ] Restore log reviewed for any failed items
- [ ] .pfx file securely deleted from the restore machine
- [ ] Extracted backup directory securely deleted

## DR Test Schedule

Test the full restore process at least **quarterly**:

1. Pull the .pfx and password from the physical safe
2. Restore the latest backup to a test vault (`-TargetVault "DR-Test"`)
3. Verify item integrity
4. Delete the test vault in 1Password
5. Return the .pfx to the safe, delete from machine
6. Document the test result and date
