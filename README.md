# 1Password BackerUpper

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)

Automated BCDR backup solution for 1Password Business. Exports all vaults via the `op` CLI, encrypts with hybrid AES-256 + CMS certificates, and runs on a Windows Scheduled Task. **Zero third-party dependencies** beyond the 1Password CLI.

## How It Works

```
Windows Scheduled Task (daily @ 2AM)
  └─ Backup-1Password.ps1
       ├─ Authenticates via service account token (DPAPI encrypted)
       ├─ Exports all accessible vaults as JSON + document files
       ├─ Compresses with Compress-Archive (.zip)
       ├─ Encrypts with AES-256-CBC (streaming) + CMS key envelope
       ├─ Writes BCDR_1PW_<timestamp>.zip.cms + .sha256 sidecar
       ├─ Prunes backups beyond retention window
       └─ Secure-wipes temp files
```

**Encryption**: A random AES-256 key encrypts the archive data via `CryptoStream` (constant memory, no size limit). The AES key is then wrapped in a CMS/PKCS#7 envelope using the backup certificate's public key. Only the `.pfx` private key (stored in a physical safe) can decrypt.

## Prerequisites

| Dependency | Version | Install |
|---|---|---|
| Windows | 10+ / Server 2019+ | -- |
| PowerShell | 5.1+ or 7+ | Built-in / `winget install Microsoft.PowerShell` |
| 1Password CLI | 2.x | `winget install AgileBits.1Password.CLI` |
| 1Password Business | -- | Admin access for service account setup |
| .NET Framework | 4.5+ | Built-in |

## Quick Start

```powershell
git clone https://github.com/Moffcorp-Labs/1Password_BackerUpper.git
cd 1Password_BackerUpper

# 1. Generate encryption certificate (prints .pfx for physical safe)
.\scripts\New-BackupCertificate.ps1

# 2. Create config with your thumbprint and backup path
Copy-Item config\backup-config.example.json config\backup-config.json
# Edit config\backup-config.json -- set CertificateThumbprint and BackupPath

# 3. Store the 1Password service account token (DPAPI encrypted)
.\scripts\Initialize-Credential.ps1

# 4. Validate everything
.\scripts\Backup-1Password.ps1 -DryRun -Verbose

# 5. Run first backup
.\scripts\Backup-1Password.ps1 -Verbose

# 6. Install daily scheduled task (requires Administrator)
.\scripts\Install-ScheduledTask.ps1
```

See [docs/SETUP.md](docs/SETUP.md) for the full 10-step walkthrough.

## Repository Structure

```
1Password_BackerUpper/
├── config/
│   └── backup-config.example.json      # Config template (copy and fill in)
├── scripts/
│   ├── Backup-1Password.ps1            # Main backup script
│   ├── Restore-1Password.ps1           # Decrypt + restore from backup
│   ├── New-BackupCertificate.ps1       # One-time certificate generation
│   ├── Initialize-Credential.ps1       # One-time service account token storage
│   ├── Install-ScheduledTask.ps1       # Windows Task Scheduler setup
│   ├── Sync-VaultAccess.ps1            # Auto-detect + fix service account vault gaps
│   └── Test-VaultCoverage.ps1          # Audit which vaults are being backed up
├── docs/
│   ├── SETUP.md                        # Full setup guide
│   ├── RECOVERY.md                     # Restore runbook (extract-only or full)
│   └── SERVICE-ACCOUNT-SETUP.md        # 1Password service account creation + SOP
├── CHANGELOG.md                        # Release history
├── CONTRIBUTING.md                     # How to contribute
├── SECURITY.md                         # Vulnerability reporting
├── LICENSE                             # MIT License
└── README.md
```

## Configuration

`config/backup-config.json`:

```json
{
  "BackupPath": "C:\\Backups\\1Password",
  "CertificateThumbprint": "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
  "RetentionDays": 7,
  "LogLevel": "INFO",
  "RateLimitDelayMs": 100
}
```

| Field | Description |
|---|---|
| `BackupPath` | Where encrypted `.zip.cms` archives are stored |
| `CertificateThumbprint` | 40-char hex thumbprint from `New-BackupCertificate.ps1` |
| `RetentionDays` | Number of daily backups to keep (default: 7) |
| `RateLimitDelayMs` | Delay between `op` CLI calls to avoid rate limiting |

## Backup Output

Each run produces:

```
C:\Backups\1Password\
├── BCDR_1PW_20260309_020000.zip.cms        # Encrypted archive
├── BCDR_1PW_20260309_020000.zip.cms.sha256 # Integrity hash
└── logs\
    └── backup_20260309_020000.log          # Run log
```

## Restore

**Extract only** (review contents without restoring to 1Password):

```powershell
.\scripts\Restore-1Password.ps1 `
    -ArchivePath "C:\Backups\1Password\BCDR_1PW_20260309_020000.zip.cms" `
    -PfxPath ".\BCDR_1PW_Backup_Key.pfx"
```

**Full restore** to original vaults or a DR recovery vault:

```powershell
.\scripts\Restore-1Password.ps1 `
    -ArchivePath "C:\Backups\1Password\BCDR_1PW_20260309_020000.zip.cms" `
    -PfxPath ".\BCDR_1PW_Backup_Key.pfx" `
    -Restore -TargetVault "DR-Recovery"
```

See [docs/RECOVERY.md](docs/RECOVERY.md) for the full runbook including manual decrypt instructions.

## Security Model

| Secret | Storage | Access |
|---|---|---|
| 1Password data | Encrypted `.zip.cms` archives | Requires .pfx private key |
| AES-256 key | CMS envelope inside each archive | Requires .pfx private key |
| Certificate private key (.pfx) | **Physical safe only** | Never stored digitally on any server |
| Certificate public key (.cer) | Windows certificate store | Encrypt only -- cannot decrypt |
| Service account token | DPAPI-encrypted file (`Export-Clixml`) | Same Windows user + same machine only |

**Key principle**: The backup server can create encrypted archives but **cannot decrypt them**. Decryption requires the `.pfx` from the physical safe.

## Vault Coverage SOP

1Password service accounts do **not** auto-inherit access to new vaults and **cannot be modified after creation**. When any vault is created in your org:

**Automated** (recommended):
```powershell
# Sign in as admin, then sync vault access
op signin
.\scripts\Sync-VaultAccess.ps1
```

This detects missing vaults, creates a new service account with full coverage, and stores the token automatically. See the script's `-WhatIf` flag for a dry run.

**Manual alternative**:
1. Admin Console > Service Accounts > Create new SA with all vaults
2. Run `.\scripts\Initialize-Credential.ps1` to store the new token
3. Delete the old SA from Admin Console
4. Run `.\scripts\Test-VaultCoverage.ps1` to verify

## DR Test Schedule

Test the full restore quarterly. See [docs/RECOVERY.md](docs/RECOVERY.md#dr-test-schedule) for the checklist.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
