# Setup Guide -- 1Password BCDR Backup

## Prerequisites

| Requirement | Version | Install |
|---|---|---|
| Windows | 10+ / Server 2019+ | -- |
| PowerShell | 5.1+ (or pwsh 7+) | Built-in / `winget install Microsoft.PowerShell` |
| 1Password CLI | 2.x | `winget install AgileBits.1Password.CLI` |
| .NET Framework | 4.5+ | Built-in on Windows 10+ |
| 1Password Business | -- | Admin access required for service account setup |

No third-party encryption tools required. CMS encryption uses built-in .NET classes.

## Step 1: Create the Service Account

See [SERVICE-ACCOUNT-SETUP.md](SERVICE-ACCOUNT-SETUP.md) for detailed instructions.

You will end up with a token starting with `ops_...`.

## Step 2: Generate Encryption Certificate

```powershell
.\scripts\New-BackupCertificate.ps1
```

This generates a 4096-bit RSA Document Encryption certificate and:
- Exports `BCDR_1PW_Backup_Key.pfx` (private key) -- for physical safe
- Exports `BCDR_1PW_Backup_Cert.cer` (public key) -- keep as digital backup
- Imports public-only cert into the Windows certificate store
- Displays the **thumbprint** you'll need for the config file

**CRITICAL after running:**
1. **Print or copy the .pfx file** to physical media and store in a **physical safe**
2. **Record the PFX password** -- store it with the .pfx in the safe
3. **Delete the .pfx from the server**: `Remove-Item .\BCDR_1PW_Backup_Key.pfx -Force`
4. The .cer file is safe to keep digitally (public key only, cannot decrypt)

## Step 3: Clone the Repository

```powershell
git clone https://github.com/Moffcorp-Labs/1Password_BackerUpper.git
cd 1Password_BackerUpper
```

## Step 4: Create Configuration File

```powershell
Copy-Item config\backup-config.example.json config\backup-config.json
```

Edit `config\backup-config.json`:

```json
{
  "BackupPath": "C:\\Backups\\1Password",
  "CertificateThumbprint": "paste_your_40_char_thumbprint_here",
  "RetentionDays": 7,
  "LogLevel": "INFO",
  "RateLimitDelayMs": 100
}
```

- `BackupPath`: Where encrypted archives land. Ensure adequate disk space.
- `CertificateThumbprint`: 40-character hex thumbprint from Step 2.
- `RetentionDays`: Number of daily backups to keep (default: 7).
- `RateLimitDelayMs`: Delay between op CLI calls to avoid rate limiting.

## Step 5: Store the Service Account Token

```powershell
.\scripts\Initialize-Credential.ps1
```

Paste the `ops_...` token when prompted. This encrypts it with Windows DPAPI -- only the current user on this machine can decrypt it.

## Step 6: Validate Setup

```powershell
# Dry run -- validates config, credentials, certificate, and op CLI auth
.\scripts\Backup-1Password.ps1 -DryRun -Verbose
```

## Step 7: Audit Vault Coverage

```powershell
.\scripts\Test-VaultCoverage.ps1
```

Compare the output against your full vault list in the [1Password admin console](https://start.1password.com). Any vault NOT listed is NOT being backed up.

**Tip**: To automatically detect and fix vault coverage gaps, use `Sync-VaultAccess.ps1` instead (requires admin sign-in via `op signin`). See [SERVICE-ACCOUNT-SETUP.md](SERVICE-ACCOUNT-SETUP.md#automated-sync-recommended).

## Step 8: Run First Backup

```powershell
.\scripts\Backup-1Password.ps1 -Verbose
```

Verify the `.zip.cms` encrypted archive appears in your `BackupPath`.

## Step 9: Install Scheduled Task

```powershell
# Requires Administrator
.\scripts\Install-ScheduledTask.ps1
```

Default: runs daily at 2:00 AM. Customize:

```powershell
.\scripts\Install-ScheduledTask.ps1 -TaskTime "03:30"
```

## Step 10: Verify Scheduled Task

```powershell
Get-ScheduledTask -TaskName '1Password BCDR Backup' -TaskPath '\BCDR\'
```

Trigger a manual run to confirm:

```powershell
Start-ScheduledTask -TaskName '1Password BCDR Backup' -TaskPath '\BCDR\'
```

Check logs in `<BackupPath>\logs\`.

## Post-Setup Checklist

- [ ] Service account created with access to ALL current vaults
- [ ] Encryption certificate generated via `New-BackupCertificate.ps1`
- [ ] .pfx and PFX password stored in physical safe
- [ ] .pfx deleted from all digital storage on the server
- [ ] `backup-config.json` created with correct thumbprint
- [ ] DPAPI credential stored via `Initialize-Credential.ps1`
- [ ] Dry run passes
- [ ] Vault coverage audit shows all expected vaults
- [ ] First backup completes successfully
- [ ] Scheduled task installed and verified
- [ ] Test restore performed (see [RECOVERY.md](RECOVERY.md))
- [ ] SOP documented: run `Sync-VaultAccess.ps1` when new vaults are created
