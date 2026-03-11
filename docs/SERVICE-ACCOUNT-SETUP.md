# 1Password Service Account Setup

## Overview

The backup script authenticates to 1Password via a **Service Account** -- a non-human identity designed for automation. Service accounts have their own token and can only access vaults explicitly granted to them.

## Step 1: Create the Service Account

1. Sign in to [1Password.com](https://start.1password.com) as an **Owner** or **Administrator**
2. Navigate to **Settings → Service Accounts** (under Integrations)
3. Click **Create Service Account**
4. Configure:
   - **Name**: `BCDR-Backup` (or similar descriptive name)
   - **Expires**: Set to your org's policy (or "Never" for long-lived automation)

## Step 2: Grant Vault Access

**Grant access to EVERY vault in your organization:**

1. On the service account page, click **Add Vault Access**
2. Select each vault and grant **Read Items** permission
3. Repeat for ALL vaults -- the service account can only backup vaults it can read

**Minimum required permissions per vault:**
- Read Items ✅
- Write Items ❌ (not needed for backup)
- Manage Vault ❌ (not needed)

## Step 3: Copy the Token

After creation, 1Password displays the service account token **once**. It starts with `ops_`.

1. Copy the token immediately
2. You will paste it into `Initialize-Credential.ps1` on the backup server
3. The token cannot be viewed again -- if lost, you must regenerate it

## Step 4: Store the Token on the Backup Server

On the Windows server that will run backups:

```powershell
.\scripts\Initialize-Credential.ps1
# Paste the ops_... token when prompted
```

This stores the token encrypted with Windows DPAPI.

## Future Vault Access -- SOP

**1Password service accounts do NOT automatically gain access to new vaults, and vault access CANNOT be modified after creation.** The only way to add vaults is to create a new service account.

### Automated Sync (Recommended)

When ANY new vault is created in your organization:

```powershell
# 1. Sign in as admin/owner
op signin

# 2. Check for gaps (dry run)
.\scripts\Sync-VaultAccess.ps1 -WhatIf

# 3. Fix gaps (creates new SA, stores token, shows next steps)
.\scripts\Sync-VaultAccess.ps1

# 4. Delete old SA from admin console (script will remind you)
```

### Manual Alternative

If you prefer not to use the automated sync:

1. Create a new service account in **Settings → Service Accounts**
2. Grant **Read Items** to ALL vaults
3. Copy the token and run `Initialize-Credential.ps1` on the backup server
4. Delete the old service account
5. Run `Test-VaultCoverage.ps1` to confirm

### Recommended: Add to Vault Creation Checklist

Add this step to your organization's vault creation procedure:

> **After creating a new vault:**
> - [ ] Run `Sync-VaultAccess.ps1` to update backup coverage (or manually grant SA access)
> - [ ] Run `Test-VaultCoverage.ps1` to verify

## Token Rotation

To rotate the service account token:

1. Go to **Settings → Service Accounts → BCDR-Backup**
2. Click **Regenerate Token**
3. Copy the new token
4. On the backup server, re-run:
   ```powershell
   .\scripts\Initialize-Credential.ps1
   ```
5. Run a dry-run test:
   ```powershell
   .\scripts\Backup-1Password.ps1 -DryRun
   ```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "No vaults accessible" | Service account has no vault grants | Grant vault access in admin console |
| "Authentication failed" | Token expired or regenerated | Re-run `Initialize-Credential.ps1` with current token |
| Missing vaults in coverage audit | New vault not shared with service account | Add vault access per SOP above |
| "Insufficient permissions" | Service account lacks Read Items | Edit vault access in admin console |
