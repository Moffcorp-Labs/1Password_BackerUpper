# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - Unreleased

### Added
- `Sync-VaultAccess.ps1` -- Detect and fix service account vault coverage gaps automatically
  - Compares admin-visible org vaults with SA-accessible vaults
  - Creates a new service account with full vault access when gaps are found
  - Stores new token in DPAPI automatically (reuses Initialize-Credential pattern)
  - Supports `-WhatIf` for gap analysis without changes
  - Filters non-grantable vault types (Personal, Everyone, Employee)
  - Validates op CLI v2.26.0+ requirement
  - Verifies new SA access after creation

## [1.0.0] - 2026-03-10

### Added
- `Backup-1Password.ps1` -- Automated vault export with hybrid AES-256 + CMS encryption
- `Restore-1Password.ps1` -- Decrypt and restore from encrypted backups (extract-only or full restore)
- `New-BackupCertificate.ps1` -- Self-signed Document Encryption certificate generation
- `Initialize-Credential.ps1` -- DPAPI-encrypted service account token storage
- `Install-ScheduledTask.ps1` -- Windows Task Scheduler setup for daily backups
- `Test-VaultCoverage.ps1` -- Audit which vaults the service account can access
- Hybrid encryption: streaming AES-256-CBC for data + CMS/PKCS#7 envelope for key material
- SHA-256 integrity sidecar files for each backup
- Configurable retention with timestamp-based pruning
- Secure temp file wiping (random overwrite before delete)
- Concurrency guard via named mutex
- Full setup guide, recovery runbook, and service account SOP

### Fixed
- PowerShell 5.1 compatibility: UTF-8 em dashes read as Windows-1252 smart quotes
- PowerShell 5.1 compatibility: `op whoami` duplicate JSON keys (`url`/`URL`)
- PowerShell 5.1 compatibility: `ConvertFrom-Json` array flattening
- PowerShell 5.1 compatibility: `.Count` on single `FileInfo` objects
- PowerShell 5.1 compatibility: `ProcessStartInfo.EnvironmentVariables` corruption
- StrictMode crash in restore `finally` block when decryption fails early
