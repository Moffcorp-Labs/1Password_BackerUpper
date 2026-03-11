# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@moffcorplabs.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Security Design

This tool handles sensitive data (1Password vault exports). Key security properties:

- **Encryption at rest**: All backups are AES-256-CBC encrypted with CMS/PKCS#7 key wrapping
- **Key separation**: The backup server holds only the public key; the private key (.pfx) is stored in a physical safe
- **Credential protection**: The service account token is DPAPI-encrypted (Windows user + machine bound)
- **Secure cleanup**: Temp files are overwritten with random data before deletion (best-effort on SSDs)
- **No secrets in code**: Zero hardcoded credentials, tokens, or keys anywhere in the codebase

## Scope

The following are in scope for security reports:
- Cryptographic weaknesses in the backup/restore encryption
- Credential exposure (token leaks, insecure temp file handling)
- Path traversal or injection in file operations
- Privilege escalation via the scheduled task

The following are out of scope:
- Vulnerabilities in the 1Password CLI itself (report to [1Password](https://bugcrowd.com/agilebits))
- Issues requiring pre-existing access to the backup server as the same Windows user
- Social engineering of the physical safe containing the .pfx
