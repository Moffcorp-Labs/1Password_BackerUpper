# Contributing

Thanks for your interest in contributing to 1Password BackerUpper!

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch: `git checkout -b feat/my-feature`
4. Make your changes
5. Test on Windows with PowerShell 5.1 (the primary target)
6. Push and open a PR against `main`

## Requirements

- **PowerShell 5.1 compatibility is mandatory.** All code must work on Windows PowerShell 5.1 (ships with Windows 10/Server 2016+). PowerShell 7+ compatibility is also expected.
- **Zero third-party dependencies** beyond the 1Password CLI. Use only built-in .NET classes and PowerShell cmdlets.
- **No plaintext secrets** anywhere in code, comments, or examples.

## PowerShell 5.1 Gotchas

These have bitten us before -- please be aware:

- **`ConvertFrom-Json` does not enumerate arrays.** Always use `ConvertFrom-JsonArray` (defined in each script) instead of `@(... | ConvertFrom-Json)`.
- **`ConvertFrom-Json` is case-insensitive.** If an API returns both `url` and `URL`, it will throw. Parse with regex for known-duplicate APIs.
- **UTF-8 without BOM reads as Windows-1252.** Never use em dashes, smart quotes, or non-ASCII characters in `.ps1` files. Stick to ASCII.
- **Single objects lack `.Count`.** Always wrap `Get-ChildItem` results with `@()` if you need `.Count`.
- **`ProcessStartInfo.EnvironmentVariables`** copies the entire environment into a case-insensitive `StringDictionary`. Don't touch it -- let child processes inherit the parent environment.

## Branch Naming

- `feat/` -- New features
- `fix/` -- Bug fixes
- `chore/` -- Maintenance, CI, docs
- `docs/` -- Documentation only

## Pull Requests

- One logical change per PR
- Include a test plan (manual steps to verify)
- Update relevant docs if behavior changes
- PRs are squash-merged into `main`

## Code Style

- Use `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'`
- Use `[CmdletBinding()]` and `param()` blocks
- Prefer full cmdlet names over aliases (`Get-ChildItem` not `gci`)
- Comment the "why", not the "what"

## Reporting Issues

- Use GitHub Issues for bugs and feature requests
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)
