## Summary
<!-- Brief description of what this PR does -->

## Test plan
<!-- How to verify this change works -->
- [ ] Tested on PowerShell 5.1
- [ ] Tested on PowerShell 7+

## Checklist
- [ ] No non-ASCII characters in `.ps1` files
- [ ] `@()` wrapping on all `Get-ChildItem` results that use `.Count`
- [ ] `ConvertFrom-JsonArray` used instead of `@(... | ConvertFrom-Json)`
- [ ] No hardcoded secrets, paths, or org-specific references
- [ ] Updated docs if behavior changed
