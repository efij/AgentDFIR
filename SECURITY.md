# Security Policy

AgentDFIR is a forensic tool: it runs on compromised hosts and parses hostile evidence. Security reports are treated with priority.

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub Security Advisories ("Report a vulnerability" on the repository's Security tab). Do not open public issues for exploitable bugs.

Of particular interest:

- collector weaponization (symlink/path tricks causing over-collection or writes outside the package)
- evidence-package tamper-detection bypasses (hash chain, SHA256SUMS, content addressing)
- parser vulnerabilities (memory exhaustion, path traversal, archive bombs)
- analyst-targeting output injection (terminal escapes, invisible Unicode, HTML report injection)

## Scope notes

AgentDFIR never bypasses OS permissions, EDR, encryption or sandboxes by design — reports that a permission boundary blocks acquisition are expected behavior, not vulnerabilities.
