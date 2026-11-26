# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | :white_check_mark: |

Memory-safe parsing of untrusted forensic artifacts (`evtx`, `regf`, `ESE`, `MDMP`, `SCCA`, `SHLLINK`, `CFBF`), strict read-only execution guarantees, and zero credential-extraction / zero process-injection posture are top priorities for `forensics2rust`.

If you discover a parser panic, integer overflow, path traversal, or security vulnerability:
1. **Do not disclose it publicly** via GitHub Issues.
2. Submit a report privately via GitHub Private Vulnerability Reporting under the Security tab:
   `https://github.com/adpaolucci/forensics2rust/security/advisories/new`
3. You will receive an acknowledgment within 48 hours.
4. A security patch and advisory will be coordinated and released promptly.
