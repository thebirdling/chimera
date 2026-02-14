# Security Policy

## Offline-First Guarantee

Chimera is designed as an offline research framework. It does not:
- Make outbound network connections (unless configured for SIEM export destinations).
- Send telemetry.
- Auto-update.

We treat any violation of this "air-gap readiness" as a critical security vulnerability.

## Reporting a Vulnerability

If you discover a security vulnerability in Chimera (e.g., potential for RCE via malicious config, or data leak in logging), please report it privately.

**Do not open a GitHub issue.**

Please email: `security@thebirdling.com`.

## Supported Versions

| Version | Supported |
|sq-------|-----------|
| 0.2.x   | ✅        |
| 0.1.x   | ❌        |

## Threat Model

Chimera is intended to run on secured research workstations or internal security analysis servers. 
- Input: Authentication logs (CSV/JSON).
- Threat: Maliciously crafted log files could potentially exploit parsing logic (e.g., CSV injection, though pandas handles this well).
- Mitigation: Run Chimera with least privilege.
