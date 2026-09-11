# Security policy

## Reporting a vulnerability

Email **security@auditai.sh** with a description and, if possible, a minimal reproduction. You will
get an acknowledgement within 72 hours and a fix or a mitigation plan within 14 days for anything
that affects users of the scanner or the hosted product.

Please do not open public issues for security reports.

## Scope

- `auditai-scan` npm package and everything in this repository.
- The hosted product at auditai.sh (GitHub App, MCP server, sandbox verification).

## What the scanner does with your code

- Reads files locally. No network calls, no telemetry, no model calls.
- Treats analyzed repository content as untrusted data: comments or strings in the scanned code
  cannot change the scanner's behavior.
- Never executes the code it scans.

## Supported versions

The latest published version of `auditai-scan` and the `main` branch.
