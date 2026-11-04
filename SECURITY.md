# Security Policy

## Supported versions

Only the latest `main` branch is actively maintained.

## Reporting a vulnerability

Please report security issues privately to the repository maintainer rather
than opening a public issue. Include the affected version, reproduction steps,
impact, and a minimal proof of concept. Do not include live credentials or
personal data.

## Safe operation

`mcp-sentinel serve` is a local, unauthenticated development interface. It is
bound to `127.0.0.1` by the CLI and must not be exposed through a public
interface without an authenticated and encrypted reverse proxy.
