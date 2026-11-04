# Security Policy

## Supported versions

Only the latest `main` branch is actively maintained.

## Reporting a vulnerability

Please report security issues privately to the repository maintainer rather
than opening a public issue. Include the affected version, reproduction steps,
impact, and a minimal proof of concept. Do not include live credentials or
personal data.

## Safe operation

`mcp-sentinel serve` is a local development interface. It is bound to
`127.0.0.1` by the CLI and protects API calls with a random per-start session
cookie plus local-origin checks. It must not be exposed through a public
interface without a separately authenticated and encrypted reverse proxy.

The landing page issues the cookie to local clients. This protects browser
requests against cross-origin access and DNS rebinding; it does not isolate
the service from other processes or users on the same computer.

On WSL, configuration discovery is scoped to the inferred Windows user by
default. The `MCP_SENTINEL_SCAN_ALL_USERS=1` override should be used only by
an operator authorized to inspect all local Windows profiles.
