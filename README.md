# 🛡️ MCP-Sentinel

<p align="center">
  <strong>The Open-Source Security & Permissions Auditor for Model Context Protocol (MCP) Servers</strong>
</p>

<p align="center">
  <a href="https://github.com/nrcb28/mcp-sentinel/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build Status"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-%3E%3D18.0.0-blue?style=flat-square" alt="Node Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-purple?style=flat-square" alt="License"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-2024--11--05-orange?style=flat-square" alt="MCP Spec"></a>
  <a href="https://sarifweb.azurewebsites.net/"><img src="https://img.shields.io/badge/SARIF-v2.1.0-blueviolet?style=flat-square" alt="SARIF 2.1.0"></a>
  <a href="https://github.com/nrcb28/mcp-sentinel"><img src="https://img.shields.io/badge/tests-25%20passed-success?style=flat-square" alt="Tests"></a>
  <a href="https://github.com/nrcb28/mcp-sentinel"><img src="https://img.shields.io/badge/PRs-welcome-green.svg?style=flat-square" alt="PRs Welcome"></a>
</p>

---

## ⚡ Overview

The **Model Context Protocol (MCP)** has rapidly become the universal standard for connecting AI coding assistants and agents (Claude Desktop, Cursor, Antigravity, Cline, Windsurf, Zed) to local tools and resources.

However, installing third-party MCP servers introduces acute security risks: **arbitrary shell execution, unrestricted file system exposure (`~/.ssh`, `.env`), credential leaks, database takeover, and container breakouts.**

**MCP-Sentinel** is a lightweight, zero-dependency security scanner that audits your MCP server configurations and live processes, identifying vulnerabilities and assigning an actionable security score from **A+** to **F**.

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                              MCP-SENTINEL                              │
   │  [Claude Desktop] [Cursor] [Cline] [Windsurf] [Zed] [WSL2] [Continue]  │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
         ┌─────────────────────────────┴─────────────────────────────┐
         ▼                                                           ▼
  Static Config & Sandbox Auditing                           Live JSON-RPC Probe
  • Sensitive Filesystem Paths (~/.ssh, .env)                • Query tools/list
  • Shell & Subprocess Execution Risks                       • Inspect inputSchemas
  • Hardcoded Plaintext Secrets (OpenAI, AWS...)             • Exfiltration detection
  • Database Root URI & Plaintext Passwords                  • Prompt injection detection
  • Supply Chain & Unpinned Packages (npx/uvx)               • Network transport checks
  • Docker Socket Mounts & Privilege Escalations
         │                                                           │
         └─────────────────────────────┬─────────────────────────────┘
                                       ▼
                    [ Security Score & Grade: A+ to F ]
   [ Terminal UI ]  [ HTML Report ]  [ SARIF v2.1.0 ]  [ Web Studio Dashboard ]
                                       │
                                       ▼
                       [ Auto-Harden & Fix Command ]
```

---

## 🚀 Key Features

- 🌐 **Deep Cross-Platform Compatibility:**
  - **Windows:** Native Roaming/Local AppData & Windows Terminal support.
  - **macOS:** Full `~/Library/Application Support/` detection.
  - **Linux & BSD:** Full XDG Base Directory specification compliance (`$XDG_CONFIG_HOME`, `~/.config`).
  - **WSL & WSL2:** Automatically inspects Windows host configurations (`/mnt/c/Users/...`) from inside Linux!
  - **Client Ecosystem:** Supports Claude Desktop, Cursor, Cline, Roo Code, Windsurf, Zed Editor, Continue.dev, and Antigravity.
- 🛡️ **Comprehensive Rule Engine:**
  - **Filesystem Isolation:** Detects root directory grants, traversal patterns (`../`), and sensitive path access (`.ssh`, `.aws`, `.env`, system directories).
  - **Arbitrary Execution Guard:** Identifies direct invocations of `powershell`, `bash`, `cmd`, inline evaluation (`-e`, `-c`), and policy bypasses (`-ExecutionPolicy Bypass`).
  - **Secret & API Key Leakage:** Detects unmasked tokens (OpenAI, Anthropic, GitHub, AWS, Stripe, Google), Bearer tokens, JWTs, and inline credentials in configs or arguments.
  - **Database Credentials & TLS:** Audits database connection strings for superuser/root roles, plaintext passwords, and disabled SSL (`sslmode=disable`).
  - **Prompt Injection Defense:** Flags unconstrained string parameters (`query`, `sql`, `command`) vulnerable to indirect prompt injection.
  - **Supply Chain Pinning:** Flags unpinned or `@latest` packages in `npx` / `uvx` and dangerous `curl | bash` patterns. The hardener never invents a package version; it leaves the package unchanged and requests a verified exact pin.
  - **Container & Docker Sandbox:** Detects dangerous docker mounts (`/var/run/docker.sock`), `--privileged` mode, and `--network host`.
  - **Network & SSRF Guard:** Identifies cloud metadata target endpoints (`169.254.169.254`), unencrypted HTTP/WS, and disabled TLS verification.
- 💻 **Interactive Web Studio (`mcp-sentinel serve`):** Launches a local dark-mode dashboard to visually inspect servers, test live configurations, and auto-harden configs with one click.
- 🛠️ **Auto-Hardener (`mcp-sentinel fix`):** Automatically sanitizes vulnerable configuration files by masking secrets with environment variable references and reporting packages that still need a verified exact pin.
- 🔎 **Live Probe Audit:** `probe` now analyzes discovered MCP tools for exfiltration, arbitrary execution, and prompt-injection surfaces instead of only listing them.
- 🔐 **Safe Artifacts:** JSON, SARIF, HTML, and hardened configurations reject symlink output targets, enforce size limits, and use private file permissions where supported.
- 📊 **OASIS SARIF v2.1.0:** Natively outputs SARIF for direct integration with **GitHub Advanced Security** and Code Scanning alerts.
- 🤖 **Native GitHub Action & Pre-commit Hook:** Integrate into your CI/CD pipelines and local git hooks with zero friction.
- ⚡ **Zero External Dependencies:** Pure modern Node.js standards. Blazing fast (<200ms scan time, <30kB package size).

---

## 📦 Installation

### Run instantly with `npx` (No installation needed)
```bash
npx mcp-sentinel scan
```

### Launch Interactive Web Studio
```bash
npx mcp-sentinel serve
```

### Install globally via `npm`
```bash
npm install -g mcp-sentinel
```

### Clone and run locally
```bash
git clone https://github.com/nrcb28/mcp-sentinel.git
cd mcp-sentinel
npm test
```

---

## 💻 CLI Usage

### 1. Scan default installed MCP clients
```bash
mcp-sentinel scan
```

### 2. Launch Local Web Studio
```bash
mcp-sentinel serve --port 4242
```

The Web Studio binds to `127.0.0.1` only and has no authentication. Do not
reverse-proxy or expose it publicly without adding an authenticated,
TLS-terminating boundary.

### 3. Scan a specific project configuration file
```bash
mcp-sentinel scan --config ./claude_desktop_config.json
```

### 4. Generate an interactive HTML security dashboard
```bash
mcp-sentinel scan --html ./security-report.html
```

### 5. Generate GitHub Code Scanning SARIF report
```bash
mcp-sentinel scan --config ./mcp.json --sarif ./results.sarif
```

### 6. Auto-harden a vulnerable configuration file
```bash
mcp-sentinel fix --config ./claude_desktop_config.json --output ./hardened_config.json
```

### 7. CI/CD Gatekeeper (fail pipeline on critical or high vulnerabilities)
```bash
mcp-sentinel scan --config ./mcp.json --fail-on HIGH
```

### 8. Probe a live MCP server over stdio
```bash
mcp-sentinel probe npx -y @modelcontextprotocol/server-filesystem C:/Projects
```

Probe children receive a minimal inherited environment by default. The full
parent environment is never forwarded automatically; pass only required
variables explicitly through the programmatic API.

On WSL, discovery scans the inferred Windows user only. Set
`MCP_SENTINEL_SCAN_ALL_USERS=1` only for an authorized multi-user audit.

---

## 🤖 GitHub Action Integration

Add MCP-Sentinel directly to your GitHub repository workflow (`.github/workflows/security.yml`):

```yaml
name: MCP Security Audit

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Audit MCP Configuration
        uses: nrcb28/mcp-sentinel@main
        with:
          config: './mcp.json'
          fail-on: 'HIGH'
          sarif: 'mcp-sentinel.sarif'

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'mcp-sentinel.sarif'
```

---

## 🪝 Pre-commit Hook Integration

Add MCP-Sentinel to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/nrcb28/mcp-sentinel
    rev: v1.4.0
    hooks:
      - id: mcp-sentinel
```

---

## 📋 Security Rules Reference

| Rule ID | Severity | Description |
| :--- | :---: | :--- |
| `FS_SENSITIVE_PATH_EXPOSURE` | **CRITICAL** | Server is granted direct access to sensitive paths (`.ssh`, `.aws`, `.env`, etc.) |
| `FS_PATH_TRAVERSAL_DETECTED` | **MEDIUM** | Arguments contain directory traversal operators (`../`) |
| `SHELL_DIRECT_INVOCATION` | **CRITICAL** | Command launches directly inside interactive shells (`powershell`, `bash`, `cmd`) |
| `SHELL_EXECUTION_POLICY_BYPASS`| **HIGH** | Explicit execution policy bypass (`-ExecutionPolicy Bypass`) |
| `SECRET_PLAINTEXT_IN_CONFIG` | **CRITICAL** | Hardcoded API keys or credentials detected in `env` variables |
| `DB_CONNECTION_PLAINTEXT_SECRET`| **CRITICAL** | Database URI contains embedded plaintext password |
| `DB_ADMIN_CREDENTIALS_EXPOSED` | **HIGH** | Database connection uses superuser or root account |
| `TOOL_ARBITRARY_EXECUTION_CAPABILITY`| **CRITICAL** | Tool exposes arbitrary shell/script execution without domain constraints |
| `SUPPLY_CHAIN_UNPINNED_PACKAGE` | **HIGH** | Package is invoked via `npx`/`uvx` without an exact version pin |
| `SUPPLY_CHAIN_REMOTE_EXECUTION` | **CRITICAL** | Remote script downloaded and piped directly to shell (`curl \| bash`) |
| `DOCKER_SOCKET_EXPOSURE` | **CRITICAL** | Docker daemon socket (`docker.sock`) mounted inside container |
| `DOCKER_PRIVILEGED_MODE` | **CRITICAL** | Container runs in privileged mode, disabling kernel protections |
| `NETWORK_CLOUD_METADATA_SSRF` | **CRITICAL** | Target endpoint accesses cloud metadata service (`169.254.169.254`) |
| `NETWORK_TLS_VERIFICATION_DISABLED` | **CRITICAL** | TLS certificate validation is disabled (`NODE_TLS_REJECT_UNAUTHORIZED=0`) |
| `EXFILTRATION_COMBINED_CAPABILITIES`| **HIGH** | Server pairs file-reading capabilities with external network requests |

---

## 🧪 Automated Testing

MCP-Sentinel includes a comprehensive automated test suite with 25 unit tests covering the core security logic across Windows, macOS, and Linux:

```bash
npm test
```

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

---

<p align="center">
  Crafted with care by <strong><a href="https://github.com/nrcb28">Nicolás Riquelme Lozano</a></strong>
</p>
