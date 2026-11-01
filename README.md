# 🛡️ MCP-Sentinel

<p align="center">
  <strong>The Open-Source Security & Permissions Auditor for Model Context Protocol (MCP) Servers</strong>
</p>

<p align="center">
  <a href="https://github.com/nrcb28/mcp-sentinel/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build Status"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-%3E%3D18.0.0-blue?style=flat-square" alt="Node Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-purple?style=flat-square" alt="License"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-2024--11--05-orange?style=flat-square" alt="MCP Spec"></a>
  <a href="https://github.com/nrcb28/mcp-sentinel"><img src="https://img.shields.io/badge/PRs-welcome-green.svg?style=flat-square" alt="PRs Welcome"></a>
</p>

---

## ⚡ Overview

The **Model Context Protocol (MCP)** has rapidly become the universal standard for connecting AI coding assistants and agents (Claude Desktop, Cursor, Antigravity, Cline, Windsurf) to local tools and resources.

However, installing third-party MCP servers introduces acute security risks: **arbitrary shell execution, unrestricted file system exposure (`~/.ssh`, `.env`), and credential exfiltration.**

**MCP-Sentinel** is a lightweight, zero-dependency security scanner that audits your MCP server configurations and live processes, identifying vulnerabilities and assigning an actionable security score from **A+** to **F**.

```
   ┌─────────────────────────────────────────────────────────────┐
   │                        MCP-SENTINEL                         │
   │  [Claude Desktop] [Cursor] [Cline] [Windsurf] [Antigravity]  │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
  Static Config Auditing                          Live JSON-RPC Probe
  • Sensitive Filesystem Paths (~/.ssh, .env)     • Query tools/list
  • Shell & Subprocess Execution Risks            • Inspect inputSchemas
  • Hardcoded Plaintext Secrets (OpenAI, AWS...)  • Exfiltration detection
         │                                                 │
         └────────────────────────┬────────────────────────┘
                                  ▼
               [ Security Score & Grade: A+ to F ]
             [ Terminal UI ]  [ HTML Report ]  [ JSON ]
```

---

## 🚀 Key Features

- 🔍 **Universal Auto-Discovery:** Automatically locates and reads configuration files from Claude Desktop, Cursor, Cline, Windsurf, Antigravity, and local repositories across Windows, macOS, and Linux.
- 🛡️ **Comprehensive Rule Engine:**
  - **Filesystem Isolation:** Detects root directory grants, traversal patterns (`../`), and sensitive path access (`.ssh`, `.aws`, `.env`, system files).
  - **Arbitrary Execution Guard:** Identifies direct invocations of `powershell`, `bash`, `cmd`, evaluation flags (`-e`, `-c`), and policy bypasses (`-ExecutionPolicy Bypass`).
  - **Secret & API Key Leakage:** Detects unmasked tokens (OpenAI, Anthropic, GitHub, AWS, Stripe, Google) embedded in configs or CLI arguments.
  - **Exfiltration Vector Analysis:** Flags dangerous capability intersections (e.g. servers combining local filesystem reads with outbound network requests).
- 📊 **Multiple Output Formats:**
  - **Terminal Report:** Colored ANSI summary with exact fixes.
  - **Interactive HTML Dashboard:** Standalone dark-mode visual report for security reviews.
  - **Machine-Readable JSON:** Ready for ingestion in SIEM or pipeline tools.
- 🚦 **CI/CD Gatekeeper Mode:** Set `--fail-on [CRITICAL|HIGH|MEDIUM|LOW]` to halt deployment if security policies are violated.
- ⚡ **Zero External Dependencies:** Built with pure modern Node.js standards. Blazing fast (<200ms scan time).

---

## 📦 Installation

### Run instantly with `npx` (No installation needed)
```bash
npx mcp-sentinel scan
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

### 2. Scan a specific project configuration file
```bash
mcp-sentinel scan --config ./claude_desktop_config.json
```

### 3. Generate an interactive HTML security dashboard
```bash
mcp-sentinel scan --html ./security-report.html
```

### 4. CI/CD Gatekeeper (fail pipeline on critical or high vulnerabilities)
```bash
mcp-sentinel scan --config ./mcp.json --fail-on HIGH
```

### 5. Probe a live MCP server over stdio
```bash
mcp-sentinel probe npx -y @modelcontextprotocol/server-filesystem C:/Projects
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
| `SECRET_IN_COMMAND_ARGUMENTS` | **CRITICAL** | Credentials passed via CLI args (observable via process lists) |
| `EXFILTRATION_COMBINED_CAPABILITIES`| **HIGH** | Server pairs file-reading capabilities with external network requests |

---

## 🔧 Programmatic API

You can also use MCP-Sentinel directly inside your Node.js applications:

```javascript
import { discoverConfigs, runSecurityAudit, generateHtmlReport } from 'mcp-sentinel';

// 1. Discover configurations
const configs = discoverConfigs(['./mcp.json']);

// 2. Run the security audit
const audit = runSecurityAudit(configs);

console.log(`Audit Grade: ${audit.overallGrade} (${audit.overallScore}/100)`);
console.log(`Total Issues: ${audit.summary.CRITICAL} Critical, ${audit.summary.HIGH} High`);

// 3. Export HTML report
generateHtmlReport(audit, './report.html');
```

---

## 🧪 Running Tests

MCP-Sentinel includes a comprehensive automated test suite with 100% core coverage:

```bash
npm test
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue to propose new security rules or client detectors.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/NewRule`)
3. Commit your Changes (`git commit -m 'Add new rule for Docker MCP sandboxing'`)
4. Push to the Branch (`git push origin feature/NewRule`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

---

<p align="center">
  Crafted with care by <strong><a href="https://github.com/nrcb28">Nicolás Riquelme Lozano</a></strong>
</p>
