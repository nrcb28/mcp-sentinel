import { discoverConfigs } from './scanner/config-detector.js';
import { runSecurityAudit } from './analyzer/engine.js';
import { printTerminalReport } from './reporter/terminal-reporter.js';
import { generateHtmlReport } from './reporter/html-reporter.js';
import { outputJsonReport } from './reporter/json-reporter.js';
import { generateSarifReport } from './reporter/sarif-reporter.js';
import { probeMcpServer } from './scanner/mcp-client.js';
import { saveHardenedConfigFile } from './hardening/config-fixer.js';
import { createWebServer } from './server/web-server.js';

export async function runCli(argv = process.argv.slice(2)) {
  const command = argv[0];

  if (!command || command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    return 0;
  }

  if (command === '--version' || command === '-v') {
    console.log('mcp-sentinel v1.2.0');
    return 0;
  }

  if (command === 'serve' || command === 'ui') {
    let port = 4242;
    for (let i = 1; i < argv.length; i++) {
      if ((argv[i] === '--port' || argv[i] === '-p') && argv[i + 1]) {
        port = parseInt(argv[++i], 10) || 4242;
      }
    }
    const server = createWebServer(port);
    server.listen(port, () => {
      console.log(`\n🛡️ MCP-Sentinel Studio running at http://localhost:${port}`);
      console.log('Press Ctrl+C to stop the server.\n');
    });
    return new Promise(() => {}); // keep running
  }

  if (command === 'scan') {
    let customConfigs = [];
    let htmlPath = null;
    let jsonPath = null;
    let sarifPath = null;
    let failOn = null;

    for (let i = 1; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '--config' || arg === '-c') {
        if (argv[i + 1]) customConfigs.push(argv[++i]);
      } else if (arg === '--html') {
        if (argv[i + 1]) htmlPath = argv[++i];
      } else if (arg === '--json') {
        if (argv[i + 1]) jsonPath = argv[++i];
      } else if (arg === '--sarif') {
        if (argv[i + 1]) sarifPath = argv[++i];
      } else if (arg === '--fail-on') {
        if (argv[i + 1]) failOn = argv[++i].toUpperCase();
      }
    }

    const configs = discoverConfigs(customConfigs);
    const result = runSecurityAudit(configs);

    printTerminalReport(result);

    if (htmlPath) {
      generateHtmlReport(result, htmlPath);
      console.log(`📄 Visual HTML report generated: ${htmlPath}`);
    }

    if (jsonPath) {
      outputJsonReport(result, jsonPath);
      console.log(`📦 Machine-readable JSON report generated: ${jsonPath}`);
    }

    if (sarifPath) {
      generateSarifReport(result, sarifPath);
      console.log(`🛡️ SARIF v2.1.0 security report generated: ${sarifPath}`);
    }

    if (failOn) {
      const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const targetIndex = severities.indexOf(failOn);

      if (targetIndex !== -1) {
        let hasFailingIssue = false;
        for (let idx = targetIndex; idx < severities.length; idx++) {
          const sev = severities[idx];
          if (result.summary[sev] > 0) {
            hasFailingIssue = true;
            break;
          }
        }

        if (hasFailingIssue) {
          console.error(`❌ Security audit failed: found issues matching or exceeding threshold ${failOn}`);
          return 1;
        }
      }
    }

    return 0;
  }

  if (command === 'fix') {
    let configPath = null;
    let outputPath = null;

    for (let i = 1; i < argv.length; i++) {
      const arg = argv[i];
      if (arg === '--config' || arg === '-c') {
        if (argv[i + 1]) configPath = argv[++i];
      } else if (arg === '--output' || arg === '-o') {
        if (argv[i + 1]) outputPath = argv[++i];
      }
    }

    if (!configPath) {
      console.error('Error: specify config path to fix using "--config <path>"');
      return 1;
    }

    const targetOutput = outputPath || configPath.replace(/\.json$/, '.hardened.json');
    try {
      const changes = saveHardenedConfigFile(configPath, targetOutput);
      console.log(`\n🛡️ Hardened configuration created: ${targetOutput}`);
      console.log(`Applied ${changes.length} security remediations:`);
      for (const ch of changes) {
        console.log(`  ✔ ${ch}`);
      }
      return 0;
    } catch (err) {
      console.error(`Failed to harden config: ${err.message}`);
      return 1;
    }
  }

  if (command === 'probe') {
    const targetCommand = argv[1];
    if (!targetCommand) {
      console.error('Error: specify the command to run the MCP server. Example: mcp-sentinel probe npx -y @modelcontextprotocol/server-filesystem');
      return 1;
    }
    const targetArgs = argv.slice(2);
    console.log(`🔍 Probing MCP server: ${targetCommand} ${targetArgs.join(' ')} ...`);
    const probeRes = await probeMcpServer(targetCommand, targetArgs);

    if (probeRes.success) {
      console.log('\n✅ Server connected successfully via JSON-RPC!');
      console.log('Server Info:', JSON.stringify(probeRes.serverInfo, null, 2));
      console.log(`Discovered Tools (${probeRes.tools.length}):`);
      for (const t of probeRes.tools) {
        console.log(`  - ${t.name}: ${t.description || '(no description)'}`);
      }
      return 0;
    } else {
      console.error(`❌ Probe failed: ${probeRes.error}`);
      return 1;
    }
  }

  console.error(`Unknown command: "${command}". Run "mcp-sentinel --help" for usage.`);
  return 1;
}

function printHelp() {
  console.log(`
🛡️ MCP-Sentinel - Security & Permissions Auditor for Model Context Protocol (MCP)

USAGE:
  mcp-sentinel scan [options]           Audit installed or specified MCP server configs
  mcp-sentinel fix --config <file>      Auto-harden a vulnerable config file and mask secrets
  mcp-sentinel serve [--port <port>]    Launch interactive local web studio dashboard
  mcp-sentinel probe <cmd> [args]       Connect to a live MCP server via stdio and inspect capabilities
  mcp-sentinel --version                Display version information
  mcp-sentinel --help                   Display this help guide

SCAN OPTIONS:
  -c, --config <path>   Specify a custom MCP config JSON path (can be used multiple times)
  --html <path>         Output an interactive HTML security dashboard report
  --json <path>         Output raw JSON audit results (for CI/CD or logging)
  --sarif <path>        Output OASIS SARIF v2.1.0 report for GitHub Code Scanning
  --fail-on <level>     Exit with code 1 if issues >= level exist [LOW, MEDIUM, HIGH, CRITICAL]

FIX OPTIONS:
  -c, --config <path>   Path to vulnerable configuration file
  -o, --output <path>   Path to save hardened configuration (default: <file>.hardened.json)

EXAMPLES:
  # Scan all default installed clients (Claude Desktop, Cursor, Cline, Zed, etc.)
  $ mcp-sentinel scan

  # Scan a specific project mcp.json and produce an HTML report
  $ mcp-sentinel scan --config ./mcp.json --html ./security-report.html

  # Generate GitHub Code Scanning SARIF report
  $ mcp-sentinel scan --config ./claude_desktop_config.json --sarif ./results.sarif

  # Automatically harden a vulnerable config file
  $ mcp-sentinel fix --config ./mcp.json --output ./mcp.hardened.json
`);
}
