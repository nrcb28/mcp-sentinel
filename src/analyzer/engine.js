import { analyzeFilesystemRisk } from './rules/filesystem-rule.js';
import { analyzeShellExecRisk } from './rules/shell-exec-rule.js';
import { analyzeSecretsLeakRisk } from './rules/secrets-leak-rule.js';
import { analyzeExfiltrationRisk } from './rules/exfiltration-rule.js';
import { analyzeSupplyChainRisk } from './rules/supply-chain-rule.js';
import { analyzeDockerSandboxRisk } from './rules/docker-sandbox-rule.js';
import { analyzeNetworkTransportRisk } from './rules/network-transport-rule.js';
import { analyzeDatabaseSafetyRisk } from './rules/database-safety-rule.js';
import { analyzePromptInjectionRisk } from './rules/prompt-injection-rule.js';

export function calculateGrade(score) {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/**
 * Evaluates a single MCP server configuration across all security domains.
 */
export function auditServer(serverName, serverConfig, liveTools = []) {
  const issues = [
    ...analyzeFilesystemRisk(serverName, serverConfig),
    ...analyzeShellExecRisk(serverName, serverConfig),
    ...analyzeSecretsLeakRisk(serverName, serverConfig),
    ...analyzeExfiltrationRisk(serverName, serverConfig, liveTools),
    ...analyzeSupplyChainRisk(serverName, serverConfig),
    ...analyzeDockerSandboxRisk(serverName, serverConfig),
    ...analyzeNetworkTransportRisk(serverName, serverConfig),
    ...analyzeDatabaseSafetyRisk(serverName, serverConfig),
    ...analyzePromptInjectionRisk(serverName, serverConfig, liveTools),
  ];

  let deductions = 0;
  for (const issue of issues) {
    if (issue.severity === 'CRITICAL') deductions += 30;
    else if (issue.severity === 'HIGH') deductions += 15;
    else if (issue.severity === 'MEDIUM') deductions += 5;
    else if (issue.severity === 'LOW') deductions += 2;
  }

  const score = Math.max(0, 100 - deductions);
  const grade = calculateGrade(score);

  return {
    server: serverName,
    config: serverConfig,
    score,
    grade,
    issues,
    liveToolsCount: liveTools.length,
  };
}

/**
 * Runs a complete security audit across all discovered configs and servers.
 */
export function runSecurityAudit(discoveredConfigs, options = {}) {
  const serverResults = [];
  let totalIssuesCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  for (const item of discoveredConfigs) {
    if (!item.servers) continue;

    for (const [name, cfg] of Object.entries(item.servers)) {
      if (!cfg || typeof cfg !== 'object') continue;

      const serverAudit = auditServer(name, cfg);
      serverAudit.sourceClient = item.client;
      serverAudit.sourcePath = item.path;

      for (const issue of serverAudit.issues) {
        if (totalIssuesCount[issue.severity] !== undefined) {
          totalIssuesCount[issue.severity]++;
        }
      }

      serverResults.push(serverAudit);
    }
  }

  // Calculate overall global score
  const totalServers = serverResults.length;
  let overallScore = 100;
  if (totalServers > 0) {
    const sum = serverResults.reduce((acc, s) => acc + s.score, 0);
    overallScore = Math.round(sum / totalServers);
  }

  const overallGrade = calculateGrade(overallScore);

  return {
    timestamp: new Date().toISOString(),
    totalConfigs: discoveredConfigs.length,
    totalServers,
    overallScore,
    overallGrade,
    summary: totalIssuesCount,
    servers: serverResults,
  };
}
