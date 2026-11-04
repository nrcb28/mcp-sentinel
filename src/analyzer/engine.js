import { analyzeFilesystemRisk } from './rules/filesystem-rule.js';
import { analyzeShellExecRisk } from './rules/shell-exec-rule.js';
import { analyzeSecretsLeakRisk } from './rules/secrets-leak-rule.js';
import { analyzeExfiltrationRisk } from './rules/exfiltration-rule.js';
import { analyzeSupplyChainRisk } from './rules/supply-chain-rule.js';
import { analyzeDockerSandboxRisk } from './rules/docker-sandbox-rule.js';
import { analyzeNetworkTransportRisk } from './rules/network-transport-rule.js';
import { analyzeDatabaseSafetyRisk } from './rules/database-safety-rule.js';
import { analyzePromptInjectionRisk } from './rules/prompt-injection-rule.js';
import { redactSensitiveConfig, redactIssue } from '../security/redaction.js';

const MAX_SERVERS_PER_AUDIT = 1000;

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
  const safeConfig = serverConfig && typeof serverConfig === 'object' && !Array.isArray(serverConfig)
    ? serverConfig
    : {};
  const safeTools = Array.isArray(liveTools) ? liveTools : [];
  const issues = [
    ...analyzeFilesystemRisk(serverName, safeConfig),
    ...analyzeShellExecRisk(serverName, safeConfig),
    ...analyzeSecretsLeakRisk(serverName, safeConfig),
    ...analyzeExfiltrationRisk(serverName, safeConfig, safeTools),
    ...analyzeSupplyChainRisk(serverName, safeConfig),
    ...analyzeDockerSandboxRisk(serverName, safeConfig),
    ...analyzeNetworkTransportRisk(serverName, safeConfig),
    ...analyzeDatabaseSafetyRisk(serverName, safeConfig),
    ...analyzePromptInjectionRisk(serverName, safeConfig, safeTools),
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
    config: redactSensitiveConfig(safeConfig),
    score,
    grade,
    issues: issues.map(redactIssue),
    liveToolsCount: safeTools.length,
  };
}

/**
 * Runs a complete security audit across all discovered configs and servers.
 */
export function runSecurityAudit(discoveredConfigs, options = {}) {
  const serverResults = [];
  let totalIssuesCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const warnings = [];
  const maxServers = Number.isInteger(options.maxServers) && options.maxServers > 0
    ? options.maxServers
    : MAX_SERVERS_PER_AUDIT;
  const safeConfigs = Array.isArray(discoveredConfigs) ? discoveredConfigs : [];

  for (const item of safeConfigs) {
    if (item?.error) {
      warnings.push(`[${item.client || 'unknown'}] ${item.error}`);
    }
    if (!item || !item.servers || typeof item.servers !== 'object' || Array.isArray(item.servers)) continue;

    for (const [name, cfg] of Object.entries(item.servers)) {
      if (serverResults.length >= maxServers) {
        warnings.push(`Audit stopped after the ${maxServers} server safety limit`);
        break;
      }
      if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) continue;

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
    totalConfigs: safeConfigs.length,
    totalServers,
    overallScore,
    overallGrade,
    summary: totalIssuesCount,
    servers: serverResults,
    warnings: [...new Set(warnings)],
    complete: warnings.length === 0,
  };
}
