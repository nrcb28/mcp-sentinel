import path from 'node:path';
import { createHash } from 'node:crypto';
import { writeTextFileSecure } from '../security/safe-write.js';

function artifactUri(sourcePath) {
  if (typeof sourcePath !== 'string' || !sourcePath) return 'unknown';
  const normalized = sourcePath.replace(/\\/g, '/');
  const isWindowsAbsolute = /^[A-Za-z]:\//.test(normalized) || normalized.startsWith('//');
  const isUnixAbsolute = normalized.startsWith('/');

  if (!isWindowsAbsolute && !isUnixAbsolute && !normalized.includes('..')) {
    return normalized;
  }

  const absolute = path.resolve(sourcePath);
  const workspace = path.resolve(process.cwd());
  const relative = path.relative(workspace, absolute).replace(/\\/g, '/');
  if (!isWindowsAbsolute && relative && !relative.startsWith('../') && relative !== '..' && !path.isAbsolute(relative)) {
    return relative;
  }

  // Do not publish usernames or home-directory layout in SARIF uploaded to a
  // CI provider. Keep a stable, non-reversible identifier for external files.
  const digest = createHash('sha256').update(normalized).digest('hex').slice(0, 16);
  const basename = path.posix.basename(normalized) || 'config.json';
  return `external/${digest}/${basename}`;
}

/**
 * Generates an OASIS SARIF v2.1.0 report for native GitHub Code Scanning integration.
 */
export function generateSarifReport(auditResult, outputPath) {
  const rulesMap = new Map();
  const results = [];

  for (const srv of auditResult.servers) {
    for (const issue of srv.issues) {
      if (!rulesMap.has(issue.id)) {
        rulesMap.set(issue.id, {
          id: issue.id,
          name: issue.rule.replace(/\s+/g, ''),
          shortDescription: { text: issue.rule },
          fullDescription: { text: issue.message },
          defaultConfiguration: {
            level: issue.severity === 'CRITICAL' || issue.severity === 'HIGH' ? 'error' : 'warning',
          },
          help: {
            text: `Fix: ${issue.remediation}`,
          },
        });
      }

      results.push({
        ruleId: issue.id,
        level: issue.severity === 'CRITICAL' || issue.severity === 'HIGH' ? 'error' : 'warning',
        message: {
          text: `[${issue.severity}] ${issue.message} Target: ${issue.target}. Fix: ${issue.remediation}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: artifactUri(srv.sourcePath),
              },
            },
          },
        ],
      });
    }
  }

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-sentinel',
            informationUri: 'https://github.com/nrcb28/mcp-sentinel',
            version: '1.5.0',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };

  const jsonStr = JSON.stringify(sarif, null, 2);
  if (outputPath) {
    writeTextFileSecure(outputPath, jsonStr);
  }
  return jsonStr;
}
