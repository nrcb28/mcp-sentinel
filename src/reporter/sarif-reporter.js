import fs from 'node:fs';

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
                uri: srv.sourcePath.replace(/\\/g, '/'),
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
            version: '1.0.0',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };

  const jsonStr = JSON.stringify(sarif, null, 2);
  if (outputPath) {
    fs.writeFileSync(outputPath, jsonStr, 'utf8');
  }
  return jsonStr;
}
