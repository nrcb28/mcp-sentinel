import fs from 'node:fs';

export function outputJsonReport(auditResult, outputPath) {
  const jsonStr = JSON.stringify(auditResult, null, 2);
  if (outputPath) {
    fs.writeFileSync(outputPath, jsonStr, 'utf8');
  }
  return jsonStr;
}
