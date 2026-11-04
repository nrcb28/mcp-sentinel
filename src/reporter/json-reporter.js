import { writeTextFileSecure } from '../security/safe-write.js';

export function outputJsonReport(auditResult, outputPath) {
  const jsonStr = JSON.stringify(auditResult, null, 2);
  if (outputPath) {
    writeTextFileSecure(outputPath, jsonStr);
  }
  return jsonStr;
}
