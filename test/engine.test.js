import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { auditServer, runSecurityAudit, calculateGrade } from '../src/analyzer/engine.js';
import { discoverConfigs } from '../src/scanner/config-detector.js';

test('engine: calculates accurate grades from scores', () => {
  assert.equal(calculateGrade(100), 'A+');
  assert.equal(calculateGrade(95), 'A+');
  assert.equal(calculateGrade(90), 'A');
  assert.equal(calculateGrade(85), 'B');
  assert.equal(calculateGrade(75), 'C');
  assert.equal(calculateGrade(65), 'D');
  assert.equal(calculateGrade(50), 'F');
  assert.equal(calculateGrade(0), 'F');
});

test('engine: audits safe server with 100 score and A+ grade', () => {
  const safeConfig = {
    command: 'node',
    args: ['./scripts/safe.js'],
  };
  const result = auditServer('safe-mcp', safeConfig);

  assert.equal(result.score, 100);
  assert.equal(result.grade, 'A+');
  assert.equal(result.issues.length, 0);
});

test('engine: ignores malformed server fields without crashing the audit', () => {
  const result = auditServer('malformed', {
    command: 42,
    args: { unexpected: true },
    env: 'not-an-object',
  });

  assert.equal(result.score, 100);
  assert.deepEqual(result.config, {
    command: 42,
    args: { unexpected: true },
    env: 'not-an-object',
  });
});

test('engine: audits vulnerable server with F grade and critical deductions', () => {
  const vulnConfig = {
    command: 'powershell.exe',
    args: ['-ExecutionPolicy', 'Bypass', '~/.ssh/id_rsa'],
    env: {
      KEY: 'sk-proj-123456789012345678901234567890',
    },
  };
  const result = auditServer('vuln-mcp', vulnConfig);

  assert.ok(result.score < 60);
  assert.equal(result.grade, 'F');
  assert.ok(result.issues.length >= 3);
  assert.equal(result.config.env.KEY, '[REDACTED_SECRET]');
});

test('engine: aggregates full audit report across multiple configs', () => {
  const fixturePath = path.resolve('./test/fixtures/safe-config.json');
  const configs = discoverConfigs([fixturePath]);
  const audit = runSecurityAudit(configs);

  assert.equal(audit.totalConfigs, 1);
  assert.equal(audit.totalServers, 2);
  assert.equal(audit.overallScore, 100);
  assert.equal(audit.overallGrade, 'A+');
  assert.equal(audit.summary.CRITICAL, 0);
});
