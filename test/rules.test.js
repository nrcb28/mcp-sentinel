import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeFilesystemRisk } from '../src/analyzer/rules/filesystem-rule.js';
import { analyzeShellExecRisk } from '../src/analyzer/rules/shell-exec-rule.js';
import { analyzeSecretsLeakRisk } from '../src/analyzer/rules/secrets-leak-rule.js';
import { analyzeExfiltrationRisk } from '../src/analyzer/rules/exfiltration-rule.js';

test('filesystem-rule: flags sensitive SSH directory and path traversal', () => {
  const serverConfig = {
    command: 'node',
    args: ['~/.ssh/id_rsa', '../secrets/keys.txt'],
  };

  const issues = analyzeFilesystemRisk('test-server', serverConfig);
  assert.ok(issues.some((i) => i.id === 'FS_SENSITIVE_PATH_EXPOSURE'));
  assert.ok(issues.some((i) => i.id === 'FS_PATH_TRAVERSAL_DETECTED'));
});

test('filesystem-rule: reports clean on isolated paths', () => {
  const serverConfig = {
    command: 'node',
    args: ['C:/Workspace/project', '--port', '3000'],
  };

  const issues = analyzeFilesystemRisk('safe-server', serverConfig);
  assert.equal(issues.length, 0);
});

test('shell-exec-rule: detects direct shell invocation and policy bypass', () => {
  const serverConfig = {
    command: 'powershell.exe',
    args: ['-ExecutionPolicy', 'Bypass', '-File', 'run.ps1'],
  };

  const issues = analyzeShellExecRisk('powershell-server', serverConfig);
  assert.ok(issues.some((i) => i.id === 'SHELL_DIRECT_INVOCATION'));
  assert.ok(issues.some((i) => i.id === 'SHELL_EXECUTION_POLICY_BYPASS'));
});

test('secrets-leak-rule: flags plaintext OpenAI and AWS API keys', () => {
  const serverConfig = {
    command: 'node',
    env: {
      OPENAI_API_KEY: 'sk-proj-abc123456789012345678901234567890',
      AWS_KEY: 'AKIA1234567890ABCDEF',
    },
  };

  const issues = analyzeSecretsLeakRisk('secret-server', serverConfig);
  assert.equal(issues.length, 2);
  assert.ok(issues.every((i) => i.id === 'SECRET_PLAINTEXT_IN_CONFIG'));
  assert.ok(issues.every((i) => i.severity === 'CRITICAL'));
});

test('secrets-leak-rule: detects bearer tokens, JWTs, and inline credential arguments', () => {
  const issues = analyzeSecretsLeakRisk('token-server', {
    command: 'node',
    args: [
      '--authorization=Bearer abcdefghijklmnopqrstuvwxyz123456',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepayload123',
      '--password=plaintext-password',
    ],
  });

  assert.ok(issues.some((i) => i.message.includes('Bearer Access Token')));
  assert.ok(issues.some((i) => i.message.includes('JSON Web Token')));
  assert.ok(issues.some((i) => i.message.includes('Inline Credential Assignment')));
  assert.ok(issues.every((i) => !i.target.includes('abcdefghijklmnopqrstuvwxyz123456')));
});

test('exfiltration-rule: identifies cross-capability read and network tools', () => {
  const liveTools = [
    { name: 'read_file', description: 'Reads local file' },
    { name: 'send_webhook', description: 'Transmits data externally' },
  ];

  const issues = analyzeExfiltrationRisk('exfil-server', {}, liveTools);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].id, 'EXFILTRATION_COMBINED_CAPABILITIES');
  assert.equal(issues[0].severity, 'HIGH');
});
