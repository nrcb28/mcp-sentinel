import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { analyzeDatabaseSafetyRisk } from '../src/analyzer/rules/database-safety-rule.js';
import { analyzePromptInjectionRisk } from '../src/analyzer/rules/prompt-injection-rule.js';
import { createWebServer } from '../src/server/web-server.js';

test('database-safety-rule: detects root/admin database credentials and disabled TLS', () => {
  const dbConfig = {
    command: 'node',
    args: ['server.js'],
    env: {
      DATABASE_URL: 'postgres://root:supersecret123@db.internal:5432/prod?sslmode=disable',
    },
  };

  const issues = analyzeDatabaseSafetyRisk('db-server', dbConfig);
  assert.ok(issues.some((i) => i.id === 'DB_ADMIN_CREDENTIALS_EXPOSED'));
  assert.ok(issues.some((i) => i.id === 'DB_CONNECTION_PLAINTEXT_SECRET'));
  assert.ok(issues.some((i) => i.id === 'DB_TLS_DISABLED'));
});

test('prompt-injection-rule: flags arbitrary execution tools and unconstrained parameters', () => {
  const liveTools = [
    {
      name: 'run_arbitrary_script',
      description: 'Executes arbitrary shell scripts',
      inputSchema: {
        type: 'object',
        properties: {
          command: { type: 'string' },
        },
      },
    },
  ];

  const issues = analyzePromptInjectionRisk('agent-server', {}, liveTools);
  assert.ok(issues.some((i) => i.id === 'TOOL_ARBITRARY_EXECUTION_CAPABILITY'));
  assert.ok(issues.some((i) => i.id === 'TOOL_UNCONSTRAINED_PARAMETER'));
});

test('web-server: responds to API endpoints correctly', async () => {
  const testPort = 4289;
  const server = createWebServer(testPort);

  await new Promise((resolve) => server.listen(testPort, resolve));

  try {
    const unauthorizedRes = await fetch(`http://localhost:${testPort}/api/scan`);
    assert.equal(unauthorizedRes.status, 401);

    const rootRes = await fetch(`http://localhost:${testPort}/`);
    assert.equal(rootRes.status, 200);
    assert.match(rootRes.headers.get('set-cookie') || '', /HttpOnly/);
    assert.match(rootRes.headers.get('content-security-policy') || '', /connect-src 'self'/);
    const authHeaders = { Cookie: `mcp_sentinel_token=${server.authToken}` };

    // Test GET /api/scan
    const scanRes = await fetch(`http://localhost:${testPort}/api/scan`, { headers: authHeaders });
    assert.equal(scanRes.status, 200);
    assert.equal(scanRes.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(scanRes.headers.get('cache-control'), 'no-store');
    const scanData = await scanRes.json();
    assert.ok(typeof scanData.overallScore === 'number');

    // Test POST /api/audit
    const auditRes = await fetch(`http://localhost:${testPort}/api/audit`, {
      method: 'POST',
      headers: { ...authHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mcpServers: {
          test: {
            command: 'node',
            args: ['test.js'],
          },
        },
      }),
    });
    assert.equal(auditRes.status, 200);
    const auditData = await auditRes.json();
    assert.equal(auditData.servers[0].score, 100);

    // Test POST /api/harden
    const hardenRes = await fetch(`http://localhost:${testPort}/api/harden`, {
      method: 'POST',
      headers: { ...authHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mcpServers: {
          vulnerable: {
            command: 'node',
            env: { API_KEY: 'sk-proj-123456789012345678901234567890' },
          },
        },
      }),
    });
    assert.equal(hardenRes.status, 200);
    const hardenData = await hardenRes.json();
    assert.equal(hardenData.hardenedConfig.mcpServers.vulnerable.env.API_KEY, '${env:API_KEY}');

    // Audit responses must not echo plaintext credentials back to API clients.
    const secretAuditRes = await fetch(`http://localhost:${testPort}/api/audit`, {
      method: 'POST',
      headers: { ...authHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mcpServers: { secret: { command: 'node', env: { API_KEY: 'sk-proj-123456789012345678901234567890' } } },
      }),
    });
    const secretAuditData = await secretAuditRes.json();
    assert.equal(secretAuditData.servers[0].config.env.API_KEY, '[REDACTED]');

    const oversizedRes = await fetch(`http://localhost:${testPort}/api/audit`, {
      method: 'POST',
      headers: { ...authHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ oversized: 'x'.repeat(1024 * 1024) }),
    });
    assert.equal(oversizedRes.status, 400);

    const crossOriginRes = await fetch(`http://localhost:${testPort}/api/scan`, {
      headers: { ...authHeaders, Origin: 'http://evil.example' },
    });
    assert.equal(crossOriginRes.status, 401);
    const rebound = await new Promise((resolve, reject) => {
      http.get(`http://localhost:${testPort}/`, {
        headers: { Host: 'attacker.example' },
      }, response => {
        response.resume();
        response.on('end', () => resolve(response));
      }).on('error', reject);
    });
    assert.equal(rebound.statusCode, 401);
    assert.equal(rebound.headers['set-cookie'], undefined);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
