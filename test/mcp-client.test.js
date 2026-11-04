import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { probeMcpServer } from '../src/scanner/mcp-client.js';

test('mcp-client: successfully connects to mock MCP server and queries tools', async () => {
  const mockPath = path.resolve('./test/fixtures/mock-server.js');
  const res = await probeMcpServer('node', [mockPath], {}, 4000);

  assert.equal(res.success, true);
  assert.equal(res.serverInfo?.name, 'mock-test-server');
  assert.equal(res.tools?.length, 2);
  assert.equal(res.tools[0].name, 'mock_read_file');
  assert.equal(res.tools[1].name, 'mock_fetch_url');
});

test('mcp-client: rejects unsafe limits and malformed arguments', async () => {
  const invalidArgs = await probeMcpServer('node', [42]);
  assert.equal(invalidArgs.success, false);
  assert.match(invalidArgs.error, /array of strings/);

  const limitedTools = await probeMcpServer('node', [path.resolve('./test/fixtures/mock-server.js')], {}, 4000, { maxTools: 1 });
  assert.equal(limitedTools.success, false);
  assert.match(limitedTools.error, /tool safety limit/);
});
