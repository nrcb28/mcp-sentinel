import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { discoverConfigs, getStandardConfigPaths } from '../src/scanner/config-detector.js';

test('scanner: returns default standard configuration paths for current OS', () => {
  const paths = getStandardConfigPaths();
  assert.ok(Array.isArray(paths));
  assert.ok(paths.length > 0);
  assert.ok(paths.some((p) => p.client === 'Claude Desktop'));
});

test('scanner: discovers and parses custom configuration file', () => {
  const fixturePath = path.resolve('./test/fixtures/safe-config.json');
  const configs = discoverConfigs([fixturePath]);

  assert.equal(configs.length, 1);
  assert.equal(configs[0].client, 'Custom Config');
  assert.ok(configs[0].servers['git-readonly']);
  assert.ok(configs[0].servers['memory-store']);
});

test('scanner: gracefully handles non-existent configuration files', () => {
  const configs = discoverConfigs(['./non-existent-file-xyz.json']);
  assert.equal(configs.length, 0);
});
