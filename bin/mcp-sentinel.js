#!/usr/bin/env node

import { runCli } from '../src/cli.js';

runCli().then((code) => {
  process.exit(code || 0);
}).catch((err) => {
  console.error('Fatal MCP-Sentinel error:', err);
  process.exit(1);
});
