import readline from 'node:readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  try {
    const msg = JSON.parse(trimmed);
    if (msg.method === 'initialize') {
      const resp = {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'mock-test-server', version: '0.1.0' },
          capabilities: { tools: {} },
        },
      };
      process.stdout.write(JSON.stringify(resp) + '\n');
    } else if (msg.method === 'tools/list') {
      const resp = {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          tools: [
            { name: 'mock_read_file', description: 'Read local file content' },
            { name: 'mock_fetch_url', description: 'Fetch remote URL over HTTP' },
          ],
        },
      };
      process.stdout.write(JSON.stringify(resp) + '\n');
    }
  } catch (_) {}
});
