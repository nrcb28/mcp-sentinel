import { spawn } from 'node:child_process';

/**
 * Probes a live MCP server via stdio using the JSON-RPC 2.0 protocol.
 * @param {string} command Executable or script to run.
 * @param {string[]} args Command arguments.
 * @param {Record<string, string>} env Environment variables.
 * @param {number} timeoutMs Timeout before terminating.
 * @returns {Promise<{success: boolean, serverInfo?: any, tools?: any[], error?: string}>}
 */
export async function probeMcpServer(command, args = [], env = {}, timeoutMs = 5000) {
  return new Promise((resolve) => {
    let resolved = false;
    let buffer = '';
    const tools = [];
    let serverInfo = null;

    const child = spawn(command, args, {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: process.platform === 'win32' && (command.endsWith('.cmd') || command.endsWith('.bat')),
    });

    const finish = (result) => {
      if (!resolved) {
        resolved = true;
        try {
          child.kill('SIGTERM');
        } catch (_) {}
        resolve(result);
      }
    };

    const timer = setTimeout(() => {
      finish({
        success: false,
        error: `Timed out after ${timeoutMs}ms while connecting to MCP server`,
        tools: [],
      });
    }, timeoutMs);

    child.on('error', (err) => {
      clearTimeout(timer);
      finish({
        success: false,
        error: `Spawn failed: ${err.message}`,
        tools: [],
      });
    });

    child.stdout.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep last incomplete chunk

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        try {
          const msg = JSON.parse(trimmed);
          if (msg.id === 1 && msg.result) {
            serverInfo = msg.result.serverInfo || msg.result;
            // Send initialized notification
            child.stdin.write(JSON.stringify({
              jsonrpc: '2.0',
              method: 'notifications/initialized',
            }) + '\n');

            // Send tools/list request
            child.stdin.write(JSON.stringify({
              jsonrpc: '2.0',
              id: 2,
              method: 'tools/list',
              params: {},
            }) + '\n');
          } else if (msg.id === 2) {
            clearTimeout(timer);
            const retrievedTools = msg.result?.tools || [];
            finish({
              success: true,
              serverInfo,
              tools: retrievedTools,
            });
            return;
          }
        } catch (_) {
          // Non-JSON output (debug logs, warnings), ignore
        }
      }
    });

    child.stderr.on('data', () => {
      // Stderr can contain logs, do not abort immediately
    });

    // Send initialize request
    try {
      const initRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: {
            name: 'mcp-sentinel',
            version: '1.0.0',
          },
        },
      };
      child.stdin.write(JSON.stringify(initRequest) + '\n');
    } catch (err) {
      clearTimeout(timer);
      finish({
        success: false,
        error: `Failed to write to stdin: ${err.message}`,
        tools: [],
      });
    }
  });
}
