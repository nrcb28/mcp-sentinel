import { spawn } from 'node:child_process';

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const MAX_TOOLS = 1000;

// Probe children do not need the caller's credentials. Keep only variables that
// are normally required to locate and start a process; callers can still pass
// explicit variables through the `env` argument.
const SAFE_INHERITED_ENV = new Set([
  'PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'ComSpec',
  'HOME', 'USERPROFILE', 'TMP', 'TEMP', 'TMPDIR', 'XDG_CONFIG_HOME',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM',
]);

function buildProbeEnvironment(explicitEnv) {
  const inherited = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (SAFE_INHERITED_ENV.has(key) && typeof value === 'string') {
      inherited[key] = value;
    }
  }

  for (const [key, value] of Object.entries(explicitEnv || {})) {
    if (typeof value !== 'string') {
      throw new TypeError(`Probe environment variable "${key}" must be a string`);
    }
    inherited[key] = value;
  }
  return inherited;
}

function prepareSpawn(command, args) {
  const isWindowsScript = process.platform === 'win32' && /\.(?:cmd|bat)$/i.test(command);
  if (!isWindowsScript) return { command, args, shell: false };

  // .cmd/.bat files require cmd.exe on Windows. Reject command metacharacters
  // before constructing the command line so user-controlled probe arguments
  // cannot become shell syntax.
  const allArgs = [command, ...args];
  if (allArgs.some((value) => /[&|<>^%!\r\n"]/.test(value))) {
    throw new Error('Windows .cmd/.bat probes reject shell metacharacters in command or arguments');
  }

  const quote = (value) => {
    if (!/[\s]/.test(value)) return value;
    return `"${value.replace(/(\\+)$/g, '$1$1')}"`;
  };

  return {
    command: process.env.ComSpec || 'cmd.exe',
    args: ['/d', '/s', '/c', allArgs.map(quote).join(' ')],
    shell: false,
  };
}

function makeErrorResult(error) {
  return { success: false, error, tools: [] };
}

/**
 * Probes a live MCP server via stdio using the JSON-RPC 2.0 protocol.
 * The child process is deliberately isolated from the caller's secret-bearing
 * environment and bounded by timeout, output, and tool-count limits.
 *
 * @param {string} command Executable or script to run.
 * @param {string[]} args Command arguments.
 * @param {Record<string, string>} env Explicit environment variables.
 * @param {number} timeoutMs Timeout before terminating.
 * @param {{maxOutputBytes?: number, maxTools?: number}} options Safety limits.
 * @returns {Promise<{success: boolean, serverInfo?: any, tools?: any[], error?: string}>}
 */
export function probeMcpServer(
  command,
  args = [],
  env = {},
  timeoutMs = DEFAULT_TIMEOUT_MS,
  options = {},
) {
  return new Promise((resolve) => {
    if (typeof command !== 'string' || !command.trim()) {
      resolve(makeErrorResult('Probe command must be a non-empty string'));
      return;
    }
    if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
      resolve(makeErrorResult('Probe arguments must be an array of strings'));
      return;
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
      resolve(makeErrorResult(`Probe timeout must be between 1 and ${MAX_TIMEOUT_MS}ms`));
      return;
    }

    const maxOutputBytes = Number.isInteger(options.maxOutputBytes) && options.maxOutputBytes > 0
      ? options.maxOutputBytes
      : MAX_OUTPUT_BYTES;
    const maxTools = Number.isInteger(options.maxTools) && options.maxTools > 0
      ? options.maxTools
      : MAX_TOOLS;

    let spawnSpec;
    let child;
    try {
      spawnSpec = prepareSpawn(command, args);
      child = spawn(spawnSpec.command, spawnSpec.args, {
        env: buildProbeEnvironment(env),
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: spawnSpec.shell,
      });
    } catch (error) {
      resolve(makeErrorResult(`Spawn preparation failed: ${error.message}`));
      return;
    }

    let resolved = false;
    let buffer = '';
    let outputBytes = 0;
    let serverInfo = null;
    let initializeResponseSeen = false;
    let toolsRequestSent = false;
    let timer;
    let killTimer;

    const terminate = () => {
      try {
        if (!child.killed) child.kill('SIGTERM');
      } catch (_) {}
      if (process.platform === 'win32' && child.pid) {
        try {
          const killer = spawn('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], {
            windowsHide: true,
            stdio: 'ignore',
          });
          killer.on('error', () => {});
        } catch (_) {}
      }
      killTimer = setTimeout(() => {
        try {
          if (!child.killed) child.kill('SIGKILL');
        } catch (_) {}
      }, 250);
      killTimer.unref?.();
    };

    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      clearTimeout(killTimer);
      try { child.stdin.end(); } catch (_) {}
      terminate();
      resolve(result);
    };

    const writeMessage = (message) => {
      if (resolved || child.stdin.destroyed || !child.stdin.writable) return false;
      try {
        child.stdin.write(`${JSON.stringify(message)}\n`);
        return true;
      } catch (error) {
        finish(makeErrorResult(`Failed to write to stdin: ${error.message}`));
        return false;
      }
    };

    timer = setTimeout(() => {
      finish(makeErrorResult(`Timed out after ${timeoutMs}ms while connecting to MCP server`));
    }, timeoutMs);
    timer.unref?.();

    child.on('error', (error) => {
      finish(makeErrorResult(`Spawn failed: ${error.message}`));
    });

    child.on('close', (code, signal) => {
      if (!resolved) {
        finish(makeErrorResult(`MCP server exited before responding (code=${code ?? 'unknown'}, signal=${signal ?? 'none'})`));
      }
    });

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      outputBytes += Buffer.byteLength(chunk, 'utf8');
      if (outputBytes > maxOutputBytes) {
        finish(makeErrorResult(`MCP server output exceeded the ${maxOutputBytes} byte safety limit`));
        return;
      }

      buffer += chunk;
      if (Buffer.byteLength(buffer, 'utf8') > maxOutputBytes) {
        finish(makeErrorResult(`MCP server message exceeded the ${maxOutputBytes} byte safety limit`));
        return;
      }

      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (resolved) return;
        const trimmed = line.trim();
        if (!trimmed) continue;

        let msg;
        try {
          msg = JSON.parse(trimmed);
        } catch (_) {
          // Non-JSON stdout (for example, a startup warning) is ignored.
          continue;
        }

        if (msg?.jsonrpc !== '2.0') continue;

        if (msg.id === 1 && msg.error) {
          finish(makeErrorResult(`MCP initialize failed: ${msg.error.message || 'unknown error'}`));
          return;
        }

        if (msg?.id === 1 && msg.result && !initializeResponseSeen) {
          initializeResponseSeen = true;
          serverInfo = msg.result.serverInfo || msg.result;
          writeMessage({ jsonrpc: '2.0', method: 'notifications/initialized' });
          toolsRequestSent = writeMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
        } else if (msg?.id === 2 && toolsRequestSent) {
          if (msg.error) {
            finish(makeErrorResult(`MCP tools/list failed: ${msg.error.message || 'unknown error'}`));
            return;
          }
          const retrievedTools = Array.isArray(msg.result?.tools)
            ? msg.result.tools.filter((tool) => tool && typeof tool === 'object' && !Array.isArray(tool))
            : [];
          if (retrievedTools.length > maxTools) {
            finish(makeErrorResult(`MCP server returned more than the ${maxTools} tool safety limit`));
            return;
          }
          finish({ success: true, serverInfo, tools: retrievedTools });
          return;
        }
      }
    });

    child.stderr.on('data', () => {
      // Stderr is intentionally discarded and never buffered, preventing a
      // noisy child from consuming unbounded memory.
    });

    writeMessage({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'mcp-sentinel', version: '1.4.0' },
      },
    });
  });
}
