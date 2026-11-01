import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

/**
 * Returns common default configuration paths for popular MCP clients.
 */
export function getStandardConfigPaths() {
  const home = os.homedir();
  const platform = process.platform;
  const paths = [];

  // Claude Desktop
  if (platform === 'win32') {
    const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    paths.push({
      client: 'Claude Desktop',
      path: path.join(appData, 'Claude', 'claude_desktop_config.json'),
    });
    // Cursor MCP
    paths.push({
      client: 'Cursor',
      path: path.join(appData, 'Cursor', 'User', 'globalStorage', 'rooveterinaryinc.cursor-mcp', 'mcp.json'),
    });
    // Cline MCP
    paths.push({
      client: 'Cline (VS Code)',
      path: path.join(appData, 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'),
    });
  } else if (platform === 'darwin') {
    paths.push({
      client: 'Claude Desktop',
      path: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    });
    paths.push({
      client: 'Cursor',
      path: path.join(home, 'Library', 'Application Support', 'Cursor', 'User', 'globalStorage', 'rooveterinaryinc.cursor-mcp', 'mcp.json'),
    });
    paths.push({
      client: 'Cline (VS Code)',
      path: path.join(home, 'Library', 'Application Support', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'),
    });
  } else {
    // Linux
    const configHome = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
    paths.push({
      client: 'Claude Desktop',
      path: path.join(configHome, 'Claude', 'claude_desktop_config.json'),
    });
    paths.push({
      client: 'Cursor',
      path: path.join(configHome, 'Cursor', 'User', 'globalStorage', 'rooveterinaryinc.cursor-mcp', 'mcp.json'),
    });
  }

  // Common cross-platform paths
  paths.push({
    client: 'Windsurf',
    path: path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
  });
  paths.push({
    client: 'Antigravity',
    path: path.join(home, '.gemini', 'antigravity-cli', 'mcp_config.json'),
  });
  paths.push({
    client: 'Local Project',
    path: path.resolve('./mcp.json'),
  });

  return paths;
}

/**
 * Discovers and parses all accessible MCP configuration files.
 * @param {string[]} [customPaths] Optional user-provided file paths.
 * @returns {Array<{client: string, path: string, servers: Record<string, any>}>}
 */
export function discoverConfigs(customPaths = []) {
  const targets = [];

  if (customPaths && customPaths.length > 0) {
    for (const p of customPaths) {
      targets.push({
        client: 'Custom Config',
        path: path.resolve(p),
      });
    }
  } else {
    targets.push(...getStandardConfigPaths());
  }

  const results = [];

  for (const item of targets) {
    if (fs.existsSync(item.path)) {
      try {
        const raw = fs.readFileSync(item.path, 'utf8');
        const parsed = JSON.parse(raw);
        // Standard formats: { mcpServers: { ... } } or { servers: { ... } }
        const servers = parsed.mcpServers || parsed.servers || parsed;

        if (servers && typeof servers === 'object') {
          results.push({
            client: item.client,
            path: item.path,
            servers,
          });
        }
      } catch (err) {
        results.push({
          client: item.client,
          path: item.path,
          error: `Failed to parse JSON: ${err.message}`,
          servers: {},
        });
      }
    }
  }

  return results;
}
