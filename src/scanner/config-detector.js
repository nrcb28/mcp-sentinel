import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

/**
 * Returns common default configuration paths for popular MCP clients across OS environments
 * (Windows, macOS, Linux, and WSL).
 */
export function getStandardConfigPaths() {
  const home = os.homedir();
  const platform = process.platform;
  const paths = [];

  // Helper to add if valid string
  const addPath = (client, targetPath) => {
    if (targetPath) {
      paths.push({ client, path: path.normalize(targetPath) });
    }
  };

  // 1. Windows Native Paths
  if (platform === 'win32') {
    const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');

    addPath('Claude Desktop', path.join(appData, 'Claude', 'claude_desktop_config.json'));
    addPath('Cursor', path.join(appData, 'Cursor', 'User', 'globalStorage', 'rooveterinaryinc.cursor-mcp', 'mcp.json'));
    addPath('Cline (VS Code)', path.join(appData, 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'));
    addPath('Roo Code (VS Code)', path.join(appData, 'Code', 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'cline_mcp_settings.json'));
    addPath('Zed Editor', path.join(appData, 'Zed', 'settings.json'));
  }
  // 2. macOS Paths
  else if (platform === 'darwin') {
    const appSupport = path.join(home, 'Library', 'Application Support');

    addPath('Claude Desktop', path.join(appSupport, 'Claude', 'claude_desktop_config.json'));
    addPath('Cursor', path.join(appSupport, 'Cursor', 'User', 'globalStorage', 'rooveterinaryinc.cursor-mcp', 'mcp.json'));
    addPath('Cline (VS Code)', path.join(appSupport, 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'));
    addPath('Roo Code (VS Code)', path.join(appSupport, 'Code', 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'cline_mcp_settings.json'));
    addPath('Zed Editor', path.join(appSupport, 'Zed', 'settings.json'));
  }
  // 3. Linux & XDG Compliance
  else {
    const configHome = process.env.XDG_CONFIG_HOME || path.join(home, '.config');

    addPath('Claude Desktop', path.join(configHome, 'Claude', 'claude_desktop_config.json'));
    addPath('Cursor', path.join(configHome, 'Cursor', 'User', 'globalStorage', 'rooveterinaryinc.cursor-mcp', 'mcp.json'));
    addPath('Cline (VS Code)', path.join(configHome, 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'));
    addPath('Zed Editor', path.join(configHome, 'zed', 'settings.json'));

    // WSL2 cross-environment support: detect Windows host configurations if accessible via /mnt/c
    if (fs.existsSync('/mnt/c/Users')) {
      try {
        const winUsers = fs.readdirSync('/mnt/c/Users');
        for (const u of winUsers) {
          if (u === 'Public' || u === 'Default' || u.startsWith('.')) continue;
          addPath('Claude Desktop (WSL Host)', `/mnt/c/Users/${u}/AppData/Roaming/Claude/claude_desktop_config.json`);
          addPath('Cursor (WSL Host)', `/mnt/c/Users/${u}/AppData/Roaming/Cursor/User/globalStorage/rooveterinaryinc.cursor-mcp/mcp.json`);
        }
      } catch (_) {}
    }
  }

  // Cross-Platform Universal Paths
  addPath('Windsurf', path.join(home, '.codeium', 'windsurf', 'mcp_config.json'));
  addPath('Continue.dev', path.join(home, '.continue', 'config.json'));
  addPath('Antigravity', path.join(home, '.gemini', 'antigravity-cli', 'mcp_config.json'));
  addPath('Antigravity Profile', path.join(home, '.agy', 'mcp.json'));
  addPath('Local Project (mcp.json)', path.resolve('./mcp.json'));
  addPath('Local Project (.mcp.json)', path.resolve('./.mcp.json'));

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
  const visitedPaths = new Set();

  for (const item of targets) {
    const normalized = path.normalize(item.path);
    if (visitedPaths.has(normalized)) continue;
    visitedPaths.add(normalized);

    if (fs.existsSync(normalized)) {
      try {
        const raw = fs.readFileSync(normalized, 'utf8');
        const parsed = JSON.parse(raw);
        // Handle common formats: { mcpServers: { ... } }, { servers: { ... } }, { experimental: { mcp: { ... } } }
        let servers = parsed.mcpServers || parsed.servers;
        if (!servers && parsed.experimental?.mcp?.servers) {
          servers = parsed.experimental.mcp.servers;
        }
        if (!servers && typeof parsed === 'object' && !parsed.mcpServers) {
          servers = parsed;
        }

        if (servers && typeof servers === 'object') {
          results.push({
            client: item.client,
            path: normalized,
            servers,
          });
        }
      } catch (err) {
        results.push({
          client: item.client,
          path: normalized,
          error: `Failed to parse JSON: ${err.message}`,
          servers: {},
        });
      }
    }
  }

  return results;
}
