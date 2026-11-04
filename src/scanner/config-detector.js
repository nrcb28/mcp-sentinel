import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const MAX_CONFIG_BYTES = 1024 * 1024;

function getWslHostUsers() {
  const usersRoot = '/mnt/c/Users';
  if (!fs.existsSync(usersRoot)) return [];

  // Reading every Windows user's MCP configuration crosses a local account
  // boundary. Scan one explicitly identified user by default; administrators
  // can opt in to the previous all-users behavior for a dedicated audit.
  if (process.env.MCP_SENTINEL_SCAN_ALL_USERS === '1') {
    try {
      return fs.readdirSync(usersRoot)
        .filter((user) => user !== 'Public' && user !== 'Default' && !user.startsWith('.'));
    } catch (_) {
      return [];
    }
  }

  const profile = process.env.USERPROFILE || '';
  const profileMatch = profile.match(/^\/mnt\/c\/Users\/([^/\\]+)$/i);
  const candidate = profileMatch?.[1] || process.env.WSL_WINDOWS_USER || process.env.USERNAME || process.env.USER;
  if (!candidate || candidate === 'Public' || candidate === 'Default' || candidate.startsWith('.')) return [];

  try {
    return fs.statSync(path.join(usersRoot, candidate)).isDirectory() ? [candidate] : [];
  } catch (_) {
    return [];
  }
}

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
    for (const u of getWslHostUsers()) {
      addPath('Claude Desktop (WSL Host)', `/mnt/c/Users/${u}/AppData/Roaming/Claude/claude_desktop_config.json`);
      addPath('Cursor (WSL Host)', `/mnt/c/Users/${u}/AppData/Roaming/Cursor/User/globalStorage/rooveterinaryinc.cursor-mcp/mcp.json`);
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
      if (typeof p !== 'string' || !p.trim()) continue;
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
    const dedupeKey = process.platform === 'win32' ? normalized.toLowerCase() : normalized;
    if (visitedPaths.has(dedupeKey)) continue;
    visitedPaths.add(dedupeKey);

    if (fs.existsSync(normalized)) {
      try {
        const stat = fs.statSync(normalized);
        if (!stat.isFile()) {
          results.push({
            client: item.client,
            path: normalized,
            error: 'Configuration path is not a regular file',
            servers: {},
          });
          continue;
        }
        if (stat.size > MAX_CONFIG_BYTES) {
          results.push({
            client: item.client,
            path: normalized,
            error: `Configuration exceeds the ${MAX_CONFIG_BYTES} byte safety limit`,
            servers: {},
          });
          continue;
        }

        const raw = fs.readFileSync(normalized, 'utf8');
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          results.push({
            client: item.client,
            path: normalized,
            error: 'Configuration root must be a JSON object',
            servers: {},
          });
          continue;
        }
        // Handle common formats: { mcpServers: { ... } }, { servers: { ... } }, { experimental: { mcp: { ... } } }
        let servers = parsed.mcpServers || parsed.servers;
        if (!servers && parsed.experimental?.mcp?.servers) {
          servers = parsed.experimental.mcp.servers;
        }
        if (!servers && typeof parsed === 'object' && !parsed.mcpServers) {
          servers = parsed;
        }

        if (servers && typeof servers === 'object' && !Array.isArray(servers)) {
          results.push({
            client: item.client,
            path: normalized,
            servers,
          });
        } else {
          results.push({
            client: item.client,
            path: normalized,
            error: 'MCP server definitions must be a JSON object',
            servers: {},
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
