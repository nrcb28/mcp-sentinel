import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { discoverConfigs } from '../scanner/config-detector.js';
import { runSecurityAudit } from '../analyzer/engine.js';
import { generateHardenedConfig } from '../hardening/config-fixer.js';

const MAX_BODY_BYTES = 1024 * 1024;
const AUTH_COOKIE = 'mcp_sentinel_token';
const SESSION_MAX_AGE_SECONDS = 3600;

function isObjectRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function constantTimeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
}

function getCookie(cookieHeader, name) {
  if (typeof cookieHeader !== 'string') return null;
  for (const part of cookieHeader.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) continue;
    const key = part.slice(0, separator).trim();
    if (key !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch (_) {
      return null;
    }
  }
  return null;
}

function originIsLocal(origin, port) {
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      (parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '::1') &&
      parsed.port === String(port);
  } catch (_) {
    return false;
  }
}

export function createWebServer(port = 4242, options = {}) {
  const authToken = typeof options.authToken === 'string' && options.authToken.length >= 32
    ? options.authToken
    : randomBytes(32).toString('hex');
  const requireAuth = options.requireAuth !== false;

  const server = http.createServer((req, res) => {
    let url;
    try {
      url = new URL(req.url, `http://localhost:${port}`);
    } catch {
      res.writeHead(400);
      res.end('Invalid URL');
      return;
    }

    // Helper for JSON responses
    const json = (data, status = 200, extraHeaders = {}) => {
      res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        ...extraHeaders,
      });
      res.end(JSON.stringify(data));
    };

    const actualPort = server.address()?.port || port;
    const allowedHosts = [`localhost:${actualPort}`, `127.0.0.1:${actualPort}`, `[::1]:${actualPort}`];
    if (!allowedHosts.includes(req.headers.host) ||
        (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) ||
        req.headers['sec-fetch-site'] === 'cross-site') {
      return json({ error: 'Untrusted request origin or host' }, 401);
    }

    if (url.pathname.startsWith('/api/') && requireAuth) {
      const bearer = typeof req.headers.authorization === 'string' && req.headers.authorization.startsWith('Bearer ')
        ? req.headers.authorization.slice('Bearer '.length)
        : null;
      const cookieToken = getCookie(req.headers.cookie, AUTH_COOKIE);
      const authenticated = constantTimeEqual(bearer, authToken) || constantTimeEqual(cookieToken, authToken);
      if (!authenticated || !originIsLocal(req.headers.origin, actualPort)) {
        return json({ error: 'Authentication required' }, 401, {
          'WWW-Authenticate': 'Bearer',
        });
      }
    }

    // Helper to read JSON request body with a hard upper bound to prevent
    // unauthenticated local callers from exhausting memory.
    const readBody = (callback) => {
      let body = '';
      let bodyBytes = 0;
      let completed = false;
      req.setEncoding('utf8');

      req.on('data', (chunk) => {
        if (completed) return;
        bodyBytes += Buffer.byteLength(chunk, 'utf8');
        if (bodyBytes > MAX_BODY_BYTES) {
          completed = true;
          callback(new Error(`Request body exceeds the ${MAX_BODY_BYTES} byte safety limit`));
          req.resume();
          return;
        }
        body += chunk;
      });
      req.on('end', () => {
        if (completed) return;
        completed = true;
        try {
          const parsed = JSON.parse(body || '{}');
          callback(null, parsed);
        } catch (err) {
          callback(err);
        }
      });
    };

    // API: Run Scan
    if (url.pathname === '/api/scan' && req.method === 'GET') {
      const configs = discoverConfigs();
      const audit = runSecurityAudit(configs);
      return json(audit);
    }

    // API: Live Audit custom config
    if (url.pathname === '/api/audit' && req.method === 'POST') {
      readBody((err, payload) => {
        if (err) return json({ error: 'Invalid JSON body' }, 400);
        if (!isObjectRecord(payload)) return json({ error: 'JSON body must be an object' }, 400);
        const servers = payload.mcpServers || payload.servers || payload;
        if (!isObjectRecord(servers)) return json({ error: 'MCP server definitions must be an object' }, 400);
        const configs = [{ client: 'Live Editor', path: 'memory', servers }];
        const audit = runSecurityAudit(configs);
        return json(audit);
      });
      return;
    }

    // API: Harden config
    if (url.pathname === '/api/harden' && req.method === 'POST') {
      readBody((err, payload) => {
        if (err) return json({ error: 'Invalid JSON body' }, 400);
        if (!isObjectRecord(payload)) return json({ error: 'JSON body must be an object' }, 400);
        try {
          const result = generateHardenedConfig(payload);
          return json(result);
        } catch (error) {
          return json({ error: 'Unable to harden configuration' }, 400);
        }
      });
      return;
    }

    // Front-end SPA
    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Content-Security-Policy': "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        ...(requireAuth ? {
          'Set-Cookie': `${AUTH_COOKIE}=${encodeURIComponent(authToken)}; Max-Age=${SESSION_MAX_AGE_SECONDS}; Path=/; HttpOnly; SameSite=Strict`,
        } : {}),
      });
      res.end(getSpaHtml(port));
      return;
    }

    res.writeHead(404, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end('Not Found');
  });

  // Bound idle/header time so a local client cannot hold connections forever.
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.authToken = authToken;
  server.requireAuth = requireAuth;

  return server;
}

function getSpaHtml(port) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ MCP-Sentinel Studio</title>
  <style>
    :root {
      --bg: #0b0f17;
      --card: #151b26;
      --border: #263040;
      --text: #e6edf3;
      --muted: #8b949e;
      --primary: #388bfd;
      --critical: #f85149;
      --high: #d29922;
      --medium: #e3b341;
      --safe: #3fb950;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
    h1 { font-size: 1.8rem; display: flex; align-items: center; gap: 0.6rem; }
    .btn { background: var(--primary); color: #fff; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
    .btn:hover { opacity: 0.9; }
    .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); margin-left: 0.5rem; }
    .tabs { display: flex; gap: 1rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
    .tab { background: none; border: none; color: var(--muted); font-size: 1rem; font-weight: 600; cursor: pointer; padding: 0.5rem 1rem; }
    .tab.active { color: var(--primary); border-bottom: 2px solid var(--primary); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; }
    .val { font-size: 2.2rem; font-weight: bold; margin-top: 0.4rem; }
    .server-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.2rem; }
    .badge { padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }
    .badge-crit { background: rgba(248,81,73,0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-high { background: rgba(210,153,34,0.2); color: var(--high); border: 1px solid var(--high); }
    .badge-safe { background: rgba(63,185,80,0.2); color: var(--safe); border: 1px solid var(--safe); }
    .issue-box { background: #0b0f17; border-left: 4px solid var(--border); padding: 0.8rem; margin-top: 0.8rem; border-radius: 4px; }
    .issue-box.CRITICAL { border-left-color: var(--critical); }
    .issue-box.HIGH { border-left-color: var(--high); }
    textarea { width: 100%; height: 260px; background: #0b0f17; border: 1px solid var(--border); color: #7ee787; font-family: monospace; font-size: 0.9rem; padding: 1rem; border-radius: 6px; resize: vertical; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🛡️ MCP-Sentinel Studio</h1>
        <div style="color: var(--muted); font-size: 0.9rem; margin-top: 0.2rem;">Model Context Protocol Security & Permissions Management</div>
      </div>
      <div>
        <button class="btn" onclick="fetchScan()">↻ Scan Environment</button>
      </div>
    </header>

    <div class="tabs">
      <button class="tab active" onclick="switchTab('dashboard', event)">Environment Dashboard</button>
      <button class="tab" onclick="switchTab('playground', event)">Live Config Auditor & Hardener</button>
    </div>

    <!-- Dashboard Tab -->
    <div id="tab-dashboard">
      <div class="grid">
        <div class="card">
          <div style="color: var(--muted); font-size: 0.85rem;">GLOBAL SCORE</div>
          <div id="stat-score" class="val" style="color: var(--safe);">--</div>
        </div>
        <div class="card">
          <div style="color: var(--muted); font-size: 0.85rem;">SERVERS SCANNED</div>
          <div id="stat-servers" class="val" style="color: var(--primary);">--</div>
        </div>
        <div class="card">
          <div style="color: var(--muted); font-size: 0.85rem;">CRITICAL VULNERABILITIES</div>
          <div id="stat-critical" class="val" style="color: var(--critical);">--</div>
        </div>
        <div class="card">
          <div style="color: var(--muted); font-size: 0.85rem;">HIGH / MEDIUM ISSUES</div>
          <div id="stat-high" class="val" style="color: var(--high);">--</div>
        </div>
      </div>
      <div id="servers-list">Loading audit results...</div>
    </div>

    <!-- Playground Tab -->
    <div id="tab-playground" style="display: none;">
      <div class="card" style="margin-bottom: 1.5rem;">
        <h3 style="margin-bottom: 0.8rem;">Paste or Edit MCP Configuration JSON</h3>
        <textarea id="live-config-input">{
  "mcpServers": {
    "sample-server": {
      "command": "powershell.exe",
      "args": ["-ExecutionPolicy", "Bypass", "~/.ssh/id_rsa"],
      "env": {
        "OPENAI_API_KEY": "sk-proj-123456789012345678901234567890"
      }
    }
  }
}</textarea>
        <div style="margin-top: 1rem;">
          <button class="btn" onclick="auditLiveConfig()">🔍 Analyze Security</button>
          <button class="btn btn-outline" onclick="hardenLiveConfig()">🛡️ Auto-Harden Config</button>
        </div>
      </div>
      <div id="live-results"></div>
    </div>
  </div>

  <script>
    const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
    const severityClass = (value) => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(value) ? value : 'LOW';

    async function fetchScan() {
      const res = await fetch('/api/scan');
      const data = await res.json();
      renderDashboard(data);
    }

    function renderDashboard(data) {
      document.getElementById('stat-score').innerText = (data.complete === false ? 'INCOMPLETE ' : '') + data.overallGrade + ' (' + data.overallScore + '/100)';
      document.getElementById('stat-servers').innerText = data.totalServers;
      document.getElementById('stat-critical').innerText = data.summary.CRITICAL;
      document.getElementById('stat-high').innerText = data.summary.HIGH + data.summary.MEDIUM;

      const list = document.getElementById('servers-list');
      const warnings = Array.isArray(data.warnings) && data.warnings.length > 0
        ? '<div class="card" style="border-left: 4px solid var(--high); color: var(--high); margin-bottom: 1rem;">' +
          '<strong>⚠ Audit incomplete or limited</strong>' +
          data.warnings.map(w => '<div style="margin-top: 0.4rem;">' + escapeHtml(w) + '</div>').join('') +
          '</div>'
        : '';
      if (data.servers.length === 0) {
        list.innerHTML = warnings + '<div class="card" style="color: var(--muted);">No MCP servers discovered in default paths. Try the Live Config Playground!</div>';
        return;
      }

      list.innerHTML = warnings + data.servers.map(s => \`
        <div class="server-card">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 0.8rem;">
            <div>
              <strong style="font-size: 1.2rem;">\${escapeHtml(s.server)}</strong>
              <span style="color: var(--muted); font-size: 0.85rem; margin-left: 0.5rem;">[\${escapeHtml(s.sourceClient)}]</span>
            </div>
            <div>
                <span class="badge \${s.score >= 90 ? 'badge-safe' : 'badge-crit'}">Grade \${escapeHtml(s.grade)} (\${escapeHtml(s.score)}/100)</span>
            </div>
          </div>
          <div style="font-size: 0.8rem; color: var(--muted);">\${escapeHtml(s.sourcePath)}</div>
          \${s.issues.length === 0 ? '<div style="color: var(--safe); margin-top:0.6rem; font-size: 0.9rem;">✔ No security issues detected.</div>' : ''}
          \${s.issues.map(i => \`
            <div class="issue-box \${severityClass(i.severity)}">
              <div style="display:flex; justify-content:space-between;">
                <span class="badge \${i.severity === 'CRITICAL' ? 'badge-crit' : 'badge-high'}">\${escapeHtml(i.severity)}</span>
                <span style="font-size: 0.8rem; color: var(--muted);">\${escapeHtml(i.rule)}</span>
              </div>
              <div style="margin-top: 0.4rem; font-weight: 500;">\${escapeHtml(i.message)}</div>
              <div style="color: var(--safe); font-size: 0.85rem; margin-top: 0.3rem;">💡 \${escapeHtml(i.remediation)}</div>
            </div>
          \`).join('')}
        </div>
      \`).join('');
    }

    async function auditLiveConfig() {
      try {
        const payload = JSON.parse(document.getElementById('live-config-input').value);
        const res = await fetch('/api/audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        document.getElementById('live-results').innerHTML = '<h3 style="margin: 1rem 0;">Audit Result</h3>' +
          data.servers.map(s => \`
            <div class="server-card">
              <h4>\${escapeHtml(s.server)} - Score: \${escapeHtml(s.score)}/100 (Grade \${escapeHtml(s.grade)})</h4>
              \${s.issues.map(i => \`
                <div class="issue-box \${severityClass(i.severity)}">
                  <strong>[\${escapeHtml(i.severity)}] \${escapeHtml(i.rule)}:</strong> \${escapeHtml(i.message)}
                  <div style="color: var(--safe); font-size: 0.85rem;">💡 \${escapeHtml(i.remediation)}</div>
                </div>
              \`).join('')}
            </div>
          \`).join('');
      } catch (err) {
        alert('Invalid JSON input: ' + err.message);
      }
    }

    async function hardenLiveConfig() {
      try {
        const payload = JSON.parse(document.getElementById('live-config-input').value);
        const res = await fetch('/api/harden', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        document.getElementById('live-config-input').value = JSON.stringify(data.hardenedConfig, null, 2);
        alert('Hardened configuration generated! Applied ' + data.changes.length + ' remediations.');
        auditLiveConfig();
      } catch (err) {
        alert('Invalid JSON input: ' + err.message);
      }
    }

    function switchTab(name, clickEvent) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      clickEvent?.target?.classList.add('active');
      document.getElementById('tab-dashboard').style.display = name === 'dashboard' ? 'block' : 'none';
      document.getElementById('tab-playground').style.display = name === 'playground' ? 'block' : 'none';
    }

    fetchScan();
  </script>
</body>
</html>`;
}
