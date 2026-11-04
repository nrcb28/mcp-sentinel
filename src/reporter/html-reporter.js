import { writeTextFileSecure } from '../security/safe-write.js';

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[char]));
}

export function generateHtmlReport(auditResult, outputPath) {
  const getBadgeClass = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      default: return 'badge-low';
    }
  };

  const getGradeClass = (grade) => {
    if (typeof grade !== 'string') return 'grade-f';
    if (grade.startsWith('A')) return 'grade-a';
    if (grade === 'B') return 'grade-b';
    if (grade === 'C') return 'grade-c';
    return 'grade-f';
  };

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP-Sentinel Security Audit Report</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --primary: #58a6ff;
      --critical: #f85149;
      --high: #d29922;
      --medium: #e3b341;
      --low: #58a6ff;
      --grade-a: #3fb950;
      --grade-b: #58a6ff;
      --grade-c: #d29922;
      --grade-f: #f85149;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 2rem;
      line-height: 1.6;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    h1 { color: var(--text-bright); font-size: 1.8rem; display: flex; align-items: center; gap: 0.5rem; }
    .subtitle { color: #8b949e; font-size: 0.9rem; margin-top: 0.3rem; }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.2rem;
      text-align: center;
    }
    .stat-val { font-size: 2.2rem; font-weight: bold; margin: 0.3rem 0; }
    .stat-label { font-size: 0.85rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
    .grade-a { color: var(--grade-a); }
    .grade-b { color: var(--grade-b); }
    .grade-c { color: var(--grade-c); }
    .grade-f { color: var(--grade-f); }
    .server-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .server-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #21262d;
      padding-bottom: 0.8rem;
      margin-bottom: 1rem;
    }
    .server-title { font-size: 1.3rem; color: var(--text-bright); font-weight: 600; }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: bold;
    }
    .badge-critical { background: rgba(248,81,73,0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-high { background: rgba(210,153,34,0.2); color: var(--high); border: 1px solid var(--high); }
    .badge-medium { background: rgba(227,179,65,0.2); color: var(--medium); border: 1px solid var(--medium); }
    .badge-low { background: rgba(88,166,255,0.2); color: var(--low); border: 1px solid var(--low); }
    .issue-item {
      background: #0d1117;
      border-left: 4px solid var(--border);
      padding: 1rem;
      margin-bottom: 0.8rem;
      border-radius: 4px;
    }
    .issue-item.CRITICAL { border-left-color: var(--critical); }
    .issue-item.HIGH { border-left-color: var(--high); }
    .issue-item.MEDIUM { border-left-color: var(--medium); }
    .issue-item.LOW { border-left-color: var(--low); }
    .issue-msg { font-weight: 500; color: var(--text-bright); margin-bottom: 0.4rem; }
    .issue-details { font-size: 0.85rem; color: #8b949e; font-family: monospace; }
    .issue-fix { color: #3fb950; font-size: 0.85rem; margin-top: 0.4rem; }
    .clean-alert { color: #3fb950; font-weight: 500; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🛡️ MCP-Sentinel Audit</h1>
        <div class="subtitle">Generated on ${escapeHtml(new Date(auditResult.timestamp).toLocaleString())}</div>
      </div>
      <div style="text-align: right;">
        <span class="stat-label">Global Health</span>
        <div class="stat-val ${getGradeClass(auditResult.overallGrade)}">${escapeHtml(auditResult.overallGrade)} (${escapeHtml(auditResult.overallScore)}/100)</div>
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Servers Scanned</div>
        <div class="stat-val" style="color: var(--primary);">${auditResult.totalServers}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Critical Issues</div>
        <div class="stat-val" style="color: var(--critical);">${auditResult.summary.CRITICAL}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">High Severity</div>
        <div class="stat-val" style="color: var(--high);">${auditResult.summary.HIGH}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Medium & Low</div>
        <div class="stat-val" style="color: var(--medium);">${auditResult.summary.MEDIUM + auditResult.summary.LOW}</div>
      </div>
    </div>

    <h2 style="margin-bottom: 1rem; color: var(--text-bright);">Detailed Server Audits</h2>

    ${auditResult.servers.map((srv) => `
      <div class="server-card">
        <div class="server-header">
          <div>
            <div class="server-title">${escapeHtml(srv.server)} <span style="font-size: 0.8rem; color: #8b949e; font-weight: normal;">(${escapeHtml(srv.sourceClient)})</span></div>
            <div style="font-size: 0.8rem; color: #8b949e; margin-top: 0.2rem;">${escapeHtml(srv.sourcePath)}</div>
          </div>
          <div style="text-align: right;">
            <div class="stat-val ${getGradeClass(srv.grade)}" style="font-size: 1.5rem;">Grade ${escapeHtml(srv.grade)}</div>
            <div style="font-size: 0.8rem; color: #8b949e;">Score: ${escapeHtml(srv.score)}/100</div>
          </div>
        </div>

        ${srv.issues.length === 0 ? `
          <div class="clean-alert">✔ Perfect Score! No security vulnerabilities identified.</div>
        ` : srv.issues.map((issue) => `
          <div class="issue-item ${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(issue.severity) ? issue.severity : 'LOW'}">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
              <span class="badge ${getBadgeClass(issue.severity)}">${escapeHtml(issue.severity)}</span>
              <span style="font-size: 0.8rem; color: #8b949e;">${escapeHtml(issue.rule)}</span>
            </div>
            <div class="issue-msg">${escapeHtml(issue.message)}</div>
            <div class="issue-details">Target: ${escapeHtml(issue.target)}</div>
            <div class="issue-fix">💡 Fix: ${escapeHtml(issue.remediation)}</div>
          </div>
        `).join('')}
      </div>
    `).join('')}
  </div>
</body>
</html>`;

  writeTextFileSecure(outputPath, html);
}
