// ANSI color helpers
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m\x1b[37m',
  bgYellow: '\x1b[43m\x1b[30m',
  bgGreen: '\x1b[42m\x1b[30m',
};

function badge(severity) {
  switch (severity) {
    case 'CRITICAL':
      return `${c.bgRed} CRITICAL ${c.reset}`;
    case 'HIGH':
      return `${c.red}● HIGH${c.reset}    `;
    case 'MEDIUM':
      return `${c.yellow}▲ MEDIUM${c.reset}  `;
    case 'LOW':
      return `${c.blue}ℹ LOW${c.reset}     `;
    default:
      return severity;
  }
}

function gradeBadge(grade) {
  if (grade.startsWith('A')) return `${c.green}${c.bold}[ ${grade} ]${c.reset}`;
  if (grade === 'B') return `${c.cyan}${c.bold}[ ${grade} ]${c.reset}`;
  if (grade === 'C') return `${c.yellow}${c.bold}[ ${grade} ]${c.reset}`;
  return `${c.red}${c.bold}[ ${grade} ]${c.reset}`;
}

export function printTerminalReport(auditResult) {
  console.log('\n' + c.bold + c.cyan + '═══════════════════════════════════════════════════════════════' + c.reset);
  console.log(c.bold + c.cyan + '             MCP-SENTINEL SECURITY AUDIT REPORT                ' + c.reset);
  console.log(c.bold + c.cyan + '═══════════════════════════════════════════════════════════════' + c.reset);

  console.log(`\n${c.bold}Overall Security Health:${c.reset} ${gradeBadge(auditResult.overallGrade)} (Score: ${auditResult.overallScore}/100)`);
  console.log(`${c.dim}Scanned Servers: ${auditResult.totalServers} | Found Configurations: ${auditResult.totalConfigs}${c.reset}`);

  const s = auditResult.summary;
  console.log(`\n${c.bold}Vulnerability Summary:${c.reset}`);
  console.log(`  ${c.red}● Critical:${c.reset} ${s.CRITICAL}   ${c.yellow}▲ High:${c.reset} ${s.HIGH}   ${c.blue}ℹ Medium:${c.reset} ${s.MEDIUM}   ${c.dim}Low:${c.reset} ${s.LOW}`);

  console.log('\n' + c.bold + '---------------------------------------------------------------' + c.reset);
  console.log(c.bold + 'Server Breakdown:' + c.reset);

  if (auditResult.servers.length === 0) {
    console.log(`\n  ${c.yellow}No MCP servers discovered in the specified paths.${c.reset}`);
    return;
  }

  for (const srv of auditResult.servers) {
    console.log(`\n▶ ${c.bold}${srv.server}${c.reset} [${srv.sourceClient}]  Grade: ${gradeBadge(srv.grade)} (${srv.score}/100)`);
    console.log(`  ${c.dim}Config: ${srv.sourcePath}${c.reset}`);

    if (srv.issues.length === 0) {
      console.log(`  ${c.green}✔ No security issues identified. Server is well-isolated.${c.reset}`);
    } else {
      for (const issue of srv.issues) {
        console.log(`  ${badge(issue.severity)} ${c.bold}${issue.rule}${c.reset}`);
        console.log(`    ${issue.message}`);
        console.log(`    ${c.dim}↳ Target: ${issue.target}${c.reset}`);
        console.log(`    ${c.green}↳ Fix: ${issue.remediation}${c.reset}`);
      }
    }
  }

  console.log('\n' + c.bold + c.cyan + '═══════════════════════════════════════════════════════════════' + c.reset + '\n');
}
