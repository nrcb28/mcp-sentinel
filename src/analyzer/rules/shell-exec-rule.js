const SHELL_COMMANDS = [
  'powershell',
  'powershell.exe',
  'pwsh',
  'pwsh.exe',
  'cmd',
  'cmd.exe',
  'bash',
  'sh',
  'zsh',
  'wscript',
  'cscript',
];

const EVAL_FLAGS = [
  '-e',
  '-c',
  '--eval',
  '/c',
  '-command',
  '-encodedcommand',
];

export function analyzeShellExecRisk(serverName, serverConfig) {
  const issues = [];
  const command = (typeof serverConfig.command === 'string' ? serverConfig.command : '').trim().toLowerCase();
  const args = (Array.isArray(serverConfig.args) ? serverConfig.args : [])
    .map((a) => (typeof a === 'string' ? a.trim() : ''));

  // Check if command is a raw shell
  const baseCommand = command.split(/[\\/]/).pop();
  if (SHELL_COMMANDS.includes(baseCommand)) {
    issues.push({
      id: 'SHELL_DIRECT_INVOCATION',
      rule: 'Arbitrary Shell Execution',
      server: serverName,
      severity: 'CRITICAL',
      target: command,
      message: `Server runs directly inside an interactive shell executable: "${command}".`,
      remediation: 'Avoid spawning raw shells. Wrap commands inside targeted scripts or isolated binaries.',
    });
  }

  // Check for eval flags in runtimes (node -e, python -c)
  for (let i = 0; i < args.length; i++) {
    const arg = args[i].toLowerCase();
    if (EVAL_FLAGS.includes(arg)) {
      issues.push({
        id: 'SHELL_EVAL_FLAG_DETECTED',
        rule: 'Dynamic Code Evaluation',
        server: serverName,
        severity: 'HIGH',
        target: `${arg} ${args[i + 1] || ''}`,
        message: `Command invokes runtime evaluation flag "${arg}" with inline script execution.`,
        remediation: 'Run a static, audited script file instead of passing inline dynamic code expressions.',
      });
    }

    if (arg === '-executionpolicy' && args[i + 1]?.toLowerCase() === 'bypass') {
      issues.push({
        id: 'SHELL_EXECUTION_POLICY_BYPASS',
        rule: 'PowerShell Policy Bypass',
        server: serverName,
        severity: 'HIGH',
        target: '-ExecutionPolicy Bypass',
        message: 'PowerShell execution policy is explicitly bypassed.',
        remediation: 'Sign scripts or run under default restricted execution policy.',
      });
    }

    if (arg === '--no-sandbox') {
      issues.push({
        id: 'BROWSER_NO_SANDBOX',
        rule: 'Sandbox Disabled',
        server: serverName,
        severity: 'HIGH',
        target: '--no-sandbox',
        message: 'Chromium / Node sandbox is explicitly disabled.',
        remediation: 'Maintain sandbox protections enabled for process isolation.',
      });
    }
  }

  return issues;
}
