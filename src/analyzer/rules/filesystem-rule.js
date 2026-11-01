import path from 'node:path';

const SENSITIVE_PATTERNS = [
  { pattern: /[\\/]\.ssh([\\/]|$)/i, desc: 'SSH credentials and private keys', severity: 'CRITICAL' },
  { pattern: /[\\/]\.aws([\\/]|$)/i, desc: 'AWS credentials and configs', severity: 'CRITICAL' },
  { pattern: /[\\/]\.gnupg([\\/]|$)/i, desc: 'GPG private keys and keyrings', severity: 'CRITICAL' },
  { pattern: /[\\/]\.azure([\\/]|$)/i, desc: 'Azure CLI access tokens', severity: 'CRITICAL' },
  { pattern: /[\\/]\.kube([\\/]|$)/i, desc: 'Kubernetes cluster tokens', severity: 'CRITICAL' },
  { pattern: /[\\/]\.env(\.local|\.prod|\.dev)?$/i, desc: 'Environment secret files', severity: 'HIGH' },
  { pattern: /^(\/|[a-z]:\\?)$/i, desc: 'Full root or system drive access', severity: 'CRITICAL' },
  { pattern: /[\\/]windows[\\/]system32/i, desc: 'Windows System32 directory', severity: 'CRITICAL' },
  { pattern: /^\/etc([\\/]|$)/i, desc: 'Unix system configuration directory', severity: 'CRITICAL' },
  { pattern: /^\/var[\\/]log/i, desc: 'System log directory', severity: 'HIGH' },
];

export function analyzeFilesystemRisk(serverName, serverConfig) {
  const issues = [];
  const args = serverConfig.args || [];
  const env = serverConfig.env || {};

  const allStrings = [
    ...args.filter((a) => typeof a === 'string'),
    ...Object.values(env).filter((v) => typeof v === 'string'),
  ];

  for (const str of allStrings) {
    for (const rule of SENSITIVE_PATTERNS) {
      if (rule.pattern.test(str)) {
        issues.push({
          id: 'FS_SENSITIVE_PATH_EXPOSURE',
          rule: 'Filesystem Isolation',
          server: serverName,
          severity: rule.severity,
          target: str,
          message: `Server is granted direct access to sensitive filesystem target: "${str}" (${rule.desc}).`,
          remediation: 'Restrict access to an isolated workspace or dedicated sandboxed folder.',
        });
      }
    }

    if (str.includes('..') && (str.includes('/') || str.includes('\\'))) {
      issues.push({
        id: 'FS_PATH_TRAVERSAL_DETECTED',
        rule: 'Path Traversal Risk',
        server: serverName,
        severity: 'MEDIUM',
        target: str,
        message: `Argument or config contains directory traversal notation: "${str}".`,
        remediation: 'Use absolute, canonical paths instead of relative parent directory traversals.',
      });
    }
  }

  return issues;
}
