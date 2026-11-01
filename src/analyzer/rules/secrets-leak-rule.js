const SECRET_SIGNATURES = [
  { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9_-]{20,}/, severity: 'CRITICAL' },
  { name: 'Anthropic API Key', regex: /sk-ant-[a-zA-Z0-9_-]{20,}/, severity: 'CRITICAL' },
  { name: 'GitHub Personal Access Token', regex: /(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}/, severity: 'CRITICAL' },
  { name: 'GitHub Fine-Grained Token', regex: /github_pat_[a-zA-Z0-9_]{82}/, severity: 'CRITICAL' },
  { name: 'AWS Access Key ID', regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/, severity: 'CRITICAL' },
  { name: 'Slack Bot / User Token', regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/, severity: 'HIGH' },
  { name: 'Google API / Gemini Key', regex: /AIza[0-9A-Za-z-_]{35}/, severity: 'CRITICAL' },
  { name: 'Stripe API Key', regex: /(sk|rk)_(live|test)_[0-9a-zA-Z]{24,99}/, severity: 'CRITICAL' },
  { name: 'Generic Private Key Header', regex: /-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/, severity: 'CRITICAL' },
];

export function analyzeSecretsLeakRisk(serverName, serverConfig) {
  const issues = [];
  const env = serverConfig.env || {};
  const args = serverConfig.args || [];

  // Check env entries
  for (const [key, val] of Object.entries(env)) {
    if (typeof val !== 'string') continue;

    for (const sig of SECRET_SIGNATURES) {
      if (sig.regex.test(val)) {
        const masked = val.length > 8 ? `${val.slice(0, 4)}...${val.slice(-4)}` : '****';
        issues.push({
          id: 'SECRET_PLAINTEXT_IN_CONFIG',
          rule: 'Credential Exposure',
          server: serverName,
          severity: sig.severity,
          target: `${key}=${masked}`,
          message: `Environment variable "${key}" contains an unmasked, plaintext ${sig.name}.`,
          remediation: `Use process environment substitution (e.g. process.env.${key}) or a secure credential store instead of hardcoding tokens in config files.`,
        });
      }
    }

    // Generic high-entropy key detection
    const lowerKey = key.toLowerCase();
    if (
      (lowerKey.includes('token') || lowerKey.includes('secret') || lowerKey.includes('password') || lowerKey.includes('api_key')) &&
      val.length > 20 &&
      !val.startsWith('${')
    ) {
      const alreadyFlagged = issues.some((i) => i.target.startsWith(`${key}=`));
      if (!alreadyFlagged) {
        issues.push({
          id: 'SECRET_SUSPECTED_TOKEN',
          rule: 'Suspected Hardcoded Secret',
          server: serverName,
          severity: 'HIGH',
          target: `${key}=****`,
          message: `Key "${key}" appears to hold an unreferenced raw credential value.`,
          remediation: 'Reference this secret via environment variables at runtime.',
        });
      }
    }
  }

  // Check args
  for (const arg of args) {
    if (typeof arg !== 'string') continue;
    for (const sig of SECRET_SIGNATURES) {
      if (sig.regex.test(arg)) {
        issues.push({
          id: 'SECRET_IN_COMMAND_ARGUMENTS',
          rule: 'Secret In Command Arguments',
          server: serverName,
          severity: 'CRITICAL',
          target: 'arg[secret]',
          message: `Command arguments contain an exposed ${sig.name}. Arguments are visible to other processes via task manager / ps.`,
          remediation: 'Pass credentials via secure environment variables or standard input, never as command-line arguments.',
        });
      }
    }
  }

  return issues;
}
