const SECRET_SIGNATURES = [
  /sk-(?:ant-)?[a-zA-Z0-9_-]{20,}/g,
  /(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}/g,
  /github_pat_[a-zA-Z0-9_]{40,}/g,
  /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
  /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
  /AIza[0-9A-Za-z_-]{35}/g,
  /(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}/g,
];

const PRIVATE_KEY_PATTERN = /-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/g;
const URI_PASSWORD_PATTERN = /(\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/@]+:)[^\s/@]+(@)/gi;
const SENSITIVE_KEY_PATTERN = /(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|auth)/i;

function redactString(value) {
  let redacted = value.replace(PRIVATE_KEY_PATTERN, '[REDACTED_PRIVATE_KEY]');
  redacted = redacted.replace(URI_PASSWORD_PATTERN, '$1[REDACTED]$2');
  for (const signature of SECRET_SIGNATURES) {
    redacted = redacted.replace(signature, '[REDACTED_SECRET]');
  }
  return redacted;
}

/**
 * Returns a copy safe to include in reports or API responses.
 * It intentionally preserves command structure while removing credential values.
 */
export function redactSensitiveConfig(config) {
  if (!config || typeof config !== 'object') return config;

  if (Array.isArray(config)) {
    return config.map((item) => redactSensitiveConfig(item));
  }

  const result = {};
  for (const [key, value] of Object.entries(config)) {
    if (typeof value === 'string') {
      if (SENSITIVE_KEY_PATTERN.test(key) && !value.startsWith('${')) {
        result[key] = '[REDACTED]';
      } else {
        result[key] = redactString(value);
      }
    } else if (value && typeof value === 'object') {
      result[key] = redactSensitiveConfig(value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

/** Redacts secrets in issue text without changing the issue shape. */
export function redactSensitiveText(value) {
  return typeof value === 'string' ? redactString(value) : value;
}

export function redactIssue(issue) {
  if (!issue || typeof issue !== 'object') return issue;
  return Object.fromEntries(
    Object.entries(issue).map(([key, value]) => [key, redactSensitiveText(value)]),
  );
}
