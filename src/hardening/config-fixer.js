import fs from 'node:fs';
import path from 'node:path';
import { writeTextFileSecure } from '../security/safe-write.js';

const SECRET_VALUE_PATTERNS = [
  /sk-(?:ant-)?[a-zA-Z0-9_-]{20,}/,
  /(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}/,
  /github_pat_[a-zA-Z0-9_]{40,}/,
  /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
  /xox[baprs]-[0-9a-zA-Z]{10,48}/,
  /AIza[0-9A-Za-z_-]{35}/,
  /(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}/,
  /-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/i,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /\b(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*[^\s,;&]+/i,
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/@]+:[^\s/@]+@/i,
];

const SENSITIVE_ENV_KEY = /(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|auth)/i;
const URI_PASSWORD = /:\/\/[^\s/@]+:[^\s/@]+@/;

function isSecretValue(key, value) {
  return SENSITIVE_ENV_KEY.test(key) || URI_PASSWORD.test(value) || SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(value));
}

/**
 * Automatically creates a hardened, sanitized template from a vulnerable MCP config.
 */
export function generateHardenedConfig(rawConfig) {
  if (!rawConfig || typeof rawConfig !== 'object' || Array.isArray(rawConfig)) {
    throw new TypeError('MCP configuration must be a JSON object');
  }

  const hardened = JSON.parse(JSON.stringify(rawConfig));
  const candidateServers = hardened.mcpServers || hardened.servers || hardened;
  const servers = candidateServers && typeof candidateServers === 'object' && !Array.isArray(candidateServers)
    ? candidateServers
    : {};
  const changes = [];

  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== 'object') continue;

    // 1. Sanitize Environment Variables (replace secrets with references)
    if (cfg.env && typeof cfg.env === 'object' && !Array.isArray(cfg.env)) {
      for (const [key, val] of Object.entries(cfg.env)) {
        if (typeof val === 'string' && !val.startsWith('${') && isSecretValue(key, val)) {
          cfg.env[key] = `\${env:${key}}`;
          changes.push(`[${name}] Replaced hardcoded secret in env.${key} with secure reference \${env:${key}}`);
        }
      }
    }

    // 2. Remove dangerous execution flags from args
    if (Array.isArray(cfg.args)) {
      const sanitizedArgs = [];
      let secretPlaceholder = 0;
      for (let i = 0; i < cfg.args.length; i++) {
        const arg = cfg.args[i];
        if (typeof arg === 'string') {
          // Remove ExecutionPolicy Bypass
          if (arg.toLowerCase() === '-executionpolicy' && cfg.args[i + 1]?.toLowerCase() === 'bypass') {
            i++; // skip both
            changes.push(`[${name}] Removed dangerous '-ExecutionPolicy Bypass' argument`);
            continue;
          }
          // Remove docker --privileged
          if (arg.toLowerCase() === '--privileged') {
            changes.push(`[${name}] Removed docker '--privileged' flag`);
            continue;
          }
          // Never invent a package version: a fake pin can redirect users to a
          // different package or make a valid package unusable. Leave it intact
          // and make the remaining manual action explicit.
          if ((cfg.command === 'npx' || cfg.command === 'uvx') && !arg.startsWith('-') && !arg.includes('@')) {
            sanitizedArgs.push(arg);
            changes.push(`[${name}] Could not safely pin package "${arg}" automatically; review and pin an exact trusted version`);
            continue;
          }

          if (SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(arg))) {
            secretPlaceholder += 1;
            const replacement = `\${env:MCP_SENTINEL_SECRET_${secretPlaceholder}}`;
            sanitizedArgs.push(replacement);
            changes.push(`[${name}] Replaced a secret command argument with secure reference ${replacement}`);
            continue;
          }
        }
        sanitizedArgs.push(arg);
      }
      cfg.args = sanitizedArgs;
    }
  }

  return {
    hardenedConfig: hardened,
    changes,
  };
}

export function saveHardenedConfigFile(sourcePath, outputPath) {
  const source = path.resolve(sourcePath);
  const output = path.resolve(outputPath);
  if (source === output) {
    throw new Error('Refusing to overwrite the source configuration; choose a different output path');
  }
  const raw = fs.readFileSync(source, 'utf8');
  const parsed = JSON.parse(raw);
  const { hardenedConfig, changes } = generateHardenedConfig(parsed);
  writeTextFileSecure(output, JSON.stringify(hardenedConfig, null, 2));
  return changes;
}
