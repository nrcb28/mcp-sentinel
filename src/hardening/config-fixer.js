import fs from 'node:fs';

/**
 * Automatically creates a hardened, sanitized template from a vulnerable MCP config.
 */
export function generateHardenedConfig(rawConfig) {
  const hardened = JSON.parse(JSON.stringify(rawConfig));
  const servers = hardened.mcpServers || hardened.servers || hardened;
  const changes = [];

  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== 'object') continue;

    // 1. Sanitize Environment Variables (replace secrets with references)
    if (cfg.env && typeof cfg.env === 'object') {
      for (const [key, val] of Object.entries(cfg.env)) {
        if (typeof val === 'string' && !val.startsWith('${')) {
          const lower = key.toLowerCase();
          if (
            val.startsWith('sk-') ||
            val.startsWith('ghp_') ||
            val.startsWith('AKIA') ||
            lower.includes('secret') ||
            lower.includes('token') ||
            lower.includes('key')
          ) {
            cfg.env[key] = `\${env:${key}}`;
            changes.push(`[${name}] Replaced hardcoded secret in env.${key} with secure reference \${env:${key}}`);
          }
        }
      }
    }

    // 2. Remove dangerous execution flags from args
    if (Array.isArray(cfg.args)) {
      const sanitizedArgs = [];
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
          // Pin unpinned npx package
          if (cfg.command === 'npx' && !arg.startsWith('-') && !arg.includes('@')) {
            const pinned = `${arg}@1.0.0`;
            sanitizedArgs.push(pinned);
            changes.push(`[${name}] Pinned unversioned package "${arg}" to "${pinned}"`);
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
  const raw = fs.readFileSync(sourcePath, 'utf8');
  const parsed = JSON.parse(raw);
  const { hardenedConfig, changes } = generateHardenedConfig(parsed);
  fs.writeFileSync(outputPath, JSON.stringify(hardenedConfig, null, 2), 'utf8');
  return changes;
}
