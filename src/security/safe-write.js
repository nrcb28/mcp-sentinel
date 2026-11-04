import fs from 'node:fs';
import path from 'node:path';

const MAX_REPORT_BYTES = 10 * 1024 * 1024;

function resolveOutputTarget(outputPath) {
  const requested = path.resolve(outputPath);
  // Resolve normal OS aliases such as macOS /var -> /private/var, while still
  // rejecting a symlink at the actual file being replaced.
  const directory = fs.realpathSync(path.dirname(requested));
  const target = path.join(directory, path.basename(requested));
  if (fs.existsSync(target) && fs.lstatSync(target).isSymbolicLink()) {
    throw new Error('Refusing to write through a symbolic-link output path');
  }
  return target;
}

/**
 * Writes generated artifacts without following an existing symlink. Reports
 * can contain local paths and security findings, so they are private by
 * default on POSIX systems.
 */
export function writeTextFileSecure(outputPath, contents, options = {}) {
  if (typeof outputPath !== 'string' || !outputPath.trim()) {
    throw new TypeError('Output path must be a non-empty string');
  }
  if (typeof contents !== 'string') {
    throw new TypeError('Output contents must be a string');
  }

  const target = resolveOutputTarget(outputPath);
  const maxBytes = Number.isInteger(options.maxBytes) && options.maxBytes > 0
    ? options.maxBytes
    : MAX_REPORT_BYTES;
  const byteLength = Buffer.byteLength(contents, 'utf8');
  if (byteLength > maxBytes) {
    throw new Error(`Generated output exceeds the ${maxBytes} byte safety limit`);
  }

  fs.writeFileSync(target, contents, { encoding: 'utf8', mode: 0o600 });
  if (process.platform !== 'win32') {
    fs.chmodSync(target, 0o600);
  }
  return target;
}
