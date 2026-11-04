/**
 * Audits package manager invocations (npx, uvx, pip, etc.) for supply chain risks:
 * - Unpinned package versions (@latest or no version)
 * - Remote script downloads (curl | bash, wget)
 * - Typosquatting / suspicious package patterns
 */
export function analyzeSupplyChainRisk(serverName, serverConfig) {
  const issues = [];
  const command = (typeof serverConfig.command === 'string' ? serverConfig.command : '').trim().toLowerCase();
  const args = (Array.isArray(serverConfig.args) ? serverConfig.args : [])
    .map((a) => (typeof a === 'string' ? a.trim() : ''));

  const isNpx = command === 'npx' || command.endsWith('/npx') || command.endsWith('\\npx');
  const isUvx = command === 'uvx' || command.endsWith('/uvx') || command.endsWith('\\uvx');

  if (isNpx || isUvx) {
    // Find package name arg (skipping -y, --yes, etc.)
    const pkgArg = args.find((a) => !a.startsWith('-'));

    if (pkgArg) {
      // Check if unpinned or @latest
      if (!pkgArg.includes('@') || pkgArg.endsWith('@latest')) {
        issues.push({
          id: 'SUPPLY_CHAIN_UNPINNED_PACKAGE',
          rule: 'Supply Chain Pinning',
          server: serverName,
          severity: 'HIGH',
          target: pkgArg,
          message: `Package "${pkgArg}" is invoked without a pinned cryptographic or semver version tag.`,
          remediation: `Pin the package to an exact version (e.g. "${pkgArg.split('@')[0]}@1.2.3") to prevent supply chain poisoning.`,
        });
      }

      // Check for suspicious typosquatting or excessive scoped namespaces
      if (pkgArg.startsWith('@') && !pkgArg.startsWith('@modelcontextprotocol/') && pkgArg.split('/').length > 2) {
        issues.push({
          id: 'SUPPLY_CHAIN_SUSPICIOUS_PACKAGE',
          rule: 'Package Namespace Validation',
          server: serverName,
          severity: 'MEDIUM',
          target: pkgArg,
          message: `Package "${pkgArg}" uses an unusual nested or non-standard namespace format.`,
          remediation: 'Verify the package author and integrity on the public registry.',
        });
      }
    }
  }

  // Check for curl / wget pipe-to-shell patterns in args
  const fullArgs = args.join(' ').toLowerCase();
  if (fullArgs.includes('curl ') || fullArgs.includes('wget ')) {
    if (fullArgs.includes('| bash') || fullArgs.includes('| sh') || fullArgs.includes('| powershell')) {
      issues.push({
        id: 'SUPPLY_CHAIN_REMOTE_EXECUTION',
        rule: 'Remote Script Execution',
        server: serverName,
        severity: 'CRITICAL',
        target: fullArgs,
        message: 'Command downloads and directly executes remote unverified script via pipe to shell.',
        remediation: 'Download and inspect scripts with checksum verification before running.',
      });
    }
  }

  return issues;
}
