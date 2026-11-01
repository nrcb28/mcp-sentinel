/**
 * Audits database connections and MCP database servers (Postgres, MySQL, SQLite, MongoDB, Redis)
 * for insecure credentials, administrative accounts, and unencrypted connections.
 */
export function analyzeDatabaseSafetyRisk(serverName, serverConfig) {
  const issues = [];
  const args = serverConfig.args || [];
  const env = serverConfig.env || {};

  const allStrings = [
    ...args.filter((a) => typeof a === 'string'),
    ...Object.values(env).filter((v) => typeof v === 'string'),
  ];

  const DB_CONN_REGEX = /(postgres|postgresql|mysql|mongodb|redis|sqlite):\/\/[^ \n"']+/i;

  for (const str of allStrings) {
    const match = str.match(DB_CONN_REGEX);
    if (match) {
      const uri = match[0];
      const lower = uri.toLowerCase();

      // Administrative / root user in connection string
      if (lower.includes('://root:') || lower.includes('://postgres:') || lower.includes('://admin:')) {
        issues.push({
          id: 'DB_ADMIN_CREDENTIALS_EXPOSED',
          rule: 'Database Principle of Least Privilege',
          server: serverName,
          severity: 'HIGH',
          target: uri.replace(/:[^:@]+@/, ':****@'),
          message: 'Database connection uses superuser or root credentials (admin/postgres/root).',
          remediation: 'Create a dedicated, unprivileged read-only database user for MCP queries.',
        });
      }

      // Plaintext password embedded in connection URI
      if (/:[^@]+@/.test(uri)) {
        issues.push({
          id: 'DB_CONNECTION_PLAINTEXT_SECRET',
          rule: 'Database URI Credential Exposure',
          server: serverName,
          severity: 'CRITICAL',
          target: uri.replace(/:[^:@]+@/, ':****@'),
          message: 'Database password is hardcoded directly inside the connection URI.',
          remediation: 'Supply connection parameters through isolated environment variables or secrets manager.',
        });
      }

      // Insecure SSL / TLS mode
      if (lower.includes('sslmode=disable') || lower.includes('tls=false')) {
        issues.push({
          id: 'DB_TLS_DISABLED',
          rule: 'Database Connection Encryption',
          server: serverName,
          severity: 'HIGH',
          target: uri.replace(/:[^:@]+@/, ':****@'),
          message: 'Database connection explicitly disables TLS / SSL encryption (sslmode=disable).',
          remediation: 'Enforce SSL/TLS encryption (e.g. sslmode=require or verify-full).',
        });
      }
    }
  }

  return issues;
}
