/**
 * Audits network endpoints and transport options for SSRF, unencrypted protocols, and TLS disabling.
 */
export function analyzeNetworkTransportRisk(serverName, serverConfig) {
  const issues = [];
  const args = Array.isArray(serverConfig.args) ? serverConfig.args : [];
  const env = serverConfig.env && typeof serverConfig.env === 'object' && !Array.isArray(serverConfig.env)
    ? serverConfig.env
    : {};

  const allStrings = [
    ...args.filter((a) => typeof a === 'string'),
    ...Object.values(env).filter((v) => typeof v === 'string'),
  ];

  for (const str of allStrings) {
    // Cloud metadata endpoint exposure (SSRF)
    if (str.includes('169.254.169.254') || str.includes('metadata.google.internal')) {
      issues.push({
        id: 'NETWORK_CLOUD_METADATA_SSRF',
        rule: 'Cloud Metadata Protection (SSRF)',
        server: serverName,
        severity: 'CRITICAL',
        target: str,
        message: 'Endpoint targets cloud instance metadata service (169.254.169.254), risking IAM credential theft.',
        remediation: 'Block egress access to cloud metadata IP addresses from MCP server processes.',
      });
    }

    // Insecure HTTP / WS endpoints
    if (str.startsWith('http://') && !str.includes('localhost') && !str.includes('127.0.0.1')) {
      issues.push({
        id: 'NETWORK_PLAINTEXT_TRANSPORT',
        rule: 'Transport Layer Security (TLS)',
        server: serverName,
        severity: 'HIGH',
        target: str,
        message: `Endpoint uses unencrypted cleartext HTTP: "${str}". MCP traffic can be intercepted.`,
        remediation: 'Always use encrypted HTTPS/TLS for remote MCP servers and SSE connections.',
      });
    }

    if (str.startsWith('ws://') && !str.includes('localhost') && !str.includes('127.0.0.1')) {
      issues.push({
        id: 'NETWORK_PLAINTEXT_WEBSOCKET',
        rule: 'Secure WebSocket (WSS)',
        server: serverName,
        severity: 'HIGH',
        target: str,
        message: `WebSocket endpoint uses unencrypted cleartext "ws://": "${str}".`,
        remediation: 'Use secure "wss://" transport.',
      });
    }

    // Disabling TLS verification
    if (str === 'NODE_TLS_REJECT_UNAUTHORIZED=0' || str === '--insecure' || str === '-k') {
      issues.push({
        id: 'NETWORK_TLS_VERIFICATION_DISABLED',
        rule: 'Certificate Validation',
        server: serverName,
        severity: 'CRITICAL',
        target: str,
        message: 'TLS certificate verification is explicitly disabled, allowing Man-in-the-Middle (MitM) attacks.',
        remediation: 'Do not disable TLS certificate validation in production or development environments.',
      });
    }
  }

  // Check specific env vars
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
    issues.push({
      id: 'NETWORK_TLS_VERIFICATION_DISABLED',
      rule: 'Certificate Validation',
      server: serverName,
      severity: 'CRITICAL',
      target: 'NODE_TLS_REJECT_UNAUTHORIZED=0',
      message: 'Node.js TLS rejection is disabled globally via environment variable.',
      remediation: 'Remove NODE_TLS_REJECT_UNAUTHORIZED=0 to enforce certificate validation.',
    });
  }

  return issues;
}
