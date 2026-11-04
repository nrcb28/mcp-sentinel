const NETWORK_INDICATORS = [
  'fetch',
  'http',
  'request',
  'webhook',
  'upload',
  'send_email',
  'post_message',
  'curl',
  'websocket',
];

const READ_INDICATORS = [
  'read_file',
  'get_file',
  'list_directory',
  'read_directory',
  'search_files',
  'read_resource',
  'read_clipboard',
];

export function analyzeExfiltrationRisk(serverName, serverConfig, liveTools = []) {
  const issues = [];

  // Check if tools were provided or discovered
  const safeTools = Array.isArray(liveTools) ? liveTools.filter((tool) => tool && typeof tool === 'object') : [];
  const toolNames = safeTools.map((t) => (typeof t.name === 'string' ? t.name : '').toLowerCase());
  const toolDescriptions = safeTools.map((t) => (typeof t.description === 'string' ? t.description : '').toLowerCase());

  const hasLocalRead = toolNames.some((name) => READ_INDICATORS.some((ind) => name.includes(ind))) ||
    toolDescriptions.some((desc) => desc.includes('read local file') || desc.includes('filesystem'));

  const hasNetworkWrite = toolNames.some((name) => NETWORK_INDICATORS.some((ind) => name.includes(ind))) ||
    toolDescriptions.some((desc) => desc.includes('http request') || desc.includes('send post') || desc.includes('upload to'));

  if (hasLocalRead && hasNetworkWrite) {
    issues.push({
      id: 'EXFILTRATION_COMBINED_CAPABILITIES',
      rule: 'Data Exfiltration Vector',
      server: serverName,
      severity: 'HIGH',
      target: 'Tool Capabilities (Read + Network)',
      message: `Server exposes both local filesystem reading and outbound network capabilities, enabling potential silent data exfiltration.`,
      remediation: 'Segregate file-reading tools and network transmission tools into separate isolated MCP servers.',
    });
  }

  return issues;
}
