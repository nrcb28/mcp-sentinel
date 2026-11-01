/**
 * Audits tool definitions and schemas for vulnerability to indirect prompt injection
 * and unconstrained code/command execution.
 */
export function analyzePromptInjectionRisk(serverName, serverConfig, liveTools = []) {
  const issues = [];

  for (const tool of liveTools) {
    const name = (tool.name || '').toLowerCase();
    const desc = (tool.description || '').toLowerCase();
    const schema = tool.inputSchema || {};
    const props = schema.properties || {};

    // 1. Tool declares dangerous arbitrary code execution
    const dangerousName = /eval|exec|script|shell|command|terminal/i.test(name);
    const dangerousDesc = /arbitrary|any command|shell command|run script|evaluate code/i.test(desc);

    if (dangerousName || dangerousDesc) {
      issues.push({
        id: 'TOOL_ARBITRARY_EXECUTION_CAPABILITY',
        rule: 'Unconstrained Execution Primitive',
        server: serverName,
        severity: 'CRITICAL',
        target: `tool:${tool.name}`,
        message: `Tool "${tool.name}" exposes arbitrary command/code execution to the LLM agent. An indirect prompt injection can execute unauthorized payloads.`,
        remediation: 'Replace generic execution tools with domain-specific, parameter-validated actions.',
      });
    }

    // 2. Unconstrained SQL / Script string parameters without schema constraints
    for (const [propName, propDef] of Object.entries(props)) {
      const lowerProp = propName.toLowerCase();
      if (
        (lowerProp === 'query' || lowerProp === 'sql' || lowerProp === 'code' || lowerProp === 'command') &&
        propDef.type === 'string' &&
        !propDef.enum &&
        !propDef.pattern
      ) {
        issues.push({
          id: 'TOOL_UNCONSTRAINED_PARAMETER',
          rule: 'Prompt Injection Surface',
          server: serverName,
          severity: 'HIGH',
          target: `tool:${tool.name}.${propName}`,
          message: `Tool parameter "${propName}" allows unconstrained raw string input, enabling SQL/command injection via adversarial agent prompts.`,
          remediation: 'Constrain parameters using regex patterns, enums, or parameterized query templates.',
        });
      }
    }
  }

  return issues;
}
