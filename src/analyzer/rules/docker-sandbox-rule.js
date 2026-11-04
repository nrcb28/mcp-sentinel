/**
 * Audits container execution (docker, podman) for sandbox breakouts and privilege escalations.
 */
export function analyzeDockerSandboxRisk(serverName, serverConfig) {
  const issues = [];
  const command = (typeof serverConfig.command === 'string' ? serverConfig.command : '').trim().toLowerCase();
  const args = (Array.isArray(serverConfig.args) ? serverConfig.args : [])
    .map((a) => (typeof a === 'string' ? a.trim() : ''));

  const isContainerTool = command === 'docker' || command.endsWith('/docker') || command.endsWith('\\docker') ||
                          command === 'podman' || command.endsWith('/podman') || command.endsWith('\\podman');

  if (!isContainerTool) return issues;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i].toLowerCase();

    // Docker socket escape
    if (arg.includes('/var/run/docker.sock') || arg.includes('docker.sock')) {
      issues.push({
        id: 'DOCKER_SOCKET_EXPOSURE',
        rule: 'Container Breakout Prevention',
        server: serverName,
        severity: 'CRITICAL',
        target: arg,
        message: 'Mounting the Docker daemon socket inside the container allows complete host system takeover.',
        remediation: 'Do not mount docker.sock into MCP containers. Use rootless mode or isolated APIs.',
      });
    }

    // Privileged flag
    if (arg === '--privileged') {
      issues.push({
        id: 'DOCKER_PRIVILEGED_MODE',
        rule: 'Privileged Container Escalation',
        server: serverName,
        severity: 'CRITICAL',
        target: '--privileged',
        message: 'Container is launched in privileged mode, disabling all kernel security boundaries.',
        remediation: 'Drop privileged mode and grant only the minimal specific Linux capabilities required.',
      });
    }

    // Host networking
    if (arg === '--net=host' || arg === '--network=host' || (arg === '--network' && args[i + 1]?.toLowerCase() === 'host')) {
      issues.push({
        id: 'DOCKER_HOST_NETWORK',
        rule: 'Network Boundary Isolation',
        server: serverName,
        severity: 'HIGH',
        target: '--network host',
        message: 'Container shares the host network namespace, exposing internal loopback services and interfaces.',
        remediation: 'Use a bridge or isolated user-defined Docker network.',
      });
    }

    // Broad volume mounts
    if (arg === '-v' || arg === '--volume') {
      const mount = (args[i + 1] || '').toLowerCase();
      if (mount.startsWith('/:') || mount.startsWith('c:\\:') || mount.startsWith('c:/:')) {
        issues.push({
          id: 'DOCKER_ROOT_MOUNT',
          rule: 'Root Filesystem Mount',
          server: serverName,
          severity: 'CRITICAL',
          target: mount,
          message: 'The entire host root filesystem is mounted into the container.',
          remediation: 'Mount only dedicated, scoped subdirectories.',
        });
      }
    }
  }

  return issues;
}
