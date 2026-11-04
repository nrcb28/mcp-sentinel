// Keep test discovery explicit and shell-independent. This avoids relying on
// glob expansion (which differs between Windows, Bash, and Node versions) and
// prevents executable MCP fixtures from being mistaken for test files.
import './database-and-web.test.js';
import './engine.test.js';
import './mcp-client.test.js';
import './new-rules.test.js';
import './rules.test.js';
import './scanner.test.js';
