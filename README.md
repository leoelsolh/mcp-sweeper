# MCP-safety scanner
 A static analysis tool that scans your MCP server configurations for dangerous patterns and security risks you may not know existed.

- - - 

### What it detects
- Hardcoded API tokens in `env` blocks (GitHub, AWS, OpenAI, Slack, GitLab, npm, Google)
- Auto-install flags (`npx -y`/`uvx --yes`)
- Overly broad filesystem access (`/`, `~`, `/home`)

### Why this exists
  MCP servers are relatively new, everyone wants them, and hostile MCP servers are a real thing, one misconfig, and someone has full access to your whole system. 

  Most configs are deployed without review. A misconfigured server can give an LLM admin-level access to a machine, leak credentials, or auto-install untrusted packages. This scanner catches common mistakes before they ship.

  Keep everyone safe and make sure you trust your MCP servers and their makers. 

### Usage 
``` python3 base.py path/to/mcp-config.json ```
Note exit codes: `0` = clean, `1` = findings, `2` = error.

### Example Output: 

```
~$ python3 base.py fixtures/unsafe_mcp.json

[MEDIUM] filesystem (auto-install-flag): npx with auto-install flag

[HIGH] filesystem (broad-fs-path): '/' exposes your entire computer to the MCP, things like your '/etc' with system configs and password databases.
'/var/log' holds all the logs.
'/usr/bin' holds every installed binary.
The LLM is now practically an admin on your system. Is this what you want? 
[HIGH] filesystem (broad-fs-path): '~' exposes things like '.ssh', '.aws', or '.env' to your MCP Server.
Is this what you want?

[CRITICAL] github (hardcoded-secret): 'GITHUB_PERSONAL_TOKEN' contains hardcoded GitHub personal access token
[CRITICAL] github (hardcoded-secret): 'AWS_ACCESS_KEY' contains hardcoded AWS access key ID

```

### Requirements: 

Python 3.9+

### What's planned next? 

- Expanded path coverage
- JSON output for piping into other tools

### License 

MIT