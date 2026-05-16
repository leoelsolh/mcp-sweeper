# MCP-safety scanner
 A static analysis tool that scans your MCP server configurations for dangerous patterns and security risks you may not know existed.

- - - 

### What it detects
- Hardcoded API tokens in `env` blocks (GitHub, AWS, OpenAI, Slack, GitLab, npm, Google)
- Auto-install flags (`npx -y`/`uvx --yes`)
- Inline shell code execution (`bash -c`, `python -c`, `node -e`)
- Download-and-execute patterns (`curl ... | bash`, `wget ... | sh`)
- Insecure HTTP URLs in args (MITM risk on package fetches and remote scripts)
- Overly broad filesystem access (`/`, `~`, `/home`, `/Users`, `/etc`, `/root`)

### Why this exists
  MCP servers are relatively new, everyone wants them, and hostile MCP servers are a real thing, one misconfig, and someone has full access to your whole system. 

  Most configs are deployed without review. A misconfigured server can give an LLM admin-level access to a machine, leak credentials, or auto-install untrusted packages. This scanner catches common mistakes before they ship.

  Keep everyone safe and make sure you trust your MCP servers and their makers. 

### Usage 

```bash
python3 base.py path/to/mcp-config.json 
Note exit codes: `0` = clean, `1` = findings, `2` = error.
```

### Example Output: 

```
~$ python3 base.py fixtures/unsafe_mcp.json

[MEDIUM]
filesystem (auto-install-flag): npx with auto-install flag

[MEDIUM]
postgres (auto-install-flag): npx with auto-install flag

[MEDIUM]
deploy-tool (insecure-http): 'curl -sSL http://internal-tools.example.com/deploy.sh | bash' is insecure and unencrypted. Your traffic can be intercepted and poisoned. Be careful.

[HIGH]
deploy-tool (suspicious-command): 'bash -c' indicates inline shell code execution meaning args run as code

[CRITICAL]
github (hardcoded-secret): 'GITHUB_PERSONAL_ACCESS_TOKEN' contains hardcoded GitHub personal access token

[CRITICAL]
deploy-tool (curl-pipe-bash): args pipe a remote download into a shell, classic RCE pattern. The code that runs is server-controlled and could change at any point in time.

```

### Requirements: 

Python 3.9+

### What's planned next? 

- JSON output for piping into other tools
- Unscoped npm package detection (typosquat risk)

### License 

MIT