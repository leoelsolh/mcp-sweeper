import os
import sys
import json
from dataclasses import dataclass


# ===  MCP SCANNER  === #


@dataclass
class Finding: 
    server_name: str 
    severity: str 
    category: str 
    message: str

def check_hardcoded_secrets(name: str, config: dict) -> list[Finding]:

    findings = []
    env = config.get("env", {})

    for var_name, value in env.items():
        if value.startswith("$"):   # env var refrense, so not a real token
            continue   

        for prefix, (token_type, min_length) in TOKEN_PREFIXES.items():

            if value.startswith(prefix) and len(value) >= min_length:
                findings.append(Finding(
                    server_name=name,
                    severity="critical",
                    category="hardcoded-secret",
                    message=f"'{var_name}' contains hardcoded {token_type}"
                ))

                break
        
    return findings 

def check_install_flags(name: str, config: dict) -> list[Finding]: 

    findings = []
    command = config["command"]
    args = config["args"]

    # Check for unsafe flags:
    if command in ("npx", "uvx") and ("-y" in args or "--yes" in args):
        findings.append(Finding(
            server_name=name,
            severity="medium",
            category="auto-install-flag",
            message=f"{command} with auto-install flag"
        ))

    return findings

def check_filesystem_paths(name: str, config: dict) -> list[Finding]:

    findings = []
    args = config["args"]

    # Check wether the server is a filesystem MCP
    is_fs_server = False

    for arg in args:
        if "server-filesystem" in arg: 
            is_fs_server = True 

    if not is_fs_server:
        return findings 

    broad_paths = {
        "/": "your entire computer to the MCP, things like your '/etc' with system configs and password databases.\n'/var/log' holds all the logs.\n'/usr/bin' holds every installed binary.\nThe LLM is now practically an admin on your system. Is this what you want? ",
        "~": "things like '.ssh', '.aws', or '.env' to your MCP Server.\nIs this what you want?",
        "~/": "things like '.ssh', '.aws', or '.env' to your MCP Server.\nIs this what you want?",
        "/home": "every user on the machine. Most concerning on shared systems. if you are on a single-user machine, this is effectively a superset of '~'. ",
        "/Users": "every user on the machine. Most concerning on shared systems. if you are on a single-user machine, this is effectively a superset of '~'. ",   # Essentially /home but on MacOS
        "/etc": "system wide configs like '/etc/passwd'. '/etc/shadow', '/etc/cron.d' etc. These contain things like password hashes, scheduled jobs, every user on your system and so much more. You're essentially planting an intelligent backdoor on your system.",
        "/root": "key files like '.ssh/', your root SSH keys. If your LLM can read /root it can become root... Don't forget .bash_history, and if you use AWS CLI, that too my friend is full cloud credentials...",
    }

    for arg in args:

        if arg in broad_paths: 
            findings.append(Finding(
                server_name=name, 
                severity="high",
                category="broad-fs-path",
                message=f"'{arg}' exposes {broad_paths[arg]}"
            ))

    return findings

def report(findings: list[Finding]) -> None:

    if not findings: 
        print("No Issues Were Found, Stay Safe.")
        return
    else:
        for f in findings:
            color = SEVERITY_COLORS.get(f.severity, "")
            print(f"{color}[{f.severity.upper()}]{COLOR_RESET} {f.server_name} ({f.category}): {f.message}")

try: 
    path = os.path.expanduser(sys.argv[1])

except IndexError: 
    print("Argument missing..." )
    sys.exit(2)

try:
    with open(path) as f:
        data = json.load(f)

except FileNotFoundError as e:
    print(f"Filename was not found: \n{e}")
    sys.exit(2)

except json.JSONDecodeError as e:
    print(f"Invalid JSON... {e}")
    sys.exit(2)

SEVERITY_COLORS = {
    "low":      "\033[38;2;255;215;0m",         # Yellow
    "medium":   "\033[38;2;255;140;0m",         # Orange
    "high":     "\033[38;2;220;30;30m",         # Red 
    "critical": "\033[38;2;139;0;0m",           # Darker Red
}

COLOR_RESET = "\033[0m"

TOKEN_PREFIXES = {
    "sk-":      ("OpenAI / Anthropic API key",   30),
    "ghp_":     ("GitHub personal access token", 40),
    "gho_":     ("GitHub OAuth token",           40),
    "ghu_":     ("GitHub user-to-server token",  40),
    "ghs_":     ("GitHub server-to-server token",40),
    "AKIA":     ("AWS access key ID",            20),
    "ASIA":     ("AWS temporary access key",     20),
    "xoxb-":    ("Slack bot token",              40),
    "xoxp-":    ("Slack user token",             40),
    "npm_":     ("npm token",                    40),
    "glpat-":   ("GitLab personal access token", 26),
    "AIza":     ("Google API key",               39),
}

CHECKS = [
    check_install_flags, 
    check_filesystem_paths,
    check_hardcoded_secrets,
]

all_findings = []

for name, config in data["mcpServers"].items():
    for check in CHECKS: 
        all_findings.extend(check(name, config))

report(all_findings)
sys.exit(1 if all_findings else 0)