import os
import sys
import json
from dataclasses import dataclass

# --- Color codes for severity tags --- #

SEVERITY_COLORS = {
    "low":      "\033[38;2;255;215;0m",         # Yellow
    "medium":   "\033[38;2;255;140;0m",         # Orange
    "high":     "\033[38;2;220;30;30m",         # Red 
    "critical": "\033[38;2;139;0;0m",           # Darker Red
}

COLOR_RESET = "\033[0m"


# ===  MCP SCANNER  === #


@dataclass
class Finding: 
    server_name: str 
    severity: str 
    category: str 
    message: str

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
        "/home": "every user on the machine. Most concerning on shared systems. if you are on a single-user machine, this is effectively a superset of '~'. ",
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

CHECKS = [
    check_install_flags, 
    check_filesystem_paths,
]

all_findings = []

for name, config in data["mcpServers"].items():
    for check in CHECKS: 
        all_findings.extend(check(name, config))

report(all_findings)
sys.exit(1 if all_findings else 0)