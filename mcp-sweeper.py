#!/usr/bin/env python3
import os
import sys
import json
import argparse
from dataclasses import dataclass

from constants import BROAD_PATHS, SEVERITY_ORDER, SEVERITY_COLORS, TOKEN_PREFIXES, COLOR_RESET

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
        if not isinstance(value, str):
            continue
        if value.startswith(("$", "{")):   # env var refrence, so not a real token
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
    command = config.get("command", "")
    args = config.get("args", [])

    # Check for unsafe flags:
    if command in ("npx", "uvx") and ("-y" in args or "--yes" in args):
        findings.append(Finding(
            server_name=name,
            severity="medium",
            category="auto-install-flag",
            message=f"{command} with auto-install flag"
        ))

    return findings


def check_suspicious_commands(name: str, config: dict) -> list[Finding]:

    findings = []
    command = config.get("command", "")
    args = config.get("args", [])

    if command in ("bash", "sh") and "-c" in args:
        findings.append(Finding(
            server_name=name,
            severity="high",
            category="suspicious-command",
            message=f"'{command} -c' indicates inline shell code execution meaning args run as code"
        ))

    elif command in ("python", "python3") and "-c" in args:
        findings.append(Finding(
            server_name=name,
            severity="high", 
            category="suspicious-command",
            message=f"'{command} -c' indicates inline python code execution, meaning args run as code"
        ))

    elif command == "node" and "-e" in args:
        findings.append(Finding(
            server_name=name,
            severity="high", 
            category="suspicious-command",
            message=f"'{command} -e' indicates inline node.js code execution, meaning args run as code"
        ))
        
    return findings


def check_curl_pipe_bash(name: str, config: dict) -> list[Finding]:

    findings = []
    args = config.get("args", [])

    for arg in args:
        has_downloader = "curl" in arg or "wget" in arg
        pipes_to_shell = "| bash" in arg or "| sh" in arg

        if has_downloader and pipes_to_shell:
            findings.append(Finding(
                server_name=name,
                severity="critical", 
                category="curl-pipe-bash",
                message=f"args pipe a remote download into a shell, classic RCE pattern. The code that runs is server-controlled and could change at any point in time."
            ))
            break

    return findings


def check_insecure_http(name: str, config: dict) -> list[Finding]:

    findings = []
    args = config.get("args", [])

    for arg in args:
        if "http://" in arg:
            findings.append(Finding(
                server_name=name,
                severity="medium",
                category="insecure-http",
                message=f"'{arg}' is insecure and unencrypted. Your traffic can be intercepted and poisoned. Be careful."
            ))

    return findings


def check_filesystem_paths(name: str, config: dict) -> list[Finding]:

    findings = []
    args = config.get("args", [])

    # Check wether the server is a filesystem MCP
    is_fs_server = False

    for arg in args:
        if "server-filesystem" in arg: 
            is_fs_server = True 

    if not is_fs_server:
        return findings 

    for arg in args:

        if arg in BROAD_PATHS: 
            findings.append(Finding(
                server_name=name, 
                severity="high",
                category="broad-fs-path",
                message=f"'{arg}' exposes {BROAD_PATHS[arg]}"
            ))

    return findings


def report(findings: list[Finding]) -> None:

    if not findings: 
        print("No Issues Were Found, Stay Safe.")
        return

    else:
        for f in findings:
            color = SEVERITY_COLORS.get(f.severity, "")
            print(f"{color}[{f.severity.upper()}]{COLOR_RESET}\n{f.server_name} ({f.category}): {f.message}\n")

CHECKS = [
    check_install_flags, 
    check_hardcoded_secrets,
    check_suspicious_commands,
    check_curl_pipe_bash,
    check_insecure_http,
    check_filesystem_paths,
]

def main():
    parser = argparse.ArgumentParser(
        description="Sweep an MCP config for common security issues."
    )
    parser.add_argument(
        "config",
        help="Path to the MCP config file (ex. ~/.cursor/mcp.json)"
    )
    parser.add_argument(
        "--severity", "-s", 
        choices=["low", "medium", "high", "critical"],
        help="Minimum severity to report (default: show all)"
    )
    args = parser.parse_args()
    path = os.path.expanduser(args.config)

    try:
        with open(path) as f:
            data = json.load(f)

    except FileNotFoundError as e:
        print(f"Filename was not found: \n{e}")
        sys.exit(2)

    except json.JSONDecodeError as e:
        print(f"Invalid JSON... {e}")
        sys.exit(2)

    try: 
        servers = data["mcpServers"]
    except KeyError: 
        print("No 'mcpServers' key found. Make sure this is an MCP config file")
        sys.exit(2)

    all_findings = []

    for name, config in servers.items():
        for check in CHECKS: 
            all_findings.extend(check(name, config))

    if args.severity: 
        threshold = SEVERITY_ORDER[args.severity]
        all_findings = [f for f in all_findings
                        if SEVERITY_ORDER[f.severity] >= threshold] 

    report(all_findings)
    sys.exit(1 if all_findings else 0)

if __name__ == "__main__":
    main()