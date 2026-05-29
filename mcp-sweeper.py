#!/usr/bin/env python3
import os
import sys
import json
import argparse
from collections import Counter
from dataclasses import dataclass


import constants 

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

        for prefix, (token_type, min_length) in constants.TOKEN_PREFIXES.items():

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

        if arg in constants.BROAD_PATHS: 
            findings.append(Finding(
                server_name=name, 
                severity="high",
                category="broad-fs-path",
                message=f"'{arg}' exposes {constants.BROAD_PATHS[arg]}"
            ))

    return findings


def check_env_injection(name: str, config: dict) -> list[Finding]:
    
    findings = []
    env = config.get("env", {})

    for var_name in env: 
        if var_name in constants.INJECTION_ENVS:
            findings.append(Finding(
                server_name=name, 
                severity="high",
                category="env-injection",
                message=f"'{var_name}' {constants.INJECTION_ENVS[var_name]}"
            ))
    
    return findings


def check_tls_bypass(name: str, config: dict) -> list[Finding]:
    
    findings = []
    args = config.get("args", [])

    for arg in args:
        if not isinstance(arg, str): 
            continue
        for token in arg.split(): 
            if token in constants.TLS_BYPASS_FLAGS:
                findings.append(Finding(
                    server_name=name, 
                    severity="high",
                    category="tls-bypass",
                    message=f"'{token}' disables TLS certificate verification. Traffic is encrypted but the server's identity is never checked, so a man-in-the-middle can impersonate it."
                ))
                break

    return findings


def check_suspicious_sources(name: str, config: dict) -> list[Finding]:

    findings = []
    args = config.get("args", [])

    for arg in args: 
        if not isinstance(arg, str):
            continue
        for domain, reason in constants.SUSPICIOUS_SOURCES.items():
            if domain in arg: 
                findings.append(Finding(
                    server_name=name, 
                    severity="medium",
                    category="suspicious-source",
                    message=f"args reference '{domain}': {reason}"
                ))
                break

    return findings


def report(findings: list[Finding]) -> None:

    findings = sorted(findings, key=lambda f: constants.SEVERITY_ORDER[f.severity], reverse=True)

    if not findings: 
        print("No Issues Were Found, Stay Safe.")
        return

    for f in findings:
        color = constants.SEVERITY_COLORS.get(f.severity, "")
        print(f"{color}[{f.severity.upper()}]{constants.COLOR_RESET}\n{f.server_name} ({f.category}): {f.message}\n")
            
    counts = Counter(f.severity for f in findings)
    parts = []

    for severity in sorted(counts, key=lambda s: constants.SEVERITY_ORDER[s], reverse=True):
        parts.append(f"{counts[severity]} {severity}")

    print(f"Found {', '.join(parts)}.")

            

CHECKS = [
    check_install_flags, 
    check_hardcoded_secrets,
    check_suspicious_commands,
    check_curl_pipe_bash,
    check_insecure_http,
    check_filesystem_paths,
    check_env_injection,
    check_tls_bypass,
    check_suspicious_sources,
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
        threshold = constants.SEVERITY_ORDER[args.severity]
        all_findings = [f for f in all_findings
                        if constants.SEVERITY_ORDER[f.severity] >= threshold] 

    report(all_findings)
    sys.exit(1 if all_findings else 0)

if __name__ == "__main__":
    main()