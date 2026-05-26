SEVERITY_COLORS = {
    "low":      "\033[38;2;255;215;0m",         # Yellow
    "medium":   "\033[38;2;255;140;0m",         # Orange
    "high":     "\033[38;2;220;30;30m",         # Red 
    "critical": "\033[38;2;139;0;0m",           # Darker Red
}

COLOR_RESET = "\033[0m"

SEVERITY_ORDER = {
    "low": 0, 
    "medium": 1, 
    "high": 2,
    "critical": 3,
}

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

BROAD_PATHS = {
    "/": "your entire computer to the MCP, things like your '/etc' with system configs and password databases.\n'/var/log' holds all the logs.\n'/usr/bin' holds every installed binary.\nThe LLM is now practically an admin on your system. Is this what you want? ",
    "~": "things like '.ssh', '.aws', or '.env' to your MCP Server.\nIs this what you want?",
    "~/": "things like '.ssh', '.aws', or '.env' to your MCP Server.\nIs this what you want?",
    "/home": "every user on the machine. Most concerning on shared systems. if you are on a single-user machine, this is effectively a superset of '~'. ",
    "/Users": "every user on the machine. Most concerning on shared systems. if you are on a single-user machine, this is effectively a superset of '~'. ",   # Essentially /home but on MacOS
    "/etc": "system wide configs like '/etc/passwd'. '/etc/shadow', '/etc/cron.d' etc. These contain things like password hashes, scheduled jobs, every user on your system and so much more. You're essentially planting an intelligent backdoor on your system.",
    "/root": "key files like '.ssh/', your root SSH keys. If your LLM can read /root it can become root... Don't forget .bash_history, and if you use AWS CLI, that too my friend is full cloud credentials...",
}