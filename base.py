import sys
import json

try: 
    path = sys.argv[1] 
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

count = 0

for name, config in data["mcpServers"].items():

    command = config["command"]
    args = config["args"]

    if command in ("npx", "uvx") and ("-y" in args or "--yes" in args): 
        count += 1
        print(f"[FOUND] {name}: {command} with auto-install flag")

    # Check wether the server is a filesystem MCP
    is_fs_server = False

    for arg in args: 
        if "server-filesystem" in arg:
            is_fs_server = True
    
    # If it is, then we check for overly broad path
    if is_fs_server:
        broad_paths = {
            "/": "your entire computer to the MCP, things like your '/etc' with system configs and password databases.\n'/var/log' holds all the logs.\n'/usr/bin' holds every installed binary.\nThe LLM is now practically an admin on your system. Is this what you want? ",
            "~": "things like '.ssh', '.aws', or '.env' to your MCP Server.\nIs this what you want?",
            "/home": "every user on the machine. Most concerning on shared systems. if you are on a single-user machine, this is effectively a superset of '~'. ",
        }
        for arg in args: 
            if arg in broad_paths:
                count += 1
                print(f"[FOUND] {name}: '{arg}' is broad... this can expose {broad_paths[arg]}") 

if count == 0:
    print("No Issues Were Found, Stay Safe. ")

sys.exit(1 if count > 0 else 0)
