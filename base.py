import sys
import json

path = sys.argv[1] 

with open(path) as f:
    data = json.load(f)

count = 0

for name, config in data["mcpServers"].items():

    command = config["command"]
    args = config["args"]

    if command in ("npx", "uvx") and ("-y" in args or "--yes" in args): 
        count += 1
        print(f"[FOUND] {name}: {command} with auto-install flag")
        
if count == 0:
    print("No Issues Were Found")

sys.exit(1 if count > 0 else 0)
