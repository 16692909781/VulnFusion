"""Generate client snippets using this checkout and Python; never edit global Agent settings."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def configurations(root: Path, python: Path) -> tuple[dict, str]:
    command = str(python.resolve())
    args = ["-u", str(root.resolve() / "agent" / "mcp_server.py")]
    json_config = {"mcpServers": {"vulnfusion": {"command": command, "args": args, "env": {"PYTHONUTF8": "1"}}}}
    toml = (
        "# Merge this section into your Codex config.toml.\n"
        "[mcp_servers.vulnfusion]\n"
        f"command = {json.dumps(command)}\n"
        f"args = {json.dumps(args)}\n"
        "startup_timeout_sec = 30\n"
        "tool_timeout_sec = 1200\n\n"
        "[mcp_servers.vulnfusion.env]\n"
        'PYTHONUTF8 = "1"\n'
    )
    return json_config, toml


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=["json", "codex"], default="json")
    parser.add_argument("--write", action="store_true", help="Write generated snippets under agent/configs only")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    json_config, toml = configurations(root, Path(sys.executable))
    json_text = json.dumps(json_config, ensure_ascii=False, indent=2) + "\n"
    if args.write:
        folder = root / "agent" / "configs"
        folder.mkdir(exist_ok=True)
        (folder / "mcp.json").write_text(json_text, encoding="utf-8")
        (folder / "codex.toml").write_text(toml, encoding="utf-8")
        print(f"Generated: {folder / 'mcp.json'}\nGenerated: {folder / 'codex.toml'}")
    else:
        print(toml if args.format == "codex" else json_text, end="")


if __name__ == "__main__":
    main()
