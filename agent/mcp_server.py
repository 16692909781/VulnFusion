"""Launch the standard MCP stdio server from any working directory."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    from dotenv import load_dotenv

    load_dotenv(root / ".env", override=False)
    data = Path(os.environ.get("VULNFUSION_DATA", "data/agent-store.json"))
    os.environ["VULNFUSION_DATA"] = str(data if data.is_absolute() else root / data)
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    from agent.service import mcp

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
