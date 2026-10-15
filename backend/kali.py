"""Remote Kali execution boundary.

Only allowlisted security tools can be dispatched. Commands are executed by the
remote Kali SSH process; the Windows controller never runs the scanner locally.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


class KaliConfigurationError(RuntimeError):
    pass


@dataclass
class KaliConfig:
    host: str = ""
    user: str = "kali"
    port: int = 22
    key_path: str = ""
    remote_root: str = "/opt/vulnfusion/workspaces"
    connect_timeout: int = 15
    httpx_binary: str = "httpx-toolkit"

    @classmethod
    def from_env(cls) -> "KaliConfig":
        def integer(name: str, default: int) -> int:
            try:
                return int(os.getenv(name, str(default)))
            except ValueError as exc:
                raise KaliConfigurationError(f"{name} must be an integer") from exc

        return cls(
            host=os.getenv("VULNFUSION_KALI_HOST", ""),
            user=os.getenv("VULNFUSION_KALI_USER", "kali"),
            port=integer("VULNFUSION_KALI_PORT", 22),
            key_path=os.getenv("VULNFUSION_KALI_KEY", ""),
            remote_root=os.getenv("VULNFUSION_KALI_REMOTE_ROOT", "/opt/vulnfusion/workspaces"),
            connect_timeout=integer("VULNFUSION_KALI_TIMEOUT", 15),
            httpx_binary=os.getenv("VULNFUSION_KALI_HTTPX", "httpx-toolkit"),
        )


@dataclass
class RemoteResult:
    ok: bool
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    error: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class KaliExecutor:
    # SSH noninteractive sessions do not normally include pipx/Go user tools.
    REMOTE_PATH = 'PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"'
    ALLOWED_TOOLS: dict[str, str] = {
        "nmap": "nmap",
        "httpx": "httpx",
        "whatweb": "whatweb",
        "ffuf": "ffuf",
        "subfinder": "subfinder",
        "nikto": "nikto",
        "nuclei": "nuclei",
        "semgrep": "semgrep",
        "gitleaks": "gitleaks",
        "sqlmap": "sqlmap",
    }

    def __init__(self, config: KaliConfig | None = None) -> None:
        self.config = config or KaliConfig.from_env()
        if not re.fullmatch(r"/[A-Za-z0-9._/-]+", self.config.remote_root):
            raise KaliConfigurationError("VULNFUSION_KALI_REMOTE_ROOT must be a simple absolute Unix path")
        if not 1 <= self.config.port <= 65535:
            raise KaliConfigurationError("VULNFUSION_KALI_PORT must be between 1 and 65535")
        if self.config.connect_timeout < 1:
            raise KaliConfigurationError("VULNFUSION_KALI_TIMEOUT must be positive")
        if self.config.httpx_binary not in {"httpx-toolkit", "httpx"}:
            raise KaliConfigurationError("VULNFUSION_KALI_HTTPX must be httpx-toolkit or httpx")

    def _executables(self) -> dict[str, str]:
        return {**self.ALLOWED_TOOLS, "httpx": self.config.httpx_binary}

    @property
    def configured(self) -> bool:
        return bool(self.config.host)

    def status(self) -> dict:
        return {
            "configured": self.configured,
            "host": self.config.host,
            "user": self.config.user,
            "port": self.config.port,
            "remote_root": self.config.remote_root,
            "key_configured": bool(self.config.key_path),
            "ssh_available": bool(shutil.which("ssh")),
            "scp_available": bool(shutil.which("scp")),
            "httpx_binary": self.config.httpx_binary,
            "connection_checked": False,
            "policy": "remote-only; allowlisted tools; approval required",
        }

    def probe(self) -> dict:
        """Authenticate and inspect the configured VM, without scanning a target."""
        result = {
            **self.status(), "connection_checked": True, "connected": False,
            "ready": False, "tools": {}, "missing_tools": [], "error": "",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        # The script and tool list are controller-owned; no project/LLM commands
        # are accepted by this diagnostics endpoint.
        script = """import json, os, platform, shutil, subprocess, sys
root = sys.argv[1]
tools = {name: shutil.which(binary) for name, binary in json.loads(sys.argv[2]).items()}
httpx_valid = False
if tools.get('httpx'):
    try:
        version = subprocess.run([tools['httpx'], '-version'], capture_output=True,
                                 text=True, timeout=5, check=False)
        httpx_valid = version.returncode == 0 and 'projectdiscovery' in (version.stdout + version.stderr).lower()
    except (OSError, subprocess.TimeoutExpired):
        pass
print(json.dumps({
    'system': platform.system(), 'hostname': platform.node(), 'tools': tools,
    'workspace_writable': os.path.isdir(root) and os.access(root, os.W_OK | os.X_OK),
    'wordlist_available': os.path.isfile('/usr/share/seclists/Discovery/Web-Content/common.txt') and os.access('/usr/share/seclists/Discovery/Web-Content/common.txt', os.R_OK),
    'httpx_valid': httpx_valid,
}))
"""
        command = f"{self.REMOTE_PATH} " + shlex.join([
            "python3", "-c", script, self.config.remote_root,
            json.dumps(self._executables()),
        ])
        try:
            completed = subprocess.run(
                [*self._base_ssh(), command], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=self.config.connect_timeout + 15, check=False,
            )
            if completed.returncode:
                result["error"] = completed.stderr[-2000:] or "Kali diagnostics failed"
                return result
            remote = json.loads(completed.stdout)
            tools = remote["tools"]
            if not isinstance(tools, dict) or set(tools) != set(self.ALLOWED_TOOLS):
                raise ValueError("invalid tool inventory from Kali")
            result.update(remote)
            result["connected"] = True
            result["missing_tools"] = [name for name, path in tools.items() if not path]
            result["ready"] = (
                remote["system"] == "Linux" and remote["workspace_writable"]
                and remote["wordlist_available"] and remote["httpx_valid"]
                and not result["missing_tools"]
            )
        except (KaliConfigurationError, OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as exc:
            result["connected"] = False
            result["ready"] = False
            result["error"] = str(exc)
        return result

    def _base_ssh(self) -> list[str]:
        if not self.configured:
            raise KaliConfigurationError("VULNFUSION_KALI_HOST is not configured")
        if not shutil.which("ssh"):
            raise KaliConfigurationError("ssh executable is not available on the controller")
        # MCP owns stdin for JSON-RPC. Child SSH must never read that stream.
        args = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"ConnectTimeout={self.config.connect_timeout}", "-p", str(self.config.port)]
        if self.config.key_path:
            args.extend(["-o", "IdentitiesOnly=yes", "-i", self.config.key_path])
        args.append(f"{self.config.user}@{self.config.host}")
        return args

    def plan(self, tool: str, args: list[str]) -> str:
        executable = self._executables().get(tool)
        if not executable:
            raise ValueError(f"tool is not allowlisted: {tool}")
        return " ".join([self.REMOTE_PATH, executable, *(shlex.quote(str(x)) for x in args)])

    def execute(self, tool: str, args: list[str], *, approved: bool = False) -> RemoteResult:
        command = self.plan(tool, args)
        if not approved:
            return RemoteResult(False, command, error="approval required")
        try:
            completed = subprocess.run(
                [*self._base_ssh(), command],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.config.connect_timeout + 900,
                check=False,
            )
            return RemoteResult(
                ok=completed.returncode == 0,
                command=command,
                stdout=completed.stdout[-100_000:],
                stderr=completed.stderr[-20_000:],
                exit_code=completed.returncode,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return RemoteResult(False, command, error=str(exc))

    def upload_project(self, local_root: str, project_id: str, *, approved: bool = False) -> str:
        """Upload source to Kali; scanning still happens only on Kali."""
        if not approved:
            raise KaliConfigurationError("approval required for source upload")
        if not self.configured or not shutil.which("scp"):
            raise KaliConfigurationError("Kali or scp is not configured")
        if not local_root.strip():
            raise KaliConfigurationError("an explicit source directory is required for upload")
        source = Path(local_root).resolve()
        if not source.is_dir():
            raise KaliConfigurationError(f"source directory does not exist: {source}")
        if not re.fullmatch(r"proj_[a-f0-9]{12}(?:/task_[a-f0-9]{12})?", project_id):
            raise KaliConfigurationError("invalid project upload identifier")
        remote = f"{self.config.remote_root.rstrip('/')}/{project_id}"
        setup = subprocess.run(
            [*self._base_ssh(), "mkdir", "-p", remote],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=self.config.connect_timeout + 30,
            check=False,
        )
        if setup.returncode:
            raise KaliConfigurationError(setup.stderr[-1000:] or "could not create remote workspace")
        target = f"{self.config.user}@{self.config.host}:{remote}"
        args = ["scp", "-r", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"ConnectTimeout={self.config.connect_timeout}", "-P", str(self.config.port)]
        if self.config.key_path:
            args.extend(["-o", "IdentitiesOnly=yes", "-i", self.config.key_path])
        args.extend([str(source), target])
        completed = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=900, check=False)
        if completed.returncode:
            raise KaliConfigurationError(completed.stderr[-1000:] or "scp upload failed")
        return remote
