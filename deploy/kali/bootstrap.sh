#!/usr/bin/env bash
set -euo pipefail

# Run as the normal Kali user: bash ~/vulnfusion/bootstrap.sh
# sudo is requested only for missing distro packages. No scanners are run.
if [[ $EUID -eq 0 ]]; then
  echo 'Run this script as your normal Kali user, without sudo.' >&2
  exit 1
fi

packages=(nmap httpx-toolkit whatweb ffuf subfinder nikto nuclei sqlmap seclists gitleaks pipx python3-venv)
missing=()
for package in "${packages[@]}"; do
  if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" != 'install ok installed' ]]; then
    missing+=("$package")
  fi
done
if ((${#missing[@]})); then
  printf 'Installing missing Kali packages: %s\n' "${missing[*]}"
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends --no-upgrade "${missing[@]}"
fi

# pipx avoids modifying Kali's externally managed system Python.
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
if ! command -v semgrep >/dev/null 2>&1; then
  pipx install semgrep
fi

workspace="${VULNFUSION_KALI_REMOTE_ROOT:-$HOME/vulnfusion/workspaces}"
mkdir -p -- "$workspace"
test -w "$workspace"

failed=0
for tool in nmap httpx-toolkit whatweb ffuf subfinder nikto nuclei semgrep gitleaks sqlmap; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '  [ok] %s\n' "$tool"
  else
    printf '  [missing] %s\n' "$tool"
    failed=1
  fi
done

if [[ ! -r /usr/share/seclists/Discovery/Web-Content/common.txt ]]; then
  echo '  [missing] SecLists common.txt'
  failed=1
fi
if ((failed)); then
  echo 'Setup incomplete. Fix the errors above and rerun this script.' >&2
  exit 1
fi
echo "Setup complete. Workspace: $workspace"
echo 'Return to VulnFusion and click the Kali connection check button.'
