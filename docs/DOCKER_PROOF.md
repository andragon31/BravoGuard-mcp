# Docker Linux proof

Proves the BravoGuard installer + test suite pass on Linux from a Windows box,
using a `python:3.11-slim-bookworm` image. Unlike Windows, Linux installs
`guarddog` normally (no `nono-py` skip).

## Files

| File | Role |
|---|---|
| `docker/Dockerfile.linux-test` | Proof image: `uv sync --frozen` + isolated Python CLIs (`semgrep bandit guarddog pip-audit ruff`) + Go binaries (`osv-scanner`, `betterleaks`/gitleaks fallback, `opengrep` best-effort) + `oxlint` via npm |
| `docker/proof-linux.sh` | Runs **inside** the container: `pytest`, `ruff`, `install.py --check`, `bravoguard doctor`, seeded `scan_diff` (>=1 real finding), `osv_lookup`. Log: `/tmp/proof.log` |
| `docker/run-linux-proof.ps1` | Host runner (Windows): daemon gate -> `docker build` -> `docker run`, host log `docker/proof-linux-host.log` |
| `docker/run-linux-proof.sh` | Same runner for Linux/macOS hosts |

## Run

Windows (PowerShell, repo root):

```powershell
powershell -File docker/run-linux-proof.ps1
```

Linux/macOS (bash, repo root):

```bash
bash docker/run-linux-proof.sh
```

Exit codes: `0` proof passed; `1` build or proof gate failed (see log);
`2` daemon down (blocked, not a pass).

## Daemon troubleshooting

The runners check `docker info` first. If the daemon is down you get exit 2
plus the exact start command — never a fake pass.

Windows:

```powershell
Start-Process "$Env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
docker info   # retry until a Server section appears (Linux engine)
powershell -File docker/run-linux-proof.ps1
```

Linux hosts: `sudo systemctl start docker`, then `docker info`, then the runner.
macOS: launch Docker Desktop, wait for the whale icon to stop animating.

Common causes: Docker Desktop not started, switched to Windows containers
(Switch to Linux containers...), or a stale `npipe:////./pipe/dockerDesktopLinuxEngine`
after hibernate (quit + relaunch Docker Desktop).

## Notes

- Tool versions follow `tools-manifest.json` (`oxlint 1.65.0`, `opengrep v1.26.0`,
  `osv-scanner V2`); `opengrep`/`oxlint` installs are best-effort with an
  explicit `NOTE` in build output so a flaky registry never fails the proof silently.
- `*.log` is gitignored; proof logs stay local.
