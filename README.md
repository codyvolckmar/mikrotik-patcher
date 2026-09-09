# MikroTik CPE Patch Cycle

**See `README_SHARED.md` for complete setup and usage instructions.**

---

## Quick Links

- **Setup Guide**: See `README_SHARED.md`
- **Interactive Patch Cycle**: `python3 patch_cycle.py`
- **Single Device Test**: `python3 test_patch.py`
- **Winbox-Only Scanner**: `python3 winbox_only.py`

## Core Library

This package provides `cpe_patcher.py`, a lightweight library for scanning and managing MikroTik RouterOS devices:

- **scan** — Discover devices on a network (port scanning, SSH banners)
- **plan** — Read device versions, compute baseline gaps
- **patch** — Apply updates via RouterOS API
- **report** — Status table or JSON output
- **inventory** — Export for Ansible

The library requires explicit credentials — no hardcoded defaults.

## For Users

Use **`patch_cycle.py`** for interactive patching with step-by-step approvals:

```bash
bash setup.sh          # One-time setup
python3 patch_cycle.py # Start patching
```

The wizard prompts for:
- Network range to scan
- Account type (Admin or Read-only)
- Username and password

## For Developers

The `cpe_patcher.py` library is generic and reusable:

```python
from cpe_patcher import APITransport

conn = APITransport("192.168.1.1", 8728, "admin", "password", use_ssl=False)
conn.connect()
conn.run("/system/package/update check-for-updates", timeout=120)
conn.close()
```

See `cpe_patcher.py` docstring for command syntax.

## Target Versions

- **RouterOS 7.24.2** — Stable branch (fixes CVE-2026-67276, CVE-2026-86060)
- **RouterOS 7.23.4** — Long-term branch (fixes CVE-2026-67276, CVE-2026-86060)
- **RouterOS 6.49.21** — EOL v6 (no security fixes available)

## Files

```
patch_cycle.py       Interactive wizard (start here)
test_patch.py        Single-device test
winbox_only.py       Scanner for Winbox-only devices
cpe_patcher.py       Core library
requirements.txt     Python dependencies
config.example.yaml  Configuration template (optional)
README_SHARED.md     Complete documentation
setup.sh             Setup script
.gitignore           Git ignore rules
```

## No Hardcoded Credentials

- Username must be provided via `--user` flag or interactively
- Password is read from `MIKROTIK_PASSWORD` env var or prompt
- **Credentials are never stored** in config or memory after exit
