# MikroTik CPE Patch Cycle

**Interactive tool to scan, plan, and patch a fleet of MikroTik RouterOS devices.**

Supports CVE-2026-67276 and CVE-2026-86060 fixes:
- RouterOS 7.24.2 (Stable) 
- RouterOS 7.23.4 (Long-term)
- RouterOS 6.49.21 (EOL)

## Quick Start

### 1. Clone & Setup

```bash
git clone <repo-url> mikro-cpe-patch
cd mikro-cpe-patch
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 2. Run Patch Cycle

```bash
python3 patch_cycle.py
```

**You will be prompted for:**
- Network range to scan (e.g., `192.168.1.0/24`)
- Account type: Admin (to patch) or Read-only (audit only)
- Username
- Password

**Credentials are never stored** — only used during the session.

### 3. Workflow

1. **Scan** — Discovers all RouterOS devices on the network
2. **Plan** — Logs in, reads OS versions, identifies devices needing patches
3. **Approve** — Review each device one-by-one:
   - `1` = approve & patch this device
   - `0` = skip this device
   - `a` = approve all remaining devices
   - `q` = quit
4. **Patch** — Devices update and reboot in parallel
5. **Report** — Shows final status

## Modes

### Admin Mode (Patch Devices)
Requires RouterOS admin account with API access (port 8728 or 8729).

Devices will be patched via RouterOS API:
```
Set update channel → Set version (v7) → Check for updates → Install & reboot
```

### Read-Only Mode (Audit Only)
Requires read-only RouterOS account.

Shows which devices need patching without making any changes.

## Requirements

- Python 3.7+
- Network access to RouterOS devices (SSH port 22 or API ports 8728/8729)
- RouterOS admin or read-only account credentials

## Other Tools

### Scan for Winbox-Only Devices
```bash
python3 winbox_only.py
```
Shows devices with Winbox (8291/8292) open but no SSH (port 22). These need manual patching or SSH enabled first.

### Test Single Device
```bash
python3 test_patch.py
```
Quick test against a single IP to verify API connectivity and patching.

## Troubleshooting

**Connection refused on device**
- Press `y` to retry after enabling API ports
- Or press `n` to skip and move on

**Version parameter not supported**
- Older v7 devices may not support version pinning
- Device will update to latest stable instead (still gets security fixes)

**Winbox-only devices**
- Enable SSH first (via Winbox)
- Or use NPK method for exact version pinning
- See `winbox_only.py` output for list of affected devices

**Network scan timeout**
- Run with larger `--threads` value in config
- Or scan from within the network (avoid NAT)

## Security Notes

- Credentials are **never stored** in config files
- Session credentials are **never logged**
- Each run is isolated — no persistent state with auth data
- SSH/API communication is encrypted when using SSL ports (8729)

## Files

```
patch_cycle.py       Main interactive patching script
test_patch.py        Single-device test script
winbox_only.py       Scanner for Winbox-only devices
cpe_patcher.py       Core library (scan/plan/patch functions)
requirements.txt     Python dependencies
config.example.yaml  Example config (edit for your environment)
```

## License

See LICENSE file.
