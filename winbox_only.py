#!/usr/bin/env python3
"""
Scanner: Find devices with Winbox (8291/8292) open but NO SSH (22)
These devices have limited patching options
"""
import json
from pathlib import Path

STATE_DIR = Path(__file__).parent / "state"
SCAN_FILE = STATE_DIR / "scan.json"

if not SCAN_FILE.exists():
    print(f"❌ {SCAN_FILE} not found. Run: python3 cpe_patcher.py scan --config config.example.yaml")
    exit(1)

with open(SCAN_FILE) as f:
    scan = json.load(f)

devices = scan.get("hosts", [])
winbox_only = []

for device in devices:
    if not device.get("mikrotik"):
        continue

    ports = device.get("ports", [])
    has_winbox = any(p in ports for p in [8291, 8292])
    has_ssh = 22 in ports

    if has_winbox and not has_ssh:
        winbox_only.append(device)

print(f"\n{'='*80}")
print(f"WINBOX-ONLY DEVICES (8291/8292 open, but NO SSH 22)")
print(f"{'='*80}\n")

if not winbox_only:
    print("✓ No winbox-only devices found (all SSH-accessible devices have port 22)\n")
    exit(0)

print(f"Found {len(winbox_only)} device(s):\n")
print(f"{'IP':<16} {'Ports':<20} {'SSH Banner':<30}")
print(f"{'─'*16} {'─'*20} {'─'*30}")

for device in winbox_only:
    ip = device.get("ip", "?").ljust(16)
    ports = ",".join(str(p) for p in device.get("ports", [])).ljust(20)
    banner = (device.get("ssh_banner") or "N/A").ljust(30)
    print(f"{ip} {ports} {banner}")

print(f"\n{'='*80}")
print(f"Options for these {len(winbox_only)} device(s):")
print(f"{'='*80}")
print(f"1. Enable SSH on the device (via Winbox)")
print(f"2. Use NPK method (download .npk and upload via SFTP)")
print(f"3. Patch manually via Winbox\n")
