#!/usr/bin/env python3
"""Quick test: patch a single device via API"""
import sys
import getpass
from pathlib import Path

# Import the APITransport from cpe_patcher
sys.path.insert(0, str(Path(__file__).parent))
from cpe_patcher import APITransport

# Target device
IP = "102.217.188.135"
HOSTNAME = "vit-cg-os-lewlef-flat-2-B120025727-PRIMARY"
BASELINE = "6.49.21"
CHANNEL = "stable"
MAJOR = 6

print(f"Testing patch on: {HOSTNAME} ({IP})")
print(f"Target: {BASELINE}\n")

# Get credentials
admin_user = input("Username: ").strip()
if not admin_user:
    print("❌ Username required")
    sys.exit(1)
admin_pass = getpass.getpass("Password: ")

# Try connection
conn = None
for port, use_ssl in [(8729, True), (8728, False)]:
    try:
        print(f"\nTrying port {port}...", end="", flush=True)
        t = APITransport(IP, port, admin_user, admin_pass, use_ssl=use_ssl)
        t.connect()
        conn = t
        print(" ✓ Connected")
        break
    except Exception as e:
        print(f" ✗ ({e})")

if conn is None:
    print("\n❌ Could not connect to device")
    sys.exit(1)

try:
    # Set channel
    print(f"\n1. Setting channel={CHANNEL}...", end="", flush=True)
    conn.run(f"/system/package/update set channel={CHANNEL}", timeout=30)
    print(" ✓")

    # Set version (v7+ only)
    if MAJOR >= 7:
        print(f"2. Setting version={BASELINE}...", end="", flush=True)
        conn.run(f"/system/package/update set version={BASELINE}", timeout=30)
        print(" ✓")

    # Check for updates
    print(f"3. Checking for updates...", end="", flush=True)
    conn.run("/system/package/update check-for-updates", timeout=120)
    print(" ✓")

    # Install
    print(f"4. Installing (device will reboot)...", end="", flush=True)
    conn.run("/system/package/update install", timeout=300)
    print(" ✓")

    print(f"\n✓ Patch command sent! Device is rebooting.\n")

except Exception as e:
    print(f"\n❌ Error: {e}\n")
    import traceback
    traceback.print_exc()
    sys.exit(1)

finally:
    try:
        conn.close()
    except:
        pass
