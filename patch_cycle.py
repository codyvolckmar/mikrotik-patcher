#!/usr/bin/env python3
"""
Unified MikroTik CPE patch cycle: scan → plan → approve & patch inline (via API)
Direct RouterOS API patching - no SSH wrapping needed
"""
import json
import os
import sys
import getpass
import subprocess
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional

# Import APITransport from cpe_patcher
sys.path.insert(0, str(Path(__file__).parent))
try:
    from cpe_patcher import APITransport
except ImportError:
    print("❌ Could not import APITransport from cpe_patcher.py")
    sys.exit(1)

PROJECT_ROOT = Path(__file__).parent
STATE_DIR = PROJECT_ROOT / "state"
CONFIG_TEMPLATE = PROJECT_ROOT / "config.example.yaml"

def load_plan() -> Dict:
    """Load plan.json."""
    plan_file = STATE_DIR / "plan.json"
    if not plan_file.exists():
        return {}
    with open(plan_file) as f:
        return json.load(f)

def save_plan(plan: Dict):
    """Save plan.json."""
    plan_file = STATE_DIR / "plan.json"
    with open(plan_file, 'w') as f:
        json.dump(plan, f, indent=2)

def send_install_async(conn, timeout: int = 300):
    """Send install command in background (non-blocking)."""
    def _install():
        try:
            conn.run("/system/package/update install", timeout=timeout)
        except:
            pass  # Device reboots - connection drops, that's fine

    thread = threading.Thread(target=_install, daemon=True)
    thread.start()

def security_badge(device: Dict[str, Any]) -> str:
    """Return security status badge."""
    version = device.get("version_num", "")
    major = device.get("major", 0)
    channel = device.get("channel", "unknown")

    if major == 7:
        if channel == "long-term":
            if version and version < "7.23.4":
                return "🔴 VULNERABLE (fixes in 7.23.4)"
        elif channel in ("stable", ""):
            if version and version < "7.24.2":
                return "🔴 VULNERABLE (fixes in 7.24.2)"
    elif major == 6:
        return "⚠️  EOL (no fix available)"

    return "✓ OK"

def patch_device_api(device: Dict[str, Any], admin_user: str, admin_pass: str, verbose: bool = False) -> bool:
    """Patch device using RouterOS API directly."""
    ip = device.get("ip")
    hostname = device.get("identity", "?")
    baseline = device.get("baseline", "?")
    major = device.get("major", 0)
    channel = device.get("channel", "stable")

    print(f"  Patching {hostname} ({ip}) → {baseline}...", end="", flush=True)

    conn = None
    last_error = None
    retry_count = 0
    max_retries = 1

    while retry_count <= max_retries:
        conn = None

        # Connect via API (try port 8728 first - more common, then 8729 SSL)
        for port, use_ssl in [(8728, False), (8729, True)]:
            try:
                if verbose:
                    print(f"\n    Trying port {port}...", end="", flush=True)

                conn = APITransport(ip, port, admin_user, admin_pass, use_ssl=use_ssl)
                conn.connect()

                if verbose:
                    print(" ✓")
                break

            except Exception as e:
                last_error = str(e)
                if verbose:
                    print(f" ✗ ({e})")
                conn = None
                continue

        if conn is not None:
            break  # Connected successfully

        # Connection failed - offer retry if it's a connection error
        if retry_count < max_retries and ("refused" in last_error.lower() or "timeout" in last_error.lower()):
            print(f" ⚠️  (connection refused)")
            ans = input(f"\n    Retry? [y/n]: ").strip().lower()
            if ans == 'y':
                retry_count += 1
                print(f"  Patching {hostname} ({ip}) → {baseline}...", end="", flush=True)
                continue
            else:
                print(f"  ⊘ Skipped")
                return False
        else:
            if verbose:
                print(f"    Error: {last_error}")
            print(f" ❌ (API error: {last_error[:30] if last_error else 'connection failed'})")
            return False

    if conn is None:
        if verbose:
            print(f"    Error: {last_error}")
        print(f" ❌ (API error: {last_error[:30] if last_error else 'connection failed'})")
        return False

    try:
        # Set update channel (preserve per-device channel or use stable)
        if verbose:
            print(f"    Setting channel={channel}")
        conn.run(f"/system/package/update set channel={channel}", timeout=30)

        # Set version (v7 only - v6 ignores this, some old v7 devices don't support it)
        if major >= 7:
            if verbose:
                print(f"    Setting version={baseline}")
            try:
                conn.run(f"/system/package/update set version={baseline}", timeout=30)
            except Exception as e:
                # Some v7 devices don't support version parameter
                if "unknown parameter version" in str(e).lower():
                    if verbose:
                        print(f"    (device doesn't support version pinning, will use latest stable)")
                else:
                    raise

        # Check for updates
        if verbose:
            print(f"    Checking for updates...")
        conn.run("/system/package/update check-for-updates", timeout=120)
        time.sleep(2)

        # Install (this triggers reboot) - send in background thread and continue immediately
        if verbose:
            print(f"    Sending install command...")
        send_install_async(conn)

        # Don't wait - close connection and move to next device
        try:
            conn.close()
        except:
            pass

        print(" ✓ (installing in background)")
        return True

    except Exception as e:
        if verbose:
            print(f"    Command error: {e}")
        print(f" ⚠️  ({str(e)[:40]})")
        try:
            conn.close()
        except:
            pass
        return True  # Still mark as sent

def inline_approval_and_patch(plan: Dict, admin_user: str, admin_pass: str, verbose: bool = False) -> tuple:
    """Walk through devices one-by-one, approve and patch inline via API."""
    pending = [c for c in plan["cpes"] if c["status"] == "pending"]

    if not pending:
        print("\n✓ No devices pending approval.")
        return 0, 0

    print(f"\n{'='*140}")
    print(f"MIKROTIK CPE PATCH CYCLE - Approve & Patch Each Device (via API)")
    print(f"{'='*140}\n")
    print(f"Total pending: {len(pending)} devices")
    print(f"CVE-2026-67276 & CVE-2026-86060 targets:")
    print(f"  • v7 stable → {plan['baselines']['v7']}")
    print(f"  • v7 long-term → {plan['baselines']['v7_longterm']}")
    print(f"  • v6 (EOL) → {plan['baselines']['v6']}\n")

    approved_count = 0
    skipped_count = 0
    idx = 0

    while idx < len(pending):
        device = pending[idx]
        print(f"\n{'─'*140}")
        print(f"[{idx+1}/{len(pending)}] {device.get('identity', '?'):<30} {device['ip']:<15}")
        print(f"    Current:  {device.get('version_num', '?')} ({device.get('channel', 'unknown')})")
        print(f"    Target:   {device.get('baseline', '?')}")
        print(f"    Status:   {security_badge(device)}")

        while True:
            try:
                ans = input("\n  [1=approve & patch, 0=skip, a=patch all, q=quit]: ").strip().lower()

                if ans == 'q':
                    print(f"\n{'='*140}")
                    print(f"Session ended.")
                    print(f"  Patched: {approved_count}")
                    print(f"  Skipped: {skipped_count}")
                    print(f"  Remaining: {len(pending) - idx}")
                    print(f"{'='*140}\n")
                    return approved_count, skipped_count

                elif ans == 'a':
                    print(f"\n⚠️  Sending updates to {len(pending) - idx} device(s)...\n")
                    for dev in pending[idx:]:
                        print(f"  [{idx+1}/{len(pending)}] {dev.get('identity', '?'):<30} {dev['ip']:<15}")
                        if patch_device_api(dev, admin_user, admin_pass, verbose):
                            approved_count += 1
                            # Mark as rebooting
                            dev["status"] = "rebooting"
                        idx += 1

                    save_plan(plan)
                    print(f"\n{'='*140}")
                    print(f"All updates sent - devices rebooting")
                    print(f"  Sent: {approved_count}")
                    print(f"{'='*140}\n")
                    return approved_count, skipped_count

                elif ans == '1' or ans == 'y':
                    print()
                    if patch_device_api(device, admin_user, admin_pass, verbose):
                        approved_count += 1
                        device["status"] = "rebooting"
                        save_plan(plan)
                    idx += 1
                    break

                elif ans == '0' or ans == 'n':
                    device["status"] = "skipped"
                    save_plan(plan)
                    skipped_count += 1
                    print(f"  ⊘ Skipped")
                    idx += 1
                    break

                else:
                    print("  Invalid input. Try again.")

            except (EOFError, KeyboardInterrupt):
                print(f"\n\n{'='*140}")
                print(f"Interrupted.")
                print(f"  Patched: {approved_count}")
                print(f"  Skipped: {skipped_count}")
                print(f"  Remaining: {len(pending) - idx}")
                print(f"{'='*140}\n")
                return approved_count, skipped_count

    return approved_count, skipped_count

def main(verbose: bool = False):
    print(f"\n{'='*80}")
    print(f"MIKROTIK CPE PATCH CYCLE (API Direct)")
    print(f"{'='*80}")
    print(f"Scan → Plan → Approve & Patch (via RouterOS API)\n")

    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Get network range
    print("Network Configuration:")
    subnet = input("  Enter subnet/IP range (e.g., 192.168.1.0/24): ").strip()
    if not subnet:
        print("❌ Subnet is required")
        sys.exit(1)

    # Get account type
    print("\nAccount Type:")
    print("  1. Admin account (can patch devices)")
    print("  2. Read-only account (audit only, no patching)")
    acc_type = input("  Choose (1 or 2, default: 1): ").strip() or "1"

    if acc_type == "2":
        print("\n📋 Running in READ-ONLY mode (audit only)")
        admin_user = input("  Read-only username: ").strip()
        admin_pass = getpass.getpass("  Read-only password: ")
        is_readonly = True
    else:
        print("\n🔧 Running in PATCH mode (will update devices)")
        admin_user = input("  Admin username: ").strip()
        admin_pass = getpass.getpass("  Admin password: ")
        is_readonly = False

    if not admin_user or not admin_pass:
        print("❌ Username and password are required")
        sys.exit(1)

    if not admin_pass:
        print("❌ Password required.")
        sys.exit(1)

    venv_python = PROJECT_ROOT / ".venv" / "bin" / "python"
    if not venv_python.exists():
        print("❌ Virtual environment not found.")
        sys.exit(1)

    # 1. SCAN
    print("\n" + "="*80)
    print("PHASE 1: SCAN")
    print("="*80)
    scan_cmd = [
        str(venv_python), "cpe_patcher.py", "scan",
        "--config", str(CONFIG_TEMPLATE),
        "--subnet", subnet
    ]
    print(f"→ Discovering MikroTik devices in {subnet}...")
    result = subprocess.run(
        scan_cmd,
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT)
    )
    if result.returncode != 0:
        print(f"❌ Scan failed: {result.stderr or result.stdout}")
        sys.exit(1)
    lines = result.stdout.strip().split('\n')
    found_count = sum(1 for line in lines if 'ports=' in line)
    print(f"✓ Found {found_count} devices")

    # 2. PLAN
    print("\n" + "="*80)
    print("PHASE 2: PLAN")
    print("="*80)
    plan_cmd = [
        str(venv_python), "cpe_patcher.py", "plan",
        "--config", str(CONFIG_TEMPLATE),
        "--user", admin_user,
        "--baseline-v6", "6.49.21",
        "--baseline-v7", "7.24.2",
        "--baseline-v7-longterm", "7.23.4"
    ]
    print("→ Reading device versions...")
    env = os.environ.copy()
    env["MIKROTIK_PASSWORD"] = admin_pass

    result = subprocess.run(
        plan_cmd,
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        env=env
    )
    if result.returncode != 0:
        print(f"⚠️  Plan had issues: {result.stderr or result.stdout}")
    else:
        for line in result.stdout.split('\n'):
            if 'plan saved:' in line:
                print(f"✓ {line.strip()}")

    # 3. LOAD & SHOW SUMMARY
    plan = load_plan()
    if not plan.get("cpes"):
        print("❌ No devices found.")
        sys.exit(1)

    pending = [c for c in plan["cpes"] if c["status"] == "pending"]
    completed = [c for c in plan["cpes"] if c["status"] == "completed"]
    skipped = [c for c in plan["cpes"] if c["status"] == "skipped"]

    print(f"\n{'='*80}")
    print(f"PLAN SUMMARY")
    print(f"{'='*80}")
    print(f"  Pending: {len(pending)}")
    print(f"  Completed: {len(completed)}")
    print(f"  Skipped: {len(skipped)}")
    print(f"  Total: {len(plan['cpes'])}")

    if is_readonly:
        print("\n📋 READ-ONLY MODE: Showing devices that need patching (no changes made)")
        if not pending:
            print("✓ No devices need patching!")
        return

    if not pending:
        print("\n✓ No devices need patching!")
        return

    # 4. INLINE APPROVAL & PATCHING (via API)
    print("\n" + "="*80)
    print("PHASE 3: APPROVE & PATCH (via API)")
    print("="*80)

    approved, skipped = inline_approval_and_patch(plan, admin_user, admin_pass, verbose)

    # 5. FINAL REPORT
    print("\n" + "="*80)
    print("FINAL REPORT")
    print("="*80)

    plan = load_plan()
    rebooting = [c for c in plan["cpes"] if c["status"] in ("rebooting", "patching")]
    skipped_cpes = [c for c in plan["cpes"] if c["status"] == "skipped"]
    pending_now = [c for c in plan["cpes"] if c["status"] == "pending"]

    print(f"  Sent to reboot: {len(rebooting)}")
    print(f"  Skipped: {len(skipped_cpes)}")
    print(f"  Still pending: {len(pending_now)}")
    print(f"  Completed/at baseline: {len([c for c in plan['cpes'] if c['status'] == 'completed'])}")

    print(f"\n{'='*80}")
    print(f"✓ Cycle complete!")
    print(f"{'='*80}\n")
    print(f"Next steps:")
    print(f"  1. Devices are rebooting now")
    print(f"  2. Wait 5-10 minutes, then run this script again to verify they're at baseline\n")

if __name__ == "__main__":
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    main(verbose=verbose)
