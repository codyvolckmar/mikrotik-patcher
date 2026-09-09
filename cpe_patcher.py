#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mikro-cpe-patch — monthly scanner + patcher for a fleet of MikroTik CPEs.

Pipeline:  scan  ->  plan  ->  patch (interactive per-device approval)  ->  reboot
           ->  next scan/plan cycle verifies (public IPs change on reboot)

  scan      : probe a subnet / IP range for RouterOS devices (SSH / Winbox / API ports)
  plan      : log in, read identity + OS version, compute the gap to the chosen baseline
              (one baseline per major: v6 and v7), and stage the exact update commands
  patch     : show candidates one at a time — hostname and current version — approve each,
              run the upgrade and reboot the device. Verification happens on the
              next scan/plan cycle: because public IPs often change on reboot, a
              fresh scan is the source of truth and devices gradually show up at
              baseline.
  report    : status table / JSON of the last plan
  inventory : export candidates as an Ansible inventory for community.routeros

Dependencies: python3, paramiko, routeros_api, PyYAML

Monthly automation: the scan step is safe to run headless from a systemd timer /
cron. plan and patch stay interactive so a human approves every single device.

Version pinning strategy:
  * RouterOS 7 (>= ~7.15): the updater supports ``set version=X`` -> exact baseline.
  * RouterOS 6: no version pin in the updater, it goes to the latest v6 stable
    (6.49.18 is the final v6 -> the usual baseline). For exact pinning use
    --update-method npk which downloads the official .npk and uploads it via SFTP.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime
import getpass
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

try:
    import paramiko  # type: ignore
except Exception:  # pragma: no cover
    paramiko = None

import logging as _logging

if paramiko is not None:
    # quiet: failed SSH banners / auth are recorded per-device, not logged as tracebacks
    _logging.getLogger("paramiko").setLevel(_logging.CRITICAL)
    _logging.getLogger("routeros_api").setLevel(_logging.CRITICAL)

try:
    import routeros_api  # type: ignore
except Exception:  # pragma: no cover
    routeros_api = None

VERSION = "1.0.0"
DEFAULT_V6 = "6.49.18"   # final v6 stable (EOL - no further security fixes)
DEFAULT_V7 = "7.24.2"    # v7 STABLE baseline - SECURITY FIXED (stable <= 7.24.1 is vulnerable)
DEFAULT_V7_LT = "7.23.4" # v7 LONG-TERM baseline - SECURITY FIXED (long-term <= 7.23.3 is vulnerable)
DEFAULT_PORTS = [22, 8291, 8728, 8729]
STATUS_ACTIVE = ("pending", "patching", "rebooting")

# ----------------------------------------------------------------------------
# small helpers
# ----------------------------------------------------------------------------

def parse_version(s: str) -> Tuple[int, ...]:
    """'7.16.2 (stable)' -> (7, 16, 2)"""
    m = re.search(r"([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?", str(s or ""))
    if not m:
        return ()
    return tuple(int(x or 0) for x in m.groups())


def version_compare(a: str, b: str) -> int:
    A, B = parse_version(a), parse_version(b)
    pad = (0,) * (3 - len(A))
    a_p = A + (0,) * (3 - len(A))
    b_p = B + (0,) * (3 - len(B))
    return (a_p > b_p) - (a_p < b_p)


def parse_kv(text: str, key: str) -> Optional[str]:
    """grab 'key: value' from RouterOS print output (handles quotes)."""
    m = re.search(r"(?im)^\s*" + re.escape(key) + r":\s*\"?(.*?)\"?\s*$", text or "")
    return m.group(1).strip() if m else None


_MAC_RE = re.compile(
    r"mac-address[=:]\s*\"?([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\"?", re.I
)

_UPDATE_RE = [
    re.compile(r"latest\s+version:\s*([0-9]+(?:\.[0-9]+)+)", re.I),
    re.compile(r"version\s+([0-9]+(?:\.[0-9]+)+)\s+is\s+available", re.I),
    re.compile(r"([0-9]+(?:\.[0-9]+)+)\s+is\s+available", re.I),
]


def parse_update_latest(text: str) -> Optional[str]:
    for rx in _UPDATE_RE:
        m = rx.search(text or "")
        if m:
            return m.group(1)
    return None


def port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_ports(ip: str, ports: List[int], timeout: float) -> List[int]:
    return [p for p in ports if port_open(ip, p, timeout)]


def ssh_banner(ip: str, timeout: float) -> Optional[str]:
    try:
        s = socket.create_connection((ip, 22), timeout=timeout)
        s.settimeout(timeout)
        data = b""
        deadline = time.time() + timeout
        while time.time() < deadline and len(data) < 256:
            try:
                chunk = s.recv(256)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
        s.close()
        return data.decode("utf-8", "replace").strip().split("\n")[0]
    except OSError:
        return None


# ----------------------------------------------------------------------------
# config / state
# ----------------------------------------------------------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    "credentials": {"username": None, "password_env": "MIKROTIK_PASSWORD"},
    "baselines": {"v6": DEFAULT_V6, "v7": DEFAULT_V7, "v7_longterm": DEFAULT_V7_LT},
    "security": {"v7_stable_fixed": DEFAULT_V7, "v7_longterm_fixed": DEFAULT_V7_LT},
    "scan": {"subnet": None, "ports": DEFAULT_PORTS, "threads": 128, "timeout": 0.7},
    "update": {"method": "auto", "channel": "stable",
               "check_timeout": 240, "npk_cache": "./npk-cache"},
    "reboot": {"offline_timeout": 240},
    "state_dir": "./state",
}


def merge_dict(base: Dict, override: Dict) -> Dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge_dict(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Optional[str]) -> Dict:
    cfg = merge_dict({}, DEFAULT_CONFIG)
    if path:
        p = Path(path)
        if not p.exists():
            raise SystemExit(f"config not found: {path}")
        if yaml is None:
            raise SystemExit("PyYAML missing: pip install -r requirements.txt")
        cfg = merge_dict(cfg, yaml.safe_load(p.read_text()) or {})
    return cfg


def load_state(path: str) -> Dict:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"state file not found: {path}")
    return json.loads(p.read_text())


def save_state(state: Dict, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, p)


def acquire_lock(path: str):
    import fcntl

    f = open(path, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit(f"another patch run holds the lock: {path}")
    return f


# ----------------------------------------------------------------------------
# transports
# ----------------------------------------------------------------------------

class SSHTransport:
    def __init__(self, host: str, port: int, user: str, password: str, timeout: int = 15):
        self.host, self.port, self.user, self.password, self.timeout = (
            host, port, user, password, timeout,
        )
        self._client = None

    def connect(self) -> None:
        if paramiko is None:
            raise RuntimeError("paramiko not installed (pip install -r requirements.txt)")
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(
            self.host, port=self.port, username=self.user, password=self.password,
            timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout,
            look_for_keys=False, allow_agent=False,
        )
        self._client = cli

    def run(self, cmd: str, timeout: int = 180) -> str:
        if self._client is None:
            self.connect()
        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        data = bytearray()
        chan = stdout.channel
        chan.settimeout(1.0)
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                try:
                    chunk = chan.recv(65536)
                except socket.timeout:
                    chunk = None
                except EOFError:
                    break
                if chunk:
                    data.extend(chunk)
                    continue
                if chan.exit_status_ready():
                    while True:  # drain remainder
                        try:
                            c = chan.recv(65536)
                        except (socket.timeout, EOFError):
                            break
                        if not c:
                            break
                        data.extend(c)
                    break
                time.sleep(0.1)
        finally:
            try:
                chan.close()
            except Exception:
                pass
        return bytes(data).decode("utf-8", "replace")

    def upload(self, local: str, remote: str) -> None:
        if self._client is None:
            self.connect()
        sftp = self._client.open_sftp()
        try:
            sftp.put(local, remote)
        finally:
            sftp.close()

    def close(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass


KNOWN_VERBS = {"print", "get", "set", "call", "install", "reboot",
               "check-for-updates", "uninstall", "add", "remove"}


class APITransport:
    def __init__(self, host: str, port: int, user: str, password: str, use_ssl: bool = False):
        self.host, self.port, self.user, self.password, self.use_ssl = (
            host, port, user, password, use_ssl,
        )
        self._api = None

    def connect(self) -> None:
        if routeros_api is None:
            raise RuntimeError("routeros_api not installed (pip install -r requirements.txt)")
        import inspect

        kw = {"port": self.port, "username": self.user, "password": self.password,
              "plaintext_login": True, "use_ssl": self.use_ssl}
        sig = inspect.signature(routeros_api.RouterOsApiPool.__init__)
        kw = {k: v for k, v in kw.items() if k in sig.parameters}
        pool = routeros_api.RouterOsApiPool(self.host, **kw)
        self._api = pool.get_api()

    @staticmethod
    def _split(cmd: str) -> Tuple[str, Optional[str], Dict[str, str]]:
        """'/system/package/update set channel=stable' -> ('/system/package/update','set',{...})"""
        path_parts: List[str] = []
        verb: Optional[str] = None
        params: Dict[str, str] = {}
        for t in cmd.split():
            if t.startswith("/"):
                path_parts.append(t)
            elif "=" in t:
                k, v = t.split("=", 1)
                params[k.strip()] = v
            elif verb is None and t in KNOWN_VERBS:
                verb = t
            else:
                path_parts.append(t)  # space-style path continuation
        path = "".join(path_parts) or "/"
        if verb is None and path.count("/") > 1 and path.rsplit("/", 1)[-1] in KNOWN_VERBS:
            path, verb = path.rsplit("/", 1)
        return path, verb, params

    @staticmethod
    def _fmt(rows) -> str:
        if not rows:
            return ""
        lines = []
        for row in rows:
            if isinstance(row, dict):
                lines.append(" ".join(f"{k}: {v}" for k, v in row.items()))
            else:
                lines.append(str(row))
        return "\n".join(lines)

    def run(self, cmd: str, timeout: int = 180) -> str:
        if self._api is None:
            self.connect()
        path, verb, params = self._split(cmd)
        res = self._api.get_resource(path)
        if verb is None or verb in ("print", "get"):
            return self._fmt(res.get())
        if verb == "set":
            res.set(**params)
            return ""
        # call-style commands: check-for-updates, install, reboot, ...
        try:
            out = res.call(verb, params)
        except Exception:
            if verb in ("install", "reboot"):
                return ""  # connection died mid-reboot: expected
            raise
        return self._fmt(out)

    def close(self) -> None:
        self._api = None


def open_transport(host: str, open_ports: List[int], user: str, password: str,
                   timeout: int = 15):
    """Try SSH first (best for slow commands + SFTP uploads), then API ports."""
    open_ports = open_ports or []
    if 22 in open_ports and paramiko is not None:
        t = SSHTransport(host, 22, user, password, timeout=timeout)
        try:
            t.connect()
            return t, "ssh"
        except Exception:
            pass
    if 8728 in open_ports and routeros_api is not None:
        t = APITransport(host, 8728, user, password, use_ssl=False)
        try:
            t.connect()
            return t, "api"
        except Exception:
            pass
    if 8729 in open_ports and routeros_api is not None:
        t = APITransport(host, 8729, user, password, use_ssl=True)
        try:
            t.connect()
            return t, "api-ssl"
        except Exception:
            pass
    return None, None


def run(conn, cmd: str, timeout: int = 180) -> str:
    try:
        return conn.run(cmd, timeout=timeout)
    except Exception as e:
        raise RuntimeError(f"command failed on {conn.host} ({cmd}): {e}") from e


def fetch_device_info(conn) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        info["identity"] = (parse_kv(run(conn, "/system identity print"), "name") or "").strip('"')
    except Exception:
        info["identity"] = ""
    res = run(conn, "/system resource print")
    raw_ver = parse_kv(res, "version") or ""
    info["version"] = raw_ver
    m = re.search(r"[0-9]+(?:\.[0-9]+)*", raw_ver)
    info["version_num"] = m.group(0) if m else raw_ver
    info["arch"] = parse_kv(res, "architecture-name") or ""
    info["board"] = parse_kv(res, "board-name") or ""
    try:
        info["channel"] = (parse_kv(run(conn, "/system package update print"), "channel") or "").strip()
    except Exception:
        info["channel"] = ""
    try:
        info["macs"] = sorted(set(_MAC_RE.findall(run(conn, "/interface ethernet print detail"))))[:8]
    except Exception:
        info["macs"] = []
    return info


# ----------------------------------------------------------------------------
# scanning
# ----------------------------------------------------------------------------

def expand_targets(spec: str) -> List[str]:
    spec = spec.strip()
    if "-" in spec and "/" not in spec:
        base, hi = spec.rsplit("-", 1)
        start = int(ipaddress.ip_address(base))
        end = int(ipaddress.ip_address(hi))
        if end < start:
            raise SystemExit(f"bad range: {spec}")
        n = end - start + 1
        if n > 131072:
            raise SystemExit(f"range too large ({n} addresses): {spec}")
        return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
    net = ipaddress.ip_network(spec, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if not hosts:  # /31 or /32
        hosts = [str(net.network_address)]
    return hosts


def _probe_one(ip: str, ports: List[int], timeout: float) -> Dict[str, Any]:
    open_ports: List[int] = []
    banner: Optional[str] = None
    for p in ports:
        if port_open(ip, p, timeout):
            open_ports.append(p)
            if p == 22 and banner is None:
                banner = ssh_banner(ip, timeout)
    mikrotik = bool(set(open_ports) & {8291, 8728, 8729}) or (
        banner is not None and "routeros" in banner.lower()
    )
    return {
        "ip": ip, "ports": sorted(open_ports), "ssh_banner": banner,
        "mikrotik": mikrotik,
    }


def scan_subnet(spec: str, cfg: Dict, on_progress=None) -> List[Dict[str, Any]]:
    ips = expand_targets(spec)
    ports = cfg["scan"]["ports"]
    timeout = cfg["scan"]["timeout"]
    threads = min(cfg["scan"]["threads"], max(1, len(ips)))
    found: List[Dict[str, Any]] = []
    done = 0
    lock = threading.Lock()

    def progress():
        nonlocal done
        with lock:
            done += 1
            if on_progress and done % 25 == 0:
                on_progress(done, len(ips))

    print(f"scanning {len(ips)} addresses (ports {','.join(map(str, ports))})...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_probe_one, ip, ports, timeout) for ip in ips]
        for fut in as_completed(futs):
            try:
                r = fut.result()
            except Exception:
                continue
            if r["mikrotik"]:
                found.append(r)
            progress()
    found.sort(key=lambda r: socket.inet_aton(r["ip"]))
    print(f"done: {len(found)} MikroTik-like host(s) found")
    return found


# ----------------------------------------------------------------------------
# plan
# ----------------------------------------------------------------------------

def resolve_credentials(cfg: Dict, args, interactive: bool = True) -> Dict[str, str]:
    user = getattr(args, "user", None) or cfg["credentials"].get("username")
    if not user:
        raise SystemExit("username required: pass --user <username> or set credentials.username in config")
    pw_env = cfg["credentials"].get("password_env") or "MIKROTIK_PASSWORD"
    password = os.environ.get(pw_env)
    if not password:
        if interactive and sys.stdin.isatty():
            password = getpass.getpass(f"RouterOS password for '{user}': ")
        else:
            raise SystemExit(
                f"no password available: export {pw_env} (or run interactively)"
            )
    return {"user": user, "password": password}


# ----------------------------------------------------------------------------
# OS security posture + per-channel baselines (v7 stable vs long-term)
# ----------------------------------------------------------------------------

def security_status(version: str, channel: str, cfg: Dict) -> Tuple[str, str]:
    """(status, note) - vulnerable|patched|eol|unknown.
    v7 stable <= 7.24.1 and v7 long-term <= 7.23.3 are vulnerable
    (fixed in 7.24.2 stable / 7.23.4 long-term)."""
    m = re.search(r"([0-9]+)", version or "")
    major = int(m.group(1)) if m else 0
    if major == 6:
        return "eol", "v6 is EOL - 6.49.18 is final, no further security fixes"
    if major == 7:
        ch = (channel or "").lower()
        is_lt = "long" in ch
        fix = (cfg["security"].get("v7_longterm_fixed", DEFAULT_V7_LT) if is_lt
               else cfg["security"].get("v7_stable_fixed", DEFAULT_V7))
        train = "long-term" if is_lt else "stable"
        if version_compare(version, fix) < 0:
            return "vulnerable", f"v7 {train} < {fix} - VULNERABLE (fixed in {fix})"
        return "patched", f"v7 {train} >= {fix}"
    return "unknown", ""


def baseline_for(major: int, channel: str, cfg: Dict) -> Optional[str]:
    """Pick the baseline for the device's release channel (v7 stable or long-term)."""
    if major == 6:
        return cfg["baselines"].get("v6")
    if major == 7:
        ch = (channel or "").lower()
        if "long" in ch:
            return cfg["baselines"].get("v7_longterm") or cfg["baselines"].get("v7")
        return cfg["baselines"].get("v7")
    return None


def resolve_baselines(cfg: Dict, args, interactive: bool = False) -> None:
    v6 = getattr(args, "baseline_v6", None) or cfg["baselines"].get("v6")
    v7 = getattr(args, "baseline_v7", None) or cfg["baselines"].get("v7")
    v7lt = getattr(args, "baseline_v7_longterm", None) or cfg["baselines"].get("v7_longterm")
    if interactive and sys.stdin.isatty():
        if not v6:
            v6 = input(f"v6 baseline version [{DEFAULT_V6}]: ").strip() or DEFAULT_V6
        if not v7:
            v7 = input(f"v7 stable baseline version [{DEFAULT_V7}]: ").strip() or DEFAULT_V7
        if not v7lt:
            v7lt = input(f"v7 long-term baseline version [{DEFAULT_V7_LT}]: ").strip() or DEFAULT_V7_LT
    cfg["baselines"]["v6"] = v6 or DEFAULT_V6
    cfg["baselines"]["v7"] = v7 or DEFAULT_V7
    cfg["baselines"]["v7_longterm"] = v7lt or DEFAULT_V7_LT
    print(f"baselines -> v6: {cfg['baselines']['v6']}   "
          f"v7 stable: {cfg['baselines']['v7']}   "
          f"v7 long-term: {cfg['baselines']['v7_longterm']}")


def plan_one(host: Dict[str, Any], creds: Dict[str, str], cfg: Dict, ts: str) -> Dict[str, Any]:
    entry = dict(host)
    entry.setdefault("status", "pending")
    entry["checked_at"] = ts
    ports = host.get("ports") or probe_ports(host["ip"], cfg["scan"]["ports"], cfg["scan"]["timeout"])
    entry["ports"] = ports
    conn, transport = open_transport(host["ip"], ports, creds["user"], creds["password"])
    if conn is None:
        entry["status"] = "skipped"
        entry["notes"] = "no reachable transport (ssh 22 / api 8728 / api-ssl 8729)"
        return entry
    try:
        info = fetch_device_info(conn)
    except Exception as e:
        entry["status"] = "skipped"
        entry["notes"] = f"query failed: {e}"
        return entry
    finally:
        conn.close()
    entry.update(info)
    entry["transport"] = transport
    if not entry.get("identity"):
        entry["identity"] = host["ip"]
    entry["channel"] = info.get("channel", "")
    entry["security_status"], entry["security_note"] = security_status(
        entry.get("version_num", ""), entry.get("channel", ""), cfg)
    m = re.search(r"([0-9]+)", entry.get("version_num", ""))
    major = int(m.group(1)) if m else 0
    entry["major"] = major
    if major in (6, 7):
        baseline = baseline_for(major, entry.get("channel", ""), cfg)
        entry["baseline"] = baseline
        cmp = version_compare(entry["version_num"], baseline or "")
        if cmp >= 0:
            entry["status"] = "completed"
            entry["notes"] = "already at/above baseline, nothing to do"
        else:
            entry["status"] = "pending"
            entry["action"] = "update"
        if entry["security_status"] == "vulnerable":
            entry["notes"] = "; ".join(x for x in
                [entry.get("notes", ""), entry.get("security_note", "VULNERABLE")] if x)
        elif entry["security_status"] == "eol":
            entry["notes"] = "; ".join(x for x in
                [entry.get("notes", ""), entry.get("security_note", "v6 EOL")] if x)
    else:
        entry["baseline"] = None
        entry["status"] = "skipped"
        entry["notes"] = f"unmanaged RouterOS major: {entry.get('version_num','?')}"
    return entry


# ----------------------------------------------------------------------------
# patching
# ----------------------------------------------------------------------------

def do_auto_update(conn, cpe: Dict, cfg: Dict) -> Dict[str, Any]:
    base, major = cpe["baseline"], cpe.get("major", 0)
    ch = (cpe.get("channel") or "").lower()
    channel = "long-term" if "long" in ch else cfg["update"].get("channel", "stable")
    notes: List[str] = [f"channel={channel}"]
    run(conn, f"/system package update set channel={channel}")
    pinned = False
    if major >= 7:
        try:
            run(conn, f"/system package update set version={base}")
            pinned = True
            notes.append(f"pinned updater to {base}")
        except Exception:
            notes.append("version pin not supported on this build; going to latest stable")
    out = run(conn, "/system package update check-for-updates",
              timeout=int(cfg["update"].get("check_timeout", 240)))
    latest = parse_update_latest(out)
    if not latest:
        notes.append("check-for-updates: no newer version reported")
        return {"install_needed": False, "latest": None, "pinned": pinned, "notes": notes}
    if version_compare(latest, cpe["version_num"]) <= 0:
        notes.append(f"updater reports {latest}; device already at {cpe['version_num']}")
        return {"install_needed": False, "latest": latest, "pinned": pinned, "notes": notes}
    if pinned and version_compare(latest, base) != 0:
        notes.append(f"WARNING: updater reports {latest}, expected {base}")
    if not pinned and version_compare(latest, base) < 0:
        notes.append(f"WARNING: latest stable {latest} is below baseline {base}")
    print(f"  update ready: {cpe['version_num']} -> {latest} (baseline {base})")
    return {"install_needed": True, "latest": latest, "pinned": pinned, "notes": notes}


NPK_ARCH = {
    "x86_64": "x86_64", "x86": "x86", "arm64": "arm64", "aarch64": "arm64",
    "arm": "arm", "mipsbe": "mipsbe", "mipsle": "mipsle",
    "powerpc": "powerpc", "ppc": "powerpc", "tile": "tile",
}


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  downloading {url}")
    try:
        urllib.request.urlretrieve(url, str(dest))  # nosec - official mikrotik CDN
    except Exception as e:
        raise RuntimeError(f"download failed: {url}: {e}")


def ensure_npk(version: str, arch: str, cache: str) -> Path:
    tag = NPK_ARCH.get((arch or "").lower().replace(" ", ""))
    if not tag:
        raise RuntimeError(f"unknown architecture '{arch}'; use --update-method auto instead")
    cache_dir = Path(cache)
    major = version.split(".")[0]
    if major == "7":
        name = f"routeros-{version}-{tag}.npk"
        local = cache_dir / name
        if not local.exists():
            _download(f"https://download.mikrotik.com/routeros/{version}/{name}", local)
        return local
    # v6: all_packages zip (historically includes every package for that arch)
    zname = f"all_packages-{tag}-{version}.zip"
    zlocal = cache_dir / zname
    if not zlocal.exists():
        _download(f"https://download.mikrotik.com/routeros/{version}/{zname}", zlocal)
    npk_name = f"routeros-{tag}-{version}.npk"
    local = cache_dir / npk_name
    if not local.exists():
        with zipfile.ZipFile(zlocal) as z:
            member = None
            for n in z.namelist():
                if re.match(rf"routeros-.*-{re.escape(version)}\.npk$", n, re.I):
                    member = n
                    break
            if not member:
                raise RuntimeError(f"routeros package not found inside {zname}")
            local.write_bytes(z.read(member))
    return local


def do_npk_update(conn, cpe: Dict, cfg: Dict) -> Dict[str, Any]:
    base = cpe["baseline"]
    if not isinstance(conn, SSHTransport):
        raise RuntimeError("--update-method npk requires SSH (SFTP) transport")
    npk = ensure_npk(base, cpe.get("arch", ""), cfg["update"].get("npk_cache", "./npk-cache"))
    remote = "/" + npk.name
    print(f"  uploading {npk.name} to {remote}")
    conn.upload(str(npk), remote)
    return {"install_needed": True, "latest": base, "pinned": True,
            "notes": [f"uploaded {npk.name} (installs on reboot)"]}


def run_install(conn) -> None:
    print("  running install ... (device will reboot; connection drop is expected)")
    try:
        conn.run("/system package update install", timeout=300)
    except Exception:
        pass  # connection died = normal
    time.sleep(5)


def wait_offline(cpe: Dict, cfg: Dict) -> bool:
    deadline = time.time() + int(cfg["reboot"].get("offline_timeout", 240))
    ports = cpe.get("ports") or [22, 8728]
    print("  waiting for device to go offline ...")
    while time.time() < deadline:
        if not any(port_open(cpe["ip"], p, 2.0) for p in ports):
            print("  device is offline (rebooting)")
            return True
        time.sleep(3)
    return False


def do_patch_device(cpe: Dict, cfg: Dict, creds: Dict[str, str], opts) -> None:
    conn, transport = open_transport(cpe["ip"], cpe.get("ports") or [],
                                     creds["user"], creds["password"])
    if conn is None:
        cpe["status"] = "failed"
        cpe["notes"] = "cannot connect at patch time"
        return
    try:
        method = cfg["update"].get("method", "auto")
        if method == "auto":
            res = do_auto_update(conn, cpe, cfg)
        elif method == "npk":
            res = do_npk_update(conn, cpe, cfg)
        else:
            raise RuntimeError(f"unknown update method: {method}")
        cpe["notes"] = "; ".join(res["notes"]) or cpe.get("notes", "")
        if not res["install_needed"]:
            cpe["status"] = "completed"
            cpe["notes"] += "; nothing to install"
            return
        if opts.dry_run:
            print("  [dry-run] would run: /system package update install")
            cpe["status"] = "pending"
            return
        if res.get("pinned") and res.get("latest"):
            cpe["target_version"] = res["latest"]
        run_install(conn)
        cpe["status"] = "rebooting"
    finally:
        conn.close()


def run_device(cpe: Dict, cfg: Dict, creds: Dict[str, str], opts, state_path: str, state: Dict) -> None:
    print(f"=> {cpe['identity']:<22} {cpe['ip']:<16} {cpe.get('version_num','?'):<10} "
          f"-> baseline {cpe.get('baseline','?')}")
    if cpe["status"] in ("pending", "patching"):
        cpe["status"] = "patching"
        save_state(state, state_path)
        do_patch_device(cpe, cfg, creds, opts)
        save_state(state, state_path)
    if cpe["status"] == "rebooting":
        if not wait_offline(cpe, cfg):
            cpe["status"] = "failed"
            cpe["notes"] = "device never went offline after install"
            save_state(state, state_path)
            return
        cpe["status"] = "rebooted"
        cpe["notes"] = "install issued; reboot confirmed — verify on next scan/plan cycle"
        save_state(state, state_path)
    stat = {"completed": "OK", "failed": "FAILED", "rebooted": "REBOOTED",
            "pending": "PENDING", "patching": "PATCHING", "skipped": "SKIPPED"}.get(
        cpe["status"], cpe["status"])
    print(f"  -> {stat:<10} {cpe.get('notes','')}")


# ----------------------------------------------------------------------------
# CLI commands
# ----------------------------------------------------------------------------

def cmd_scan(args, cfg) -> None:
    subnet = args.subnet or cfg["scan"].get("subnet")
    if not subnet:
        raise SystemExit("no subnet: pass --subnet or set scan.subnet in config.yaml")
    held = cfg["scan"]["ports"]
    if args.ports:
        held = [int(x) for x in args.ports.split(",") if x.strip()]
        cfg["scan"]["ports"] = held
    if args.threads:
        cfg["scan"]["threads"] = args.threads
    if args.timeout:
        cfg["scan"]["timeout"] = args.timeout

    def progress(done, total):
        print(f"\r  probed {done}/{total}", end="", flush=True)

    found = scan_subnet(subnet, cfg, on_progress=progress)
    print()
    for f in found:
        print(f"  {f['ip']:<16} ports={','.join(map(str, f['ports'])):<12} banner={f['ssh_banner']}")
    out = Path(args.out or f"{cfg['state_dir']}/scan.json")
    state = {"scan": {"spec": subnet, "at": datetime.datetime.now().isoformat(timespec='seconds')},
             "hosts": found}
    save_state(state, str(out))
    print(f"inventory saved: {out}")


def cmd_plan(args, cfg) -> None:
    resolve_baselines(cfg, args, interactive=True)
    creds = resolve_credentials(cfg, args)
    inv_path = Path(args.inventory or f"{cfg['state_dir']}/scan.json")
    state = load_state(str(inv_path))
    hosts = [h for h in state.get("hosts", []) if h.get("mikrotik")]
    print(f"planning {len(hosts)} device(s) ...")
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    cpes = []
    for h in hosts:
        print(f"  {h['ip']} ... ", end="", flush=True)
        e = plan_one(h, creds, cfg, ts)
        cpes.append(e)
        print(f"{e.get('identity','?')}  {e.get('version_num','?')}  [{e.get('status')}]")
    plan = {"baselines": cfg["baselines"], "created_at": ts, "cpes": cpes}
    out = Path(args.out or f"{cfg['state_dir']}/plan.json")
    save_state(plan, str(out))
    done = sum(1 for c in cpes if c["status"] == "completed")
    pend = sum(1 for c in cpes if c["status"] == "pending")
    skip = sum(1 for c in cpes if c["status"] == "skipped")
    print(f"plan saved: {out}  (done={done} pending={pend} skipped={skip})")


# (HTML reporting removed - use patch_cycle.py for version audits)
    """Read-only: identity + OS version + arch/board. No set/install commands."""
    ip = host["ip"]
    ports = host.get("ports") or probe_ports(ip, cfg["scan"]["ports"], cfg["scan"]["timeout"])
    row = {"ip": ip, "ports": ports, "hostname": "", "version": "", "arch": "",
           "board": "", "baseline": "", "status": "unreachable", "notes": ""}
    has_login_port = any(p in ports for p in (22, 8728, 8729))
    if not has_login_port:
        row["status"] = "no transport"
        row["notes"] = "winbox only (8291) - no ssh/api"
        return row
    conn, _ = open_transport(ip, ports, creds["user"], creds["password"])
    if conn is None:
        row["status"] = "auth-failed"
        row["notes"] = "ssh/api reachable but login rejected (wrong user/password?)"
        return row
    try:
        info = fetch_device_info(conn)
    except Exception as e:
        row["status"] = "error"
        row["notes"] = str(e)[:100]
        return row
    finally:
        conn.close()
    row["hostname"] = info.get("identity") or ip
    row["version"] = info.get("version_num") or info.get("version") or "?"
    row["channel"] = info.get("channel") or ""
    row["arch"] = info.get("arch") or ""
    row["board"] = info.get("board") or ""
    sec, sec_note = security_status(row["version"], row["channel"], cfg)
    row["security_status"], row["security_note"] = sec, sec_note
    m = re.search(r"([0-9]+)", row["version"])
    major = int(m.group(1)) if m else 0
    if major in (6, 7):
        base = baseline_for(major, row["channel"], cfg)
        row["baseline"] = base
        if sec == "vulnerable":
            row["status"] = "vulnerable"
            row["notes"] = sec_note
        elif version_compare(row["version"], base or "") >= 0:
            row["status"] = "ok"
            row["notes"] = sec_note if sec == "eol" else ""
        else:
            row["status"] = "update"
            row["notes"] = sec_note if sec == "eol" else ""
    else:
        row["status"] = "other"
        row["notes"] = f"unmanaged RouterOS major ({row['version']})"
    return row




# (HTML reporting removed)

def 
def _ip_key(ip: str):
    try:
        return socket.inet_aton(ip)
    except OSError:
        return b""



def _render_table(entries: List[Dict]) -> None:
    print()
    print(f"{'#':<3} {'STATUS':<10} {'HOSTNAME':<22} {'IP':<16} {'CURRENT':<10} {'BASELINE':<10} NOTES")
    print("-" * 100)
    for i, e in enumerate(entries, 1):
        name = (e.get("identity") or e["ip"])[:22]
        notes = (e.get("notes") or "")[:30]
        print(f"{i:<3} {e.get('status','?')[:10]:<10} {name:<22} {e.get('ip',''):<16} "
              f"{e.get('version_num','?'):<10} {str(e.get('baseline') or '?'):<10} {notes}")
    print()


def run_patch_loop(entries: List[Dict], cfg: Dict, creds: Dict[str, str],
                   opts, state_path: str, state: Dict) -> None:
    idx = 0
    while idx < len(entries):
        e = entries[idx]
        if e["status"] not in STATUS_ACTIVE:
            idx += 1
            continue
        _render_table(entries)
        if opts.auto:
            choice = str(idx + 1)
        else:
            choice = input(
                f"approve device #{idx+1} ({e.get('identity','?')})?  [1..n]=pick, a=all, "
                "r=refresh, q=quit > ").strip().lower()
        if choice in ("q", "quit", "exit"):
            print("bye")
            break
        if choice in ("r", "refresh", ""):
            continue
        if choice == "a":
            for sub in list(entries):
                if sub["status"] in STATUS_ACTIVE:
                    run_device(sub, cfg, creds, opts, state_path, state)
            break
        try:
            n = int(choice)
        except ValueError:
            print(f"  unknown input: {choice}")
            continue
        if n < 1 or n > len(entries):
            print(f"  index out of range: {n}")
            continue
        run_device(entries[n - 1], cfg, creds, opts, state_path, state)


def cmd_patch(args, cfg) -> None:
    creds = resolve_credentials(cfg, args)
    plan_path = Path(args.plan or f"{cfg['state_dir']}/plan.json")
    state = load_state(str(plan_path))
    lock = acquire_lock(str(plan_path.with_name(plan_path.name + ".lock")))
    try:
        entries = state["cpes"]
        active = [e for e in entries if e["status"] in STATUS_ACTIVE]
        if not active:
            print("nothing to approve - no pending devices")
            return
        print(f"patch session: {len(active)} device(s) awaiting approval "
              f"(update method: {cfg['update'].get('method','auto')})")
        if args.dry_run:
            print("dry-run mode - showing update plan, not executing")
            for e in active:
                print(f"  {e.get('identity'):<22} {e['ip']:<16} "
                      f"{e.get('version_num','?')} -> baseline {e.get('baseline')}")
                print("      /system package update set channel=stable")
                if e.get("major", 0) >= 7:
                    print(f"      /system package update set version={e.get('baseline')}")
                print("      /system package update check-for-updates")
                print("      /system package update install   (+ reboot; next scan/plan verifies)")
            return
        run_patch_loop(entries, cfg, creds, args, str(plan_path), state)
    finally:
        lock.close()
    save_state(state, str(plan_path))
    print(f"state saved: {plan_path}")


STATUS_LABEL = {"pending": "pending", "patching": "patching", "rebooting": "rebooting",
                "rebooted": "rebooted", "completed": "done", "failed": "failed",
                "skipped": "skipped"}


def cmd_report(args, cfg) -> None:
    plan_path = Path(args.plan or f"{cfg['state_dir']}/plan.json")
    state = load_state(str(plan_path))
    entries = state["cpes"]
    _render_table(entries)
    counts: Dict[str, int] = {}
    for e in entries:
        s = STATUS_LABEL.get(e.get("status", "?"), "?")
        counts[s] = counts.get(s, 0) + 1
    print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if args.json:
        print(json.dumps(state, indent=2))


def cmd_inventory(args, cfg) -> None:
    plan_path = Path(args.plan or f"{cfg['state_dir']}/plan.json")
    state = load_state(str(plan_path))
    entries = [e for e in state["cpes"]
               if e["status"] in STATUS_ACTIVE and e.get("identity")]
    user = cfg["credentials"].get("username")
    if not user:
        raise SystemExit("username required for inventory export (pass --user or set credentials.username)")
    lines = ["[cpe_pending]"]
    for e in entries:
        line = (f"{e['identity']} ansible_host={e['ip']} ansible_user={user} "
                "ansible_network_os=community.routeros.routeros "
                "ansible_connection=ansible.netcommon.network_cli")
        if args.include_pass:
            pw = os.environ.get(cfg["credentials"].get("password_env") or "MIKROTIK_PASSWORD", "")
            if pw:
                line += f" ansible_ssh_pass={pw}"
        lines.append(line)
    if args.out:
        Path(args.out).write_text("\n".join(lines) + "\n")
        print(f"ansible inventory saved: {args.out} ({len(entries)} host(s))")
    else:
        print("\n".join(lines))


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=None, help="YAML config (see config.example.yaml)")
    ap = argparse.ArgumentParser(
        prog="cpe_patcher",
        description="Monthly MikroTik CPE patcher: scan -> plan -> approve -> patch/reboot -> next scan verifies")
    ap.add_argument("--config", default=None, help="YAML config (see config.example.yaml)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = ap.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", parents=[common], help="probe a subnet/IP range for MikroTik CPEs")
    p_scan.add_argument("--subnet", default=None, help="CIDR or range; defaults to scan.subnet in config.yaml")
    p_scan.add_argument("--ports", default=None, help="comma list, default 22,8291,8728,8729")
    p_scan.add_argument("--threads", type=int, default=None)
    p_scan.add_argument("--timeout", type=float, default=None)
    p_scan.add_argument("--out", default=None, help="inventory JSON path")

    p_plan = sub.add_parser("plan", parents=[common], help="login, read version, compute gap to baselines")
    p_plan.add_argument("--inventory", default=None, help="scan JSON (default state/scan.json)")
    p_plan.add_argument("--baseline-v6", default=None)
    p_plan.add_argument("--baseline-v7", default=None,
                        help="v7 stable baseline (default 7.24.2 - fixed version)")
    p_plan.add_argument("--baseline-v7-longterm", default=None,
                        help="v7 long-term baseline (default 7.23.4 - fixed version)")
    p_plan.add_argument("--user", default=None)
    p_plan.add_argument("--out", default=None, help="plan JSON path")

    p_patch = sub.add_parser("patch", parents=[common], help="interactive per-device approval + update + reboot + verify")
    p_patch.add_argument("--plan", default=None, help="plan JSON (default state/plan.json)")
    p_patch.add_argument("--user", default=None)
    p_patch.add_argument("--auto", action="store_true", help="approve all without prompting")
    p_patch.add_argument("--dry-run", action="store_true", help="show commands only")

    p_rep = sub.add_parser("report", help="show status of the last plan")
    p_rep.add_argument("--plan", default=None)
    p_rep.add_argument("--json", action="store_true")

    p_inv = sub.add_parser("inventory", help="export pending CPEs as an Ansible inventory")
    p_inv.add_argument("--plan", default=None)
    p_inv.add_argument("--out", default=None)
    p_inv.add_argument("--include-pass", action="store_true", help="embed ssh password in inventory")

    args = ap.parse_args(argv)
    cfg = load_config(args.config)

    try:
        if args.command == "scan":
            cmd_scan(args, cfg)
        elif args.command == "plan":
            cmd_plan(args, cfg)
        elif args.command == "patch":
            cmd_patch(args, cfg)
        elif args.command == "report":
            cmd_report(args, cfg)

        elif args.command == "inventory":
            cmd_inventory(args, cfg)
    except (KeyboardInterrupt, EOFError):
        print("\ninterrupted - state preserved in JSON, resume later")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())