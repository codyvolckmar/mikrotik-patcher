# mikro-cpe-patch

Monthly patching tool for a fleet of MikroTik CPEs (RouterOS 6 & 7).

```
scan  ->  plan  ->  patch (approve one at a time)  ->  reboot  ->  next scan verifies
```

* **scan** — probe a subnet / IP range, find RouterOS devices (SSH 22, Winbox 8291,
  API 8728/8729, SSH banner fingerprint). Read-only, safe to run from cron.
* **plan** — log in with runtime credentials, read **hostname (identity)**, OS version,
  CPU architecture **and release channel** (stable vs long-term); compare against the
  **baseline you choose per channel** (v6 → 6.49.18, v7 stable → 7.24.2, v7 long-term →
  7.23.4) and flag **vulnerable** devices; stages the exact upgrade commands.
* **patch** — shows every candidate as *hostname | IP | current | baseline* and makes you
  **approve them one at a time** (`1..n`, `a` = all, `q` = quit, state is saved after every
  step so Ctrl-C is safe and you can resume).
* **reboot + verify by fresh scan** — after `install` the device reboots; the tool confirms
  it went offline and marks it **rebooted**. Because CPE public IPs often change on reboot,
  the tool does **no** reconnect logic — you simply re-run `scan` + `plan` (or wait for the
  next monthly cycle) and patched devices gradually appear **already at baseline**.

## Why Python (not bash, not Ansible)?

| need                              | bash        | Ansible (community.routeros)      | this tool |
|-----------------------------------|-------------|-----------------------------------|-----------|
| parallel port scan                | nmap glue  | not its job                       | threads   |
| SSH + RouterOS API + SFTP upload  | expect/ssh | network_cli/api connectors        | paramiko + routeros_api |
| interactive one-by-one approvals  | painful    | not its job                       | built in  |
| re-run scan to confirm progress | nmap glue | custom modules                  | built in  |
| exact version pinning             | manual     | manual                            | auto/npk  |

Ansible is still a good fit if you already run it: `cpe_patcher.py inventory` exports the
pending CPEs as an Ansible inventory, and `ansible/patch-cpes.yml` is a starter playbook.

## Install

```bash
cd /root/mikro-cpe-patch
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp config.example.yaml config.yaml && $EDITOR config.yaml   # baselines, defaults
```

## Usage

```bash
# 1. discover devices (read-only) - can be automated monthly
.venv/bin/python cpe_patcher.py scan --config config.yaml

# 2. login at runtime, read versions, set baselines (prompts, or flags below)
.venv/bin/python cpe_patcher.py plan --config config.yaml \
    --baseline-v6 6.49.18 --baseline-v7 7.24.2 --baseline-v7-longterm 7.23.4
#    -> asks RouterOS username + password at the prompt (or export MIKROTIK_PASSWORD)

# 3. approve one device at a time: update -> reboot; verification is the NEXT scan/plan
.venv/bin/python cpe_patcher.py patch --config config.yaml
#    -> shows the table, waits for your per-host approval
#    (--auto to approve all, --dry-run to only print commands)

# 3b. next cycle: fresh discovery + plan shows who has come up to baseline
.venv/bin/python cpe_patcher.py scan --config config.yaml
.venv/bin/python cpe_patcher.py plan --config config.yaml

# 4. status any time
.venv/bin/python cpe_patcher.py report --config config.yaml          # table
.venv/bin/python cpe_patcher.py report --config config.yaml --json   # machine readable
```

## Read-only audit before patching (no changes to CPEs)

Nervous about the rollout? Do a read-only reconnaissance pass first: it logs into every
device with the **`cg-readonly`** account and writes a sortable **HTML report** of
hostnames, OS versions, and how far each device is from the v6/v7 baselines.

```bash
cd /root/mikro-cpe-patch
export MIKROTIK_PASSWORD='readonly-password'      # password prompt also works
.venv/bin/python cpe_patcher.py versions --config config.yaml
# -> state/versions.html (open in a browser)
```

* Runs **only** `/system identity print`, `/system resource print` and
  `/interface ethernet print detail` — read-only, nothing is set or installed.
* The report is **skinned to CloudGistics branding** (mirrors www.cloudgistics.net): dark
  `#0a0e17` background, cyan `#00d4ff` → purple `#7c3aed` gradient accents, Inter +
  JetBrains Mono fonts, a network-edge background, and the CloudGistics logo + BGP ASN
  328970 header. It's a single self-contained HTML file (fonts load from Google Fonts,
  so a browser with internet renders it fully).
* Logs in as `credentials.readonly_username` (default **`cg-readonly`**); per-run override
  with `--user <name>`.
* Does **not** touch `plan.json` — it cannot accidentally start a patch.
* Statuses per device: **VULNERABLE (security fix available)** | **at/above baseline** |
  **update available** | **login rejected** | **winbox only (no ssh/api)** |
  **unmanaged major**. Columns are sortable (click header).
* `--threads` controls parallel logins (default **16**, capped at 24 — be polite to the
  CPEs), `--out <path>` sets the HTML file.

## Vulnerability checking (v7 security thresholds)

Both v7 trains recently shipped security fixes. The tool's `versions` audit, `plan`, and
`report` flag devices below the fixed versions and warn you before patching:

| Channel     | Vulnerable | Fixed in | Baselines use |
|-------------|------------|----------|---------------|
| v7 stable   | ≤ 7.24.1   | 7.24.2   | `baselines.v7` = 7.24.2 |
| v7 long-term| ≤ 7.23.3   | 7.23.4   | `baselines.v7_longterm` = 7.23.4 |
| v6 (EOL)    | all        | none     | 6.49.18 (final) |

Behavior:
* Every device's **release channel** is read from `/system package update print` (read-only)
  and shown in the audit report — a stable-train box is judged against 7.24.2, a
  long-term box against 7.23.4.
* Devices below the fixed version get status **VULNERABLE** (red) in `versions.html` and a
  `VULNERABLE (fixed in 7.24.2/7.23.4)` note in the `patch` approval prompt.
* `patch` **preserves the device's channel**: long-term devices update to the long-term
  baseline, stable devices to the stable baseline (change `update.channel` to force stable).
* Old v7 baselines (≤ 7.24.1 / ≤ 7.23.3) are never used by default — the defaults in
  `config.yaml` are the fixed versions. Don't lower them below the fixed versions.

## Monthly automation (scan only — approvals stay manual)

systemd:
```bash
cp systemd/mikrotik-cpe-scan.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now mikrotik-cpe-scan.timer
systemctl list-timers mikrotik-cpe-scan.timer
```
cron equivalent:
```
0 2 1 * *  /opt/mikro-cpe-patch/.venv/bin/python /opt/mikro-cpe-patch/cpe_patcher.py scan --config /opt/mikro-cpe-patch/config.yaml
```

## How the update works

**auto (default):**
```
/system package update set channel=stable       # or long-term, preserved per device
/system package update set version=7.24.2        # v7.15+ only, pins the exact baseline
/system package update check-for-updates
/system package update install                # downloads from MikroTik, reboots
```
RouterOS 6 has no version pin — the updater lands on the last v6 stable (6.49.18).
If you must pin an *exact* v6 version, use:

**npk** (`update.method: npk` in config):
```
downloads routeros-<ver>-<arch>.npk from download.mikrotik.com
SFTP-uploads it to the CPE, reboots -> RouterOS installs it on boot
```

## Verification model (no reconnect logic)

CPE public IPs change on every reboot, so the tool makes no attempt to follow a patched
device to its new address:

1. `patch` runs `install`, waits for the device to **go offline** (confirms the reboot
   started) and marks it **`rebooted`** (`reboot.offline_timeout`).
2. Verification is the **next `scan` + `plan` cycle** — re-run both (or just wait for the
   monthly scan timer). Devices that finished appear with their new version and are marked
   **already at/above baseline**, no action needed. Devices you haven't touched yet stay
   in the approval list.
3. That's the whole loop: approve → reboot → next cycle confirms. `report` shows the
   current plan's state (**pending / rebooted / failed** …) from the last run.

## Safety checklist

* Test on **one** CPE first (`patch`, approve just the first row), confirm the version
  shows up at baseline on the next `plan`, then do the rest.
* `plan` and `report` are read-only. `patch --dry-run` prints everything without touching
  devices.
* Back up configs before large runs:
  `/system export file=pre-update-backup` (or `fetch` them out beforehand).
* Credentials: prefer `export MIKROTIK_PASSWORD=...` or the getpass prompt over
  embedding them in config/cron. Don't run the patch over raw public internet without
  SSH/API firewall allowance — put this box on the management network or VPN.
* Two `patch` runs at once are blocked by a file lock (plan file `.lock`).
* v6 is EOL at MikroTik: 6.49.18 is the last v6 build. A long-term v6→v7 migration
  is a separate project — this tool keeps 6.x and 7.x on their own baselines.

## Troubleshooting

* **"no reachable transport"** — API port (8728/8729) and SSH must be reachable from the
  patch box. Many CPEs only expose Winbox; open SSH on the management interface first.
* **scan finds nothing** — raise `scan.timeout`, or the range is behind NAT; scan from
  inside the management network.
* **"version pin not supported"** — device is v6 or old v7; it will take latest stable,
  or switch to `method: npk` for an exact pin.
* **update never finishes** — slow CPE uplink; raise `update.check_timeout` / install poll.
* **device stays `rebooted` in `report`** — that's expected: confirmation comes from the
  next `scan`/`plan` cycle. To see it sooner, re-run `scan` then `plan`; the device will
  show its new version and be marked as already at baseline. If it *never* reappears,
  check it manually (new public IP, firewall, power).

## Files

```
cpe_patcher.py            main tool (scan/plan/patch/report/inventory)
config.example.yaml       configuration template
requirements.txt          python dependencies
systemd/                  monthly scan service + timer
ansible/patch-cpes.yml    optional Ansible playbook (community.routeros)
state/                    scan.json / plan.json (created at runtime)
npk-cache/                downloaded .npk packages (method: npk)
```