# SentinelForge

SentinelForge is a modular, production-grade Bash toolkit for hardening Ubuntu and Debian VPS hosts. It ships with an interactive TUI, in-depth SSH auditing, firewall guardrails, Fail2ban provisioning, sysctl profiles, and update awareness — all without depending on any third-party scripts.

> **Important:** SentinelForge improves baseline hardening but cannot withstand massive, sustained DDoS campaigns or replace upstream network mitigation.

## Highlights
- **Self-contained security companion** — no external integrations, re-implemented SSH audit, firewall guidance, and hardening logic within the project.
- **Safety-first workflows** — every SSH or firewall mutation preserves current access, creates timestamped backups, and prints recovery commands.
- **Modular architecture** — core helpers live under `src/core/`, features under `src/features/`, templated assets in `share/templates/`, and configs in `etc/`.
- **Rich dashboard** — color banner, 30-character security score bar, SSH awareness matrix, firewall/Fail2ban/sysctl summaries, update telemetry, and repo footer.
- **Layered DDoS defense** — apply SentinelForge guard chains, curate ipset/nftables blocklists, tune kernel parameters, and deploy the MIT-licensed Lua challenge for nginx/OpenResty.
- **Installer with dependency management** — `scripts/install.sh` ensures apt package lists are fresh and installs required packages (openssh-server, ufw, fail2ban, etc.).
- **AGPL-3.0 licensed** — source and installer carry SPDX headers; LICENSE bundled.

## Directory Layout
```
bin/                    # CLI entrypoint (sentinelforge)
src/core/               # Colors, UI, utils, detection, scoring modules
src/features/           # SSH, firewall, fail2ban, sysctl, updates, dashboard logic
etc/                    # Default configuration + sysctl profile sample
share/templates/        # Fail2ban + nginx anti-DDoS templates
scripts/                # install/uninstall/doctor/purge helpers
tests/                  # bats tests (optional)
```

## Installation
### Local checkout
```bash
sudo ./scripts/install.sh
```

### Remote install
```bash
curl -fsSL https://raw.githubusercontent.com/YrustPd/SentinelForge/main/scripts/install.sh | sudo bash
```
The installer:
1. Verifies root/sudo access.
2. Runs `apt-get update` when package lists are missing or stale.
3. Installs required packages if absent (openssh-server, whiptail, ufw, fail2ban, iproute2, coreutils, grep/gawk/sed, procps, curl, ca-certificates, make, git).
4. Copies SentinelForge to `/usr/local/share/sentinelforge`, installs the CLI to `/usr/local/bin/sentinelforge`, and seeds `/etc/sentinelforge.conf` if missing.

Reinstall using `./scripts/install.sh --reinstall`. Uninstall with `./scripts/install.sh --uninstall` (configuration/backups remain intact), or run `sudo ./scripts/uninstall.sh --purge` to remove SentinelForge and all of its data and DDoS artifacts.

## Usage
Run the dashboard as root:
```bash
sudo sentinelforge
```
Main actions:
1. Review the system overview, live security score, and top talkers.
2. Manage SSH (audit report, key onboarding, port changes, password/root hardening).
3. Guide the firewall backend (UFW/nftables/iptables), rate limiting, and allowlists.
4. Harden against DDoS (apply iptables/nftables guard chains, curate ipset/nft blocklists, apply SentinelForge kernel profile, run Gatekeeper readiness checks, and deploy the nginx Lua challenge derived from MIT scripts).
5. Provision and monitor Fail2ban jails for sshd (and optional nginx-http-auth).
6. System maintenance: apply the baseline sysctl profile, manage unattended-upgrades, check for SentinelForge updates, or launch the uninstall/purge workflows.
7. Exit the dashboard.

`sentinelforge --version` prints the current release, maintainer, and repo URL. `sentinelforge --doctor` executes dependency checks via `scripts/doctor.sh`.

## Safety Guarantees
- SSH changes: always backup `/etc/ssh/sshd_config` to `/etc/sentinelforge/backups`, validate with `sshd -t`, and reload the service only after success.
- Firewall changes: detect backend (UFW/nftables/iptables), allow the active SSH port before applying default deny rules, and confirm each step interactively.
- Fail2ban + sysctl: previous files are copied with timestamps prior to writes; instructions are printed for recovery.
- Logging: `/var/log/sentinelforge.log` captures actions and errors.

## Testing & Linting
- `make lint` runs shellcheck when available.
- `make test` runs Bats tests when the `bats` binary is present.

## License
SentinelForge is licensed under the **GNU Affero General Public License v3.0**. See `LICENSE` for the complete text. All scripts declare `SPDX-License-Identifier: AGPL-3.0-only`.

Third-party components and their MIT license texts are listed in `THIRD_PARTY_LICENSES.md`.
