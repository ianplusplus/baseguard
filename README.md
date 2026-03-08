# baseguard

A lightweight host-based intrusion detection script for Linux that creates a system baseline and alerts you when anything changes.

---

## Overview

`baseguard` captures a snapshot of your Linux system's state and compares it on every subsequent run, reporting anything that has been added, changed, or removed. It is designed to be simple to deploy, easy to understand, and useful on any modern Linux distribution.

On first run it creates a baseline. On every run after that it compares the current system state against the baseline and reports differences — optionally sending an email alert via AWS SES.

---

## What It Monitors

| Category | Details |
|---|---|
| **Processes** | Running processes by user and full command line |
| **Listening Ports** | Active TCP/UDP listeners and the processes behind them |
| **Systemd Units** | All enabled units — a common persistence vector |
| **Cron Jobs** | System-wide and per-user crontabs |
| **Binary Hashes** | SHA256 of every executable in `/bin`, `/usr/bin`, `/usr/sbin`, `/sbin` |
| **Kernel Modules** | Loaded modules — rootkits often load here |
| **SUID Binaries** | All setuid files on the filesystem |
| **SSH Config** | Hashes of `sshd_config`, `authorized_keys`, and related files |
| **User Accounts** | `/etc/passwd`, `/etc/shadow` status, and sudo group membership |

---

## Requirements

- Bash 4+
- Root access (for full visibility)
- Standard tools: `ps`, `ss` or `netstat`, `sha256sum`, `find`, `systemctl`, `lsmod`, `flock`

For email alerts:
- Postfix configured to relay through AWS SES (or any SMTP relay)
- `mailx` or `sendmail`

Install dependencies on Debian/Ubuntu:
```bash
sudo apt install -y coreutils procps iproute2 util-linux mailutils
```

Install dependencies on RHEL/CentOS/Fedora:
```bash
sudo dnf install -y coreutils procps-ng iproute util-linux mailx
```

---

## Installation

```bash
sudo cp baseguard.sh /usr/local/bin/baseguard.sh
sudo chmod 700 /usr/local/bin/baseguard.sh
sudo chown root:root /usr/local/bin/baseguard.sh
```

---

## Usage

```bash
# First run — create baseline
sudo baseguard.sh

# Subsequent runs — compare against baseline
sudo baseguard.sh

# Reset baseline (backs up existing before clearing)
sudo baseguard.sh --reset

# Show help
sudo baseguard.sh --help
```

---

## Email Alerts

Set `ALERT_EMAIL` in the script or as an environment variable to receive alerts when changes are detected. Alerts are rate-limited — if the same changes are detected on consecutive runs, only one email is sent.

```bash
# One-off override
sudo ALERT_EMAIL=you@example.com baseguard.sh
```

Or set it permanently by editing the variable near the top of the script:
```bash
ALERT_EMAIL="${ALERT_EMAIL:-you@example.com}"
```

### AWS SES Setup

1. Verify your sending domain or address in the AWS SES console
2. Create SMTP credentials: SES Console → SMTP Settings → Create SMTP Credentials
3. Install and configure Postfix:

```bash
sudo apt install postfix libsasl2-modules -y
```

Add to `/etc/postfix/main.cf`:
```
relayhost = [email-smtp.us-east-1.amazonaws.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_security_options = noanonymous
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_use_tls = yes
smtp_tls_security_level = encrypt
smtp_generic_maps = hash:/etc/postfix/generic
smtp_header_checks = regexp:/etc/postfix/header_checks
```

Create `/etc/postfix/sasl_passwd`:
```
[email-smtp.us-east-1.amazonaws.com]:587 SMTP_USERNAME:SMTP_PASSWORD
```

Create `/etc/postfix/generic` (replace with your verified sender):
```
@yourhostname    Your Name <you@yourdomain.com>
```

Create `/etc/postfix/header_checks`:
```
/^From:.*/ REPLACE From: Your Name <you@yourdomain.com>
```

```bash
sudo postmap /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/generic
sudo postmap /etc/postfix/header_checks
sudo systemctl restart postfix
```

---

## Automating with Cron

Run as root for full visibility:

```bash
sudo crontab -e
```

Add:
```
0 * * * * umask 077; /usr/local/bin/baseguard.sh >> /root/.baseline_monitor/reports/cron.log 2>&1
```

> The `umask 077` ensures `cron.log` is created `600` (owner-only). Without it, shell redirection uses the default umask and the log file may be world-readable.

---

## File Structure

```
~/.baseline_monitor/
├── processes.baseline       # Baseline process snapshot
├── network.baseline         # Baseline listening ports
├── systemd.baseline         # Baseline enabled systemd units
├── cron.baseline            # Baseline cron jobs
├── binaries.baseline        # Baseline binary hashes
├── kmods.baseline           # Baseline kernel modules
├── suid.baseline            # Baseline SUID binaries
├── ssh.baseline             # Baseline SSH config hashes
├── users.baseline           # Baseline user accounts
├── baseline.sha256          # Integrity hash of all baseline files
├── last_alert.sha256        # Hash of last alert sent (rate limiting)
├── backups/                 # Timestamped baseline backups
│   └── baseline_YYYY-MM-DD_HH-MM-SS.tar.gz
└── reports/                 # Timestamped comparison reports
    └── YYYY-MM-DD_HH-MM-SS.txt
```

---

## Security Notes

**Baseline trust** — if malware is already present when the baseline is created, it will be treated as trusted. For best results, create the baseline immediately after a clean OS install.

**Kernel rootkits** — if a rootkit has compromised the kernel, it can hide processes and ports from `ps` and `ss`. This script cannot detect what the kernel itself conceals.

**Baseline integrity** — all baseline files are protected with SHA256 hashes and `chmod 600` permissions. The baseline directory and its `backups/` and `reports/` subdirectories are all `chmod 700`. If the integrity check fails at comparison time, the script will refuse to run and alert you to possible tampering.

---

## Suspicious Port Detection

The script flags known attacker ports even if they were present at baseline time:

`4444` `5555` `6666` `9001` `1337` `31337` `1234` `6667` `6668` `6669` `8888`

These are commonly used for reverse shells, C2 servers, and backdoors.

---

## Known Limitations

- Baseline trust problem shared by all HIDS tools — mitigated by baselining on a clean install
- Kernel-level rootkits can conceal processes and ports
- Binary hash scanning and SUID scanning perform a full filesystem walk and may take several seconds on large systems

---

## Comparison to Other Tools

| Tool | Language | File Integrity | Process Monitor | Network Monitor | Lightweight |
|---|---|---|---|---|---|
| **baseguard** | Bash | ✓ | ✓ | ✓ | ✓ |
| Tripwire | C | ✓ | ✗ | ✗ | ✗ |
| AIDE | C | ✓ | ✗ | ✗ | ✗ |
| OSSEC | C | ✓ | ✓ | ✓ | ✗ |
| Wazuh | C | ✓ | ✓ | ✓ | ✗ |

---

## License

MIT License — see [LICENSE](LICENSE) for details.
