#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# baseline_monitor.sh — Mini HIDS
#
# Monitors: processes, listening ports, systemd units, cron jobs, binary hashes
#
# First run  : creates baseline + SHA256 integrity hash
# Later runs : verifies baseline integrity, compares, saves timestamped report
#
# Usage:
#   ./baseline_monitor.sh             # create baseline or compare
#   ./baseline_monitor.sh --reset     # backup + delete baseline for a fresh one
#   ./baseline_monitor.sh --help      # show usage
#
# Recommended: run as root for full visibility
#   sudo ./baseline_monitor.sh
#
# Email alerts: export ALERT_EMAIL=you@example.com

BASELINE_DIR="${HOME}/.baseline_monitor"
PROCESS_BASELINE="${BASELINE_DIR}/processes.baseline"
NETWORK_BASELINE="${BASELINE_DIR}/network.baseline"
SYSTEMD_BASELINE="${BASELINE_DIR}/systemd.baseline"
CRON_BASELINE="${BASELINE_DIR}/cron.baseline"
BINARY_BASELINE="${BASELINE_DIR}/binaries.baseline"
KMODS_BASELINE="${BASELINE_DIR}/kmods.baseline"
SUID_BASELINE="${BASELINE_DIR}/suid.baseline"
SSH_BASELINE="${BASELINE_DIR}/ssh.baseline"
USERS_BASELINE="${BASELINE_DIR}/users.baseline"
REPORTS_DIR="${BASELINE_DIR}/reports"
BACKUP_DIR="${BASELINE_DIR}/backups"
ALERT_HASH_FILE="${BASELINE_DIR}/last_alert.sha256"
LOCK_FILE="${BASELINE_DIR}/.lock"
ALERT_EMAIL="${ALERT_EMAIL:-}"

# ── Distro detection ──────────────────────────────────────────────────────────

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID,,}"
        DISTRO_LIKE="${ID_LIKE,,}"
    elif command -v lsb_release &>/dev/null; then
        DISTRO_ID=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        DISTRO_LIKE=""
    else
        DISTRO_ID="unknown"
        DISTRO_LIKE=""
    fi
}

is_debian_based() {
    [[ "${DISTRO_ID}" == "debian" || "${DISTRO_ID}" == "ubuntu" ||        "${DISTRO_LIKE}" == *"debian"* || "${DISTRO_LIKE}" == *"ubuntu"* ]]
}

is_rhel_based() {
    [[ "${DISTRO_ID}" == "rhel" || "${DISTRO_ID}" == "centos" ||        "${DISTRO_ID}" == "fedora" || "${DISTRO_ID}" == "almalinux" ||        "${DISTRO_ID}" == "rocky" || "${DISTRO_LIKE}" == *"rhel"* ||        "${DISTRO_LIKE}" == *"fedora"* ]]
}

# Directories to hash for file integrity monitoring
BINARY_DIRS=(/bin /usr/bin /usr/sbin /sbin)

# ── Colours ───────────────────────────────────────────────────────────────────

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
MAGENTA="\e[35m"
BOLD="\e[1m"
RESET="\e[0m"

# ── Known suspicious ports (reverse shells, C2, backdoors) ───────────────────

SUSPICIOUS_PORTS=(4444 5555 6666 9001 1337 31337 1234 6667 6668 6669 8888)

# ── Lock file — prevent concurrent runs (e.g. cron overlap) ──────────────────

acquire_lock() {
    mkdir -p "${BASELINE_DIR}"
    chmod 700 "${BASELINE_DIR}"
    exec 9>"${LOCK_FILE}"
    if ! flock -n 9; then
        echo -e "${YELLOW}[!] Another instance is already running. Exiting.${RESET}"
        exit 1
    fi
}

# ── Dependency check ──────────────────────────────────────────────────────────

check_deps() {
    detect_distro
    local missing=()
    for cmd in ps sort comm sha256sum stat tar flock; do
        command -v "${cmd}" >/dev/null 2>&1 || missing+=("${cmd}")
    done
    if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
        missing+=("ss or netstat")
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[!] Missing required commands: ${missing[*]}${RESET}"
        if is_debian_based; then
            echo -e "${RED}    Try: sudo apt install -y coreutils procps iproute2 util-linux mailutils${RESET}"
        elif is_rhel_based; then
            echo -e "${RED}    Try: sudo dnf install -y coreutils procps-ng iproute util-linux mailx${RESET}"
        else
            echo -e "${RED}    Install the missing commands using your package manager.${RESET}"
        fi
        exit 1
    fi
}

# ── Privilege warning ─────────────────────────────────────────────────────────

check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[!] Not running as root — some process/port/cron details may be hidden.${RESET}"
        echo -e "${YELLOW}    Re-run with sudo for full visibility.${RESET}"
        echo ""
    fi
}

# ── Data collection ───────────────────────────────────────────────────────────

get_processes() {
    # Filter transient processes that cause false positives:
    # - kworker threads change task names constantly
    # - postfix workers appear briefly during email sends
    # - sshd session processes appear/disappear with connections
    # - cron execution processes only exist while cron is running the script
    # - fwupd runs intermittently for firmware checks
    # - sudo/bash/sh invocations of this script are transient
    ps -eo user,cmd --no-headers \
        | grep -v '\[kworker/' \
        | grep -v '^postfix\s\+cleanup\|^postfix\s\+smtp\|^postfix\s\+trivial-rewrite\|^postfix\s\+bounce\|^postfix\s\+local\|^postfix\s\+pipe\|^postfix\s\+virtual' \
        | grep -v '^sshd\s\+sshd:' \
        | grep -v '/usr/sbin/CRON\|/bin/sh -c.*baseline_monitor\|sudo.*baseline_monitor\|fwupd' \
        | grep -v '^[a-z]\+\s\+-bash$\|^[a-z]\+\s\+-sh$' \
        | sort -u
}

get_network() {
    if command -v ss &>/dev/null; then
        ss -lntup 2>/dev/null \
            | tail -n +2 \
            | awk '{print $1, $2, $5, $7}' \
            | sed 's/,fd=[0-9]*//g' \
            | sort -u
    else
        netstat -lntup 2>/dev/null \
            | awk 'NR>2 && /LISTEN/ {print $1, $6, $4, $7}' \
            | sort -u
    fi
}

get_systemd_units() {
    if ! command -v systemctl &>/dev/null; then
        echo "systemctl not available"
        return
    fi
    # Capture enabled units — these survive reboots and are a common persistence vector
    systemctl list-unit-files --state=enabled --no-legend 2>/dev/null \
        | awk '{print $1, $2}' \
        | sort -u
}

get_cron_jobs() {
    # Strip comments, blank lines, and volatile timestamp lines from crontab output
    # to avoid false positives on every crontab edit
    _clean_crontab() {
        grep -v '^\s*#'         | grep -v '^\s*$'         | sort -u
    }

    {
        # /etc/crontab and /etc/cron.d/
        if [[ -f /etc/crontab ]]; then
            _clean_crontab < /etc/crontab || true
        fi
        for f in /etc/cron.d/*; do
            [[ -f "${f}" ]] || continue
            _clean_crontab < "${f}" || true
        done
        # cron.hourly/daily/weekly/monthly (list scripts only, not content)
        for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
            [[ -d "${dir}" ]] || continue
            ls -1 "${dir}" 2>/dev/null || true
        done
        # Per-user crontabs
        # Debian/Ubuntu: /var/spool/cron/crontabs/
        # RHEL/CentOS:   /var/spool/cron/
        # Arch:          /var/spool/cron/tabs/
        if [[ $EUID -eq 0 ]]; then
            for spool_dir in /var/spool/cron/crontabs /var/spool/cron/tabs /var/spool/cron; do
                [[ -d "${spool_dir}" ]] || continue
                for f in "${spool_dir}"/*; do
                    [[ -f "${f}" ]] || continue
                    _clean_crontab < "${f}" || true
                done
            done
        else
            crontab -l 2>/dev/null | _clean_crontab || true
        fi
    } | sort -u
}

get_binary_hashes() {
    # SHA256 every executable in monitored dirs — the core of file integrity monitoring
    for dir in "${BINARY_DIRS[@]}"; do
        [[ -d "${dir}" ]] || continue
        find "${dir}" -maxdepth 1 -type f -executable -print0 2>/dev/null \
            | sort -z \
            | xargs -0 sha256sum 2>/dev/null \
            || true
    done
}


get_kernel_modules() {
    if ! command -v lsmod &>/dev/null; then
        echo "lsmod not available"
        return
    fi
    lsmod | tail -n +2 | awk '{print $1}' | sort -u
}

get_suid_binaries() {
    # SUID files outside expected system paths are a red flag for privilege escalation implants
    find / -xdev -perm -4000 -type f 2>/dev/null | sort -u || true
}

get_ssh_config() {
    # Hash SSH config files — attackers modify these to weaken auth or add backdoor keys
    local ssh_files=(
        /etc/ssh/sshd_config
        /etc/ssh/ssh_config
        /root/.ssh/authorized_keys
        "${HOME}/.ssh/authorized_keys"
    )
    {
        for f in "${ssh_files[@]}"; do
            [[ -f "${f}" ]] || continue
            sha256sum "${f}" 2>/dev/null || true
        done
        if [[ -d /etc/ssh/sshd_config.d ]]; then
            find /etc/ssh/sshd_config.d -type f 2>/dev/null \
                | sort | xargs sha256sum 2>/dev/null || true
        fi
    } | sort -u
}

get_user_accounts() {
    # Detect new accounts, UID 0 backdoors, added sudo members, or changed shells
    {
        echo "=== /etc/passwd ==="
        cut -d: -f1,3,4,6,7 /etc/passwd 2>/dev/null | sort || true
        echo "=== /etc/shadow ==="
        # Track whether a password is set — avoids false positives from routine password changes
        awk -F: '$2 != "" && $2 != "!" && $2 != "*" {print $1, "has_password"}
                 $2 == "!" || $2 == "*"             {print $1, "locked"}' \
            /etc/shadow 2>/dev/null | sort || true
        echo "=== sudo/wheel members ==="
        getent group sudo wheel 2>/dev/null | sort || true
    }
}


get_ssh_sessions() {
    # Active SSH sessions — tracked separately from processes since they are
    # intentionally transient but we still want to know who is connected
    who 2>/dev/null | grep -v '^$' | sort -u || true
}

get_failed_logins() {
    # Show failed SSH login attempts since the last hour
    # Uses auth.log on Debian/Ubuntu, secure on RHEL/CentOS
    local auth_log=""
    if [[ -f /var/log/auth.log ]]; then
        auth_log="/var/log/auth.log"
    elif [[ -f /var/log/secure ]]; then
        auth_log="/var/log/secure"
    else
        echo "No auth log found"
        return
    fi

    # Filter to last hour and extract failed attempts
    local since
    since=$(date -d "1 hour ago" '+%b %e %H:%M' 2>/dev/null || date -v-1H '+%b %e %H:%M' 2>/dev/null)

    grep "Failed password\|Invalid user\|authentication failure" "${auth_log}" 2>/dev/null         | grep -v "^$"         | tail -50         | sort -u         || true
}

# ── Suspicious port detection ─────────────────────────────────────────────────

flag_suspicious_ports() {
    local port_data="$1"
    local flagged=""
    for port in "${SUSPICIOUS_PORTS[@]}"; do
        local matches
        matches=$(echo "${port_data}" | grep -E "[:.]${port}\b" || true)
        if [[ -n "${matches}" ]]; then
            flagged+="${matches}\n"
        fi
    done
    echo -e "${flagged}"
}

# ── Integrity helpers ─────────────────────────────────────────────────────────

write_hashes() {
    sha256sum \
        "${PROCESS_BASELINE}" \
        "${NETWORK_BASELINE}" \
        "${SYSTEMD_BASELINE}" \
        "${CRON_BASELINE}" \
        "${BINARY_BASELINE}" \
        "${KMODS_BASELINE}" \
        "${SUID_BASELINE}" \
        "${SSH_BASELINE}" \
        "${USERS_BASELINE}" \
        > "${BASELINE_DIR}/baseline.sha256"
    chmod 600 "${BASELINE_DIR}/baseline.sha256"
}

verify_hashes() {
    if [[ ! -f "${BASELINE_DIR}/baseline.sha256" ]]; then
        echo -e "${RED}[!] No integrity file found — baseline may have been tampered with.${RESET}"
        return 1
    fi
    if ! sha256sum --check "${BASELINE_DIR}/baseline.sha256" --status 2>/dev/null; then
        echo -e "${RED}[!] INTEGRITY CHECK FAILED — baseline files do not match stored hashes.${RESET}"
        echo -e "${RED}    Possible tampering or corruption. Re-run with --reset to rebuild.${RESET}"
        return 1
    fi
    echo -e "${GREEN}[✓] Baseline integrity verified.${RESET}"
    return 0
}

# ── Backup ────────────────────────────────────────────────────────────────────

backup_baseline() {
    mkdir -p "${BACKUP_DIR}"
    local archive="${BACKUP_DIR}/baseline_$(date '+%Y-%m-%d_%H-%M-%S').tar.gz"
    tar -czf "${archive}" \
        -C "${BASELINE_DIR}" \
        processes.baseline network.baseline systemd.baseline \
        cron.baseline binaries.baseline \
        kmods.baseline suid.baseline ssh.baseline users.baseline \
        baseline.sha256 \
        2>/dev/null || true
    chmod 600 "${archive}"
    echo -e "${CYAN}[i] Backup saved: ${archive}${RESET}"
}

# ── Email alert with rate-limiting ────────────────────────────────────────────

send_alert() {
    local report_file="$1"
    local report_hash

    [[ -z "${ALERT_EMAIL:-}" ]] && return

    # Use provided hash if given (e.g. diff-only hash), otherwise hash the full report
    if [[ -n "${2:-}" ]]; then
        report_hash="$2"
    else
        report_hash=$(sha256sum "${report_file}" | awk '{print $1}')
    fi
    if [[ -f "${ALERT_HASH_FILE}" ]]; then
        local last_hash
        last_hash=$(cat "${ALERT_HASH_FILE}")
        if [[ "${report_hash}" == "${last_hash}" ]]; then
            echo -e "${CYAN}[i] Changes identical to last alert — skipping email to avoid spam.${RESET}"
            return
        fi
    fi

    local subject="[baseline_monitor] Changes detected on $(hostname) at $(date '+%Y-%m-%d %H:%M')"
    local sent=0

    # mailx behaves differently across distros — try multiple invocations
    if command -v mailx &>/dev/null; then
        mailx -s "${subject}" "${ALERT_EMAIL}" < "${report_file}" && sent=1
    elif command -v mail &>/dev/null; then
        mail -s "${subject}" "${ALERT_EMAIL}" < "${report_file}" && sent=1
    elif command -v sendmail &>/dev/null; then
        { echo "To: ${ALERT_EMAIL}"; echo "Subject: ${subject}"; echo ""; cat "${report_file}"; } \
            | sendmail -t && sent=1
    else
        echo -e "${YELLOW}[!] ALERT_EMAIL set but no mail client found.${RESET}"
        if is_debian_based; then
            echo -e "${YELLOW}    Install with: sudo apt install -y mailutils${RESET}"
        elif is_rhel_based; then
            echo -e "${YELLOW}    Install with: sudo dnf install -y mailx${RESET}"
        fi
        return
    fi

    if [[ "${sent}" -eq 1 ]]; then
        echo "${report_hash}" > "${ALERT_HASH_FILE}"
        chmod 600 "${ALERT_HASH_FILE}"
        echo -e "${CYAN}[i] Alert sent to ${ALERT_EMAIL}${RESET}"
    else
        echo -e "${YELLOW}[!] Failed to send alert email.${RESET}"
    fi
}

# ── Diff helper ───────────────────────────────────────────────────────────────

# Appends a labelled diff section to the report variable.
# Usage: section_diff "LABEL" baseline_file current_file report_var changes_var
section_diff() {
    local label="$1"
    local baseline="$2"
    local current="$3"
    local -n _report="$4"   # nameref — appends into caller's variable
    local -n _changes="$5"

    local added removed sorted_baseline sorted_current
    sorted_baseline=$(mktemp)
    sorted_current=$(mktemp)
    sort "${baseline}" > "${sorted_baseline}"
    sort "${current}"  > "${sorted_current}"
    added=$(comm -13 "${sorted_baseline}" "${sorted_current}")
    removed=$(comm -23 "${sorted_baseline}" "${sorted_current}")
    rm -f "${sorted_baseline}" "${sorted_current}"

    _report+="\n── ${label} ────────────────────────────────────────────\n"

    if [[ -n "${added}" ]]; then
        _report+="${RED}[+] NEW (not in baseline):${RESET}\n"
        while IFS= read -r line; do
            _report+="    ${line}\n"
        done <<< "${added}"
        _report+="\n"
        _changes=1
    fi

    if [[ -n "${removed}" ]]; then
        _report+="${YELLOW}[-] REMOVED (were in baseline):${RESET}\n"
        while IFS= read -r line; do
            _report+="    ${line}\n"
        done <<< "${removed}"
        _report+="\n"
        _changes=1
    fi

    if [[ -z "${added}" && -z "${removed}" ]]; then
        _report+="${GREEN}    No changes detected.${RESET}\n"
    fi
}

# ── Baseline creation ─────────────────────────────────────────────────────────

create_baseline() {
    mkdir -p "${BASELINE_DIR}" "${REPORTS_DIR}" "${BACKUP_DIR}"
    chmod 700 "${BASELINE_DIR}" "${REPORTS_DIR}" "${BACKUP_DIR}"

    echo -e "${CYAN}[*] Capturing baseline...${RESET}"

    echo -e "    processes..."
    get_processes       > "${PROCESS_BASELINE}"

    echo -e "    listening ports..."
    get_network         > "${NETWORK_BASELINE}"

    echo -e "    systemd units..."
    get_systemd_units   > "${SYSTEMD_BASELINE}"

    echo -e "    cron jobs..."
    get_cron_jobs       > "${CRON_BASELINE}"

    echo -e "    binary hashes (this may take a moment)..."
    get_binary_hashes   > "${BINARY_BASELINE}"
    echo -e "    kernel modules..."
    get_kernel_modules  > "${KMODS_BASELINE}"
    echo -e "    SUID binaries (this may take a moment)..."
    get_suid_binaries   > "${SUID_BASELINE}"
    echo -e "    SSH config..."
    get_ssh_config      > "${SSH_BASELINE}"
    echo -e "    user accounts..."
    get_user_accounts   > "${USERS_BASELINE}"

    chmod 600 "${PROCESS_BASELINE}" "${NETWORK_BASELINE}" \
              "${SYSTEMD_BASELINE}" "${CRON_BASELINE}" "${BINARY_BASELINE}" \
              "${KMODS_BASELINE}" "${SUID_BASELINE}" "${SSH_BASELINE}" "${USERS_BASELINE}"

    write_hashes
    backup_baseline

    local binary_count
    binary_count=$(wc -l < "${BINARY_BASELINE}")

    echo ""
    echo -e "${GREEN}[+] Baseline created at $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    echo ""
    echo    "    Host                : $(hostname)"
    echo    "    Distro              : ${DISTRO_ID:-unknown}"
    echo    "    Running as          : $(whoami) (EUID=${EUID})"
    echo    "    Processes captured  : $(wc -l < "${PROCESS_BASELINE}")"
    echo    "    Listening ports     : $(wc -l < "${NETWORK_BASELINE}")"
    echo    "    Systemd units       : $(wc -l < "${SYSTEMD_BASELINE}")"
    echo    "    Cron entries        : $(wc -l < "${CRON_BASELINE}")"
    local binary_dirs_display
    binary_dirs_display=$(IFS=' '; echo "${BINARY_DIRS[*]}")
    echo    "    Binaries hashed     : ${binary_count} files in ${binary_dirs_display}"
    echo    "    Kernel modules      : $(wc -l < "${KMODS_BASELINE}")"
    echo    "    SUID binaries       : $(wc -l < "${SUID_BASELINE}")"
    echo    "    SSH config files    : $(wc -l < "${SSH_BASELINE}")"
    echo    "    User accounts       : $(grep -c '^root\|^[^:]*:[^:]*:[0-9]\+' "${USERS_BASELINE}" 2>/dev/null || echo 0) entries"
    echo    "    Directory perms     : 700 (owner-only)"
    echo    "    File perms          : 600 (owner-only)"
    echo ""
    echo -e "${YELLOW}[i] Trust warning: if malware was already running when this baseline was"
    echo -e "    created, it will be treated as trusted. Baseline on a clean install.${RESET}"
    echo ""
    echo -e "${YELLOW}[i] Kernel-level rootkits can hide processes/ports from ps and ss."
    echo -e "    This script cannot detect what the kernel itself conceals.${RESET}"
    echo ""
    echo -e "${CYAN}[i] Set ALERT_EMAIL to receive rate-limited email alerts:${RESET}"
    echo    "    export ALERT_EMAIL=you@example.com"
    echo ""
    echo -e "${CYAN}[i] To automate hourly checks via cron:${RESET}"
    echo    "    sudo crontab -e"
    echo    "    0 * * * * umask 077; $(realpath "$0") >> ${REPORTS_DIR}/cron.log 2>&1"
}

# ── Comparison ────────────────────────────────────────────────────────────────

compare() {
    local current_procs current_net current_systemd current_cron current_bins
    local current_kmods current_suid current_ssh current_users
    current_procs=$(mktemp)
    current_net=$(mktemp)
    current_systemd=$(mktemp)
    current_cron=$(mktemp)
    current_bins=$(mktemp)
    current_kmods=$(mktemp)
    current_suid=$(mktemp)
    current_ssh=$(mktemp)
    current_users=$(mktemp)

    trap 'rm -f "${current_procs:-}" "${current_net:-}" "${current_systemd:-}" "${current_cron:-}" "${current_bins:-}" "${current_kmods:-}" "${current_suid:-}" "${current_ssh:-}" "${current_users:-}"' EXIT

    echo -e "    collecting processes..."
    get_processes       > "${current_procs}"
    echo -e "    collecting ports..."
    get_network         > "${current_net}"
    echo -e "    collecting systemd units..."
    get_systemd_units   > "${current_systemd}"
    echo -e "    collecting cron jobs..."
    get_cron_jobs       > "${current_cron}"
    echo -e "    hashing binaries (may take a moment)..."
    get_binary_hashes   > "${current_bins}"
    echo -e "    collecting kernel modules..."
    get_kernel_modules  > "${current_kmods}"
    echo -e "    scanning SUID binaries (may take a moment)..."
    get_suid_binaries   > "${current_suid}"
    echo -e "    checking SSH config..."
    get_ssh_config      > "${current_ssh}"
    echo -e "    checking user accounts..."
    get_user_accounts   > "${current_users}"
    echo ""

    local report=""
    local changes=0

    section_diff "PROCESSES"       "${PROCESS_BASELINE}" "${current_procs}"    report changes
    section_diff "LISTENING PORTS" "${NETWORK_BASELINE}" "${current_net}"      report changes
    section_diff "SYSTEMD UNITS"   "${SYSTEMD_BASELINE}" "${current_systemd}"  report changes
    section_diff "CRON JOBS"       "${CRON_BASELINE}"    "${current_cron}"     report changes
    section_diff "BINARY HASHES"   "${BINARY_BASELINE}"  "${current_bins}"     report changes
    section_diff "KERNEL MODULES"  "${KMODS_BASELINE}"   "${current_kmods}"    report changes
    section_diff "SUID BINARIES"   "${SUID_BASELINE}"    "${current_suid}"     report changes
    section_diff "SSH CONFIG"      "${SSH_BASELINE}"     "${current_ssh}"      report changes
    section_diff "USER ACCOUNTS"   "${USERS_BASELINE}"   "${current_users}"    report changes

    # ── Suspicious port scan (all current listeners, not just new ones) ───────
    local current_net_data suspicious_hits
    current_net_data=$(cat "${current_net}")
    suspicious_hits=$(flag_suspicious_ports "${current_net_data}")

    if [[ -n "${suspicious_hits}" ]]; then
        report+="\n${MAGENTA}${BOLD}── ⚠  SUSPICIOUS PORTS DETECTED ─────────────────────${RESET}\n"
        report+="${MAGENTA}   Known attacker/C2/reverse-shell ports currently listening:${RESET}\n"
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            report+="${MAGENTA}   ${line}${RESET}\n"
        done <<< "${suspicious_hits}"
        report+="\n"
        changes=1
    fi

    # ── Active SSH sessions (always reported, not diffed) ────────────────────
    local active_sessions
    active_sessions=$(get_ssh_sessions)

    report+="
── ACTIVE SESSIONS ──────────────────────────────────
"
    if [[ -n "${active_sessions}" ]]; then
        report+="${YELLOW}[!] Users currently logged in:${RESET}
"
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            report+="    ${line}
"
        done <<< "${active_sessions}"
        report+="
"
    else
        report+="${GREEN}    No active sessions.${RESET}
"
    fi

    # ── Failed login attempts (always reported, not diffed) ──────────────────
    local failed_logins
    failed_logins=$(get_failed_logins)

    report+="
── FAILED LOGIN ATTEMPTS (last hour) ────────────────
"
    if [[ -n "${failed_logins}" && "${failed_logins}" != "No auth log found" ]]; then
        report+="${RED}[!] Failed login attempts detected:${RESET}
"
        local count=0
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            # Extract just the relevant parts: time, method, user, source IP
            local summary
            summary=$(echo "${line}" | grep -oP '(\w+\s+\d+\s+\d+:\d+:\d+).*?(Failed password for( invalid user)? \S+|Invalid user \S+).*?from \S+' || echo "${line}")
            report+="    ${summary}
"
            (( count++ )) || true
        done <<< "${failed_logins}"
        report+="
    Total: ${count} failed attempt(s)

"
    else
        report+="${GREEN}    No failed login attempts in the last hour.${RESET}
"
    fi

    # ── Summary ───────────────────────────────────────────────────────────────
    local timestamp baseline_date
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    baseline_date=$(stat -c '%y' "${PROCESS_BASELINE}" | cut -d'.' -f1)

    report+="\n── SUMMARY ──────────────────────────────────────────\n"
    if [[ "${changes}" -eq 0 ]]; then
        report+="${GREEN}${BOLD}    System matches baseline. No differences found.${RESET}\n"
    else
        report+="${RED}${BOLD}    Differences detected — review items above.${RESET}\n"
    fi
    report+="\n"
    report+="    Host             : $(hostname)\n"
    report+="    Distro           : ${DISTRO_ID:-unknown}\n"
    report+="    Running as       : $(whoami) (EUID=${EUID})\n"
    report+="    Baseline created : ${baseline_date}\n"
    report+="    Compared at      : ${timestamp}\n"

    echo ""
    echo -e "${report}"

    mkdir -p "${REPORTS_DIR}"
    local report_file="${REPORTS_DIR}/$(date '+%Y-%m-%d_%H-%M-%S').txt"
    echo -e "${report}" | sed 's/\x1b\[[0-9;]*m//g' > "${report_file}"
    chmod 600 "${report_file}"
    echo -e "${CYAN}[i] Report saved to: ${report_file}${RESET}"

    if [[ "${changes}" -eq 1 ]]; then
        # Rate-limit based on diff content only — not SSH sessions which change every hour
        local diff_hash
        diff_hash=$(echo "${report}" | grep -A999 'PROCESSES' | grep -v 'ACTIVE SESSIONS' | sha256sum | awk '{print $1}')
        send_alert "${report_file}" "${diff_hash}"
    fi
}

# ── Reset ─────────────────────────────────────────────────────────────────────

reset_baseline() {
    echo -e "${YELLOW}[*] Creating backup before reset...${RESET}"
    [[ -f "${PROCESS_BASELINE}" ]] && backup_baseline
    rm -f "${PROCESS_BASELINE}" "${NETWORK_BASELINE}" "${SYSTEMD_BASELINE}" \
          "${CRON_BASELINE}" "${BINARY_BASELINE}" \
          "${KMODS_BASELINE}" "${SUID_BASELINE}" "${SSH_BASELINE}" "${USERS_BASELINE}" \
          "${BASELINE_DIR}/baseline.sha256" "${ALERT_HASH_FILE}"
    echo -e "${YELLOW}[*] Baseline cleared. Run without arguments to create a new one.${RESET}"
}

# ── Header ────────────────────────────────────────────────────────────────────

print_header() {
    echo -e "${BOLD}${CYAN}"
    echo "================================================"
    echo "  System Baseline Monitor"
    echo "  $(hostname)  |  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "================================================"
    echo -e "${RESET}"
}

# ── Main ──────────────────────────────────────────────────────────────────────

check_deps
acquire_lock

case "${1:-}" in
    --reset)
        print_header
        reset_baseline
        ;;
    --help|-h)
        echo "Usage: $0 [--reset | --help]"
        echo ""
        echo "  (no args)  Create baseline if none exists, otherwise compare"
        echo "  --reset    Backup and delete existing baseline for a fresh one"
        echo "  --help     Show this help"
        echo ""
        echo "Monitors:"
        echo "  - Running processes"
        echo "  - Listening ports"
        echo "  - Enabled systemd units"
        echo "  - Cron jobs (system + user)"
        echo "  - Binary hashes: $(IFS=' '; echo "${BINARY_DIRS[*]}")"
        echo "  - Kernel modules (lsmod)"
        echo "  - SUID binaries (find / -perm -4000)"
        echo "  - SSH config file hashes"
        echo "  - User accounts (/etc/passwd, /etc/shadow, sudo groups)"
        echo ""
        echo "Environment:"
        echo "  ALERT_EMAIL=you@example.com   Send email on detected changes (rate-limited)"
        echo ""
        echo "Paths:"
        echo "  Baseline : ${BASELINE_DIR}"
        echo "  Reports  : ${REPORTS_DIR}"
        echo "  Backups  : ${BACKUP_DIR}"
        echo ""
        echo "Known limitations:"
        echo "  - Baseline trust: malware present at baseline creation is treated as trusted"
        echo "  - Kernel rootkits can hide processes/ports from ps and ss"
        ;;
    *)
        print_header
        check_privileges
        if [[ -f "${PROCESS_BASELINE}" && -f "${NETWORK_BASELINE}" ]]; then
            verify_hashes || exit 1
            echo -e "${CYAN}[*] Running comparison...${RESET}"
            echo ""
            compare
        else
            create_baseline
        fi
        ;;
