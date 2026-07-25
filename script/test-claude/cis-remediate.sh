#!/bin/bash
#===============================================================================
# CIS Benchmark REMEDIATION Script — OL9 / RHEL 9 & Ubuntu 24.04 / Debian 12
#
# Companion to cis_audit.sh. Check IDs and OS-family detection match that
# script 1:1 (same detect_os/set_os_vars logic, same file paths), so the
# workflow is: audit -> remediate -> re-audit, watching the same IDs flip
# from FAIL to PASS.
#
# SAFETY MODEL (read before running on anything you care about):
#   - Must run as root.
#   - Every file this script touches is backed up first, timestamped, under
#     /var/backups/cis_remediation/<run-timestamp>/<original path>.
#   - --dry-run shows every change with nothing written to disk.
#   - Interactive by default: prints a plan and asks for confirmation. Use
#     --yes to skip the prompt (for automation).
#   - SSH hardening goes into a drop-in and is syntax-checked with `sshd -t`
#     before being made active — if it fails validation, the drop-in is
#     removed and sshd is left untouched.
#   - sudo hardening is checked with `visudo -cf` before being made active,
#     same rollback-on-failure behavior.
#   - High-blast-radius items (SELinux/AppArmor enforcing, disabling kernel
#     modules, disabling services) are OFF by default. Turn them on with
#     --aggressive.
#   - Filesystem/partition mount options (nodev/nosuid/noexec) are NEVER
#     changed by this script — that needs an fstab change and a planned
#     remount/reboot. Always flagged MANUAL.
#   - A reboot is required for SELinux enforcing mode, GRUB/kernel cmdline
#     changes, and audit -e 2 (immutable) rule changes to fully take effect.
#   - --exclude ID1,ID2,... skips specific items (prefix match).
#   - --restore TIMESTAMP copies every backed-up file from a previous run
#     back to its original location.
#
# Usage:
#   sudo ./cis_remediate.sh --dry-run                  # show plan only
#   sudo ./cis_remediate.sh                             # interactive apply
#   sudo ./cis_remediate.sh --yes                       # non-interactive
#   sudo ./cis_remediate.sh --yes --section 5.1         # just SSH
#   sudo ./cis_remediate.sh --yes --exclude 1.4.1,5.2.4 # skip specific items
#   sudo ./cis_remediate.sh --yes --aggressive          # include risky items
#   sudo ./cis_remediate.sh --list                      # list all item IDs
#   sudo ./cis_remediate.sh --json report.json --yes    # machine-readable summary
#   sudo ./cis_remediate.sh --restore 20260721_094500   # roll back a prior run
#===============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
DRY_RUN=false
ASSUME_YES=false
AGGRESSIVE=false
SECTION_FILTER=""
LIST_ONLY=false
JSON_OUT=""
RESTORE_TS=""
declare -a EXCLUDE_IDS=()

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

TS=$(date +%Y%m%d_%H%M%S)
BACKUP_ROOT="/var/backups/cis_remediation"
BACKUP_DIR="${BACKUP_ROOT}/${TS}"
LOG_DIR="/var/log/cis_remediation"
LOG_FILE="${LOG_DIR}/cis_remediate_${TS}.log"
LOCK_FILE="/var/run/cis_remediate.lock"

APPLIED=0; SKIPPED=0; FAILED=0; MANUAL=0
REBOOT_NEEDED=false
declare -a MANUAL_ITEMS=()
declare -a FAILED_ITEMS=()
declare -a JSON_ROWS=()

# ---------------------------------------------------------------------------
# OS detection — kept IDENTICAL to cis_audit.sh's detect_os/set_os_vars so
# both scripts agree on which family a host belongs to and which paths to use.
# ---------------------------------------------------------------------------
detect_os() {
  OS_ID=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
  OS_LIKE=$(grep '^ID_LIKE=' /etc/os-release | cut -d= -f2 | tr -d '"')
  OS_VERSION=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
  OS_NAME=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
  if [[ "$OS_LIKE" == *rhel* || "$OS_ID" == "rhel" || "$OS_ID" == "ol" || "$OS_ID" == "centos" || "$OS_ID" == "rocky" || "$OS_ID" == "almalinux" ]]; then
    OS_FAMILY="rhel"
  elif [[ "$OS_LIKE" == *debian* || "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]]; then
    OS_FAMILY="debian"
  else
    OS_FAMILY="unknown"
  fi
}

set_os_vars() {
  if [ "$OS_FAMILY" = "rhel" ]; then
    CRON_SVC="crond"
    GRUB_CFG="/boot/grub2/grub.cfg"; GRUB_DEFAULT="/etc/default/grub"
    PAM_PASSWD="/etc/pam.d/system-auth"; PAM_AUTH="/etc/pam.d/system-auth"
    PAM_SU="/etc/pam.d/su"
    AUDIT_RULE_DIR="/etc/audit/rules.d"
    SELINUX_CFG="/etc/selinux/config"
    LOGINDEFS="/etc/login.defs"; SECURITY_LIMITS="/etc/security/limits.conf"
    PWQUALITY_CONF="/etc/security/pwquality.conf"
    PWHISTORY_CONF="/etc/security/pwhistory.conf"
    FAILLOCK_CONF="/etc/security/faillock.conf"
    GDM_PKG="gdm"
    SSHD_DROPIN="/etc/ssh/sshd_config.d/50-cis.conf"
    SUDOERS_DROPIN="/etc/sudoers.d/99-cis"
    RSYSLOG_CONF="/etc/rsyslog.conf"
  else
    CRON_SVC="cron"
    GRUB_CFG="/boot/grub/grub.cfg"; GRUB_DEFAULT="/etc/default/grub"
    PAM_PASSWD="/etc/pam.d/common-password"; PAM_AUTH="/etc/pam.d/common-auth"
    PAM_SU="/etc/pam.d/su"
    AUDIT_RULE_DIR="/etc/audit/rules.d"
    SELINUX_CFG=""
    LOGINDEFS="/etc/login.defs"; SECURITY_LIMITS="/etc/security/limits.conf"
    PWQUALITY_CONF="/etc/security/pwquality.conf"
    PWHISTORY_CONF="/etc/security/pwhistory.conf"
    FAILLOCK_CONF="/etc/security/faillock.conf"
    GDM_PKG="gdm3"
    SSHD_DROPIN="/etc/ssh/sshd_config.d/50-cis.conf"
    SUDOERS_DROPIN="/etc/sudoers.d/99-cis"
    RSYSLOG_CONF="/etc/rsyslog.conf"
  fi
}

pkg_installed() {
  local pkg="$1"
  if [ "$OS_FAMILY" = "rhel" ]; then rpm -q "$pkg" &>/dev/null
  else dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; fi
}

pkg_install() {
  local pkg="$1"
  if [ "$OS_FAMILY" = "rhel" ]; then dnf install -y "$pkg" &>>"$LOG_FILE"
  else DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" &>>"$LOG_FILE"; fi
}

pkg_remove_cmd() {
  local pkg="$1"
  if [ "$OS_FAMILY" = "rhel" ]; then dnf remove -y "$pkg" &>>"$LOG_FILE"
  else DEBIAN_FRONTEND=noninteractive apt-get remove -y "$pkg" &>>"$LOG_FILE"; fi
}

usage() {
  cat <<'EOF'
Usage: sudo ./cis_remediate.sh [OPTIONS]
  --dry-run          Show every change that would be made, apply nothing
  --yes              Do not prompt for confirmation (for automation/CI)
  --aggressive       Also apply high-blast-radius items (SELinux/AppArmor
                     enforcing, disabling extra kernel modules/services)
  --section NUM      Only run one section, e.g. --section 5.1
  --exclude IDS      Comma-separated list of item IDs to skip (prefix match)
  --list             List all remediation item IDs and titles, then exit
  --json FILE        Also write a machine-readable JSON summary to FILE
  --restore TS       Restore every backed-up file from run TS back to its
                     original location. Prompts unless --yes.
  -h, --help         Show this help
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --yes|-y) ASSUME_YES=true; shift ;;
    --aggressive) AGGRESSIVE=true; shift ;;
    --section) SECTION_FILTER="$2"; shift 2 ;;
    --exclude) IFS=',' read -ra EXCLUDE_IDS <<< "$2"; shift 2 ;;
    --list) LIST_ONLY=true; shift ;;
    --json) JSON_OUT="$2"; shift 2 ;;
    --restore) RESTORE_TS="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

should_run() {
  local sec="$1"
  [ -z "$SECTION_FILTER" ] && return 0
  [[ "$sec" == "$SECTION_FILTER"* ]] && return 0
  return 1
}

is_excluded() {
  local id="$1" pat
  for pat in "${EXCLUDE_IDS[@]:-}"; do
    [ -z "$pat" ] && continue
    [[ "$id" == "$pat"* ]] && return 0
  done
  return 1
}

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }

say()      { echo -e "$*"; }
say_ok()   { say "  ${GREEN}✓${NC} $*"; }
say_skip() { say "  ${DIM}·${NC} $*"; }
say_fail() { say "  ${RED}✗${NC} $*"; }
say_man()  { say "  ${YELLOW}![MANUAL]${NC} $*"; }
say_warn() { say "  ${YELLOW}⚠${NC} $*"; }

json_row() {
  local id="$1" status="$2" desc="$3"
  desc="${desc//\"/\\\"}"
  JSON_ROWS+=("{\"id\":\"${id}\",\"status\":\"${status}\",\"desc\":\"${desc}\"}")
}

item_manual() {
  local id="$1" desc="$2"
  if is_excluded "$id"; then say_skip "$id  $desc ${DIM}(excluded)${NC}"; ((SKIPPED++)); json_row "$id" "EXCLUDED" "$desc"; return; fi
  ((MANUAL++)); MANUAL_ITEMS+=("$id: $desc")
  $LIST_ONLY || say_man "$id  $desc"
  log "[MANUAL] $id - $desc"
  json_row "$id" "MANUAL" "$desc"
}

backup_file() {
  local f="$1"
  [ -e "$f" ] || return 0
  $DRY_RUN && return 0
  local dest="${BACKUP_DIR}${f}"
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest" 2>>"$LOG_FILE"
}

# ---------------------------------------------------------------------------
# Core action helpers — every helper checks is_excluded first
# ---------------------------------------------------------------------------

# ensure_line <id> <desc> <file> <key-regex-to-detect-present> <exact-line>
ensure_line() {
  local id="$1" desc="$2" file="$3" key_regex="$4" line="$5"
  if is_excluded "$id"; then say_skip "$id  $desc ${DIM}(excluded)${NC}"; ((SKIPPED++)); json_row "$id" "EXCLUDED" "$desc"; return; fi
  if [ -f "$file" ] && grep -Fxq "$line" "$file" 2>/dev/null; then
    say_skip "$id  $desc ${DIM}(already set)${NC}"; ((SKIPPED++)); log "[SKIP] $id already set in $file"; json_row "$id" "SKIPPED" "$desc"; return 0
  fi
  if $DRY_RUN; then
    say "  ${CYAN}~${NC} $id  $desc"
    say "      ${DIM}file: $file  ->  $line${NC}"
    json_row "$id" "WOULD_APPLY" "$desc"
    return 0
  fi
  mkdir -p "$(dirname "$file")"
  touch "$file"
  backup_file "$file"
  if [ -n "$key_regex" ] && grep -Eq "^${key_regex}" "$file" 2>/dev/null; then
    sed -i -E "s|^${key_regex}.*$|${line//|/\\|}|" "$file"
  else
    echo "$line" >> "$file"
  fi
  if [ $? -eq 0 ]; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id -> $file: $line"; json_row "$id" "APPLIED" "$desc"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id"); log "[FAILED] $id -> $file"; json_row "$id" "FAILED" "$desc"
  fi
}

# set_sysctl <id> <desc> <key> <value> [dropin-file]
set_sysctl() {
  local id="$1" desc="$2" key="$3" val="$4" file="${5:-/etc/sysctl.d/60-cis.conf}"
  ensure_line "$id" "$desc" "$file" "${key//./\\.}[[:space:]]*=" "${key} = ${val}"
}

apply_sysctl_runtime() {
  $DRY_RUN && return 0
  sysctl --system &>>"$LOG_FILE"
}

# write_managed_file <id> <desc> <target-path> <mode> <content>
write_managed_file() {
  local id="$1" desc="$2" target="$3" mode="$4" content="$5"
  if is_excluded "$id"; then say_skip "$id  $desc ${DIM}(excluded)${NC}"; ((SKIPPED++)); json_row "$id" "EXCLUDED" "$desc"; return; fi
  if [ -f "$target" ] && diff -q <(echo "$content") "$target" &>/dev/null; then
    say_skip "$id  $desc ${DIM}(already up to date)${NC}"; ((SKIPPED++)); json_row "$id" "SKIPPED" "$desc"; return 0
  fi
  if $DRY_RUN; then
    say "  ${CYAN}~${NC} $id  $desc"
    say "      ${DIM}would write: $target (mode $mode)${NC}"
    json_row "$id" "WOULD_APPLY" "$desc"
    return 0
  fi
  backup_file "$target"
  mkdir -p "$(dirname "$target")"
  printf '%s\n' "$content" > "$target"
  chmod "$mode" "$target"
  chown root:root "$target"
  say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id -> wrote $target"; json_row "$id" "APPLIED" "$desc"
}

# set_perm <id> <desc> <path> <mode> [<owner:group>]
set_perm() {
  local id="$1" desc="$2" path="$3" mode="$4" own="${5:-root:root}"
  if is_excluded "$id"; then say_skip "$id  $desc ${DIM}(excluded)${NC}"; ((SKIPPED++)); json_row "$id" "EXCLUDED" "$desc"; return; fi
  [ -e "$path" ] || { say_skip "$id  $desc ${DIM}(file not present)${NC}"; ((SKIPPED++)); json_row "$id" "SKIPPED" "$desc"; return 0; }
  local cur_mode cur_own
  cur_mode=$(stat -c '%a' "$path" 2>/dev/null)
  cur_own=$(stat -c '%U:%G' "$path" 2>/dev/null)
  if [ "$cur_mode" = "$mode" ] && [ "$cur_own" = "$own" ]; then
    say_skip "$id  $desc ${DIM}(already $mode $own)${NC}"; ((SKIPPED++)); json_row "$id" "SKIPPED" "$desc"; return 0
  fi
  if $DRY_RUN; then
    say "  ${CYAN}~${NC} $id  $desc"
    say "      ${DIM}$path: $cur_mode $cur_own -> $mode $own${NC}"
    json_row "$id" "WOULD_APPLY" "$desc"
    return 0
  fi
  backup_file "$path"
  chmod "$mode" "$path" 2>>"$LOG_FILE" && chown "$own" "$path" 2>>"$LOG_FILE"
  if [ $? -eq 0 ]; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id -> $path chmod $mode chown $own"; json_row "$id" "APPLIED" "$desc"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id"); json_row "$id" "FAILED" "$desc"
  fi
}

# pkg_remove <id> <desc> <pkg>
pkg_remove() {
  local id="$1" desc="$2" pkg="$3"
  if is_excluded "$id"; then say_skip "$id  $desc ${DIM}(excluded)${NC}"; ((SKIPPED++)); json_row "$id" "EXCLUDED" "$desc"; return; fi
  if ! pkg_installed "$pkg"; then
    say_skip "$id  $desc ${DIM}(not installed)${NC}"; ((SKIPPED++)); json_row "$id" "SKIPPED" "$desc"; return 0
  fi
  if $DRY_RUN; then say "  ${CYAN}~${NC} $id  $desc ${DIM}(remove $pkg)${NC}"; json_row "$id" "WOULD_APPLY" "$desc"; return 0; fi
  if pkg_remove_cmd "$pkg"; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id removed $pkg"; json_row "$id" "APPLIED" "$desc"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id"); json_row "$id" "FAILED" "$desc"
  fi
}

# pkg_ensure_installed <id> <desc> <pkg>
pkg_ensure_installed() {
  local id="$1" desc="$2" pkg="$3"
  if is_excluded "$id"; then say_skip "$id  $desc ${DIM}(excluded)${NC}"; ((SKIPPED++)); json_row "$id" "EXCLUDED" "$desc"; return; fi
  if pkg_installed "$pkg"; then
    say_skip "$id  $desc ${DIM}(already installed)${NC}"; ((SKIPPED++)); json_row "$id" "SKIPPED" "$desc"; return 0
  fi
  if $DRY_RUN; then say "  ${CYAN}~${NC} $id  $desc ${DIM}(install $pkg)${NC}"; json_row "$id" "WOULD_APPLY" "$desc"; return 0; fi
  if pkg_install "$pkg"; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id installed $pkg"; json_row "$id" "APPLIED" "$desc"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id"); json_row "$id" "FAILED" "$desc"
  fi
}

# svc_disable <id> <desc> <service>
svc_disable() {
  local id="$1" desc="$2" svc="$3"
  if is_excluded "$id"; then say_skip "$id  $desc ${DIM}(excluded)${NC}"; ((SKIPPED++)); json_row "$id" "EXCLUDED" "$desc"; return; fi
  if ! systemctl list-unit-files "${svc}.service" &>/dev/null | grep -q "${svc}.service"; then
    say_skip "$id  $desc ${DIM}(unit not present)${NC}"; ((SKIPPED++)); json_row "$id" "SKIPPED" "$desc"; return 0
  fi
  if ! systemctl is-enabled "$svc" &>/dev/null && ! systemctl is-active --quiet "$svc"; then
    say_skip "$id  $desc ${DIM}(already disabled)${NC}"; ((SKIPPED++)); json_row "$id" "SKIPPED" "$desc"; return 0
  fi
  if $DRY_RUN; then say "  ${CYAN}~${NC} $id  $desc ${DIM}(systemctl disable --now $svc)${NC}"; json_row "$id" "WOULD_APPLY" "$desc"; return 0; fi
  if systemctl disable --now "$svc" &>>"$LOG_FILE"; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id disabled $svc"; json_row "$id" "APPLIED" "$desc"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id"); json_row "$id" "FAILED" "$desc"
  fi
}

# svc_enable <id> <desc> <service>
svc_enable() {
  local id="$1" desc="$2" svc="$3"
  if is_excluded "$id"; then say_skip "$id  $desc ${DIM}(excluded)${NC}"; ((SKIPPED++)); json_row "$id" "EXCLUDED" "$desc"; return; fi
  if ! systemctl list-unit-files "${svc}.service" &>/dev/null | grep -q "${svc}.service"; then
    say_skip "$id  $desc ${DIM}(unit not present — package not installed?)${NC}"; ((SKIPPED++)); json_row "$id" "SKIPPED" "$desc"; return 0
  fi
  if systemctl is-enabled "$svc" &>/dev/null && systemctl is-active --quiet "$svc"; then
    say_skip "$id  $desc ${DIM}(already enabled+active)${NC}"; ((SKIPPED++)); json_row "$id" "SKIPPED" "$desc"; return 0
  fi
  if $DRY_RUN; then say "  ${CYAN}~${NC} $id  $desc ${DIM}(systemctl enable --now $svc)${NC}"; json_row "$id" "WOULD_APPLY" "$desc"; return 0; fi
  if systemctl enable --now "$svc" &>>"$LOG_FILE"; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id enabled $svc"; json_row "$id" "APPLIED" "$desc"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id"); json_row "$id" "FAILED" "$desc"
  fi
}

# mod_block <id> <desc> <module> <dropin-file>
mod_block() {
  local id="$1" desc="$2" mod="$3" file="$4"
  write_managed_file "$id" "$desc" "$file" 644 "install ${mod} /bin/false"
  if ! $DRY_RUN && lsmod | grep -q "^${mod}[[:space:]]"; then
    say_warn "$id  $mod is blocked from future loads but is CURRENTLY loaded — run 'rmmod $mod' if safe, or reboot."
  fi
}

# ============================================================
# SECTION 1  INITIAL SETUP
# ============================================================

section_1_1() {
  should_run "1.1" || return
  say ""; say "${BOLD}${BLUE}1.1.1  Filesystem Kernel Modules${NC}"
  local -a fs_mods=(cramfs freevxfs hfs hfsplus jffs2 squashfs udf)
  local fs_idx=1
  for mod in "${fs_mods[@]}"; do
    mod_block "1.1.1.${fs_idx}" "Disable $mod kernel module" "$mod" "/etc/modprobe.d/cis-filesystems.conf"
    ((fs_idx++))
  done
  if $AGGRESSIVE; then
    mod_block "1.1.1.8" "Disable usb-storage kernel module (--aggressive: breaks USB mass storage)" "usb_storage" "/etc/modprobe.d/cis-usb-storage.conf"
  else
    if is_excluded "1.1.1.8"; then say_skip "1.1.1.8  ${DIM}(excluded)${NC}"; ((SKIPPED++));
    else say_skip "1.1.1.8  Disable usb-storage module ${DIM}(skipped — needs --aggressive)${NC}"; ((SKIPPED++)); fi
  fi
  item_manual "1.1.1.9" "Review for other unused filesystem kernel modules specific to your hardware/workload"
  item_manual "1.1.2" "Separate partitions and mount options (nodev/nosuid/noexec) — requires fstab + planned remount/reboot, not automated by this script"
}

section_1_2() {
  should_run "1.2" || return
  say ""; say "${BOLD}${BLUE}1.2  Package Management${NC}"
  if [ "$OS_FAMILY" = "rhel" ]; then
    item_manual "1.2.1.1" "Verify GPG keys configured for all enabled repos"
    ensure_line "1.2.1.2" "Ensure gpgcheck is globally activated" "/etc/dnf/dnf.conf" "gpgcheck[[:space:]]*=" "gpgcheck=1"
    item_manual "1.2.1.3" "Ensure repo_gpgcheck is globally activated"
    item_manual "1.2.1.4" "Ensure package manager repositories are configured as intended"
  else
    item_manual "1.2.1.1" "Ensure GPG keys are configured (apt-key list, or migrate to signed-by in sources)"
    item_manual "1.2.1.2" "Ensure repository GPG keys use signed-by in sources.list(.d)"
    item_manual "1.2.1.3" "Ensure package manager repositories are configured as intended"
  fi
  item_manual "1.2.2.1" "Confirm patch/update cadence and additional security tooling per your policy"
}

section_1_3() {
  should_run "1.3" || return
  say ""; say "${BOLD}${BLUE}1.3  Mandatory Access Control${NC}"
  if [ "$OS_FAMILY" = "rhel" ]; then
    pkg_ensure_installed "1.3.1.1" "Ensure libselinux-utils is installed" "libselinux-utils"
    if $AGGRESSIVE; then
      if grep -Eq 'selinux=0|enforcing=0' "$GRUB_DEFAULT" 2>/dev/null; then
        if $DRY_RUN; then say "  ${CYAN}~${NC} 1.3.1.2  Remove selinux=0/enforcing=0 from GRUB"
        elif is_excluded "1.3.1.2"; then say_skip "1.3.1.2 ${DIM}(excluded)${NC}"; ((SKIPPED++))
        else
          backup_file "$GRUB_DEFAULT"
          sed -i -E 's/\s*(selinux|enforcing)=0//g' "$GRUB_DEFAULT"
          grub2-mkconfig -o "$GRUB_CFG" &>>"$LOG_FILE" || true
          say_ok "1.3.1.2  Removed selinux=0/enforcing=0 from GRUB, regenerated grub.cfg"; ((APPLIED++)); REBOOT_NEEDED=true
        fi
      else
        say_skip "1.3.1.2  ${DIM}(already clean)${NC}"; ((SKIPPED++))
      fi
      item_manual "1.3.1.3" "Confirm SELinux policy is configured (sestatus)"
      ensure_line "1.3.1.4" "Ensure SELinux mode is not disabled" "$SELINUX_CFG" "SELINUX[[:space:]]*=" "SELINUX=enforcing"
      local mode; mode=$(getenforce 2>/dev/null || echo Unknown)
      if [ "$mode" != "Enforcing" ] && ! is_excluded "1.3.1.5"; then
        say_warn "1.3.1.5  SELINUX=enforcing written — mode only becomes Enforcing after a REBOOT (relabeling required if switching from disabled). Watch console on first reboot."
        REBOOT_NEEDED=true; ((APPLIED++))
      elif [ "$mode" = "Enforcing" ]; then
        say_skip "1.3.1.5  Already Enforcing"; ((SKIPPED++))
      fi
      pkg_remove "1.3.1.7" "Remove mcstrans" "mcstrans"
      pkg_remove "1.3.1.8" "Remove setroubleshoot" "setroubleshoot"
    else
      for id in 1.3.1.2 1.3.1.4 1.3.1.5; do
        if is_excluded "$id"; then say_skip "$id ${DIM}(excluded)${NC}"; ((SKIPPED++))
        else say_skip "$id  ${DIM}(skipped — needs --aggressive; switching SELinux modes needs a reboot and can lock you out if a service isn't labeled)${NC}"; ((SKIPPED++)); fi
      done
      item_manual "1.3.1.3" "Confirm SELinux policy is configured (sestatus)"
      pkg_remove "1.3.1.7" "Remove mcstrans" "mcstrans"
      pkg_remove "1.3.1.8" "Remove setroubleshoot" "setroubleshoot"
    fi
    item_manual "1.3.1.6" "Review for unconfined SELinux domains: semanage permissive -l"
  else
    pkg_ensure_installed "1.3.1.1" "Ensure AppArmor is installed" "apparmor"
    if $AGGRESSIVE; then
      if ! grep -q 'apparmor=1' "$GRUB_DEFAULT" 2>/dev/null; then
        if $DRY_RUN; then say "  ${CYAN}~${NC} 1.3.1.2  Add apparmor=1 security=apparmor to GRUB_CMDLINE_LINUX"
        elif is_excluded "1.3.1.2"; then say_skip "1.3.1.2 ${DIM}(excluded)${NC}"; ((SKIPPED++))
        else
          backup_file "$GRUB_DEFAULT"
          sed -i -E 's/(GRUB_CMDLINE_LINUX="[^"]*)"/\1 apparmor=1 security=apparmor"/' "$GRUB_DEFAULT"
          command -v update-grub &>/dev/null && update-grub &>>"$LOG_FILE" || true
          say_ok "1.3.1.2  Added apparmor=1 security=apparmor to GRUB, regenerated grub.cfg"; ((APPLIED++)); REBOOT_NEEDED=true
        fi
      else
        say_skip "1.3.1.2  ${DIM}(already set)${NC}"; ((SKIPPED++))
      fi
      if $DRY_RUN; then say "  ${CYAN}~${NC} 1.3.1.3/1.3.1.4  aa-enforce all profiles"
      elif is_excluded "1.3.1.3"; then say_skip "1.3.1.3/1.3.1.4 ${DIM}(excluded)${NC}"; ((SKIPPED++))
      elif command -v aa-enforce &>/dev/null; then
        find /etc/apparmor.d -maxdepth 1 -type f -exec aa-enforce {} \; &>>"$LOG_FILE" || true
        say_ok "1.3.1.3/1.3.1.4  Set all AppArmor profiles to enforce mode"; ((APPLIED++)); REBOOT_NEEDED=true
      else
        say_fail "1.3.1.3/1.3.1.4  aa-enforce not found"; ((FAILED++)); FAILED_ITEMS+=("1.3.1.3/1.3.1.4")
      fi
    else
      for id in 1.3.1.2 1.3.1.3 1.3.1.4; do
        if is_excluded "$id"; then say_skip "$id ${DIM}(excluded)${NC}"; ((SKIPPED++))
        else say_skip "$id  ${DIM}(skipped — needs --aggressive)${NC}"; ((SKIPPED++)); fi
      done
    fi
    svc_enable "1.3.1.5" "Ensure AppArmor service is active" "apparmor"
  fi
}

section_1_4() {
  should_run "1.4" || return
  say ""; say "${BOLD}${BLUE}1.4  Bootloader${NC}"
  if [ -f "$GRUB_CFG" ]; then
    set_perm "1.4.2" "Restrict access to bootloader config" "$GRUB_CFG" 400 root:root
  fi
  item_manual "1.4.1" "Set a bootloader password (grub2-setpassword on RHEL, grub-mkpasswd-pbkdf2 + 40_custom on Debian) — needs an interactive password choice, not automated"
}

section_1_5() {
  should_run "1.5" || return
  say ""; say "${BOLD}${BLUE}1.5  Additional Process Hardening${NC}"
  set_sysctl "1.5.1" "Enable ASLR" "kernel.randomize_va_space" "2"
  set_sysctl "1.5.2" "Restrict ptrace scope" "kernel.yama.ptrace_scope" "1"
  ensure_line "1.5.3" "Disable core dump backtraces (limits.conf)" "/etc/security/limits.d/99-cis.conf" "\\*[[:space:]]+hard[[:space:]]+core" "* hard core 0"
  # NOTE: cis_audit.sh greps /etc/systemd/coredump.conf directly (not conf.d),
  # so we write there to match, not a drop-in.
  write_managed_file "1.5.4" "Disable core dump storage (systemd-coredump)" "/etc/systemd/coredump.conf" 644 \
"[Coredump]
Storage=none
ProcessSizeMax=0"
  apply_sysctl_runtime
}

section_1_6() {
  should_run "1.6" || return
  say ""; say "${BOLD}${BLUE}1.6  System-Wide Crypto Policy${NC}"
  if [ "$OS_FAMILY" != "rhel" ]; then
    say_skip "1.6.x  Crypto policy checks are RHEL-specific ${DIM}(N/A on Debian family, matches cis_audit.sh)${NC}"; ((SKIPPED++))
    return
  fi
  local pol
  pol=$(update-crypto-policies --show 2>/dev/null || echo "UNKNOWN")
  if [ "$pol" = "LEGACY" ] || [ "$pol" = "DEFAULT" ] || [ "$pol" = "UNKNOWN" ]; then
    if is_excluded "1.6.1"; then say_skip "1.6.1 ${DIM}(excluded)${NC}"; ((SKIPPED++))
    elif $DRY_RUN; then say "  ${CYAN}~${NC} 1.6.1  update-crypto-policies --set FUTURE ${DIM}(current: ${pol})${NC}"
    else
      update-crypto-policies --set FUTURE &>>"$LOG_FILE"
      say_ok "1.6.1  Moved crypto policy to FUTURE (current was ${pol})"; ((APPLIED++))
      say_warn "1.6.1  FUTURE disallows SHA-1 and weak ciphers — test SSH/TLS client compatibility. This also satisfies 1.6.3/1.6.4/1.6.5 (SHA1/weak-MAC/CBC disabled), which are just consequences of the policy, not separate settings."
    fi
  else
    say_skip "1.6.1  Already FUTURE/FIPS ${DIM}(current: ${pol})${NC}"; ((SKIPPED++))
  fi
  # 1.6.2: cis_audit.sh wants NO Ciphers/MACs/KexAlgorithms lines in the
  # *main* sshd_config (system crypto policy should drive these instead).
  if is_excluded "1.6.2"; then
    say_skip "1.6.2 ${DIM}(excluded)${NC}"; ((SKIPPED++))
  else
    local sshd_main="/etc/ssh/sshd_config"
    if grep -Eq '^(Ciphers|MACs|KexAlgorithms)' "$sshd_main" 2>/dev/null; then
      if $DRY_RUN; then
        say "  ${CYAN}~${NC} 1.6.2  Remove Ciphers/MACs/KexAlgorithms lines from $sshd_main"
      else
        backup_file "$sshd_main"
        sed -i -E '/^(Ciphers|MACs|KexAlgorithms)/d' "$sshd_main"
        if sshd -t &>>"$LOG_FILE"; then
          say_ok "1.6.2  Removed explicit Ciphers/MACs/KexAlgorithms from $sshd_main (inherits system crypto policy)"; ((APPLIED++))
        else
          say_fail "1.6.2  sshd -t failed after edit — check $sshd_main manually, backup at $BACKUP_DIR"; ((FAILED++)); FAILED_ITEMS+=("1.6.2")
        fi
      fi
    else
      say_skip "1.6.2  Already clean"; ((SKIPPED++))
    fi
  fi
  item_manual "1.6.6" "Confirm system-wide crypto policy disables chacha20-poly1305 for ssh per your compliance target"
  item_manual "1.6.7" "Confirm system-wide crypto policy disables encrypt-then-mac (EtM) for ssh per your compliance target"
}

section_1_7() {
  should_run "1.7" || return
  say ""; say "${BOLD}${BLUE}1.7  Warning Banners${NC}"
  local banner="Authorized uses only. All activity may be monitored and reported."
  write_managed_file "1.7.1" "Configure /etc/motd" /etc/motd 644 "$banner"
  write_managed_file "1.7.2" "Configure /etc/issue" /etc/issue 644 "$banner"
  write_managed_file "1.7.3" "Configure /etc/issue.net" /etc/issue.net 644 "$banner"
  set_perm "1.7.4" "Permissions on /etc/motd" /etc/motd 644 root:root
  set_perm "1.7.5" "Permissions on /etc/issue" /etc/issue 644 root:root
  set_perm "1.7.6" "Permissions on /etc/issue.net" /etc/issue.net 644 root:root
}

section_1_8() {
  should_run "1.8" || return
  say ""; say "${BOLD}${BLUE}1.8  GNOME Display Manager${NC}"
  if ! pkg_installed "$GDM_PKG"; then
    say_skip "1.8.x  $GDM_PKG not installed ${DIM}(nothing to do — 1.8.1 already compliant)${NC}"; ((SKIPPED++))
    return
  fi
  if $AGGRESSIVE; then
    item_manual "1.8.1" "Decide whether to remove $GDM_PKG entirely on this server (--aggressive doesn't auto-remove the display manager — too disruptive to automate)"
  else
    say_skip "1.8.1  ${DIM}(skipped — removing the display manager is disruptive; needs --aggressive + manual confirmation)${NC}"; ((SKIPPED++))
  fi
  local dconf_d="/etc/dconf/db/local.d" locks_d="/etc/dconf/db/local.d/locks"
  write_managed_file "1.8.2" "Configure GDM login banner + disable-user-list" "${dconf_d}/00-cis-login" 644 \
"[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized uses only.'
disable-user-list=true"
  write_managed_file "1.8.3" "Ensure GDM disable-user-list option is enabled" "${dconf_d}/00-cis-userlist" 644 \
"[org/gnome/login-screen]
disable-user-list=true"
  write_managed_file "1.8.4" "Configure GDM idle screen lock" "${dconf_d}/00-cis-screensaver" 644 \
"[org/gnome/desktop/screensaver]
lock-enabled=true
idle-delay=uint32 900"
  write_managed_file "1.8.5" "Lock GDM screensaver settings against override" "${locks_d}/00-cis-screensaver" 644 \
"/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/idle-delay"
  write_managed_file "1.8.6" "Disable GDM automount of removable media" "${dconf_d}/00-cis-automount" 644 \
"[org/gnome/desktop/media-handling]
automount=false
automount-open=false"
  write_managed_file "1.8.7" "Lock GDM automount settings against override" "${locks_d}/00-cis-automount" 644 \
"/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/automount-open"
  write_managed_file "1.8.8" "Ensure GDM autorun-never is enabled" "${dconf_d}/00-cis-autorun" 644 \
"[org/gnome/desktop/media-handling]
autorun-never=true"
  write_managed_file "1.8.9" "Ensure GDM autorun-never is not overridden" "${locks_d}/00-cis-autorun" 644 \
"/org/gnome/desktop/media-handling/autorun-never"
  if [ -f /etc/gdm/custom.conf ] && grep -A3 -i '\[xdmcp\]' /etc/gdm/custom.conf 2>/dev/null | grep -qi 'Enable=true'; then
    if $DRY_RUN; then say "  ${CYAN}~${NC} 1.8.10  Disable XDMCP in /etc/gdm/custom.conf"
    elif is_excluded "1.8.10"; then say_skip "1.8.10 ${DIM}(excluded)${NC}"; ((SKIPPED++))
    else
      backup_file /etc/gdm/custom.conf
      sed -i -E '/^\[xdmcp\]/,/^\[/ s/^Enable[[:space:]]*=[[:space:]]*true/Enable=false/I' /etc/gdm/custom.conf
      say_ok "1.8.10  Disabled XDMCP"; ((APPLIED++))
    fi
  else
    is_excluded "1.8.10" && { say_skip "1.8.10 ${DIM}(excluded)${NC}"; ((SKIPPED++)); } || { say_skip "1.8.10  XDMCP already not enabled"; ((SKIPPED++)); }
  fi
  if ! $DRY_RUN; then dconf update &>>"$LOG_FILE" || true; fi
}

# ============================================================
# SECTION 2  SERVICES
# ============================================================

section_2_1() {
  should_run "2.1" || return
  say ""; say "${BOLD}${BLUE}2.1  Server Services${NC}"
  # NOTE: cis_audit.sh's 2.1.x checks PACKAGE absence (! pkg_installed),
  # not service state — so we must remove the package, not just stop the
  # service, or the audit will keep reporting FAIL.
  local -a svc_pkgs x11_pkg mta_pkg
  if [ "$OS_FAMILY" = "rhel" ]; then
    svc_pkgs=(autofs avahi dhcp-server bind dnsmasq samba vsftpd dovecot nfs-utils ypserv cups
              rpcbind rsync-daemon snmpd telnet-server tftp-server squid httpd nginx xinetd)
    x11_pkg="xorg-x11-server-Xorg"; mta_pkg="postfix"
  else
    svc_pkgs=(autofs avahi-daemon isc-dhcp-server bind9 dnsmasq samba vsftpd dovecot-core nfs-kernel-server nis
              cups rpcbind rsync snmpd telnetd tftpd-hpa squid apache2 nginx xinetd)
    x11_pkg="xorg"; mta_pkg="postfix"
  fi
  local idx=1
  for p in "${svc_pkgs[@]}"; do
    pkg_remove "2.1.$idx" "Ensure $p services are not in use" "$p"
    ((idx++))
  done
  pkg_remove "2.1.20" "Ensure X window server services are not in use" "$x11_pkg"
  if [ -f "/etc/${mta_pkg}/main.cf" ]; then
    ensure_line "2.1.21" "Ensure mail transfer agent is local-only" "/etc/${mta_pkg}/main.cf" "inet_interfaces[[:space:]]*=" "inet_interfaces = loopback-only"
  else
    say_skip "2.1.21  ${mta_pkg} not installed ${DIM}(nothing to do)${NC}"; ((SKIPPED++))
  fi
  item_manual "2.1.22" "Confirm only approved services are listening on a network interface: ss -tulnp"
}

section_2_2() {
  should_run "2.2" || return
  say ""; say "${BOLD}${BLUE}2.2  Client Packages${NC}"
  local -a clients
  if [ "$OS_FAMILY" = "rhel" ]; then clients=(ftp openldap-clients ypbind telnet tftp)
  else clients=(ftp ldap-utils nis telnet tftp); fi
  local -a labels=("ftp client" "ldap client" "nis client" "telnet client" "tftp client")
  for i in 0 1 2 3 4; do
    pkg_remove "2.2.$((i+1))" "Ensure ${labels[$i]} is not installed" "${clients[$i]}"
  done
}

section_2_3() {
  should_run "2.3" || return
  say ""; say "${BOLD}${BLUE}2.3  Time Synchronization${NC}"
  local chrony_active=false timesyncd_active=false
  systemctl is-active --quiet chronyd 2>/dev/null && chrony_active=true
  systemctl is-active --quiet systemd-timesyncd 2>/dev/null && timesyncd_active=true

  if $chrony_active || $timesyncd_active; then
    say_skip "2.3.1  Time sync already in use ${DIM}($($chrony_active && echo chronyd || echo systemd-timesyncd))${NC}"; ((SKIPPED++))
  else
    if is_excluded "2.3.1"; then say_skip "2.3.1 ${DIM}(excluded)${NC}"; ((SKIPPED++))
    elif $DRY_RUN; then say "  ${CYAN}~${NC} 2.3.1  Install and enable chrony"
    else
      pkg_install chrony
      systemctl enable --now chronyd &>>"$LOG_FILE"
      if systemctl is-active --quiet chronyd; then
        say_ok "2.3.1  Installed and started chronyd"; ((APPLIED++)); chrony_active=true
      else
        say_fail "2.3.1  Failed to start chronyd"; ((FAILED++)); FAILED_ITEMS+=("2.3.1")
      fi
    fi
  fi

  local chrony_conf
  if [ "$OS_FAMILY" = "rhel" ]; then chrony_conf="/etc/chrony.conf"; else chrony_conf="/etc/chrony/chrony.conf"; fi
  [ -f "$chrony_conf" ] || chrony_conf="/etc/chrony/chrony.conf"
  if $chrony_active && [ -f "$chrony_conf" ]; then
    ensure_line "2.3.2" "Ensure chrony has an NTP server configured" "$chrony_conf" "___never_matches___" "server time.cloudflare.com iburst"
    ensure_line "2.3.3" "Ensure chrony does not run as root" "$chrony_conf" "user[[:space:]]" "user _chrony"
  else
    say_skip "2.3.2/2.3.3  chrony not in use on this host ${DIM}(using systemd-timesyncd instead — N/A)${NC}"; ((SKIPPED+=2))
  fi
}

section_2_4() {
  should_run "2.4" || return
  say ""; say "${BOLD}${BLUE}2.4  Job Schedulers (cron / at)${NC}"
  svc_enable "2.4.1.1" "Ensure cron daemon is enabled and active" "$CRON_SVC"
  set_perm "2.4.1.2" "Permissions on /etc/crontab" /etc/crontab 644 root:root
  local -a crondirs=(/etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d)
  local -a cronids=(2.4.1.3 2.4.1.4 2.4.1.5 2.4.1.6 2.4.1.7)
  for i in 0 1 2 3 4; do
    set_perm "${cronids[$i]}" "Permissions on ${crondirs[$i]}" "${crondirs[$i]}" 755 root:root
  done

  if is_excluded "2.4.1.8"; then
    say_skip "2.4.1.8 ${DIM}(excluded)${NC}"; ((SKIPPED++))
  elif $DRY_RUN; then
    say "  ${CYAN}~${NC} 2.4.1.8  Write /etc/cron.allow (600, root), remove /etc/cron.deny"
  else
    backup_file /etc/cron.allow; backup_file /etc/cron.deny
    printf '%s\n' "root" > /etc/cron.allow
    chmod 640 /etc/cron.allow; chown root:root /etc/cron.allow
    rm -f /etc/cron.deny
    say_ok "2.4.1.8  Restricted cron to root (cron.allow, cron.deny removed)"; ((APPLIED++))
  fi

  if is_excluded "2.4.2.1"; then
    say_skip "2.4.2.1 ${DIM}(excluded)${NC}"; ((SKIPPED++))
  elif $DRY_RUN; then
    say "  ${CYAN}~${NC} 2.4.2.1  Write /etc/at.allow (600, root), remove /etc/at.deny"
  else
    backup_file /etc/at.allow; backup_file /etc/at.deny
    printf '%s\n' "root" > /etc/at.allow
    chmod 640 /etc/at.allow; chown root:root /etc/at.allow
    rm -f /etc/at.deny
    say_ok "2.4.2.1  Restricted at to root (at.allow, at.deny removed)"; ((APPLIED++))
  fi
}

# ============================================================
# SECTION 3  NETWORK
# ============================================================

section_3_1() {
  should_run "3.1" || return
  say ""; say "${BOLD}${BLUE}3.1  Network Devices${NC}"
  item_manual "3.1.1" "Decide and document whether IPv6 is required on this host"
  if command -v nmcli &>/dev/null; then
    if is_excluded "3.1.2"; then say_skip "3.1.2 ${DIM}(excluded)${NC}"; ((SKIPPED++))
    elif $DRY_RUN; then say "  ${CYAN}~${NC} 3.1.2  nmcli radio wifi off"
    else
      nmcli radio wifi off &>>"$LOG_FILE" && { say_ok "3.1.2  Disabled wifi radio via nmcli"; ((APPLIED++)); } \
        || { say_skip "3.1.2  No wifi radio to disable"; ((SKIPPED++)); }
    fi
  else
    item_manual "3.1.2" "Confirm wireless interfaces are disabled if not required (nmcli not found)"
  fi
  svc_disable "3.1.3" "Ensure bluetooth service is not in use" "bluetooth"
}

section_3_2() {
  should_run "3.2" || return
  say ""; say "${BOLD}${BLUE}3.2  Network Kernel Modules${NC}"
  if $AGGRESSIVE; then
    local -a net_mods=(dccp tipc rds sctp)
    local net_idx=1
    for mod in "${net_mods[@]}"; do
      mod_block "3.2.${net_idx}" "Disable $mod kernel module (--aggressive: sctp is used by some clustering/telecom stacks)" "$mod" "/etc/modprobe.d/cis-net-protocols.conf"
      ((net_idx++))
    done
  else
    for id in 3.2.1 3.2.2 3.2.3 3.2.4; do
      if is_excluded "$id"; then say_skip "$id ${DIM}(excluded)${NC}"; ((SKIPPED++))
      else say_skip "$id  ${DIM}(skipped — needs --aggressive)${NC}"; ((SKIPPED++)); fi
    done
  fi
}

section_3_3() {
  should_run "3.3" || return
  say ""; say "${BOLD}${BLUE}3.3  Network Kernel Parameters${NC}"
  set_sysctl "3.3.1"  "Disable IP forwarding"                 "net.ipv4.ip_forward" "0"
  set_sysctl "3.3.2"  "Disable send_redirects (all+default)"  "net.ipv4.conf.all.send_redirects" "0"
  set_sysctl "3.3.2b" "Disable send_redirects (default)"      "net.ipv4.conf.default.send_redirects" "0"
  set_sysctl "3.3.3"  "Ignore bogus ICMP error responses"     "net.ipv4.icmp_ignore_bogus_error_responses" "1"
  set_sysctl "3.3.4"  "Ignore broadcast ICMP requests"        "net.ipv4.icmp_echo_ignore_broadcasts" "1"
  set_sysctl "3.3.5"  "Ignore ICMP redirects (all)"           "net.ipv4.conf.all.accept_redirects" "0"
  set_sysctl "3.3.5b" "Ignore ICMP redirects (default)"       "net.ipv4.conf.default.accept_redirects" "0"
  set_sysctl "3.3.6"  "Ignore secure ICMP redirects (all)"    "net.ipv4.conf.all.secure_redirects" "0"
  set_sysctl "3.3.6b" "Ignore secure ICMP redirects (default)" "net.ipv4.conf.default.secure_redirects" "0"
  set_sysctl "3.3.7"  "Reverse path filtering (all)"          "net.ipv4.conf.all.rp_filter" "1"
  set_sysctl "3.3.7b" "Reverse path filtering (default)"      "net.ipv4.conf.default.rp_filter" "1"
  set_sysctl "3.3.8"  "Reject source-routed packets (all)"    "net.ipv4.conf.all.accept_source_route" "0"
  set_sysctl "3.3.8b" "Reject source-routed packets (default)" "net.ipv4.conf.default.accept_source_route" "0"
  set_sysctl "3.3.9"  "Log martian packets (all)"             "net.ipv4.conf.all.log_martians" "1"
  set_sysctl "3.3.9b" "Log martian packets (default)"         "net.ipv4.conf.default.log_martians" "1"
  set_sysctl "3.3.10" "Enable TCP SYN cookies"                "net.ipv4.tcp_syncookies" "1"
  set_sysctl "3.3.11" "Ignore IPv6 router advertisements (all)"     "net.ipv6.conf.all.accept_ra" "0"
  set_sysctl "3.3.11b" "Ignore IPv6 router advertisements (default)" "net.ipv6.conf.default.accept_ra" "0"
  apply_sysctl_runtime
}

# ============================================================
# SECTION 4  HOST-BASED FIREWALL
# ============================================================

section_4() {
  should_run "4" || return
  say ""; say "${BOLD}${BLUE}4  Host-Based Firewall${NC}"
  pkg_ensure_installed "4.1.1" "Ensure nftables is installed" "nftables"

  local fw=""
  systemctl is-active --quiet firewalld 2>/dev/null && fw="firewalld"
  systemctl is-active --quiet ufw 2>/dev/null && fw="ufw"
  systemctl is-active --quiet nftables 2>/dev/null && [ -z "$fw" ] && fw="nftables"

  if [ -n "$fw" ]; then
    say_skip "4.1.2  A firewall utility is already active ${DIM}($fw)${NC}"; ((SKIPPED++))
  else
    if [ "$OS_FAMILY" = "rhel" ]; then
      pkg_ensure_installed "4.1.1-fwd" "Ensure firewalld is installed" "firewalld"
      svc_enable "4.1.2" "Ensure a firewall utility is active (firewalld)" "firewalld"
      fw="firewalld"
    else
      pkg_ensure_installed "4.1.1-ufw" "Ensure ufw is installed" "ufw"
      if is_excluded "4.1.2"; then say_skip "4.1.2 ${DIM}(excluded)${NC}"; ((SKIPPED++))
      elif $DRY_RUN; then say "  ${CYAN}~${NC} 4.1.2  ufw --force enable"
      else
        ufw --force enable &>>"$LOG_FILE" && { say_ok "4.1.2  Enabled ufw"; ((APPLIED++)); fw="ufw"; } \
          || { say_fail "4.1.2  Failed to enable ufw"; ((FAILED++)); FAILED_ITEMS+=("4.1.2"); }
      fi
    fi
  fi

  say_warn "4.x  NOT auto-changing firewall zones/rules beyond enabling the service — that risks locking you out of SSH remotely. Review the ruleset yourself and set allowed services deliberately."
  if [ "$fw" = "firewalld" ]; then
    item_manual "4.2.1" "Review firewalld drops unnecessary services/ports for your role"
    item_manual "4.2.2" "Confirm firewalld loopback traffic is explicitly allowed (firewall-cmd --list-all-zones)"
  else
    item_manual "4.3.1" "Ensure a base chain/ruleset policy exists for your firewall utility"
    item_manual "4.3.2" "Ensure established connections are configured"
    item_manual "4.3.3" "Confirm default-deny policy on inbound traffic"
    item_manual "4.3.4" "Confirm loopback traffic is explicitly allowed"
  fi
}

# ============================================================
# SECTION 5  ACCESS CONTROL
# ============================================================

section_5_1() {
  should_run "5.1" || return
  say ""; say "${BOLD}${BLUE}5.1  SSH Server${NC}"
  if [ ! -f /etc/ssh/sshd_config ]; then
    say_skip "5.1.x  sshd not installed"; ((SKIPPED++)); return
  fi

  set_perm "5.1.1" "Permissions on /etc/ssh/sshd_config" /etc/ssh/sshd_config 600 root:root

  if is_excluded "5.1.2"; then say_skip "5.1.2 ${DIM}(excluded)${NC}"; ((SKIPPED++))
  elif $DRY_RUN; then say "  ${CYAN}~${NC} 5.1.2  chmod 600 SSH private host keys"
  else
    find /etc/ssh -type f -name '*_key' -exec chmod 600 {} \; 2>>"$LOG_FILE"
    say_ok "5.1.2  SSH private host key permissions fixed (600)"; ((APPLIED++))
  fi
  if is_excluded "5.1.3"; then say_skip "5.1.3 ${DIM}(excluded)${NC}"; ((SKIPPED++))
  elif $DRY_RUN; then say "  ${CYAN}~${NC} 5.1.3  chmod 644 SSH public host keys"
  else
    find /etc/ssh -type f -name '*.pub' -exec chmod 644 {} \; 2>>"$LOG_FILE"
    say_ok "5.1.3  SSH public host key permissions fixed (644)"; ((APPLIED++))
  fi

  # 5.1.4/5.1.5/5.1.6 (Ciphers/KexAlgorithms/MACs "configured") are reported
  # via `sshd -T`, which always shows the effective, negotiated values even
  # with no explicit directive — inherited from the system crypto policy
  # (see 1.6.2, which deliberately keeps them OUT of sshd_config). No
  # explicit action needed here; they pass once sshd is running validly.

  local admin_group="wheel"
  [ "$OS_FAMILY" = "debian" ] && admin_group="sudo"
  local other_sudo_user
  other_sudo_user=$(getent group "$admin_group" 2>/dev/null | cut -d: -f4)

  local content="# CIS hardening — managed by cis_remediate.sh, do not edit by hand
LogLevel INFO
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no
GSSAPIAuthentication no
DisableForwarding yes
PermitUserEnvironment no
MaxAuthTries 4
MaxSessions 10
MaxStartups 10:30:60
ClientAliveInterval 15
ClientAliveCountMax 3
LoginGraceTime 60
UsePAM yes
Banner /etc/issue.net
AllowGroups ${admin_group}"

  if [ -z "$other_sudo_user" ]; then
    say_warn "5.1.7/5.1.20  Skipping AllowGroups/PermitRootLogin no — no user found in the '${admin_group}' group, and either change could lock you out with no other access path. Add an admin user to '${admin_group}' first, then re-run."
    content=$(echo "$content" | grep -v '^AllowGroups')
    item_manual "5.1.7" "Set AllowUsers/AllowGroups once a non-root admin user exists (currently no user in '${admin_group}')"
    item_manual "5.1.20" "Set PermitRootLogin no once a non-root admin user exists"
  else
    content="${content}
PermitRootLogin no"
  fi

  if is_excluded "5.1.8-5.1.22"; then
    say_skip "5.1.8-5.1.22 ${DIM}(excluded)${NC}"; ((SKIPPED++))
  elif $DRY_RUN; then
    say "  ${CYAN}~${NC} 5.1.8-5.1.22  Write SSH hardening drop-in"
    say "      ${DIM}file: $SSHD_DROPIN${NC}"
    echo "$content" | sed 's/^/      /'
  else
    backup_file "$SSHD_DROPIN"
    mkdir -p "$(dirname "$SSHD_DROPIN")"
    printf '%s\n' "$content" > "$SSHD_DROPIN"
    chmod 600 "$SSHD_DROPIN"; chown root:root "$SSHD_DROPIN"
    if sshd -t &>>"$LOG_FILE"; then
      systemctl reload sshd &>>"$LOG_FILE" || systemctl reload ssh &>>"$LOG_FILE" || systemctl restart sshd &>>"$LOG_FILE" || systemctl restart ssh &>>"$LOG_FILE"
      say_ok "5.1.8-5.1.22  SSH hardening applied and sshd reloaded (validated with 'sshd -t' first)"
      ((APPLIED++)); log "[APPLIED] 5.1.x wrote $SSHD_DROPIN, sshd -t passed, reloaded"
    else
      rm -f "$SSHD_DROPIN"
      say_fail "5.1.8-5.1.22  sshd -t FAILED validation — drop-in removed, sshd left untouched. Check $LOG_FILE"
      ((FAILED++)); FAILED_ITEMS+=("5.1.x")
    fi
  fi
  say_warn "5.1.4-6  Ciphers/MACs/KexAlgorithms intentionally left unset so sshd inherits the system-wide crypto policy instead of a hardcoded list that can drift out of date (matches 1.6.2)."
}

section_5_2() {
  should_run "5.2" || return
  say ""; say "${BOLD}${BLUE}5.2  Privilege Escalation (sudo)${NC}"
  pkg_ensure_installed "5.2.1" "Ensure sudo is installed" "sudo"

  local content="Defaults use_pty
Defaults logfile=\"/var/log/sudo.log\"
Defaults timestamp_timeout=15"
  if [ -f "$SUDOERS_DROPIN" ] && diff -q <(echo "$content") "$SUDOERS_DROPIN" &>/dev/null; then
    say_skip "5.2.2/5.2.3/5.2.6  sudo hardening already in place"; ((SKIPPED++))
  elif is_excluded "5.2.2"; then
    say_skip "5.2.2/5.2.3/5.2.6 ${DIM}(excluded)${NC}"; ((SKIPPED++))
  elif $DRY_RUN; then
    say "  ${CYAN}~${NC} 5.2.2/5.2.3/5.2.6  Write $SUDOERS_DROPIN"; echo "$content" | sed 's/^/      /'
  else
    backup_file "$SUDOERS_DROPIN"
    printf '%s\n' "$content" > "$SUDOERS_DROPIN"
    chmod 440 "$SUDOERS_DROPIN"; chown root:root "$SUDOERS_DROPIN"
    if visudo -cf "$SUDOERS_DROPIN" &>>"$LOG_FILE"; then
      say_ok "5.2.2/5.2.3/5.2.6  sudo hardening applied (use_pty, logfile, 15min timeout)"; ((APPLIED++))
    else
      rm -f "$SUDOERS_DROPIN"
      say_fail "5.2.2/5.2.3/5.2.6  visudo syntax check failed — not applied"; ((FAILED++)); FAILED_ITEMS+=("5.2.x")
    fi
  fi

  if grep -rq 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    item_manual "5.2.4" "NOPASSWD entries found in sudoers — review and remove manually (could be intentional for automation accounts): $(grep -rl 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | tr '\n' ' ')"
  else
    say_skip "5.2.4  No NOPASSWD entries found"; ((SKIPPED++))
  fi
  if grep -rq '!authenticate' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    item_manual "5.2.5" "'!authenticate' found in sudoers — review and remove manually"
  else
    say_skip "5.2.5  No '!authenticate' override found"; ((SKIPPED++))
  fi

  local admin_group="wheel"
  [ "$OS_FAMILY" = "debian" ] && admin_group="sudo"
  ensure_line "5.2.7" "Restrict su to the ${admin_group} group" "$PAM_SU" "auth[[:space:]]+required[[:space:]]+pam_wheel\\.so" "auth             required        pam_wheel.so use_uid group=${admin_group}"
}

section_5_3() {
  should_run "5.3" || return
  say ""; say "${BOLD}${BLUE}5.3  PAM${NC}"
  if [ "$OS_FAMILY" = "rhel" ]; then
    pkg_ensure_installed "5.3.1.1" "Ensure pam is installed" "pam"
    pkg_ensure_installed "5.3.1.2" "Ensure authselect is installed" "authselect"
    pkg_ensure_installed "5.3.1.3" "Ensure libpwquality is installed" "libpwquality"
    if command -v authselect &>/dev/null; then
      local current
      current=$(authselect current 2>/dev/null)
      if echo "$current" | grep -q 'No existing configuration'; then
        if $DRY_RUN; then say "  ${CYAN}~${NC} 5.3.2.1-5.3.2.5  authselect select sssd with-faillock with-pwquality --force"
        elif is_excluded "5.3.2.1"; then say_skip "5.3.2.1-5.3.2.5 ${DIM}(excluded)${NC}"; ((SKIPPED++))
        else
          authselect select sssd with-faillock with-pwquality --force &>>"$LOG_FILE" \
            && { say_ok "5.3.2.1-5.3.2.5  authselect profile applied (sssd + faillock + pwquality)"; ((APPLIED++)); } \
            || { say_fail "5.3.2.1-5.3.2.5  authselect apply failed"; ((FAILED++)); FAILED_ITEMS+=("5.3.2.1"); }
        fi
      elif echo "$current" | grep -q 'with-faillock' && echo "$current" | grep -q 'with-pwquality'; then
        say_skip "5.3.2.1-5.3.2.5  authselect already has faillock + pwquality features"; ((SKIPPED++))
      elif is_excluded "5.3.2.1"; then
        say_skip "5.3.2.1-5.3.2.5 ${DIM}(excluded)${NC}"; ((SKIPPED++))
      elif $DRY_RUN; then
        say "  ${CYAN}~${NC} 5.3.2.1-5.3.2.5  authselect enable-feature with-faillock / with-pwquality"
      else
        authselect enable-feature with-faillock &>>"$LOG_FILE"
        authselect enable-feature with-pwquality &>>"$LOG_FILE"
        say_ok "5.3.2.1-5.3.2.5  Enabled faillock + pwquality authselect features (covers pam_faillock/pwquality/pwhistory/unix module lines)"; ((APPLIED++))
      fi
    fi
  else
    pkg_ensure_installed "5.3.1.1" "Ensure libpam0g is installed" "libpam0g"
    pkg_ensure_installed "5.3.1.3" "Ensure libpam-pwquality is installed" "libpam-pwquality"
    item_manual "5.3.2.x" "Debian has no authselect — enabling pam_faillock/pam_pwquality/pam_pwhistory requires editing /etc/pam.d/common-auth and common-password directly (e.g. via pam-auth-update or manual stanza edits). Not automated here: hand-editing a live PAM stack incorrectly can lock out all logins including root, so this needs a human at the console."
  fi

  ensure_line "5.3.3.2.1" "Set password dcredit (require a digit)"     "$PWQUALITY_CONF" "dcredit"     "dcredit = -1"
  ensure_line "5.3.3.2.2" "Enforce minimum password length 14"         "$PWQUALITY_CONF" "minlen"      "minlen = 14"
  item_manual "5.3.3.2.3" "Confirm password complexity settings (ucredit/lcredit/ocredit/minclass) match your policy — CIS treats the exact mix as a judgment call"
  ensure_line "5.3.3.2.4" "Limit consecutive repeated characters"      "$PWQUALITY_CONF" "maxrepeat"   "maxrepeat = 3"
  ensure_line "5.3.3.2.5" "Limit maximum sequential characters"        "$PWQUALITY_CONF" "maxsequence" "maxsequence = 3"
  ensure_line "5.3.3.2.6" "Deny dictionary/username-based passwords"   "$PWQUALITY_CONF" "dictcheck"   "dictcheck = 1"
  ensure_line "5.3.3.2.7" "Enforce password quality for root too"      "$PWQUALITY_CONF" "enforce_for_root" "enforce_for_root"

  if [ "$OS_FAMILY" = "rhel" ]; then
    ensure_line "5.3.3.1.1" "Lockout after 5 failed attempts" "$FAILLOCK_CONF" "deny"          "deny = 5"
    ensure_line "5.3.3.1.2" "Account unlock time (900s)"      "$FAILLOCK_CONF" "unlock_time"   "unlock_time = 900"
    ensure_line "5.3.3.1.3" "Apply lockout to root too"       "$FAILLOCK_CONF" "even_deny_root" "even_deny_root"
  else
    item_manual "5.3.3.1.1" "On Debian, deny= is set directly on the pam_faillock.so line in /etc/pam.d/common-auth — requires manual PAM stack edit (see 5.3.2.x note above)"
    item_manual "5.3.3.1.2" "Same as 5.3.3.1.1 — unlock_time= on the pam_faillock.so line in common-auth"
  fi

  ensure_line "5.3.3.3.1" "Remember last 24 passwords"                "$PWHISTORY_CONF" "remember"    "remember = 24"
  ensure_line "5.3.3.3.2" "Enforce password history on root too"      "$PWHISTORY_CONF" "enforce_for_root" "enforce_for_root"
  item_manual "5.3.3.3.3" "Confirm pam_pwhistory includes 'use_authtok' in $PAM_PASSWD — needs manual PAM stack edit, not automated here"

  if grep -q 'nullok' "$PAM_PASSWD" 2>/dev/null; then
    if is_excluded "5.3.3.4.1"; then say_skip "5.3.3.4.1 ${DIM}(excluded)${NC}"; ((SKIPPED++))
    elif $DRY_RUN; then say "  ${CYAN}~${NC} 5.3.3.4.1  Remove 'nullok' token from $PAM_PASSWD"
    else
      backup_file "$PAM_PASSWD"
      sed -i -E 's/\s+nullok\b//g; s/\bnullok\s+//g; s/\bnullok\b//g' "$PAM_PASSWD"
      say_ok "5.3.3.4.1  Removed 'nullok' from $PAM_PASSWD"; ((APPLIED++))
    fi
  else
    say_skip "5.3.3.4.1  'nullok' not present"; ((SKIPPED++))
  fi
  if grep -q 'remember=' "$PAM_PASSWD" 2>/dev/null; then
    item_manual "5.3.3.4.2" "pam_unix.so has a 'remember=' argument in $PAM_PASSWD — history should be handled by pam_pwhistory instead; review and remove manually"
  else
    say_skip "5.3.3.4.2  No 'remember=' argument on pam_unix.so"; ((SKIPPED++))
  fi
  item_manual "5.3.3.4.3" "Confirm pam_unix.so uses sha512 in $PAM_PASSWD — on RHEL this is normally set by the authselect profile; on Debian it requires a manual pam-auth-update/PAM edit"
  item_manual "5.3.3.4.4" "Confirm pam_unix.so includes 'use_authtok' in $PAM_PASSWD — needs manual PAM stack edit, not automated here"
}

section_5_4() {
  should_run "5.4" || return
  say ""; say "${BOLD}${BLUE}5.4  User Accounts and Environment${NC}"
  ensure_line "5.4.1.1" "PASS_MAX_DAYS 1-365"  "$LOGINDEFS" "PASS_MAX_DAYS" "PASS_MAX_DAYS   365"
  item_manual "5.4.1.2" "Set PASS_MIN_DAYS per-account with 'chage --mindays' — only affects newly created users, review existing accounts individually"
  ensure_line "5.4.1.3" "PASS_WARN_AGE >= 7"    "$LOGINDEFS" "PASS_WARN_AGE" "PASS_WARN_AGE   7"
  if [ "$OS_FAMILY" = "rhel" ]; then
    ensure_line "5.4.1.4" "SHA-512 password hashing (login.defs)" "$LOGINDEFS" "ENCRYPT_METHOD" "ENCRYPT_METHOD SHA512"
  else
    item_manual "5.4.1.4" "Debian's login.defs ENCRYPT_METHOD is often superseded by PAM's pam_unix.so hash argument — confirm both agree (sha512)"
  fi
  ensure_line "5.4.1.5" "Inactive account lock (30 days)" "/etc/default/useradd" "INACTIVE" "INACTIVE=30"
  item_manual "5.4.1.6" "Confirm no interactive user's last password change date is 'Never' (passwd -S <user> for each account >= UID 1000)"

  if grep -Eq '^\s*umask\s+077' /root/.profile /etc/profile /etc/bashrc /root/.bashrc 2>/dev/null; then
    say_skip "5.4.2.6  Root umask 077 already set"; ((SKIPPED++))
  else
    ensure_line "5.4.2.6" "Root umask 077" /root/.bashrc "umask" "umask 077"
  fi

  if $DRY_RUN; then
    say "  ${CYAN}~${NC} 5.4.2.7  Lock any system accounts (UID<1000, not root) that still have a login shell"
  else
    local changed=0
    while IFS=: read -r user _ uid _ _ _ shell; do
      if [ "$uid" -lt 1000 ] && [ "$user" != "root" ] && [ "$shell" != "/sbin/nologin" ] && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
        usermod -s /sbin/nologin "$user" 2>>"$LOG_FILE" && changed=$((changed+1))
      fi
    done < /etc/passwd
    if [ "$changed" -gt 0 ]; then say_ok "5.4.2.7  Set nologin shell on $changed system account(s)"; ((APPLIED++)); log "[APPLIED] 5.4.2.7 changed $changed accounts";
    else say_skip "5.4.2.7  All system accounts already have nologin/false shell"; ((SKIPPED++)); fi
  fi

  item_manual "5.4.2.1" "Confirm root is the only UID 0 account: awk -F: '(\$3==0)' /etc/passwd"
  item_manual "5.4.2.2" "Confirm root is the only account with GID 0"
  item_manual "5.4.2.3" "Confirm the 'root' group is the only group with GID 0"
  item_manual "5.4.2.4" "Confirm root account access is controlled (passwd -S root shows P or PS)"
  item_manual "5.4.2.5" "Confirm root's \$PATH has no empty/relative entries ('::' or leading ':')"
  item_manual "5.4.2.8" "Confirm accounts without a valid login shell also have a locked password field in /etc/shadow (leading ! or *)"

  if grep -q '/usr/sbin/nologin' /etc/shells 2>/dev/null; then
    if is_excluded "5.4.3.1"; then say_skip "5.4.3.1 ${DIM}(excluded)${NC}"; ((SKIPPED++))
    elif $DRY_RUN; then say "  ${CYAN}~${NC} 5.4.3.1  Remove /usr/sbin/nologin from /etc/shells"
    else
      backup_file /etc/shells
      sed -i '\#^/usr/sbin/nologin$#d' /etc/shells
      say_ok "5.4.3.1  Removed /usr/sbin/nologin from /etc/shells"; ((APPLIED++))
    fi
  else
    say_skip "5.4.3.1  /usr/sbin/nologin not listed in /etc/shells"; ((SKIPPED++))
  fi

  ensure_line "5.4.3.2" "Default shell idle timeout (TMOUT, 900s)" /etc/profile "TMOUT" "TMOUT=900"
  ensure_line "5.4.3.3" "Default umask 077 (login.defs)" "$LOGINDEFS" "umask" "umask 077"
}

# ============================================================
# SECTION 6  LOGGING AND AUDITING
# ============================================================

section_6_1() {
  should_run "6.1" || return
  say ""; say "${BOLD}${BLUE}6.1  Integrity Checking (AIDE)${NC}"
  local aide_pkg="aide"
  pkg_ensure_installed "6.1.1" "Ensure AIDE is installed" "$aide_pkg"
  if command -v aide &>/dev/null; then
    write_managed_file "6.1.2" "Schedule a daily AIDE integrity check" /etc/cron.d/aide-check 644 \
"0 5 * * * root /usr/sbin/aide --check >> /var/log/aide/aide-check.log 2>&1"
  else
    say_skip "6.1.2  aide not installed yet ${DIM}(will apply on next run once installed)${NC}"; ((SKIPPED++))
  fi
  item_manual "6.1.3" "Initialize the AIDE database (aide --init; mv aide.db.new.gz aide.db.gz) — not automated because initial init can take a long time and should be run at a known-good baseline"
}

section_6_2() {
  should_run "6.2" || return
  say ""; say "${BOLD}${BLUE}6.2  System Logging${NC}"
  svc_enable "6.2.1.1" "Ensure journald service is enabled and active" "systemd-journald"
  item_manual "6.2.1.2" "Confirm journald log file access matches your policy"
  item_manual "6.2.1.3" "Confirm journald log rotation settings match your retention policy"
  item_manual "6.2.1.4" "Confirm only one logging system (rsyslog XOR journald) is actively receiving logs, per your design — stopping either service here would be destructive, not automated"

  if command -v systemd-journal-remote &>/dev/null; then
    item_manual "6.2.2.1.2" "Configure systemd-journal-upload TLS client authentication"
    svc_enable "6.2.2.1.3" "Ensure systemd-journal-upload is enabled and active" "systemd-journal-upload"
    svc_disable "6.2.2.1.4" "Ensure systemd-journal-remote service is not in use (unless this host is a log aggregator)" "systemd-journal-remote"
  fi

  local jc="/etc/systemd/journald.conf"
  ensure_line "6.2.2.2" "journald ForwardToSyslog=yes" "$jc" "ForwardToSyslog" "ForwardToSyslog=yes"
  ensure_line "6.2.2.3" "journald Compress=yes" "$jc" "Compress" "Compress=yes"
  ensure_line "6.2.2.4" "journald Storage=persistent" "$jc" "Storage" "Storage=persistent"
  if ! $DRY_RUN; then systemctl restart systemd-journald &>>"$LOG_FILE" || true; fi

  pkg_ensure_installed "6.2.3.1" "Ensure rsyslog is installed" "rsyslog"
  svc_enable "6.2.3.2" "Ensure rsyslog service is enabled and active" "rsyslog"
  say_skip "6.2.3.3  Covered by 6.2.2.2 (ForwardToSyslog=yes)"; ((SKIPPED++))
  ensure_line "6.2.3.4" "rsyslog default file permissions" "$RSYSLOG_CONF" "\\\$FileCreateMode" "\$FileCreateMode 0640"
  item_manual "6.2.3.5" "Confirm rsyslog is capturing the log sources your policy requires (auth, authpriv, cron, kern, etc.)"
  item_manual "6.2.3.6" "Configure rsyslog remote log forwarding to your central log host if required by policy"
  if grep -rq 'imtcp' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v '^#'; then
    item_manual "6.2.3.7" "rsyslog appears configured to RECEIVE logs from remote clients (imtcp module) — confirm this host is meant to be a log aggregator, otherwise remove that module"
  else
    say_skip "6.2.3.7  rsyslog not configured as a remote log receiver"; ((SKIPPED++))
  fi
  item_manual "6.2.3.8" "Confirm rsyslog logrotate is configured and matches your retention window"

  set_perm "6.2.4.1" "Permissions on /var/log" /var/log 755 root:root
}

section_6_3() {
  should_run "6.3" || return
  say ""; say "${BOLD}${BLUE}6.3  System Auditing (auditd)${NC}"
  local audit_pkg="audit"
  [ "$OS_FAMILY" = "debian" ] && audit_pkg="auditd"
  pkg_ensure_installed "6.3.1.1" "Ensure auditd packages are installed" "$audit_pkg"
  item_manual "6.3.1.2" "audit=1 on the kernel command line requires a reboot — add via 'grubby --update-kernel=ALL --args=\"audit=1\"' (RHEL) or edit GRUB_CMDLINE_LINUX + update-grub (Debian)"
  item_manual "6.3.1.3" "audit_backlog_limit requires a reboot — add via the same mechanism alongside audit=1 (e.g. audit_backlog_limit=8192)"
  svc_enable "6.3.1.4" "Ensure auditd service is enabled and active" "auditd"

  ensure_line "6.3.2.1" "Audit log max size (MB)"          /etc/audit/auditd.conf "max_log_file[[:space:]]*=" "max_log_file = 50"
  ensure_line "6.3.2.2" "Never auto-delete audit logs"      /etc/audit/auditd.conf "max_log_file_action[[:space:]]*=" "max_log_file_action = keep_logs"
  ensure_line "6.3.2.3" "Email admin when space is low"     /etc/audit/auditd.conf "space_left_action[[:space:]]*=" "space_left_action = email"
  ensure_line "6.3.2.4" "Halt system when audit space is critically low" /etc/audit/auditd.conf "admin_space_left_action[[:space:]]*=" "admin_space_left_action = halt"

  local rules="${AUDIT_RULE_DIR}/50-cis.rules"
  # Rule content is written so every literal substring cis_audit.sh's
  # `auditctl -l | grep -q '...'` checks for (sudoers, execve, sudo_log,
  # localtime/adjtimex/settimeofday, sethostname/setdomainname, chmod/chown,
  # EACCES/EPERM, /etc/passwd|group|shadow, mount, unlink/rename,
  # wtmp/btmp, lastlog/faillog, setenforce/selinux, chcon, setfacl, chacl,
  # usermod, init_module, -e 2) is actually present.
  local content="## CIS audit rules — managed by cis_remediate.sh
-D
-b 8192
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k sudo_log
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/hostname -p wa -k system-locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/sbin/setenforce -p x -k MAC-policy
-w /usr/sbin/setsebool -p x -k MAC-policy
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modules
-w /usr/bin/chcon -p x -k privileged
-w /usr/bin/setfacl -p x -k privileged
-w /usr/bin/chacl -p x -k privileged
-w /usr/sbin/usermod -p x -k privileged
-e 2"
  write_managed_file "6.3.3.1-19" "Write standard CIS audit rules (immutable, -e 2)" "$rules" 600 "$content"
  if ! $DRY_RUN && [ -f "$rules" ]; then
    augenrules --load &>>"$LOG_FILE" || service auditd restart &>>"$LOG_FILE" || true
    say_warn "6.3.3.20  Audit ruleset ends in '-e 2' (immutable) — further rule changes need a REBOOT to take effect, by CIS design."
    REBOOT_NEEDED=true
  fi
  item_manual "6.3.3.21" "After the next reboot, confirm the running audit configuration (auditctl -l) matches what's on disk in ${AUDIT_RULE_DIR}/"

  set_perm "6.3.4.1" "Mode on /var/log/audit" /var/log/audit 700 root:root
  if [ -d /var/log/audit ] && ! $DRY_RUN; then
    if is_excluded "6.3.4.2-4"; then say_skip "6.3.4.2-4 ${DIM}(excluded)${NC}"; ((SKIPPED++))
    else
      find /var/log/audit -type f -exec chmod 600 {} \; -exec chown root:root {} \; 2>>"$LOG_FILE"
      say_ok "6.3.4.2-4  Audit log files set to 600 root:root"; ((APPLIED++))
    fi
  fi
  set_perm "6.3.4.5" "Mode on auditd.conf" /etc/audit/auditd.conf 640 root:root
  if [ -x /sbin/auditctl ] || [ -x /usr/sbin/auditctl ]; then
    local auditctl_bin; auditctl_bin=$(command -v auditctl)
    set_perm "6.3.4.8-10" "Permissions/ownership on audit tools" "$auditctl_bin" 750 root:root
  fi
}

# ============================================================
# SECTION 7  SYSTEM MAINTENANCE
# ============================================================

section_7_1() {
  should_run "7.1" || return
  say ""; say "${BOLD}${BLUE}7.1  System File Permissions${NC}"
  set_perm "7.1.1" "Permissions on /etc/passwd"  /etc/passwd  644 root:root
  set_perm "7.1.2" "Permissions on /etc/passwd-" /etc/passwd- 644 root:root
  set_perm "7.1.3" "Permissions on /etc/group"   /etc/group   644 root:root
  set_perm "7.1.4" "Permissions on /etc/group-"  /etc/group-  644 root:root
  set_perm "7.1.5" "Permissions on /etc/shadow"  /etc/shadow  000 root:root
  set_perm "7.1.6" "Permissions on /etc/shadow-" /etc/shadow- 000 root:root
  set_perm "7.1.7" "Permissions on /etc/gshadow" /etc/gshadow 000 root:root
  set_perm "7.1.8" "Permissions on /etc/gshadow-" /etc/gshadow- 000 root:root
  set_perm "7.1.9" "Permissions on /etc/shells"  /etc/shells  644 root:root
  set_perm "7.1.10" "Permissions on /etc/security/opasswd" /etc/security/opasswd 600 root:root
  item_manual "7.1.11" "World-writable files: find / -xdev -type f -perm -0002 — review and fix individually, don't blanket chmod"
  item_manual "7.1.12" "Orphaned files (no owner/group): find / -xdev -nouser -o -nogroup — review and reassign individually"
  item_manual "7.1.13" "Review SUID/SGID binaries against a known-good baseline"
}

section_7_2() {
  should_run "7.2" || return
  say ""; say "${BOLD}${BLUE}7.2  Local User and Group Settings${NC}"
  # All of 7.2 is read-only validation of existing account/group data in
  # cis_audit.sh (duplicate UIDs, shadowed passwords, orphaned group refs,
  # home directory ownership). None of it is safe to auto-fix without
  # human judgment about which entry is "correct" — merging/renumbering
  # accounts incorrectly can break logins and file ownership across the
  # whole system. Every item here stays MANUAL by design.
  item_manual "7.2.1" "Confirm all accounts in /etc/passwd use shadowed passwords (field 2 = 'x')"
  item_manual "7.2.2" "Confirm no /etc/shadow password fields are empty"
  item_manual "7.2.3" "Confirm every group referenced in /etc/passwd exists in /etc/group"
  local dupu dupg dupn dupgn
  dupu=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
  dupg=$(cut -d: -f3 /etc/group | sort | uniq -d)
  dupn=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
  dupgn=$(cut -d: -f1 /etc/group | sort | uniq -d)
  [ -n "$dupu" ] && item_manual "7.2.4" "Duplicate UIDs found — resolve manually (this script will not merge/renumber accounts for you): $dupu" || { say_skip "7.2.4  No duplicate UIDs"; ((SKIPPED++)); }
  [ -n "$dupg" ] && item_manual "7.2.5" "Duplicate GIDs found — resolve manually: $dupg" || { say_skip "7.2.5  No duplicate GIDs"; ((SKIPPED++)); }
  [ -n "$dupn" ] && item_manual "7.2.6" "Duplicate user names found — resolve manually: $dupn" || { say_skip "7.2.6  No duplicate user names"; ((SKIPPED++)); }
  [ -n "$dupgn" ] && item_manual "7.2.7" "Duplicate group names found — resolve manually: $dupgn" || { say_skip "7.2.7  No duplicate group names"; ((SKIPPED++)); }
  item_manual "7.2.8" "Confirm every interactive user's home directory exists and is owned by them"
  item_manual "7.2.9" "Review dot-file permissions in home directories (.netrc, .forward, .rhosts etc.)"
}

# ============================================================
# RESTORE
# ============================================================

do_restore() {
  local src="${BACKUP_ROOT}/${RESTORE_TS}"
  if [ ! -d "$src" ]; then
    echo -e "${RED}No backup directory found at ${src}${NC}"
    echo "Available backups:"
    ls -1 "$BACKUP_ROOT" 2>/dev/null || echo "  (none)"
    exit 1
  fi
  local -a files=()
  while IFS= read -r -d '' f; do files+=("$f"); done < <(find "$src" -type f -print0)
  if [ ${#files[@]} -eq 0 ]; then
    echo "No files found under ${src} — nothing to restore."; exit 0
  fi

  say "${BOLD}${WHITE}Restore plan — ${#files[@]} file(s) from ${src}${NC}"
  local f orig
  for f in "${files[@]}"; do
    orig="${f#$src}"
    say "  ${CYAN}${f}${NC}  ->  ${orig}"
  done

  if $DRY_RUN; then
    say ""; say "Dry run — nothing restored."
    exit 0
  fi

  if ! $ASSUME_YES; then
    echo ""
    read -r -p "Restore these ${#files[@]} file(s) to their original locations? This overwrites current content. [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted, nothing restored."; exit 0; }
  fi

  local n=0
  for f in "${files[@]}"; do
    orig="${f#$src}"
    mkdir -p "$(dirname "$orig")"
    cp -a "$f" "$orig" && n=$((n+1))
  done
  say "${GREEN}Restored ${n}/${#files[@]} file(s).${NC}"
  say "Services that read the restored files (sshd, sudo, auditd, rsyslog, etc.) may need a reload/restart to pick up the change."
  exit 0
}

# ============================================================
# MAIN
# ============================================================

run_all_sections() {
  section_1_1; section_1_2; section_1_3; section_1_4; section_1_5; section_1_6; section_1_7; section_1_8
  section_2_1; section_2_2; section_2_3; section_2_4
  section_3_1; section_3_2; section_3_3
  section_4
  section_5_1; section_5_2; section_5_3; section_5_4
  section_6_1; section_6_2; section_6_3
  section_7_1; section_7_2
}

write_json() {
  [ -z "$JSON_OUT" ] && return
  {
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"os_family\": \"${OS_FAMILY}\","
    echo "  \"dry_run\": ${DRY_RUN},"
    echo "  \"aggressive\": ${AGGRESSIVE},"
    echo "  \"applied\": ${APPLIED},"
    echo "  \"skipped\": ${SKIPPED},"
    echo "  \"failed\": ${FAILED},"
    echo "  \"manual\": ${MANUAL},"
    echo "  \"reboot_needed\": ${REBOOT_NEEDED},"
    echo "  \"backup_dir\": \"${BACKUP_DIR}\","
    echo "  \"items\": ["
    local n=${#JSON_ROWS[@]} i=0
    for row in "${JSON_ROWS[@]}"; do
      i=$((i+1))
      echo -n "    $row"
      [ "$i" -lt "$n" ] && echo "," || echo ""
    done
    echo "  ]"
    echo "}"
  } > "$JSON_OUT"
}

show_summary() {
  say ""
  say "${BOLD}${WHITE}================  REMEDIATION SUMMARY  ================${NC}"
  say "  OS family: $OS_FAMILY ($OS_NAME)"
  say "  ${GREEN}Applied:${NC}  $APPLIED"
  say "  ${DIM}Skipped (already compliant / excluded):${NC} $SKIPPED"
  say "  ${RED}Failed:${NC}   $FAILED"
  say "  ${YELLOW}Manual review needed:${NC} $MANUAL"
  if [ ${#FAILED_ITEMS[@]} -gt 0 ]; then
    say ""; say "  ${RED}Failed items:${NC}"
    for i in "${FAILED_ITEMS[@]}"; do say "    - $i"; done
  fi
  if [ ${#MANUAL_ITEMS[@]} -gt 0 ]; then
    say ""; say "  ${YELLOW}Needs manual attention:${NC}"
    for i in "${MANUAL_ITEMS[@]}"; do say "    - $i"; done
  fi
  say ""
  if ! $DRY_RUN; then
    say "  Backups of every changed file: ${CYAN}${BACKUP_DIR}${NC}"
    say "  Restore this run with:         ${CYAN}sudo $0 --restore ${TS}${NC}"
    say "  Full log:                      ${CYAN}${LOG_FILE}${NC}"
  fi
  [ -n "$JSON_OUT" ] && say "  JSON summary:                  ${CYAN}${JSON_OUT}${NC}"
  if $REBOOT_NEEDED; then
    say ""; say "  ${YELLOW}${BOLD}A REBOOT is required for some changes (SELinux/AppArmor mode, GRUB, audit -e 2 rules) to fully take effect.${NC}"
    say "  ${YELLOW}Reboot only when you're ready to be at the console/have out-of-band access.${NC}"
  fi
  say "${BOLD}${WHITE}=========================================================${NC}"
  say ""
  say "Next step: re-run cis_audit.sh to confirm the FAIL count dropped, and review every MANUAL item above."
}

list_items() {
  say "Listing all remediation items (no changes will be made — this implies --dry-run)."
  DRY_RUN=true
  run_all_sections
  exit 0
}

acquire_lock() {
  exec 200>"$LOCK_FILE" 2>/dev/null || return 0
  if ! flock -n 200; then
    echo -e "${RED}Another cis_remediate.sh run appears to be in progress (lock: ${LOCK_FILE}). Exiting.${NC}"
    exit 1
  fi
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root (it edits system files under /etc, /boot, /var).${NC}"
    exit 1
  fi

  detect_os
  if [ "$OS_FAMILY" = "unknown" ]; then
    echo -e "${RED}Unsupported OS (ID=${OS_ID:-unknown}). Exiting.${NC}"; exit 1
  fi
  set_os_vars

  mkdir -p "$LOG_DIR" 2>/dev/null
  acquire_lock

  if [ -n "$RESTORE_TS" ]; then
    do_restore
  fi

  $LIST_ONLY && list_items

  $DRY_RUN || mkdir -p "$BACKUP_DIR"
  log "=== CIS remediation run started (os=$OS_FAMILY dry_run=$DRY_RUN aggressive=$AGGRESSIVE section=${SECTION_FILTER:-all} exclude=${EXCLUDE_IDS[*]:-none}) ==="

  say ""
  say "${BOLD}${WHITE}CIS Benchmark Remediation${NC}"
  say "  OS:        $OS_NAME ($OS_FAMILY family)"
  say "  Mode:      $($DRY_RUN && echo 'DRY RUN (no changes will be written)' || echo 'APPLY')"
  say "  Aggressive: $AGGRESSIVE"
  [ -n "$SECTION_FILTER" ] && say "  Section:   $SECTION_FILTER"
  [ ${#EXCLUDE_IDS[@]} -gt 0 ] && say "  Excluded:  ${EXCLUDE_IDS[*]}"
  if [ "$OS_FAMILY" = "debian" ]; then
    say "  ${YELLOW}Note: this remediator's deepest coverage targets OL9/RHEL9. On Debian/Ubuntu, PAM-stack items (5.3.x/5.3.3.1.x) are left MANUAL rather than auto-edited, since Debian has no authselect safety net.${NC}"
  fi
  say ""

  if ! $DRY_RUN && ! $ASSUME_YES; then
    echo -e "${YELLOW}This will modify system configuration files (SSH, PAM, sysctl, auditd, sudoers, permissions, etc).${NC}"
    echo -e "${YELLOW}Every file touched is backed up to ${BACKUP_DIR} first. Recommend running with --dry-run first if you haven't.${NC}"
    read -r -p "Continue? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted, nothing changed."; exit 0; }
  fi

  run_all_sections
  write_json
  show_summary
  log "=== CIS remediation run finished: applied=$APPLIED skipped=$SKIPPED failed=$FAILED manual=$MANUAL ==="

  [ "$FAILED" -gt 0 ] && exit 1 || exit 0
}

main
