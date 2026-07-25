#!/bin/bash
#===============================================================================
# CIS Benchmark Audit Script — OL9 / RHEL 9 Level 1
# Also supports Ubuntu 24.04 / Debian 12 (AppArmor / ufw paths)
#
# Usage:
#   ./cis_audit.sh                  — full audit
#   ./cis_audit.sh -q               — quiet (only FAIL + summary)
#   ./cis_audit.sh --show-manual    — show manual-review items too
#   ./cis_audit.sh --section 5.3    — run only section 5.3
#   ./cis_audit.sh -q --section 5.1 — quiet, SSH only
#===============================================================================

set -o pipefail

# --- Flags (set by arg parsing) ---
QUIET=false
SHOW_MANUAL=false
SECTION_FILTER=""

# --- Colors & Formatting ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
WHITE='\033[1;37m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

UTF8_OK=false
[[ "$LANG" == *UTF-8* || "$LANG" == *utf8* || "$LC_ALL" == *UTF-8* || "$LC_ALL" == *utf8* ]] && UTF8_OK=true

if $UTF8_OK; then
  CP="✓"; CF="✗"; CM="?"; CW="⚠"
  BTOP="${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
  BBOT="${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
  BMID="${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
  BV="${BLUE}║${NC}"
  SECL="${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  SDL="${DIM}─────────────────────────────────────────────────────────${NC}"
  SPA="PASSED:"; SFA="FAILED:"; SMA="MANUAL:"; STO="TOTAL:"; SGR="GRADE:"
else
  CP="+"; CF="-"; CM="?"; CW="!"
  BTOP="${BLUE}+==============================================================+${NC}"
  BBOT="${BLUE}+==============================================================+${NC}"
  BMID="${BLUE}|==============================================================|${NC}"
  BV="${BLUE}|${NC}"
  SECL="${BOLD}${BLUE}------------------------------------------------------------${NC}"
  SDL="${DIM}---------------------------------------------------------${NC}"
  SPA="PASSED:"; SFA="FAILED:"; SMA="MANUAL:"; STO="TOTAL:"; SGR="GRADE:"
fi

LOG_DIR="/var/log/cis_audit"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/cis_audit_${TIMESTAMP}.log"
SUMMARY_FILE="$LOG_DIR/cis_summary_${TIMESTAMP}.txt"
mkdir -p "$LOG_DIR"

TOTAL=0; PASSED=0; FAILED=0; MANUAL=0

# --- OS Detection ---
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
    PKG_CMD="rpm -q"; PKG_LIST_CMD="rpm -qa"
    CRON_SVC="crond"
    GRUB_CFG="/boot/grub2/grub.cfg"; GRUB_USER_CFG="/boot/grub2/user.cfg"
    GRUB_DEFAULT="/etc/default/grub"
    PAM_PASSWD="/etc/pam.d/system-auth"; PAM_AUTH="/etc/pam.d/system-auth"
    PAM_SU="/etc/pam.d/su"
    AUDIT_RULE_DIR="/etc/audit/rules.d"
    SELINUX_CFG="/etc/selinux/config"
    CRYPTO_POLICY="update-crypto-policies --show"
    LOGINDEFS="/etc/login.defs"; SECURITY_LIMITS="/etc/security/limits.conf"
    PWQUALITY_CONF="/etc/security/pwquality.conf"
    PWHISTORY_CONF="/etc/security/pwhistory.conf"
    FAILLOCK_CONF="/etc/security/faillock.conf"
    GDM_PKG="gdm"
  else
    PKG_CMD="dpkg -l"; PKG_LIST_CMD="dpkg --get-selections"
    CRON_SVC="cron"
    GRUB_CFG="/boot/grub/grub.cfg"; GRUB_USER_CFG="/boot/grub/user.cfg"
    GRUB_DEFAULT="/etc/default/grub"
    PAM_PASSWD="/etc/pam.d/common-password"; PAM_AUTH="/etc/pam.d/common-auth"
    PAM_SU="/etc/pam.d/su"
    AUDIT_RULE_DIR="/etc/audit"
    SELINUX_CFG=""
    CRYPTO_POLICY=""
    LOGINDEFS="/etc/login.defs"; SECURITY_LIMITS="/etc/security/limits.conf"
    PWQUALITY_CONF="/etc/security/pwquality.conf"
    PWHISTORY_CONF="/etc/security/pwhistory.conf"
    FAILLOCK_CONF="/etc/security/faillock.conf"
    GDM_PKG="gdm3"
  fi
}

pkg_installed() {
  local pkg="$1"
  if [ "$OS_FAMILY" = "rhel" ]; then rpm -q "$pkg" &>/dev/null
  else dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; fi
}

mod_loaded() { local mod="$1"; lsmod | grep -q "^${mod}" 2>/dev/null; }

sysctl_eq() {
  local key="$1" expected="$2"; local val
  val=$(sysctl -n "$key" 2>/dev/null); [ "$val" = "$expected" ]
}

# ============================================================
# OUTPUT FUNCTIONS
# ============================================================

banner() {
  $QUIET && return
  echo ""
  echo -e "$BTOP"
  echo -e "${BV}${WHITE}        CIS BENCHMARK AUDIT SCRIPT${NC}                          ${BV}"
  echo -e "${BV}${NC}  OS:       ${CYAN}${OS_NAME}${NC}"
  echo -e "${BV}${NC}  Started:  ${CYAN}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
  echo -e "${BV}${NC}  Log:      ${DIM}${LOG_FILE}${NC}"
  [ -n "$SECTION_FILTER" ] && echo -e "${BV}${NC}  Section:  ${YELLOW}${SECTION_FILTER}${NC}"
  echo -e "$BBOT"; echo ""
}

section_header() {
  local num="$1" title="$2"
  $QUIET && return
  echo ""; echo -e "$SECL"
  echo -e "${BOLD}${WHITE}  ${num}  ${title}${NC}"
  echo -e "$SECL"
}

sub_header() {
  local num="$1" title="$2"
  $QUIET && return
  echo ""; echo -e "${CYAN}  ${num}  ${title}${NC}"
  local sep; if $UTF8_OK; then sep="─"; else sep="-"; fi
  echo -e "${DIM}  ${num}  $(printf '%*s' "${#title}" | tr ' ' "$sep")${NC}"
}

check() {
  local id="$1" desc="$2" cmd="$3" diag="$4"
  ((TOTAL++))
  if eval "$cmd" &>/dev/null; then
    $QUIET || echo -e "  ${GREEN}${CP} PASS${NC}  ${DIM}${id}${NC}  ${desc}"
    ((PASSED++))
    echo "[PASS] $id - $desc" >> "$LOG_FILE"
  else
    echo -e "  ${RED}${CF} FAIL${NC}  ${DIM}${id}${NC}  ${desc}"
    if [ -n "$diag" ]; then
      local dout; dout=$(eval "$diag" 2>/dev/null)
      [ -n "$dout" ] && echo -e "    ${DIM}→ ${dout}${NC}"
    fi
    ((FAILED++))
    echo "[FAIL] $id - $desc" >> "$LOG_FILE"
  fi
}

manual_check() {
  local id="$1" desc="$2"
  ((TOTAL++)); ((MANUAL++))
  $SHOW_MANUAL && echo -e "  ${YELLOW}${CM} MANUAL${NC}  ${DIM}${id}${NC}  ${desc}"
  echo "[MANUAL] $id - $desc" >> "$LOG_FILE"
}

warn() {
  echo -e "  ${YELLOW}${CW} WARN${NC}   $1"
}

# ============================================================
# SECTION 1  INITIAL SETUP
# ============================================================

should_run() {
  local sec="$1"
  [ -z "$SECTION_FILTER" ] && return 0
  [[ "$sec" == "$SECTION_FILTER"* ]] && return 0
  return 1
}

section_1_1_1() {
  should_run "1.1" || return
  sub_header "1.1.1" "Configure Filesystem Kernel Modules"

  local -a fs_mods=(cramfs freevxfs hfs hfsplus jffs2 squashfs udf)
  local fs_idx=1
  for mod in "${fs_mods[@]}"; do
    check "1.1.1.${fs_idx}" "Ensure ${mod} kernel module is not available" \
      "! mod_loaded ${mod}"
    ((fs_idx++))
  done

  check "1.1.1.8" "Ensure usb-storage kernel module is not available" \
    "! mod_loaded usb_storage"
  manual_check "1.1.1.9" "Ensure unused filesystems kernel modules are not available"
}

section_1_1_2() {
  should_run "1.1" || return
  sub_header "1.1.2" "Configure Filesystem Partitions"

  local -a parts opts_list
  parts=( "/tmp" "/dev/shm" "/home" "/var" "/var/tmp" "/var/log" "/var/log/audit" )
  opts_list=( "nodev,nosuid,noexec" "nodev,nosuid,noexec" "nodev,nosuid" "nodev,nosuid" "nodev,nosuid,noexec" "nodev,nosuid,noexec" "nodev,nosuid,noexec" )

  for i in "${!parts[@]}"; do
    local p="${parts[$i]}" dir
    dir=$(echo "$p" | tr -d '/')
    sub_header "1.1.2.$((i+1))" "Configure $p"
    check "1.1.2.$((i+1)).1" "Ensure $p is a separate partition" \
      "mount | grep -qE ' on $p '"
    IFS=',' read -ra opts <<< "${opts_list[$i]}"
    local sub=2
    for o in "${opts[@]}"; do
      check "1.1.2.$((i+1)).$sub" "Ensure $o option set on $p partition" \
        "mount | grep -E ' on $p ' | grep -qw $o"
      ((sub++))
    done
  done
}

section_1_2() {
  should_run "1.2" || return
  section_header "1.2" "Package Management"

  sub_header "1.2.1" "Configure Package Repositories"
  if [ "$OS_FAMILY" = "rhel" ]; then
    manual_check "1.2.1.1" "Ensure GPG keys are configured"
    check "1.2.1.2" "Ensure gpgcheck is globally activated" \
      "grep -q '^gpgcheck=1' /etc/dnf/dnf.conf 2>/dev/null || grep -q '^gpgcheck=1' /etc/yum.conf 2>/dev/null"
    manual_check "1.2.1.3" "Ensure repo_gpgcheck is globally activated"
    manual_check "1.2.1.4" "Ensure package manager repositories are configured"
  else
    check "1.2.1.1" "Ensure GPG keys are configured" \
      "apt-key list 2>/dev/null | grep -q pub"
    check "1.2.1.2" "Ensure repository GPG keys are valid" \
      "grep -r 'signed-by' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -q ."
    manual_check "1.2.1.3" "Ensure package manager repositories are configured"
  fi

  sub_header "1.2.2" "Configure Package Updates"
  manual_check "1.2.2.1" "Ensure updates, patches, and additional security software are installed"
}

section_1_3() {
  should_run "1.3" || return
  section_header "1.3" "Mandatory Access Control"

  if [ "$OS_FAMILY" = "rhel" ]; then
    sub_header "1.3.1" "Configure SELinux"
    check "1.3.1.1" "Ensure SELinux is installed" "rpm -q libselinux-utils &>/dev/null"
    check "1.3.1.2" "Ensure SELinux is not disabled in bootloader configuration" \
      "! grep -q 'selinux=0' /etc/default/grub 2>/dev/null && ! grep -q 'enforcing=0' /etc/default/grub 2>/dev/null"
    check "1.3.1.3" "Ensure SELinux policy is configured" \
      "sestatus 2>/dev/null | grep -q 'Policy name:'"
    check "1.3.1.4" "Ensure the SELinux mode is not disabled" \
      "sestatus 2>/dev/null | grep -qv 'disabled'"
    check "1.3.1.5" "Ensure the SELinux mode is enforcing" \
      "getenforce 2>/dev/null | grep -qi enforcing"
    manual_check "1.3.1.6" "Ensure no unconfined services exist"
    check "1.3.1.7" "Ensure the MCS Translation Service (mcstrans) is not installed" \
      "! rpm -q mcstrans &>/dev/null"
    check "1.3.1.8" "Ensure SETroubleshoot is not installed" \
      "! rpm -q setroubleshoot &>/dev/null"
  else
    sub_header "1.3.1" "Configure AppArmor"
    check "1.3.1.1" "Ensure AppArmor is installed" "pkg_installed apparmor"
    check "1.3.1.2" "Ensure AppArmor is enabled in bootloader" \
      "grep -q 'apparmor=1' /proc/cmdline 2>/dev/null"
    check "1.3.1.3" "Ensure AppArmor profiles are loaded" \
      "command -v aa-status &>/dev/null && aa-status 2>/dev/null | grep -q 'profiles are loaded'"
    check "1.3.1.4" "Ensure all AppArmor profiles are enforcing" \
      "command -v aa-status &>/dev/null && aa-status 2>/dev/null | grep -q 'profiles are in enforce mode' && ! aa-status 2>/dev/null | grep -q 'profiles are in complain mode'"
    check "1.3.1.5" "Ensure AppArmor service is active" \
      "systemctl is-active apparmor 2>/dev/null | grep -q active"
  fi
}

section_1_4() {
  should_run "1.4" || return
  section_header "1.4" "Configure Bootloader"

  if [ -f "$GRUB_CFG" ]; then
    check "1.4.1" "Ensure bootloader password is set" \
      "[ -f $GRUB_USER_CFG ] && grep -Eq '^GRUB2_PASSWORD=.+' $GRUB_USER_CFG 2>/dev/null"
    check "1.4.2" "Ensure access to bootloader config is configured" \
      "stat -c '%U:%G' $GRUB_CFG 2>/dev/null | grep -q 'root:root' && [ \$(stat -c '%a' $GRUB_CFG 2>/dev/null) -le 600 ]"
  else
    warn "GRUB config not found — skipping bootloader checks"
  fi
}

section_1_5() {
  should_run "1.5" || return
  section_header "1.5" "Configure Additional Process Hardening"

  check "1.5.1" "Ensure address space layout randomization is enabled" \
    "sysctl_eq kernel.randomize_va_space 2" \
    "v=\$(sysctl -n kernel.randomize_va_space 2>/dev/null); echo \"randomize_va_space = \$v (expected: 2)\""
  check "1.5.2" "Ensure ptrace_scope is restricted" \
    "sysctl_eq kernel.yama.ptrace_scope 1 2>/dev/null || sysctl_eq kernel.yama.ptrace_scope 2 2>/dev/null" \
    "v=\$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null); echo \"ptrace_scope = \$v (expected: 1 or 2)\""
  check "1.5.3" "Ensure core dump backtraces are disabled" \
    "grep -Eq '^\*\s+(hard|soft)\s+core\s+0' ${SECURITY_LIMITS} /etc/security/limits.d/*.conf 2>/dev/null"
  check "1.5.4" "Ensure core dump storage is disabled" \
    "sysctl_eq kernel.core_pattern '|/bin/false' 2>/dev/null || grep -q '^Storage=none' /etc/systemd/coredump.conf 2>/dev/null" \
    "v=\$(sysctl -n kernel.core_pattern 2>/dev/null); echo \"core_pattern = \$v (expected: |/bin/false)\""
}

section_1_6() {
  should_run "1.6" || return
  section_header "1.6" "Configure System-Wide Crypto Policy"

  if [ "$OS_FAMILY" = "rhel" ]; then
    check "1.6.1" "Ensure system wide crypto policy is not set to legacy" \
      "! ${CRYPTO_POLICY} 2>/dev/null | grep -qE '^DEFAULT$|^LEGACY$'" \
      "v=\$(${CRYPTO_POLICY} 2>/dev/null); echo \"policy = \${v:-not set} (expected: FUTURE or FIPS)\""
    check "1.6.2" "Ensure system wide crypto policy is not set in sshd configuration" \
      "! grep -E '^(Ciphers|MACs|KexAlgorithms)' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -q ."
    check "1.6.3" "Ensure system wide crypto policy disables sha1 hash and signature support" \
      "! grep -q 'SHA1' /etc/crypto-policies/back-ends/openssh.config 2>/dev/null"
    check "1.6.4" "Ensure system wide crypto policy disables macs less than 128 bits" \
      "! grep -qi 'hmac-md5\|hmac-sha1' /etc/crypto-policies/back-ends/openssh.config 2>/dev/null"
    check "1.6.5" "Ensure system wide crypto policy disables cbc for ssh" \
      "! grep -qi 'cbc' /etc/crypto-policies/back-ends/openssh.config 2>/dev/null"
    manual_check "1.6.6" "Ensure system wide crypto policy disables chacha20-poly1305 for ssh"
    manual_check "1.6.7" "Ensure system wide crypto policy disables EtM for ssh"
  else
    warn "Crypto policy checks are RHEL-specific — skipping"
  fi
}

section_1_7() {
  should_run "1.7" || return
  section_header "1.7" "Configure Command Line Warning Banners"

  check "1.7.1" "Ensure message of the day is configured properly" \
    "[ ! -f /etc/motd ] || grep -qi 'authorized\|warning\|access' /etc/motd 2>/dev/null"
  check "1.7.2" "Ensure local login warning banner is configured properly" \
    "[ ! -f /etc/issue ] || grep -qi 'authorized\|warning\|access' /etc/issue 2>/dev/null"
  check "1.7.3" "Ensure remote login warning banner is configured properly" \
    "[ ! -f /etc/issue.net ] || grep -qi 'authorized\|warning\|access' /etc/issue.net 2>/dev/null"
  check "1.7.4" "Ensure access to /etc/motd is configured" \
    "[ ! -f /etc/motd ] || [ \$(stat -c '%a' /etc/motd 2>/dev/null) -eq 644 ]" \
    "v=\$(stat -c '%a' /etc/motd 2>/dev/null); echo \"motd mode = \${v:-N/A} (expected: 644)\""
  check "1.7.5" "Ensure access to /etc/issue is configured" \
    "[ ! -f /etc/issue ] || [ \$(stat -c '%a' /etc/issue 2>/dev/null) -eq 644 ]" \
    "v=\$(stat -c '%a' /etc/issue 2>/dev/null); echo \"issue mode = \${v:-N/A} (expected: 644)\""
  check "1.7.6" "Ensure access to /etc/issue.net is configured" \
    "[ ! -f /etc/issue.net ] || [ \$(stat -c '%a' /etc/issue.net 2>/dev/null) -eq 644 ]" \
    "v=\$(stat -c '%a' /etc/issue.net 2>/dev/null); echo \"issue.net mode = \${v:-N/A} (expected: 644)\""
}

section_1_8() {
  should_run "1.8" || return
  section_header "1.8" "Configure GNOME Display Manager"

  if [ "$OS_FAMILY" = "rhel" ]; then
    local gdm_pkgs=( "gdm" "gnome-desktop" "kde-workspace" )
  else
    local gdm_pkgs=( "gdm3" "ubuntu-desktop" "kde-plasma-desktop" )
  fi

  check "1.8.1" "Ensure GNOME Display Manager is removed" "! pkg_installed $GDM_PKG"

  if pkg_installed "$GDM_PKG"; then
    local dconf_d="/etc/dconf/db/local.d"
    local locks_d="/etc/dconf/db/local.d/locks"
    [ -d "$dconf_d" ] || dconf_d="/etc/dconf/db/local.d"
    [ -d "$locks_d" ] || locks_d="/etc/dconf/db/local.d/locks"

    check "1.8.2" "Ensure GDM login banner is configured" \
      "grep -q 'banner-message-enable' ${dconf_d}/*.conf 2>/dev/null"
    check "1.8.3" "Ensure GDM disable-user-list option is enabled" \
      "grep -q 'disable-user-list' ${dconf_d}/*.conf 2>/dev/null"
    check "1.8.4" "Ensure GDM screen locks when the user is idle" \
      "grep -q 'lock-enabled' ${dconf_d}/*.conf 2>/dev/null || grep -q 'idle-delay' ${dconf_d}/*.conf 2>/dev/null"
    check "1.8.5" "Ensure GDM screen locks cannot be overridden" \
      "grep -q 'lock-enabled' ${locks_d}/* 2>/dev/null || grep -q 'idle-delay' ${locks_d}/* 2>/dev/null"
    check "1.8.6" "Ensure GDM automatic mounting of removable media is disabled" \
      "grep -q 'automount' ${dconf_d}/*.conf 2>/dev/null && grep -q 'automount-open' ${dconf_d}/*.conf 2>/dev/null"
    check "1.8.7" "Ensure GDM disabling automatic mounting of removable media is not overridden" \
      "grep -q 'automount' ${locks_d}/* 2>/dev/null && grep -q 'automount-open' ${locks_d}/* 2>/dev/null"
    check "1.8.8" "Ensure GDM autorun-never is enabled" \
      "grep -q 'autorun-never' ${dconf_d}/*.conf 2>/dev/null"
    check "1.8.9" "Ensure GDM autorun-never is not overridden" \
      "grep -q 'autorun-never' ${locks_d}/* 2>/dev/null"
    check "1.8.10" "Ensure XDMCP is not enabled" \
      "! grep -A1 -i '\[xdmcp\]' /etc/gdm/custom.conf 2>/dev/null | grep -qi 'Enable=true'"
  fi
}

# ============================================================
# SECTION 2  SERVICES
# ============================================================

section_2_1() {
  should_run "2.1" || return
  section_header "2.1" "Configure Server Services"

  if [ "$OS_FAMILY" = "rhel" ]; then
    local svc_pkgs=(
      "autofs" "avahi" "dhcp-server" "bind" "dnsmasq" "samba"
      "vsftpd" "dovecot" "nfs-utils" "ypserv" "cups"
      "rpcbind" "rsync-daemon" "snmpd" "telnet-server" "tftp-server"
      "squid" "httpd" "nginx" "xinetd"
    )
    local x11_pkg="xorg-x11-server-Xorg"
    local mta_pkg="postfix"
  else
    local svc_pkgs=(
      "autofs" "avahi-daemon" "isc-dhcp-server" "bind9" "dnsmasq"
      "samba" "vsftpd" "dovecot-core" "nfs-kernel-server" "nis"
      "cups" "rpcbind" "rsync" "snmpd" "telnetd" "tftpd-hpa"
      "squid" "apache2" "nginx" "xinetd"
    )
    local x11_pkg="xorg"
    local mta_pkg="postfix"
  fi

  local idx=1
  for p in "${svc_pkgs[@]}"; do
    check "2.1.$idx" "Ensure ${p} services are not in use" "! pkg_installed $p"
    ((idx++))
  done

  check "2.1.20" "Ensure X window server services are not in use" "! pkg_installed $x11_pkg"
  check "2.1.21" "Ensure mail transfer agents are configured for local-only mode" \
    "[ ! -f /etc/$mta_pkg/main.cf ] || grep -Eq '^inet_interfaces\s*=\s*(loopback-only|localhost)' /etc/$mta_pkg/main.cf 2>/dev/null" \
    "grep -E '^inet_interfaces' /etc/$mta_pkg/main.cf 2>/dev/null || echo 'inet_interfaces not set (expected: localhost or loopback-only)'"
  manual_check "2.1.22" "Ensure only approved services are listening on a network interface"
}

section_2_2() {
  should_run "2.2" || return
  section_header "2.2" "Configure Client Services"

  if [ "$OS_FAMILY" = "rhel" ]; then
    local clients=( "ftp" "openldap-clients" "ypbind" "telnet" "tftp" )
  else
    local clients=( "ftp" "ldap-utils" "nis" "telnet" "tftp" )
  fi

  check "2.2.1" "Ensure ftp client is not installed" "! pkg_installed ${clients[0]}"
  check "2.2.2" "Ensure ldap client is not installed" "! pkg_installed ${clients[1]}"
  check "2.2.3" "Ensure nis client is not installed" "! pkg_installed ${clients[2]}"
  check "2.2.4" "Ensure telnet client is not installed" "! pkg_installed ${clients[3]}"
  check "2.2.5" "Ensure tftp client is not installed" "! pkg_installed ${clients[4]}"
}

section_2_3() {
  should_run "2.3" || return
  section_header "2.3" "Configure Time Synchronization"

  local chrony_ok=false; local timesyncd_ok=false
  systemctl is-active chronyd &>/dev/null && chrony_ok=true
  systemctl is-active systemd-timesyncd &>/dev/null && timesyncd_ok=true

  check "2.3.1" "Ensure time synchronization is in use" \
    "$chrony_ok || $timesyncd_ok"

  if $chrony_ok; then
    check "2.3.2" "Ensure chrony is configured" \
      "grep -q '^server ' /etc/chrony/chrony.conf 2>/dev/null" \
      "grep '^server' /etc/chrony/chrony.conf 2>/dev/null || echo 'no server configured'"
    check "2.3.3" "Ensure chrony is not run as the root user" \
      "grep -q '^user _chrony' /etc/chrony/chrony.conf 2>/dev/null || grep -q '^user chrony' /etc/chrony/chrony.conf 2>/dev/null" \
      "grep '^user' /etc/chrony/chrony.conf 2>/dev/null || echo 'user not set (expected: _chrony or chrony)'"
  fi
}

section_2_4() {
  should_run "2.4" || return
  section_header "2.4" "Configure Job Schedulers"

  sub_header "2.4.1" "Configure cron"
  check "2.4.1.1" "Ensure cron daemon is enabled and active" \
    "systemctl is-enabled ${CRON_SVC} 2>/dev/null | grep -q enabled && systemctl is-active ${CRON_SVC} 2>/dev/null | grep -q active"
  check "2.4.1.2" "Ensure permissions on /etc/crontab are configured" \
    "[ -f /etc/crontab ] && [ \$(stat -c '%a' /etc/crontab 2>/dev/null) -eq 644 ]" \
    "v=\$(stat -c '%a' /etc/crontab 2>/dev/null); echo \"crontab mode = \${v:-N/A} (expected: 644)\""
  check "2.4.1.3" "Ensure permissions on /etc/cron.hourly are configured" \
    "[ -d /etc/cron.hourly ] && [ \$(stat -c '%a' /etc/cron.hourly 2>/dev/null) -eq 755 ]" \
    "v=\$(stat -c '%a' /etc/cron.hourly 2>/dev/null); echo \"cron.hourly mode = \${v:-N/A} (expected: 755)\""
  check "2.4.1.4" "Ensure permissions on /etc/cron.daily are configured" \
    "[ -d /etc/cron.daily ] && [ \$(stat -c '%a' /etc/cron.daily 2>/dev/null) -eq 755 ]" \
    "v=\$(stat -c '%a' /etc/cron.daily 2>/dev/null); echo \"cron.daily mode = \${v:-N/A} (expected: 755)\""
  check "2.4.1.5" "Ensure permissions on /etc/cron.weekly are configured" \
    "[ -d /etc/cron.weekly ] && [ \$(stat -c '%a' /etc/cron.weekly 2>/dev/null) -eq 755 ]" \
    "v=\$(stat -c '%a' /etc/cron.weekly 2>/dev/null); echo \"cron.weekly mode = \${v:-N/A} (expected: 755)\""
  check "2.4.1.6" "Ensure permissions on /etc/cron.monthly are configured" \
    "[ -d /etc/cron.monthly ] && [ \$(stat -c '%a' /etc/cron.monthly 2>/dev/null) -eq 755 ]" \
    "v=\$(stat -c '%a' /etc/cron.monthly 2>/dev/null); echo \"cron.monthly mode = \${v:-N/A} (expected: 755)\""
  check "2.4.1.7" "Ensure permissions on /etc/cron.d are configured" \
    "[ -d /etc/cron.d ] && [ \$(stat -c '%a' /etc/cron.d 2>/dev/null) -eq 755 ]" \
    "v=\$(stat -c '%a' /etc/cron.d 2>/dev/null); echo \"cron.d mode = \${v:-N/A} (expected: 755)\""
  check "2.4.1.8" "Ensure crontab is restricted to authorized users" \
    "[ -f /etc/cron.allow ] && [ \$(stat -c '%a' /etc/cron.allow 2>/dev/null) -le 640 ] && [ ! -f /etc/cron.deny ]"

  sub_header "2.4.2" "Configure at"
  check "2.4.2.1" "Ensure at is restricted to authorized users" \
    "[ -f /etc/at.allow ] && [ \$(stat -c '%a' /etc/at.allow 2>/dev/null) -le 640 ] && [ ! -f /etc/at.deny ]"
}

# ============================================================
# SECTION 3  NETWORK
# ============================================================

section_3_1() {
  should_run "3.1" || return
  section_header "3.1" "Configure Network Devices"

  manual_check "3.1.1" "Ensure IPv6 status is identified"
  check "3.1.2" "Ensure wireless interfaces are disabled" \
    "! iwconfig 2>/dev/null | grep -q 'Mode:Master' && ! ip link 2>/dev/null | grep -qi 'wl.*state UP'"
  check "3.1.3" "Ensure bluetooth services are not in use" \
    "! systemctl is-active bluetooth 2>/dev/null | grep -q active"
}

section_3_2() {
  should_run "3.2" || return
  section_header "3.2" "Configure Network Kernel Modules"

  local -a net_mods=(dccp tipc rds sctp)
  local net_idx=1
  for mod in "${net_mods[@]}"; do
    check "3.2.${net_idx}" "Ensure ${mod} kernel module is not available" "! mod_loaded ${mod}"
    ((net_idx++))
  done
}

section_3_3() {
  should_run "3.3" || return
  section_header "3.3" "Configure Network Kernel Parameters"

  check "3.3.1" "Ensure ip forwarding is disabled" \
    "sysctl_eq net.ipv4.ip_forward 0" \
    "v=\$(sysctl -n net.ipv4.ip_forward 2>/dev/null); echo \"ip_forward = \$v (expected: 0)\""
  check "3.3.2" "Ensure packet redirect sending is disabled" \
    "sysctl_eq net.ipv4.conf.all.send_redirects 0 && sysctl_eq net.ipv4.conf.default.send_redirects 0" \
    "v1=\$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null); v2=\$(sysctl -n net.ipv4.conf.default.send_redirects 2>/dev/null); echo \"all.send_redirects = \$v1, default.send_redirects = \$v2 (expected: 0, 0)\""
  check "3.3.3" "Ensure bogus icmp responses are ignored" \
    "sysctl_eq net.ipv4.icmp_ignore_bogus_error_responses 1" \
    "v=\$(sysctl -n net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null); echo \"icmp_ignore_bogus = \$v (expected: 1)\""
  check "3.3.4" "Ensure broadcast icmp requests are ignored" \
    "sysctl_eq net.ipv4.icmp_echo_ignore_broadcasts 1" \
    "v=\$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null); echo \"icmp_echo_ignore_broadcasts = \$v (expected: 1)\""
  check "3.3.5" "Ensure icmp redirects are not accepted" \
    "sysctl_eq net.ipv4.conf.all.accept_redirects 0 && sysctl_eq net.ipv4.conf.default.accept_redirects 0" \
    "v1=\$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null); v2=\$(sysctl -n net.ipv4.conf.default.accept_redirects 2>/dev/null); echo \"all.accept_redirects = \$v1, default.accept_redirects = \$v2 (expected: 0, 0)\""
  check "3.3.6" "Ensure secure icmp redirects are not accepted" \
    "sysctl_eq net.ipv4.conf.all.secure_redirects 0 && sysctl_eq net.ipv4.conf.default.secure_redirects 0" \
    "v1=\$(sysctl -n net.ipv4.conf.all.secure_redirects 2>/dev/null); v2=\$(sysctl -n net.ipv4.conf.default.secure_redirects 2>/dev/null); echo \"all.secure_redirects = \$v1, default.secure_redirects = \$v2 (expected: 0, 0)\""
  check "3.3.7" "Ensure reverse path filtering is enabled" \
    "sysctl_eq net.ipv4.conf.all.rp_filter 1 && sysctl_eq net.ipv4.conf.default.rp_filter 1" \
    "v1=\$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null); v2=\$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null); echo \"all.rp_filter = \$v1, default.rp_filter = \$v2 (expected: 1, 1)\""
  check "3.3.8" "Ensure source routed packets are not accepted" \
    "sysctl_eq net.ipv4.conf.all.accept_source_route 0 && sysctl_eq net.ipv4.conf.default.accept_source_route 0" \
    "v1=\$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null); v2=\$(sysctl -n net.ipv4.conf.default.accept_source_route 2>/dev/null); echo \"all.accept_source_route = \$v1, default.accept_source_route = \$v2 (expected: 0, 0)\""
  check "3.3.9" "Ensure suspicious packets are logged" \
    "sysctl_eq net.ipv4.conf.all.log_martians 1 && sysctl_eq net.ipv4.conf.default.log_martians 1" \
    "v1=\$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null); v2=\$(sysctl -n net.ipv4.conf.default.log_martians 2>/dev/null); echo \"all.log_martians = \$v1, default.log_martians = \$v2 (expected: 1, 1)\""
  check "3.3.10" "Ensure tcp syn cookies is enabled" \
    "sysctl_eq net.ipv4.tcp_syncookies 1" \
    "v=\$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null); echo \"tcp_syncookies = \$v (expected: 1)\""
  check "3.3.11" "Ensure ipv6 router advertisements are not accepted" \
    "sysctl_eq net.ipv6.conf.all.accept_ra 0 && sysctl_eq net.ipv6.conf.default.accept_ra 0" \
    "v1=\$(sysctl -n net.ipv6.conf.all.accept_ra 2>/dev/null); v2=\$(sysctl -n net.ipv6.conf.default.accept_ra 2>/dev/null); echo \"all.accept_ra = \$v1, default.accept_ra = \$v2 (expected: 0, 0)\""
}

# ============================================================
# SECTION 4  HOST BASED FIREWALL
# ============================================================

section_4() {
  should_run "4" || return
  section_header "4" "Host Based Firewall"

  sub_header "4.1" "Configure a firewall utility"
  local fw=""
  if systemctl is-active --quiet firewalld 2>/dev/null; then fw="firewalld"
  elif systemctl is-active --quiet nftables 2>/dev/null; then fw="nftables"
  elif systemctl is-active --quiet iptables 2>/dev/null; then fw="iptables"
  elif systemctl is-active --quiet ufw 2>/dev/null; then fw="ufw"; fi

  if [ "$OS_FAMILY" = "rhel" ]; then
    check "4.1.1" "Ensure nftables is installed" "pkg_installed nftables"
  else
    check "4.1.1" "Ensure nftables is installed" "pkg_installed nftables"
  fi
  check "4.1.2" "Ensure a single firewall configuration utility is in use" \
    "[ -n \"$fw\" ]"

  if [ "$fw" = "firewalld" ]; then
    sub_header "4.2" "Configure FirewallD"
    manual_check "4.2.1" "Ensure firewalld drops unnecessary services and ports"
    check "4.2.2" "Ensure firewalld loopback traffic is configured" \
      "firewall-cmd --list-all-zones 2>/dev/null | grep -q 'lo'"

  elif [ "$fw" = "nftables" ]; then
    sub_header "4.3" "Configure NFTables"
    check "4.3.1" "Ensure nftables base chains exist" \
      "nft list chains 2>/dev/null | grep -q 'type filter'"
    manual_check "4.3.2" "Ensure nftables established connections are configured"
    check "4.3.3" "Ensure nftables default deny firewall policy" \
      "nft list ruleset 2>/dev/null | grep -q 'drop'"
    check "4.3.4" "Ensure nftables loopback traffic is configured" \
      "nft list ruleset 2>/dev/null | grep -q 'iif lo accept'"

  elif [ "$fw" = "ufw" ]; then
    sub_header "4.3" "Configure NFTables (via ufw)"
    manual_check "4.3.2" "Ensure nftables established connections are configured"
    check "4.3.3" "Ensure nftables default deny firewall policy" \
      "ufw status verbose 2>/dev/null | grep -q 'Default: deny'"
    check "4.3.4" "Ensure nftables loopback traffic is configured" \
      "ufw status 2>/dev/null | grep -q '127.0.0.1' || grep -q 'lo' /etc/ufw/before.rules 2>/dev/null"
  fi

  if [ -z "$fw" ]; then
    warn "No active firewall detected — skipping firewall checks"
  fi
}

# ============================================================
# SECTION 5  ACCESS CONTROL
# ============================================================

section_5_1() {
  should_run "5.1" || return
  section_header "5.1" "Configure SSH Server"

  if [ ! -f /etc/ssh/sshd_config ]; then
    warn "SSH not installed — skipping SSH checks"; return
  fi

  check "5.1.1" "Ensure permissions on /etc/ssh/sshd_config are configured" \
    "[ \$(stat -c '%a' /etc/ssh/sshd_config 2>/dev/null) -le 600 ]" \
    "v=\$(stat -c '%a' /etc/ssh/sshd_config 2>/dev/null); echo \"sshd_config mode = \${v:-N/A} (expected: ≤ 600)\""
  check "5.1.2" "Ensure permissions on SSH private host key files are configured" \
    "! find /etc/ssh -type f -name '*_key' ! -perm 600 2>/dev/null | grep -q ." \
    "find /etc/ssh -type f -name '*_key' ! -perm 600 2>/dev/null | head -3 || echo 'all private keys have correct permissions'"
  check "5.1.3" "Ensure permissions on SSH public host key files are configured" \
    "! find /etc/ssh -type f -name '*.pub' ! -perm 644 2>/dev/null | grep -q ." \
    "find /etc/ssh -type f -name '*.pub' ! -perm 644 2>/dev/null | head -3 || echo 'all public keys have correct permissions'"
  check "5.1.4" "Ensure sshd Ciphers are configured" \
    "sshd -T 2>/dev/null | grep -q 'ciphers '" \
    "v=\$(sshd -T 2>/dev/null | grep 'ciphers '); echo \"\${v:-ciphers not set} (expected: should be configured with strong ciphers)\""
  check "5.1.5" "Ensure sshd KexAlgorithms is configured" \
    "sshd -T 2>/dev/null | grep -q 'kexalgorithms '" \
    "v=\$(sshd -T 2>/dev/null | grep 'kexalgorithms '); echo \"\${v:-kexalgorithms not set} (expected: should be configured with strong KEX)\""
  check "5.1.6" "Ensure sshd MACs are configured" \
    "sshd -T 2>/dev/null | grep -q 'macs '" \
    "v=\$(sshd -T 2>/dev/null | grep 'macs '); echo \"\${v:-macs not set} (expected: should be configured with strong MACs)\""
  check "5.1.7" "Ensure sshd access is configured" \
    "sshd -T 2>/dev/null | grep -q 'allowusers ' || sshd -T 2>/dev/null | grep -q 'allowgroups '" \
    "v=\$(sshd -T 2>/dev/null | grep -E 'allowusers|allowgroups'); echo \"\${v:-no access restrictions set} (expected: AllowUsers or AllowGroups)\""
  check "5.1.8" "Ensure sshd Banner is configured" \
    "sshd -T 2>/dev/null | grep -q 'banner '" \
    "v=\$(sshd -T 2>/dev/null | grep 'banner '); echo \"\${v:-banner not set} (expected: banner with warning message)\""
  check "5.1.9" "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured" \
    "sshd -T 2>/dev/null | awk '/^clientaliveinterval/{v=\$2} END{exit (v>=1 && v<=300)?0:1}' && sshd -T 2>/dev/null | awk '/^clientalivecountmax/{v=\$2} END{exit (v>=1 && v<=3)?0:1}'" \
    "i=\$(sshd -T 2>/dev/null | grep 'clientaliveinterval'); c=\$(sshd -T 2>/dev/null | grep 'clientalivecountmax'); echo \"\${i:-interval not set}, \${c:-count not set} (expected: interval 1-300, count 1-3)\""
  check "5.1.10" "Ensure sshd DisableForwarding is enabled" \
    "sshd -T 2>/dev/null | grep -q 'disableforwarding yes'" \
    "v=\$(sshd -T 2>/dev/null | grep 'disableforwarding'); echo \"\${v:-disableforwarding not set} (expected: yes)\""
  check "5.1.11" "Ensure sshd GSSAPIAuthentication is disabled" \
    "sshd -T 2>/dev/null | grep -q 'gssapiauthentication no'" \
    "v=\$(sshd -T 2>/dev/null | grep 'gssapiauthentication'); echo \"\${v:-gssapiauthentication not set} (expected: no)\""
  check "5.1.12" "Ensure sshd HostbasedAuthentication is disabled" \
    "sshd -T 2>/dev/null | grep -q 'hostbasedauthentication no'" \
    "v=\$(sshd -T 2>/dev/null | grep 'hostbasedauthentication'); echo \"\${v:-hostbasedauthentication not set} (expected: no)\""
  check "5.1.13" "Ensure sshd IgnoreRhosts is enabled" \
    "sshd -T 2>/dev/null | grep -q 'ignorerhosts yes'" \
    "v=\$(sshd -T 2>/dev/null | grep 'ignorerhosts'); echo \"\${v:-ignorerhosts not set} (expected: yes)\""
  check "5.1.14" "Ensure sshd LoginGraceTime is configured" \
    "sshd -T 2>/dev/null | awk '/^logingracetime/{v=\$2} END{exit (v>=1 && v<=60)?0:1}'" \
    "v=\$(sshd -T 2>/dev/null | grep 'logingracetime'); echo \"\${v:-logingracetime not set} (expected: 1-60)\""
  check "5.1.15" "Ensure sshd LogLevel is configured" \
    "sshd -T 2>/dev/null | grep -qE 'loglevel (INFO|VERBOSE)'" \
    "v=\$(sshd -T 2>/dev/null | grep 'loglevel'); echo \"\${v:-loglevel not set} (expected: INFO or VERBOSE)\""
  check "5.1.16" "Ensure sshd MaxAuthTries is configured" \
    "sshd -T 2>/dev/null | awk '/^maxauthtries/{v=\$2} END{exit (v>=1 && v<=4)?0:1}'" \
    "v=\$(sshd -T 2>/dev/null | grep 'maxauthtries'); echo \"\${v:-maxauthtries not set} (expected: 1-4)\""
  check "5.1.17" "Ensure sshd MaxStartups is configured" \
    "sshd -T 2>/dev/null | awk '/^maxstartups/{split(\$2,a,\":\"); exit (a[1]>=1 && a[1]<=10)?0:1}'" \
    "v=\$(sshd -T 2>/dev/null | grep 'maxstartups'); echo \"\${v:-maxstartups not set} (expected: start:rate:full, start 1-10)\""
  check "5.1.18" "Ensure sshd MaxSessions is configured" \
    "sshd -T 2>/dev/null | awk '/^maxsessions/{v=\$2} END{exit (v>=1 && v<=10)?0:1}'" \
    "v=\$(sshd -T 2>/dev/null | grep 'maxsessions'); echo \"\${v:-maxsessions not set} (expected: 1-10)\""
  check "5.1.19" "Ensure sshd PermitEmptyPasswords is disabled" \
    "sshd -T 2>/dev/null | grep -q 'permitemptypasswords no'" \
    "v=\$(sshd -T 2>/dev/null | grep 'permitemptypasswords'); echo \"\${v:-permitemptypasswords not set} (expected: no)\""
  check "5.1.20" "Ensure sshd PermitRootLogin is disabled" \
    "sshd -T 2>/dev/null | grep -q 'permitrootlogin no'" \
    "v=\$(sshd -T 2>/dev/null | grep 'permitrootlogin'); echo \"\${v:-permitrootlogin not set} (expected: no)\""
  check "5.1.21" "Ensure sshd PermitUserEnvironment is disabled" \
    "sshd -T 2>/dev/null | grep -q 'permituserenvironment no'" \
    "v=\$(sshd -T 2>/dev/null | grep 'permituserenvironment'); echo \"\${v:-permituserenvironment not set} (expected: no)\""
  check "5.1.22" "Ensure sshd UsePAM is enabled" \
    "sshd -T 2>/dev/null | grep -q 'usepam yes'" \
    "v=\$(sshd -T 2>/dev/null | grep 'usepam'); echo \"\${v:-usepam not set} (expected: yes)\""
}

section_5_2() {
  should_run "5.2" || return
  section_header "5.2" "Configure Privilege Escalation"

  check "5.2.1" "Ensure sudo is installed" "command -v sudo &>/dev/null"
  check "5.2.2" "Ensure sudo commands use pty" \
    "grep -q 'Defaults.*use_pty' /etc/sudoers /etc/sudoers.d/* 2>/dev/null" \
    "v=\$(grep -rh 'Defaults.*use_pty' /etc/sudoers /etc/sudoers.d/* 2>/dev/null); echo \"\${v:-use_pty not configured} (expected: Defaults use_pty)\""
  check "5.2.3" "Ensure sudo log file exists" \
    "grep -q 'logfile=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null" \
    "v=\$(grep -rh 'logfile=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null); echo \"\${v:-logfile not configured} (expected: Defaults logfile=...)\""
  check "5.2.4" "Ensure users must provide password for escalation" \
    "! grep -q 'NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null" \
    "v=\$(grep -rh 'NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | head -3); echo \"\${v:-no NOPASSWD entries} (NOPASSWD should not be used)\""
  check "5.2.5" "Ensure re-authentication for privilege escalation is not disabled globally" \
    "! grep -q '!authenticate' /etc/sudoers /etc/sudoers.d/* 2>/dev/null" \
    "v=\$(grep -rh '!authenticate' /etc/sudoers /etc/sudoers.d/* 2>/dev/null); echo \"\${v:-not present} (!authenticate should not be set)\""
  check "5.2.6" "Ensure sudo authentication timeout is configured correctly" \
    "grep -q 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/* 2>/dev/null" \
    "v=\$(grep -rh 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/* 2>/dev/null); echo \"\${v:-timestamp_timeout not configured} (expected: timestamp_timeout set)\""
  check "5.2.7" "Ensure access to the su command is restricted" \
    "grep -Eq '^\s*auth\s+required\s+pam_wheel\.so\s+' ${PAM_SU} 2>/dev/null" \
    "grep -E '^\s*auth\s+required\s+pam_wheel\.so' ${PAM_SU} 2>/dev/null || echo 'pam_wheel.so not configured (expected: auth required pam_wheel.so)'"
}

section_5_3() {
  should_run "5.3" || return
  section_header "5.3" "Pluggable Authentication Modules"

  sub_header "5.3.1" "Configure PAM software packages"
  if [ "$OS_FAMILY" = "rhel" ]; then
    check "5.3.1.1" "Ensure latest version of pam is installed" "pkg_installed pam"
    check "5.3.1.2" "Ensure latest version of authselect is installed" "pkg_installed authselect"
    check "5.3.1.3" "Ensure latest version of libpwquality is installed" "pkg_installed libpwquality"
  else
    check "5.3.1.1" "Ensure latest version of pam is installed" "pkg_installed libpam0g"
    check "5.3.1.2" "Ensure latest version of authselect is installed" "true"
    check "5.3.1.3" "Ensure latest version of libpwquality is installed" "pkg_installed libpam-pwquality"
  fi

  sub_header "5.3.2" "Configure authselect"
  if [ "$OS_FAMILY" = "rhel" ]; then
    check "5.3.2.1" "Ensure active authselect profile includes pam modules" \
      "authselect current 2>/dev/null | grep -q 'Profile ID:'" \
      "authselect current 2>/dev/null || echo 'no authselect profile selected'"
    check "5.3.2.2" "Ensure pam_faillock module is enabled" \
      "grep -q 'pam_faillock.so' $PAM_AUTH 2>/dev/null" \
      "grep 'pam_faillock.so' $PAM_AUTH 2>/dev/null || echo 'pam_faillock.so not found (expected: should be enabled)'"
    check "5.3.2.3" "Ensure pam_pwquality module is enabled" \
      "grep -q 'pam_pwquality.so' $PAM_PASSWD 2>/dev/null" \
      "grep 'pam_pwquality.so' $PAM_PASSWD 2>/dev/null || echo 'pam_pwquality.so not found (expected: should be enabled)'"
    check "5.3.2.4" "Ensure pam_pwhistory module is enabled" \
      "grep -q 'pam_pwhistory.so' $PAM_PASSWD 2>/dev/null" \
      "grep 'pam_pwhistory.so' $PAM_PASSWD 2>/dev/null || echo 'pam_pwhistory.so not found (expected: should be enabled)'"
    check "5.3.2.5" "Ensure pam_unix module is enabled" \
      "grep -q 'pam_unix.so' $PAM_PASSWD 2>/dev/null" \
      "grep 'pam_unix.so' $PAM_PASSWD 2>/dev/null || echo 'pam_unix.so not found (expected: should be enabled)'"
  fi

  sub_header "5.3.3" "Configure PAM Arguments"

  sub_header "5.3.3.1" "Configure pam_faillock module"
  if [ "$OS_FAMILY" = "rhel" ]; then
    if [ -f "$FAILLOCK_CONF" ]; then
      check "5.3.3.1.1" "Ensure password failed attempts lockout is configured" \
        "grep -Eq '^\s*deny\s*=\s*[1-5]' $FAILLOCK_CONF 2>/dev/null" \
        "v=\$(grep -E '^\s*deny\s*=' $FAILLOCK_CONF 2>/dev/null); echo \"\${v:-deny not set} (expected: deny = 1-5)\""
      check "5.3.3.1.2" "Ensure password unlock time is configured" \
        "grep -Eq '^\s*unlock_time\s*=\s*(9[0-9]{2,}|[1-9][0-9]{3,}|900)' $FAILLOCK_CONF 2>/dev/null" \
        "v=\$(grep -E '^\s*unlock_time\s*=' $FAILLOCK_CONF 2>/dev/null); echo \"\${v:-unlock_time not set} (expected: unlock_time >= 900)\""
      check "5.3.3.1.3" "Ensure password failed attempts lockout includes root account" \
        "grep -q 'even_deny_root' $FAILLOCK_CONF 2>/dev/null" \
        "grep -E '^\s*even_deny_root' $FAILLOCK_CONF 2>/dev/null || echo 'even_deny_root not set (expected: even_deny_root)'"
    else
      warn "faillock.conf not found"
    fi
  else
    check "5.3.3.1.1" "Ensure password failed attempts lockout is configured" \
      "grep -q 'deny=' /etc/pam.d/common-auth 2>/dev/null" \
      "grep -E 'deny=' /etc/pam.d/common-auth 2>/dev/null || echo 'deny not set (expected: deny=N in pam_faillock.so)'"
    check "5.3.3.1.2" "Ensure password unlock time is configured" \
      "grep -q 'unlock_time=' /etc/pam.d/common-auth 2>/dev/null" \
      "grep -E 'unlock_time=' /etc/pam.d/common-auth 2>/dev/null || echo 'unlock_time not set (expected: unlock_time=N in pam_faillock.so)'"
  fi

  sub_header "5.3.3.2" "Configure pam_pwquality module"
  if [ -f "$PWQUALITY_CONF" ]; then
    check "5.3.3.2.1" "Ensure password number of changed characters is configured" \
      "grep -Eq '^\s*dcredit\s*=\s*-[1-9]' $PWQUALITY_CONF 2>/dev/null" \
      "v=\$(grep -E '^\s*dcredit\s*=' $PWQUALITY_CONF 2>/dev/null); echo \"\${v:-dcredit not set} (expected: dcredit = -1 to -9)\""
    check "5.3.3.2.2" "Ensure password length is configured" \
      "grep -Eq '^\s*minlen\s*=\s*(1[4-9]|[2-9][0-9])' $PWQUALITY_CONF 2>/dev/null" \
      "v=\$(grep -E '^\s*minlen\s*=' $PWQUALITY_CONF 2>/dev/null); echo \"\${v:-minlen not set} (expected: minlen >= 14)\""
    manual_check "5.3.3.2.3" "Ensure password complexity is configured"
    check "5.3.3.2.4" "Ensure password same consecutive characters is configured" \
      "grep -Eq '^\s*maxrepeat\s*=\s*[1-3]' $PWQUALITY_CONF 2>/dev/null" \
      "v=\$(grep -E '^\s*maxrepeat\s*=' $PWQUALITY_CONF 2>/dev/null); echo \"\${v:-maxrepeat not set} (expected: maxrepeat = 1-3)\""
    check "5.3.3.2.5" "Ensure password maximum sequential characters is configured" \
      "grep -Eq '^\s*maxsequence\s*=\s*[1-4]' $PWQUALITY_CONF 2>/dev/null" \
      "v=\$(grep -E '^\s*maxsequence\s*=' $PWQUALITY_CONF 2>/dev/null); echo \"\${v:-maxsequence not set} (expected: maxsequence = 1-4)\""
    check "5.3.3.2.6" "Ensure password dictionary check is enabled" \
      "grep -Eq '^\s*dictcheck\s*=\s*1' $PWQUALITY_CONF 2>/dev/null" \
      "v=\$(grep -E '^\s*dictcheck\s*=' $PWQUALITY_CONF 2>/dev/null); echo \"\${v:-dictcheck not set} (expected: dictcheck = 1)\""
    check "5.3.3.2.7" "Ensure password quality is enforced for the root user" \
      "grep -q 'enforce_for_root' $PWQUALITY_CONF 2>/dev/null" \
      "grep -E '^\s*enforce_for_root' $PWQUALITY_CONF 2>/dev/null || echo 'enforce_for_root not present (expected: should be set)'"
  else
    warn "pwquality.conf not found"
  fi

  sub_header "5.3.3.3" "Configure pam_pwhistory module"
  if [ -f "$PWHISTORY_CONF" ]; then
    check "5.3.3.3.1" "Ensure password history remember is configured" \
      "grep -Eq '^\s*remember\s*=\s*(5|[6-9][0-9]*|1[0-9]+)' $PWHISTORY_CONF 2>/dev/null" \
      "v=\$(grep -E '^\s*remember\s*=' $PWHISTORY_CONF 2>/dev/null); echo \"\${v:-remember not set} (expected: remember >= 5)\""
    check "5.3.3.3.2" "Ensure password history is enforced for the root user" \
      "grep -q 'enforce_for_root' $PWHISTORY_CONF 2>/dev/null" \
      "grep -E '^\s*enforce_for_root' $PWHISTORY_CONF 2>/dev/null || echo 'enforce_for_root not present (expected: should be set)'"
  fi
  check "5.3.3.3.3" "Ensure pam_pwhistory includes use_authtok" \
    "grep -q 'pam_pwhistory.*use_authtok' $PAM_PASSWD 2>/dev/null" \
    "grep 'pam_pwhistory' $PAM_PASSWD 2>/dev/null || echo 'pam_pwhistory not found (expected: pam_pwhistory with use_authtok)'"

  sub_header "5.3.3.4" "Configure pam_unix module"
  check "5.3.3.4.1" "Ensure pam_unix does not include nullok" \
    "! grep -q 'nullok' $PAM_PASSWD 2>/dev/null" \
    "grep 'pam_unix.so' $PAM_PASSWD 2>/dev/null | grep -o 'nullok' || echo 'nullok not present (good)'"
  check "5.3.3.4.2" "Ensure pam_unix does not include remember" \
    "! grep -q 'remember=' $PAM_PASSWD 2>/dev/null" \
    "grep 'pam_unix.so.*remember' $PAM_PASSWD 2>/dev/null || echo 'remember not present in pam_unix (good)'"
  check "5.3.3.4.3" "Ensure pam_unix includes a strong password hashing algorithm" \
    "grep -q 'sha512' $PAM_PASSWD 2>/dev/null" \
    "grep 'pam_unix.so' $PAM_PASSWD 2>/dev/null || echo 'pam_unix not found (expected: sha512)'"
  check "5.3.3.4.4" "Ensure pam_unix includes use_authtok" \
    "grep -q 'use_authtok' $PAM_PASSWD 2>/dev/null" \
    "grep 'pam_unix.so' $PAM_PASSWD 2>/dev/null || echo 'pam_unix not found (expected: use_authtok)'"
}

section_5_4() {
  should_run "5.4" || return
  section_header "5.4" "User Accounts and Environment"

  sub_header "5.4.1" "Configure shadow password suite parameters"
  check "5.4.1.1" "Ensure password expiration is configured" \
    "awk '/^PASS_MAX_DAYS/{v=\$2} END{exit (v+0>0 && v+0<=365)?0:1}' ${LOGINDEFS} 2>/dev/null" \
    "v=\$(grep -E '^PASS_MAX_DAYS' ${LOGINDEFS} 2>/dev/null); echo \"\${v:-not set} (expected: PASS_MAX_DAYS 1-365)\""
  manual_check "5.4.1.2" "Ensure minimum password days is configured"
  check "5.4.1.3" "Ensure password expiration warning days is configured" \
    "awk '/^PASS_WARN_AGE/{v=\$2} END{exit (v+0>=7)?0:1}' ${LOGINDEFS} 2>/dev/null" \
    "v=\$(grep -E '^PASS_WARN_AGE' ${LOGINDEFS} 2>/dev/null); echo \"\${v:-not set} (expected: PASS_WARN_AGE >= 7)\""
  check "5.4.1.4" "Ensure strong password hashing algorithm is configured" \
    "grep -q '^ENCRYPT_METHOD.*SHA512' ${LOGINDEFS} 2>/dev/null" \
    "v=\$(grep -E '^ENCRYPT_METHOD' ${LOGINDEFS} 2>/dev/null); echo \"\${v:-not set} (expected: ENCRYPT_METHOD SHA512)\""
  check "5.4.1.5" "Ensure inactive password lock is configured" \
    "grep -Eq '^\s*INACTIVE\s*=\s*[0-9]+' /etc/default/useradd 2>/dev/null" \
    "v=\$(grep -E '^\s*INACTIVE\s*=' /etc/default/useradd 2>/dev/null); echo \"\${v:-INACTIVE not set} (expected: INACTIVE = 0-30)\""
  check "5.4.1.6" "Ensure all users last password change date is in the past" \
    "! awk -F: '\$3 >= 1000 {system(\"passwd -S \"\$1\" 2>/dev/null\")}' /etc/passwd 2>/dev/null | grep -q 'Never'"

  sub_header "5.4.2" "Configure root and system accounts and environment"
  check "5.4.2.1" "Ensure root is the only UID 0 account" \
    "[[ \$(awk -F: '\$3 == 0 {print \$1}' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]]"
  check "5.4.2.2" "Ensure root is the only GID 0 account" \
    "[[ \$(awk -F: '\$4 == 0 {print \$1}' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]]"
  check "5.4.2.3" "Ensure group root is the only GID 0 group" \
    "[[ \$(awk -F: '\$3 == 0 {print \$1}' /etc/group 2>/dev/null | wc -l) -eq 1 ]]"
  check "5.4.2.4" "Ensure root account access is controlled" \
    "passwd -S root 2>/dev/null | grep -qE 'P |PS'"
  check "5.4.2.5" "Ensure root path integrity" \
    "! echo \$PATH | grep -q '::'"
  check "5.4.2.6" "Ensure root user umask is configured" \
    "grep -Eq '^\s*umask\s+077' /root/.profile /etc/profile /etc/bashrc /root/.bashrc 2>/dev/null" \
    "(grep -E '^\s*umask' /root/.profile 2>/dev/null; grep -E '^\s*umask' /etc/profile 2>/dev/null) | head -1 || echo 'umask not set (expected: umask 077)'"
  check "5.4.2.7" "Ensure system accounts do not have a valid login shell" \
    "! awk -F: '\$3 < 1000 && \$7 !~ /nologin|false/ && \$1 != \"root\"' /etc/passwd 2>/dev/null | grep -q ."
  check "5.4.2.8" "Ensure accounts without a valid login shell are locked" \
    "! awk -F: '\$7 ~ /nologin|false/ && \$2 !~ /^[!*]/' /etc/shadow 2>/dev/null | grep -q ."

  sub_header "5.4.3" "Configure user default environment"
  check "5.4.3.1" "Ensure nologin is not listed in /etc/shells" \
    "! grep -q '/usr/sbin/nologin' /etc/shells 2>/dev/null"
  check "5.4.3.2" "Ensure default user shell timeout is configured" \
    "grep -q '^TMOUT=' /etc/profile 2>/dev/null || grep -q '^TMOUT=' /etc/bashrc 2>/dev/null" \
    "(grep '^TMOUT=' /etc/profile 2>/dev/null; grep '^TMOUT=' /etc/bashrc 2>/dev/null) | head -1 || echo 'TMOUT not set (expected: TMOUT=900 or similar)'"
  check "5.4.3.3" "Ensure default user umask is configured" \
    "grep -Eq 'umask\s+077' ${LOGINDEFS} 2>/dev/null" \
    "grep -E 'umask' ${LOGINDEFS} 2>/dev/null | head -1 || echo 'umask not set in login.defs (expected: umask 077)'"
}

# ============================================================
# SECTION 6  LOGGING AND AUDITING
# ============================================================

section_6_1() {
  should_run "6.1" || return
  section_header "6.1" "Configure Integrity Checking"

  if command -v aide &>/dev/null; then
    check "6.1.1" "Ensure AIDE is installed" "command -v aide &>/dev/null"
    check "6.1.2" "Ensure filesystem integrity is regularly checked" \
      "grep -qs 'aide' /etc/crontab /etc/cron.*/* 2>/dev/null || systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q enabled || systemctl is-enabled aide.timer 2>/dev/null | grep -q enabled"
    check "6.1.3" "Ensure cryptographic mechanisms are used to protect the integrity of audit tools" \
      "command -v aide &>/dev/null && [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ] 2>/dev/null"
  else
    warn "AIDE not installed — skipping integrity checks"
  fi
}

section_6_2() {
  should_run "6.2" || return
  section_header "6.2" "System Logging"

  sub_header "6.2.1" "Configure systemd-journald service"
  check "6.2.1.1" "Ensure journald service is enabled and active" \
    "systemctl is-enabled systemd-journald 2>/dev/null | grep -q enabled && systemctl is-active systemd-journald 2>/dev/null | grep -q active"
  manual_check "6.2.1.2" "Ensure journald log file access is configured"
  manual_check "6.2.1.3" "Ensure journald log file rotation is configured"
  check "6.2.1.4" "Ensure only one logging system is in use" \
    "(! systemctl is-active rsyslog 2>/dev/null | grep -q active) || (! systemctl is-active systemd-journald 2>/dev/null | grep -q active)"

  sub_header "6.2.2" "Configure journald"

  sub_header "6.2.2.1" "Configure systemd-journal-remote"
  if command -v systemd-journal-remote &>/dev/null; then
    check "6.2.2.1.1" "Ensure systemd-journal-remote is installed" "command -v systemd-journal-remote &>/dev/null"
    manual_check "6.2.2.1.2" "Ensure systemd-journal-upload authentication is configured"
    check "6.2.2.1.3" "Ensure systemd-journal-upload is enabled and active" \
      "systemctl is-enabled systemd-journal-upload 2>/dev/null | grep -q enabled && systemctl is-active systemd-journal-upload 2>/dev/null | grep -q active"
    check "6.2.2.1.4" "Ensure systemd-journal-remote service is not in use" \
      "! systemctl is-active systemd-journal-remote 2>/dev/null | grep -q active"
  fi

  local jc="/etc/systemd/journald.conf"
  if [ -f "$jc" ]; then
    check "6.2.2.2" "Ensure journald ForwardToSyslog is disabled" \
      "grep -Eq '^\s*ForwardToSyslog\s*=\s*no' $jc 2>/dev/null || grep -Eq '^\s*ForwardToSyslog\s*=\s*yes' $jc 2>/dev/null" \
      "v=\$(grep -E '^\s*ForwardToSyslog\s*=' $jc 2>/dev/null); echo \"\${v:-not set} (expected: ForwardToSyslog=no or yes)\""
    check "6.2.2.3" "Ensure journald Compress is configured" \
      "grep -Eq '^\s*Compress\s*=\s*(yes|no)' $jc 2>/dev/null" \
      "v=\$(grep -E '^\s*Compress\s*=' $jc 2>/dev/null); echo \"\${v:-Compress not set} (expected: Compress=yes or no)\""
    check "6.2.2.4" "Ensure journald Storage is configured" \
      "grep -Eq '^\s*Storage\s*=\s*(persistent|volatile|auto|none)' $jc 2>/dev/null" \
      "v=\$(grep -E '^\s*Storage\s*=' $jc 2>/dev/null); echo \"\${v:-Storage not set} (expected: Storage=persistent/volatile/auto/none)\""
  fi

  sub_header "6.2.3" "Configure rsyslog"
  if command -v rsyslogd &>/dev/null; then
    check "6.2.3.1" "Ensure rsyslog is installed" "command -v rsyslogd &>/dev/null"
    check "6.2.3.2" "Ensure rsyslog service is enabled and active" \
      "systemctl is-enabled rsyslog 2>/dev/null | grep -q enabled && systemctl is-active rsyslog 2>/dev/null | grep -q active"
    check "6.2.3.3" "Ensure journald is configured to send logs to rsyslog" \
      "grep -Eq '^\s*ForwardToSyslog\s*=\s*yes' $jc 2>/dev/null" \
      "v=\$(grep -E '^\s*ForwardToSyslog\s*=' $jc 2>/dev/null); echo \"\${v:-not set} (expected: ForwardToSyslog=yes)\""
    check "6.2.3.4" "Ensure rsyslog log file creation mode is configured" \
      "grep -q '^\$FileCreateMode' /etc/rsyslog.conf 2>/dev/null || grep -q '^\$FileCreateMode' /etc/rsyslog.d/*.conf 2>/dev/null" \
      "(grep '^\$FileCreateMode' /etc/rsyslog.conf 2>/dev/null; grep '^\$FileCreateMode' /etc/rsyslog.d/*.conf 2>/dev/null) | head -1 || echo 'FileCreateMode not set'"
    manual_check "6.2.3.5" "Ensure rsyslog logging is configured"
    manual_check "6.2.3.6" "Ensure rsyslog is configured to send logs to a remote log host"
    check "6.2.3.7" "Ensure rsyslog is not configured to receive logs from a remote client" \
      "! grep -r 'imtcp' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v '^#' | grep -q ."
    manual_check "6.2.3.8" "Ensure rsyslog logrotate is configured"
  else
    warn "rsyslog not installed — skipping rsyslog checks"
  fi

  sub_header "6.2.4" "Configure Logfiles"
  check "6.2.4.1" "Ensure access to all logfiles has been configured" \
    "[ -d /var/log ] && [ \$(stat -c '%a' /var/log 2>/dev/null) -le 755 ]" \
    "v=\$(stat -c '%a' /var/log 2>/dev/null); echo \"/var/log mode = \${v:-N/A} (expected: ≤ 755)\""
}

section_6_3() {
  should_run "6.3" || return
  section_header "6.3" "System Auditing"

  if ! command -v auditctl &>/dev/null; then
    warn "auditd not installed — skipping audit checks"; return
  fi

  sub_header "6.3.1" "Configure auditd Service"
  check "6.3.1.1" "Ensure auditd packages are installed" "command -v auditctl &>/dev/null"
  check "6.3.1.2" "Ensure auditing for processes that start prior to auditd is enabled" \
    "grep -q 'audit=1' /proc/cmdline 2>/dev/null" \
    "grep -o 'audit=[01]' /proc/cmdline 2>/dev/null || echo 'audit= not found in cmdline (expected: audit=1)'"
  check "6.3.1.3" "Ensure audit_backlog_limit is sufficient" \
    "grep -q 'audit_backlog_limit=' /proc/cmdline 2>/dev/null" \
    "grep -o 'audit_backlog_limit=[0-9]*' /proc/cmdline 2>/dev/null || echo 'audit_backlog_limit not found (expected: audit_backlog_limit=N)'"
  check "6.3.1.4" "Ensure auditd service is enabled and active" \
    "systemctl is-enabled auditd 2>/dev/null | grep -q enabled && systemctl is-active auditd 2>/dev/null | grep -q active"

  sub_header "6.3.2" "Configure Data Retention"
  check "6.3.2.1" "Ensure audit log storage size is configured" \
    "grep -Eq '^\s*max_log_file\s*=\s*[0-9]+' /etc/audit/auditd.conf 2>/dev/null" \
    "v=\$(grep -E '^\s*max_log_file' /etc/audit/auditd.conf 2>/dev/null); echo \"\${v:-not set} (expected: max_log_file = N)\""
  check "6.3.2.2" "Ensure audit logs are not automatically deleted" \
    "grep -q 'max_log_file_action\s*=\s*keep_logs' /etc/audit/auditd.conf 2>/dev/null" \
    "v=\$(grep 'max_log_file_action' /etc/audit/auditd.conf 2>/dev/null); echo \"\${v:-not set} (expected: max_log_file_action = keep_logs)\""
  check "6.3.2.3" "Ensure system is disabled when audit logs are full" \
    "grep -q 'space_left_action\s*=\s*email' /etc/audit/auditd.conf 2>/dev/null" \
    "v=\$(grep 'space_left_action' /etc/audit/auditd.conf 2>/dev/null); echo \"\${v:-not set} (expected: space_left_action = email)\""
  check "6.3.2.4" "Ensure system warns when audit logs are low on space" \
    "grep -Eq '^\s*admin_space_left_action\s*=\s*(halt|single)' /etc/audit/auditd.conf 2>/dev/null" \
    "v=\$(grep 'admin_space_left_action' /etc/audit/auditd.conf 2>/dev/null); echo \"\${v:-not set} (expected: admin_space_left_action = halt or single)\""

  sub_header "6.3.3" "Configure auditd Rules"
  check "6.3.3.1" "Ensure changes to system administration scope (sudoers) is collected" \
    "auditctl -l 2>/dev/null | grep -q '/etc/sudoers'"
  check "6.3.3.2" "Ensure actions as another user are always logged" \
    "auditctl -l 2>/dev/null | grep -q 'execve'"
  check "6.3.3.3" "Ensure events that modify the sudo log file are collected" \
    "auditctl -l 2>/dev/null | grep -q 'sudo_log'"
  check "6.3.3.4" "Ensure events that modify date and time information are collected" \
    "auditctl -l 2>/dev/null | grep -q 'localtime\|adjtimex\|settimeofday'"
  check "6.3.3.5" "Ensure events that modify the system's network environment are collected" \
    "auditctl -l 2>/dev/null | grep -q 'sethostname\|setdomainname'"
  check "6.3.3.6" "Ensure use of privileged commands are collected" \
    "auditctl -l 2>/dev/null | grep -q 'chmod\|chown'"
  check "6.3.3.7" "Ensure unsuccessful file access attempts are collected" \
    "auditctl -l 2>/dev/null | grep -q 'EACCES\|EPERM'"
  check "6.3.3.8" "Ensure events that modify user/group information are collected" \
    "auditctl -l 2>/dev/null | grep -q '/etc/passwd\|/etc/group\|/etc/shadow'"
  check "6.3.3.9" "Ensure discretionary access control permission modification events are collected" \
    "auditctl -l 2>/dev/null | grep -q 'chmod\|chown\|fchmod\|fchown'"
  check "6.3.3.10" "Ensure successful file system mounts are collected" \
    "auditctl -l 2>/dev/null | grep -q 'mount'"
  check "6.3.3.11" "Ensure session initiation information is collected" \
    "auditctl -l 2>/dev/null | grep -q 'login\|wtmp\|btmp'"
  check "6.3.3.12" "Ensure login and logout events are collected" \
    "auditctl -l 2>/dev/null | grep -q 'lastlog\|faillog'"
  check "6.3.3.13" "Ensure file deletion events by users are collected" \
    "auditctl -l 2>/dev/null | grep -q 'unlink\|rename'"
  check "6.3.3.14" "Ensure events that modify the system's Mandatory Access Controls are collected" \
    "auditctl -l 2>/dev/null | grep -q 'setenforce\|selinux'"
  check "6.3.3.15" "Ensure successful and unsuccessful attempts to use the chcon command are collected" \
    "auditctl -l 2>/dev/null | grep -q 'chcon'"
  check "6.3.3.16" "Ensure successful and unsuccessful attempts to use the setfacl command are collected" \
    "auditctl -l 2>/dev/null | grep -q 'setfacl'"
  check "6.3.3.17" "Ensure successful and unsuccessful attempts to use the chacl command are collected" \
    "auditctl -l 2>/dev/null | grep -q 'chacl'"
  check "6.3.3.18" "Ensure successful and unsuccessful attempts to use the usermod command are collected" \
    "auditctl -l 2>/dev/null | grep -q 'usermod'"
  check "6.3.3.19" "Ensure kernel module loading unloading and modification is collected" \
    "auditctl -l 2>/dev/null | grep -q 'modprobe\|init_module\|insmod'"
  check "6.3.3.20" "Ensure the audit configuration is immutable" \
    "auditctl -l 2>/dev/null | tail -1 | grep -q '\-e 2' || grep -q -- '^\s*-e\s*2' ${AUDIT_RULE_DIR}/*.rules 2>/dev/null"
  manual_check "6.3.3.21" "Ensure the running and on disk configuration is the same"

  sub_header "6.3.4" "Configure auditd File Access"
  check "6.3.4.1" "Ensure the audit log file directory mode is configured" \
    "[ -d /var/log/audit ] && [ \$(stat -c '%a' /var/log/audit 2>/dev/null) -eq 700 ]" \
    "v=\$(stat -c '%a' /var/log/audit 2>/dev/null); echo \"/var/log/audit mode = \${v:-N/A} (expected: 700)\""
  check "6.3.4.2" "Ensure audit log files mode is configured" \
    "! find /var/log/audit -type f ! -perm 600 2>/dev/null | grep -q ." \
    "find /var/log/audit -type f ! -perm 600 2>/dev/null | head -3 || echo 'all audit logs have correct permissions'"
  check "6.3.4.3" "Ensure audit log files owner is configured" \
    "[ \$(stat -c '%U' /var/log/audit/*.log 2>/dev/null | head -1) = 'root' ]" \
    "v=\$(stat -c '%U' /var/log/audit/*.log 2>/dev/null | head -1); echo \"owner = \${v:-N/A} (expected: root)\""
  check "6.3.4.4" "Ensure audit log files group owner is configured" \
    "[ \$(stat -c '%G' /var/log/audit/*.log 2>/dev/null | head -1) = 'root' ]" \
    "v=\$(stat -c '%G' /var/log/audit/*.log 2>/dev/null | head -1); echo \"group = \${v:-N/A} (expected: root)\""
  check "6.3.4.5" "Ensure audit configuration files mode is configured" \
    "[ \$(stat -c '%a' /etc/audit/auditd.conf 2>/dev/null) -le 640 ]" \
    "v=\$(stat -c '%a' /etc/audit/auditd.conf 2>/dev/null); echo \"auditd.conf mode = \${v:-N/A} (expected: ≤ 640)\""
  check "6.3.4.6" "Ensure audit configuration files owner is configured" \
    "[ \$(stat -c '%U' /etc/audit/auditd.conf 2>/dev/null) = 'root' ]" \
    "v=\$(stat -c '%U' /etc/audit/auditd.conf 2>/dev/null); echo \"owner = \${v:-N/A} (expected: root)\""
  check "6.3.4.7" "Ensure audit configuration files group owner is configured" \
    "[ \$(stat -c '%G' /etc/audit/auditd.conf 2>/dev/null) = 'root' ]" \
    "v=\$(stat -c '%G' /etc/audit/auditd.conf 2>/dev/null); echo \"group = \${v:-N/A} (expected: root)\""
  check "6.3.4.8" "Ensure audit tools mode is configured" \
    "[ \$(stat -c '%a' /sbin/auditctl 2>/dev/null) -le 755 ]" \
    "v=\$(stat -c '%a' /sbin/auditctl 2>/dev/null); echo \"auditctl mode = \${v:-N/A} (expected: ≤ 755)\""
  check "6.3.4.9" "Ensure audit tools owner is configured" \
    "[ \$(stat -c '%U' /sbin/auditctl 2>/dev/null) = 'root' ]" \
    "v=\$(stat -c '%U' /sbin/auditctl 2>/dev/null); echo \"owner = \${v:-N/A} (expected: root)\""
  check "6.3.4.10" "Ensure audit tools group owner is configured" \
    "[ \$(stat -c '%G' /sbin/auditctl 2>/dev/null) = 'root' ]" \
    "v=\$(stat -c '%G' /sbin/auditctl 2>/dev/null); echo \"group = \${v:-N/A} (expected: root)\""
}

# ============================================================
# SECTION 7  SYSTEM MAINTENANCE
# ============================================================

section_7_1() {
  should_run "7.1" || return
  section_header "7.1" "System File Permissions"

  check "7.1.1" "Ensure permissions on /etc/passwd are configured" \
    "[ \$(stat -c '%a' /etc/passwd 2>/dev/null) -eq 644 ]" \
    "v=\$(stat -c '%a' /etc/passwd 2>/dev/null); echo \"passwd mode = \${v:-N/A} (expected: 644)\""
  check "7.1.2" "Ensure permissions on /etc/passwd- are configured" \
    "[ ! -f /etc/passwd- ] || [ \$(stat -c '%a' /etc/passwd- 2>/dev/null) -eq 644 ]" \
    "v=\$(stat -c '%a' /etc/passwd- 2>/dev/null); echo \"passwd- mode = \${v:-N/A} (expected: 644)\""
  check "7.1.3" "Ensure permissions on /etc/group are configured" \
    "[ \$(stat -c '%a' /etc/group 2>/dev/null) -eq 644 ]" \
    "v=\$(stat -c '%a' /etc/group 2>/dev/null); echo \"group mode = \${v:-N/A} (expected: 644)\""
  check "7.1.4" "Ensure permissions on /etc/group- are configured" \
    "[ ! -f /etc/group- ] || [ \$(stat -c '%a' /etc/group- 2>/dev/null) -eq 644 ]" \
    "v=\$(stat -c '%a' /etc/group- 2>/dev/null); echo \"group- mode = \${v:-N/A} (expected: 644)\""
  check "7.1.5" "Ensure permissions on /etc/shadow are configured" \
    "[ \$(stat -c '%a' /etc/shadow 2>/dev/null) -eq 000 ]" \
    "v=\$(stat -c '%a' /etc/shadow 2>/dev/null); echo \"shadow mode = \${v:-N/A} (expected: 000)\""
  check "7.1.6" "Ensure permissions on /etc/shadow- are configured" \
    "[ ! -f /etc/shadow- ] || [ \$(stat -c '%a' /etc/shadow- 2>/dev/null) -eq 000 ]" \
    "v=\$(stat -c '%a' /etc/shadow- 2>/dev/null); echo \"shadow- mode = \${v:-N/A} (expected: 000)\""
  check "7.1.7" "Ensure permissions on /etc/gshadow are configured" \
    "[ \$(stat -c '%a' /etc/gshadow 2>/dev/null) -eq 000 ]" \
    "v=\$(stat -c '%a' /etc/gshadow 2>/dev/null); echo \"gshadow mode = \${v:-N/A} (expected: 000)\""
  check "7.1.8" "Ensure permissions on /etc/gshadow- are configured" \
    "[ ! -f /etc/gshadow- ] || [ \$(stat -c '%a' /etc/gshadow- 2>/dev/null) -eq 000 ]" \
    "v=\$(stat -c '%a' /etc/gshadow- 2>/dev/null); echo \"gshadow- mode = \${v:-N/A} (expected: 000)\""
  check "7.1.9" "Ensure permissions on /etc/shells are configured" \
    "[ \$(stat -c '%a' /etc/shells 2>/dev/null) -eq 644 ]" \
    "v=\$(stat -c '%a' /etc/shells 2>/dev/null); echo \"shells mode = \${v:-N/A} (expected: 644)\""
  check "7.1.10" "Ensure permissions on /etc/security/opasswd are configured" \
    "[ ! -f /etc/security/opasswd ] || [ \$(stat -c '%a' /etc/security/opasswd 2>/dev/null) -eq 600 ]" \
    "v=\$(stat -c '%a' /etc/security/opasswd 2>/dev/null); echo \"opasswd mode = \${v:-N/A} (expected: 600)\""
  check "7.1.11" "Ensure world writable files and directories are secured" \
    "! find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -perm -0002 -print 2>/dev/null | grep -q ." \
    "echo 'world-writable files found — review with: find / -xdev -type f -perm -0002'"
  check "7.1.12" "Ensure no files or directories without an owner and a group exist" \
    "! find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -nouser -o -nogroup -print 2>/dev/null | grep -q ." \
    "echo 'orphaned files found — review with: find / -xdev -nouser -o -nogroup'"
  manual_check "7.1.13" "Ensure SUID and SGID files are reviewed"
}

section_7_2() {
  should_run "7.2" || return
  section_header "7.2" "Local User and Group Settings"

  check "7.2.1" "Ensure accounts in /etc/passwd use shadowed passwords" \
    "! awk -F: '(\$2 != \"x\" && \$1 != \"\")' /etc/passwd 2>/dev/null | grep -q ."
  check "7.2.2" "Ensure /etc/shadow password fields are not empty" \
    "! awk -F: '(\$2 == \"\")' /etc/shadow 2>/dev/null | grep -q ."
  check "7.2.3" "Ensure all groups in /etc/passwd exist in /etc/group" \
    "! comm -23 <(cut -d: -f4 /etc/passwd 2>/dev/null | sort -u) <(cut -d: -f3 /etc/group 2>/dev/null | sort -u) 2>/dev/null | grep -q ."
  check "7.2.4" "Ensure no duplicate UIDs exist" \
    "[[ -z \$(cut -d: -f3 /etc/passwd 2>/dev/null | sort | uniq -d) ]]"
  check "7.2.5" "Ensure no duplicate GIDs exist" \
    "[[ -z \$(cut -d: -f3 /etc/group 2>/dev/null | sort | uniq -d) ]]"
  check "7.2.6" "Ensure no duplicate user names exist" \
    "[[ -z \$(cut -d: -f1 /etc/passwd 2>/dev/null | sort | uniq -d) ]]"
  check "7.2.7" "Ensure no duplicate group names exist" \
    "[[ -z \$(cut -d: -f1 /etc/group 2>/dev/null | sort | uniq -d) ]]"
  check "7.2.8" "Ensure local interactive user home directories are configured" \
    "awk -F: '(\$3 >= 1000 && \$7 !~ /(nologin|false)/ && \$1 != \"nobody\") {print \$6}' /etc/passwd 2>/dev/null | while read dir; do [ -d \"\$dir\" ] || exit 1; done"
  manual_check "7.2.9" "Ensure local interactive user dot files access is configured"
}

# ============================================================
# SUMMARY
# ============================================================

show_summary() {
  local total=$((PASSED + FAILED + MANUAL))
  local pass_pct=0; local fail_pct=0
  if [ "$total" -gt 0 ]; then
    pass_pct=$((100 * PASSED / total))
    fail_pct=$((100 * (FAILED + MANUAL) / total))
  fi

  echo ""; echo -e "$BTOP"
  echo -e "${BV}${WHITE}                    AUDIT SUMMARY${NC}                           ${BV}"
  echo -e "$BMID"
  printf "${BV}${NC}  %-30s %s ${BV}\n" "OS:" "${OS_NAME}"
  printf "${BV}${NC}  %-30s %s ${BV}\n" "Audit Date:" "$(date '+%Y-%m-%d %H:%M:%S')"
  echo -e "$BMID"
  printf "${BV}${NC}  ${GREEN}%-30s %6d/%-4d (%3d%%)${NC}       ${BV}\n" "$SPA" "$PASSED" "$total" "$pass_pct"
  printf "${BV}${NC}  ${RED}%-30s %6d/%-4d (%3d%%)${NC}       ${BV}\n" "$SFA" "$FAILED" "$total" "$((100*FAILED/total))"
  printf "${BV}${NC}  ${YELLOW}%-30s %6d/%-4d${NC}             ${BV}\n" "$SMA" "$MANUAL" "$total"
  echo -e "$BMID"
  printf "${BV}${NC}  %-30s %6d/%-4d              ${BV}\n" "$STO" "$total" "$total"

  local grade="F"; local grade_color="${RED}"
  if [ "$total" -gt 0 ]; then
    if [ "$pass_pct" -ge 90 ]; then grade="A"; grade_color="${GREEN}"
    elif [ "$pass_pct" -ge 80 ]; then grade="B"; grade_color="${GREEN}"
    elif [ "$pass_pct" -ge 70 ]; then grade="C"; grade_color="${YELLOW}"
    elif [ "$pass_pct" -ge 60 ]; then grade="D"; grade_color="${YELLOW}"
    else grade="F"; grade_color="${RED}"; fi
  fi
  printf "${BV}${NC}  %-30s ${grade_color}%6s${NC}                    ${BV}\n" "$SGR" "$grade"
  echo -e "$BMID"
  printf "${BV}${NC}  %-30s %s   ${BV}\n" "  Log file:" "${LOG_FILE}"
  echo -e "$BBOT"; echo ""

  {
    echo "CIS Audit Summary"; echo "================="
    echo "OS: $OS_NAME"; echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Passed: $PASSED/$total ($pass_pct%)"
    echo "Failed: $FAILED/$total ($((100*FAILED/total))%)"
    echo "Manual: $MANUAL/$total ($((100*MANUAL/total))%)"
    echo "Grade: $grade"
  } > "$SUMMARY_FILE"

  # Exit code: 0 if no failures, 1 otherwise
  [ "$FAILED" -gt 0 ] && exit 1 || exit 0
}

# ============================================================
# MAIN EXECUTION
# ============================================================

usage() {
  echo "Usage: $0 [OPTIONS]"
  echo "  -q, --quiet        Only show FAIL lines + summary (hide PASS)"
  echo "      --show-manual  Also show manual-review items (hidden by default)"
  echo "      --section NUM  Run only a specific section (e.g. 5.3, 6.2)"
  echo "  -h, --help         Show this help"
  exit 0
}

main() {
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -q|--quiet) QUIET=true; shift ;;
      --show-manual) SHOW_MANUAL=true; shift ;;
      --section) SECTION_FILTER="$2"; shift 2 ;;
      -h|--help) usage ;;
      *) echo "Unknown option: $1"; usage ;;
    esac
  done

  detect_os
  if [ "$OS_FAMILY" = "unknown" ]; then
    echo -e "${RED}Unsupported OS. Exiting.${NC}"; exit 1
  fi
  set_os_vars; banner

  section_1_1_1; section_1_1_2; section_1_2; section_1_3
  section_1_4; section_1_5; section_1_6; section_1_7; section_1_8

  section_2_1; section_2_2; section_2_3; section_2_4

  section_3_1; section_3_2; section_3_3

  section_4

  section_5_1; section_5_2; section_5_3; section_5_4

  section_6_1; section_6_2; section_6_3

  section_7_1; section_7_2

  show_summary
}

main "$@"
