#!/bin/bash
# CIS Hardening audit Script - for rhel and debian
# Author: Behnam0x
# Detect OS family
OS_ID=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
OS_LIKE=$(grep '^ID_LIKE=' /etc/os-release | cut -d= -f2 | tr -d '"')

if [[ "$OS_LIKE" == *rhel* || "$OS_ID" == "rhel" || "$OS_ID" == "ol" || "$OS_ID" == "centos" ]]; then
  OS_FAMILY="rhel"
elif [[ "$OS_LIKE" == *debian* || "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]]; then
  OS_FAMILY="debian"
else
  OS_FAMILY="unknown"
fi

echo "🧭 Detected OS family: $OS_FAMILY" | tee -a "$RESULT_FILE"

LOG_DIR="/var/log/cis_audit"
mkdir -p "$LOG_DIR"
RESULT_FILE="$LOG_DIR/cis_audit_results.log"
> "$RESULT_FILE"

PASS_COUNT=0
FAIL_COUNT=0

start_section() {
  echo -e "\n🔹 $1" | tee -a "$RESULT_FILE"
}

check_item() {
  local description="$1"
  local command="$2"
  local GREEN='\033[0;32m'
  local RED='\033[0;31m'
  local NC='\033[0m' # No Color

  if eval "$command" &>/dev/null; then
    echo -e "  ${GREEN}✅ $description${NC}" | tee -a "$RESULT_FILE"
    ((PASS_COUNT++))
  else
    echo -e "  ${RED}❌ $description${NC}" | tee -a "$RESULT_FILE"
    ((FAIL_COUNT++))
  fi
}

check_package_installed() {
  local package="$1"
  if [ "$OS_FAMILY" = "debian" ]; then
    dpkg -l | grep -q "$package"
  elif [ "$OS_FAMILY" = "rhel" ]; then
    rpm -q "$package" &>/dev/null
  else
    return 1
  fi
}

if [ "$OS_FAMILY" = "debian" ]; then
  PAM_PASSWORD_FILE="$PAM_PASSWORD_FILE"
else
  PAM_PASSWORD_FILE="/etc/pam.d/system-auth"
fi


# === SECTION 1: Initial Setup ===
start_section "1.1.1 - Filesystem Kernel Modules"
check_item "1.1.1.1 cramfs not loaded" "! lsmod | grep -q cramfs"
check_item "1.1.1.2 freevxfs not loaded" "! lsmod | grep -q freevxfs"
check_item "1.1.1.3 hfs not loaded" "! lsmod | grep -q hfs"
check_item "1.1.1.4 hfsplus not loaded" "! lsmod | grep -q hfsplus"
check_item "1.1.1.5 jffs2 not loaded" "! lsmod | grep -q jffs2"
check_item "1.1.1.6 overlayfs not loaded" "! lsmod | grep -q overlayfs"
check_item "1.1.1.7 squashfs not loaded" "! lsmod | grep -q squashfs"
check_item "1.1.1.8 udf not loaded" "! lsmod | grep -q udf"
check_item "1.1.1.9 usb-storage not loaded" "! lsmod | grep -q usb_storage"

start_section "1.1.2 - Filesystem Partitions"
for mp in /tmp /dev/shm /home /var /var/tmp /var/log /var/log/audit; do
  check_item "$mp is a separate partition" "mount | grep -q 'on $mp '"
  check_item "$mp has nodev" "mount | grep $mp | grep -q nodev"
  check_item "$mp has nosuid" "mount | grep $mp | grep -q nosuid"
  check_item "$mp has noexec" "mount | grep $mp | grep -q noexec"
done

start_section "1.2 - Package Updates"

if [ "$OS_FAMILY" = "debian" ]; then
  check_item "1.2.2.1 System updated (APT)" "[ \$(find /var/lib/apt/lists/ -type f | wc -l) -gt 0 ]"
elif [ "$OS_FAMILY" = "rhel" ]; then
  check_item "1.2.2.1 System updated (DNF/YUM)" "dnf check-update >/dev/null 2>&1 || yum check-update >/dev/null 2>&1"
fi


start_section "1.3 - Mandatory Access Control"

if [ "$OS_FAMILY" = "debian" ]; then
  check_item "1.3.1.1 AppArmor installed" "check_package_installed apparmor"
  check_item "1.3.1.2 AppArmor enabled in GRUB" "grep -E '^\s*GRUB_CMDLINE_LINUX=.*apparmor=1' /etc/default/grub"
  check_item "1.3.1.3 AppArmor profiles enforcing" "command -v aa-status >/dev/null && aa-status | grep -q 'profiles are in enforce mode'"
elif [ "$OS_FAMILY" = "rhel" ]; then
  check_item "SELinux enforcing" "getenforce | grep -q Enforcing"
  check_item "SELinux config set to enforcing" "grep -q '^SELINUX=enforcing' /etc/selinux/config"
fi



start_section "1.4 - Bootloader"
check_item "1.4.1 GRUB password set" "grep -q 'password_pbkdf2' /boot/grub/grub.cfg"
check_item "1.4.2 GRUB config owned by root" "stat -c '%U:%G' /boot/grub/grub.cfg | grep -q 'root:root'"
check_item "1.4.2 GRUB config permissions ≤ 600" "[ $(stat -c '%a' /boot/grub/grub.cfg) -le 600 ]"

start_section "1.5 - Kernel Hardening"
check_item "1.5.1 ASLR enabled" "sysctl kernel.randomize_va_space | grep -q '2'"
check_item "1.5.2 ptrace restricted" "sysctl kernel.yama.ptrace_scope | grep -q '1'"

check_item "1.5.3.1 fs.suid_dumpable = 0" "sysctl fs.suid_dumpable | grep -q 'fs.suid_dumpable = 0'"
check_item "1.5.3.2 kernel.core_pattern = |/bin/false" "sysctl kernel.core_pattern | grep -q '|/bin/false'"
check_item "1.5.3.3 limits.conf disables core dumps" "grep -Eq '^\* (hard|soft) core 0' /etc/security/limits.conf"

check_item "1.5.4 Ensure prelink is not installed" "! check_package_installed prelink"

if [ "$OS_FAMILY" = "debian" ]; then
  check_item "1.5.5 Ensure apport is disabled" "[ -f /etc/default/apport ] && grep -q '^enabled=0' /etc/default/apport"
elif [ "$OS_FAMILY" = "rhel" ]; then
  check_item "1.5.5 Ensure ABRT is removed" "! check_package_installed abrt"
  check_item "1.5.5 Ensure ABRT CLI is removed" "! check_package_installed abrt-cli"
  check_item "1.5.5 Ensure ABRT GUI is removed" "! check_package_installed abrt-gui"
fi

if [ "$OS_FAMILY" = "rhel" ]; then
  start_section "1.6 - Configure System-Wide Crypto Policy"

  check_item "1.6.1 crypto policy is set to FUTURE" \
    "[ \"$(update-crypto-policies --show)\" = \"FUTURE\" ]"

  check_item "1.6.2 sshd_config does not override crypto policy" \
    "! grep -Ei '^(Ciphers|MACs|KexAlgorithms)' /etc/ssh/sshd_config"

  check_item "1.6.3 SHA1 hash/signature support disabled" \
    "grep -q 'SHA1' /etc/crypto-policies/back-ends/openssh.config && false || true"

  check_item "1.6.4 MACs <128 bits disabled" \
    "grep -Eq 'umac-64@openssh.com|hmac-md5' /etc/crypto-policies/back-ends/openssh.config && false || true"

  check_item "1.6.5 CBC ciphers disabled" \
    "grep -Eq 'cbc' /etc/crypto-policies/back-ends/openssh.config && false || true"

  check_item "1.6.6 chacha20-poly1305 disabled" \
    "grep -q 'chacha20-poly1305@openssh.com' /etc/crypto-policies/back-ends/openssh.config && false || true"

  check_item "1.6.7 EtM MACs disabled" \
    "grep -Eq 'hmac-sha2-(256|512)-etm@openssh.com' /etc/crypto-policies/back-ends/openssh.config && false || true"
fi


if [ "$OS_FAMILY" = "rhel" ]; then
  SECTION_LOGIN_BANNER="1.7"
  SECTION_GRAPHICAL="1.8"
elif [ "$OS_FAMILY" = "debian" ]; then
  SECTION_LOGIN_BANNER="1.6"
  SECTION_GRAPHICAL="1.7"
else
  SECTION_LOGIN_BANNER="unknown"
  SECTION_GRAPHICAL="unknown"
fi

start_section "$SECTION_LOGIN_BANNER - Login Banners"
for file in /etc/motd /etc/issue /etc/issue.net; do
  check_item "$SECTION_LOGIN_BANNER.1 $file contains banner" "grep -q 'Authorized Access Only' $file"
  check_item "$SECTION_LOGIN_BANNER.2 $file permissions = 644" "[ $(stat -c '%a' $file) -eq 644 ]"
  check_item "$SECTION_LOGIN_BANNER.4 $file owned by root" "stat -c '%U:%G' $file | grep -q 'root:root'"
done

start_section "$SECTION_GRAPHICAL - Graphical Packages Not Installed"

if [ "$OS_FAMILY" = "debian" ]; then
  for pkg in gdm3 ubuntu-desktop gnome-shell kde-plasma-desktop xfce4 \
             x11-common x11-utils x11-xserver-utils \
             libwayland-client0 libwayland-server0 \
             xterm gnome-terminal \
             fonts-dejavu fonts-freefont-ttf \
             gnome-themes-standard gnome-icon-theme; do
    check_item "$SECTION_GRAPHICAL $pkg not installed" "! check_package_installed $pkg"
  done

elif [ "$OS_FAMILY" = "rhel" ]; then
  for pkg in gdm gnome-desktop gnome-shell kde-workspace plasma-desktop xfce4 \
             xorg-x11-server-Xorg xorg-x11-utils xorg-x11-xinit \
             wayland xterm gnome-terminal \
             dejavu-fonts-common gnome-themes-standard gnome-icon-theme; do
    check_item "$SECTION_GRAPHICAL $pkg not installed" "! check_package_installed $pkg"
  done

else
  echo "⚠️ Unsupported OS family — skipping graphical package audit" | tee -a "$RESULT_FILE"
fi


# === SECTION 2: Services ===

start_section "2.1 - Server Services"

if [ "$OS_FAMILY" = "debian" ]; then
  SERVER_PKGS=(
    autofs avahi-daemon isc-dhcp-server bind9 dnsmasq vsftpd slapd dovecot
    nfs-kernel-server ypserv cups rpcbind rsync samba snmpd tftpd-hpa squid
    apache2 nginx xinetd xserver-common
  )
elif [ "$OS_FAMILY" = "rhel" ]; then
  SERVER_PKGS=(
    autofs avahi dhcp bind dnsmasq vsftpd openldap-servers dovecot
    nfs-utils ypserv cups rpcbind rsync samba snmpd tftp-server squid
    httpd nginx xinetd xorg-x11-server-common
  )
else
  SERVER_PKGS=()
fi

for svc in "${SERVER_PKGS[@]}"; do
  check_item "$svc not installed" "! check_package_installed $svc"
done

# Postfix local-only mode (Debian and RHEL)
check_item "Postfix local-only mode" "[ -f /etc/postfix/main.cf ] && grep -q '^inet_interfaces = loopback-only' /etc/postfix/main.cf"

# === SECTION 2.2: Client Services ===

start_section "2.2 - Client Services"

if [ "$OS_FAMILY" = "debian" ]; then
  CLIENT_PKGS=(nis rsh-client talk talkd telnet ldap-utils ftp tnftp)
elif [ "$OS_FAMILY" = "rhel" ]; then
  CLIENT_PKGS=(ypbind rsh talk talk-server telnet openldap-clients ftp)
else
  CLIENT_PKGS=()
fi

for cli in "${CLIENT_PKGS[@]}"; do
  check_item "$cli not installed" "! check_package_installed $cli"
done


start_section "2.3 - Time Synchronization"

# 2.3.1.1 Ensure a single time synchronization daemon is in use
check_item "2.3.1.1 Single time sync daemon active" \
  "! pgrep -x systemd-timesyncd || ! pgrep -x chronyd"

# 2.3.2.1 Ensure systemd-timesyncd configured with authorized timeserver
check_item "2.3.2.1 systemd-timesyncd configured with NTP server" \
  "[ -f /etc/systemd/timesyncd.conf ] && grep -q '^NTP=' /etc/systemd/timesyncd.conf"

# 2.3.2.2 Ensure systemd-timesyncd is enabled and running
check_item "2.3.2.2 systemd-timesyncd enabled and running" \
  "systemctl is-enabled systemd-timesyncd 2>/dev/null | grep -q enabled && \
   systemctl is-active systemd-timesyncd 2>/dev/null | grep -q active"

# 2.3.3.1 Ensure chrony is configured with authorized timeserver
check_item "2.3.3.1 chrony configured with NTP server" \
  "[ -f /etc/chrony/chrony.conf ] && grep -q '^server ' /etc/chrony/chrony.conf"

# 2.3.3.2 Ensure chrony is running as user _chrony
check_item "2.3.3.2 chrony runs as _chrony user" \
  "ps -eo user,comm | grep '^_chrony *chronyd'"

# 2.3.3.3 Ensure chrony is enabled and running
check_item "2.3.3.3 chrony enabled and running" \
  "systemctl is-enabled chrony 2>/dev/null | grep -q enabled && \
   systemctl is-active chrony 2>/dev/null | grep -q active"

start_section "2.4 - Job Schedulers"

# 2.4.1.1 Ensure cron daemon is enabled and active
check_item "2.4.1.1 cron daemon enabled and active" \
  "systemctl is-enabled cron 2>/dev/null | grep -q enabled && \
   systemctl is-active cron 2>/dev/null | grep -q active"

# 2.4.1.2–2.4.1.7 Ensure permissions on cron files/directories
check_item "2.4.1.2 /etc/crontab = 644" \
  "[ -f /etc/crontab ] && [ $(stat -c '%a' /etc/crontab) -eq 644 ]"

check_item "2.4.1.3 /etc/cron.hourly = 755" \
  "[ -d /etc/cron.hourly ] && [ $(stat -c '%a' /etc/cron.hourly) -eq 755 ]"

check_item "2.4.1.4 /etc/cron.daily = 755" \
  "[ -d /etc/cron.daily ] && [ $(stat -c '%a' /etc/cron.daily) -eq 755 ]"

check_item "2.4.1.5 /etc/cron.weekly = 755" \
  "[ -d /etc/cron.weekly ] && [ $(stat -c '%a' /etc/cron.weekly) -eq 755 ]"

check_item "2.4.1.6 /etc/cron.monthly = 755" \
  "[ -d /etc/cron.monthly ] && [ $(stat -c '%a' /etc/cron.monthly) -eq 755 ]"

check_item "2.4.1.7 /etc/cron.d = 755" \
  "[ -d /etc/cron.d ] && [ $(stat -c '%a' /etc/cron.d) -eq 755 ]"

# 2.4.1.8 Ensure crontab is restricted to authorized users
check_item "2.4.1.8 /etc/cron.allow exists" "[ -f /etc/cron.allow ]"
check_item "2.4.1.8 /etc/cron.deny removed" "[ ! -f /etc/cron.deny ]"

# 2.4.2.1 Ensure at is restricted to authorized users
check_item "2.4.2.1 /etc/at.allow exists" "[ -f /etc/at.allow ]"
check_item "2.4.2.1 /etc/at.deny removed" "[ ! -f /etc/at.deny ]"



# === SECTION 3: Network Configuration ===

start_section "3.1 - Network Devices"

# 3.1.1 IPv6 status identified
check_item "3.1.1 IPv6 status identified" "command -v ip >/dev/null && ip a | grep -q inet6"

# 3.1.2 Wireless interfaces disabled
check_item "3.1.2 Wireless interfaces disabled" "command -v nmcli >/dev/null && ! nmcli device status | grep -i wifi | grep -q connected"

# 3.1.3 Bluetooth service not active
check_item "3.1.3 Bluetooth service not active" "systemctl is-active bluetooth 2>/dev/null | grep -vq active"

# === Kernel Modules ===
start_section "3.2 - Network Kernel Modules"

for mod in dccp tipc rds sctp; do
  check_item "$mod kernel module not loaded" "! lsmod | grep -q '^$mod'"
  check_item "$mod module is blacklisted" "grep -E '^(blacklist|install)' /etc/modprobe.d/*.conf 2>/dev/null | grep -q $mod"
done


start_section "3.3 - Configure Network Kernel Parameters"

check_item "3.3.1 Ensure IP forwarding is disabled" \
  "sysctl net.ipv4.ip_forward 2>/dev/null | grep -q '^net.ipv4.ip_forward = 0'"

check_item "3.3.2 Ensure packet redirect sending is disabled" \
  "sysctl net.ipv4.conf.all.send_redirects 2>/dev/null | grep -q '^net.ipv4.conf.all.send_redirects = 0' && \
   sysctl net.ipv4.conf.default.send_redirects 2>/dev/null | grep -q '^net.ipv4.conf.default.send_redirects = 0'"

check_item "3.3.3 Ensure bogus ICMP responses are ignored" \
  "sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null | grep -q '^net.ipv4.icmp_ignore_bogus_error_responses = 1'"

check_item "3.3.4 Ensure broadcast ICMP requests are ignored" \
  "sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null | grep -q '^net.ipv4.icmp_echo_ignore_broadcasts = 1'"

check_item "3.3.5 Ensure ICMP redirects are not accepted" \
  "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q '^net.ipv4.conf.all.accept_redirects = 0' && \
   sysctl net.ipv4.conf.default.accept_redirects 2>/dev/null | grep -q '^net.ipv4.conf.default.accept_redirects = 0'"

check_item "3.3.6 Ensure secure ICMP redirects are not accepted" \
  "sysctl net.ipv4.conf.all.secure_redirects 2>/dev/null | grep -q '^net.ipv4.conf.all.secure_redirects = 0' && \
   sysctl net.ipv4.conf.default.secure_redirects 2>/dev/null | grep -q '^net.ipv4.conf.default.secure_redirects = 0'"

check_item "3.3.7 Ensure reverse path filtering is enabled" \
  "sysctl net.ipv4.conf.all.rp_filter 2>/dev/null | grep -q '^net.ipv4.conf.all.rp_filter = 1' && \
   sysctl net.ipv4.conf.default.rp_filter 2>/dev/null | grep -q '^net.ipv4.conf.default.rp_filter = 1'"

check_item "3.3.8 Ensure source routed packets are not accepted" \
  "sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | grep -q '^net.ipv4.conf.all.accept_source_route = 0' && \
   sysctl net.ipv4.conf.default.accept_source_route 2>/dev/null | grep -q '^net.ipv4.conf.default.accept_source_route = 0'"

check_item "3.3.9 Ensure suspicious packets are logged" \
  "sysctl net.ipv4.conf.all.log_martians 2>/dev/null | grep -q '^net.ipv4.conf.all.log_martians = 1' && \
   sysctl net.ipv4.conf.default.log_martians 2>/dev/null | grep -q '^net.ipv4.conf.default.log_martians = 1'"

check_item "3.3.10 Ensure TCP SYN cookies are enabled" \
  "sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q '^net.ipv4.tcp_syncookies = 1'"

check_item "3.3.11 Ensure IPv6 router advertisements are not accepted" \
  "sysctl net.ipv6.conf.all.accept_ra 2>/dev/null | grep -q '^net.ipv6.conf.all.accept_ra = 0' && \
   sysctl net.ipv6.conf.default.accept_ra 2>/dev/null | grep -q '^net.ipv6.conf.default.accept_ra = 0'"


# === SECTION 4: Host-Based Firewall ===

start_section "4.1 - Firewall Utility"

if [ "$OS_FAMILY" = "debian" ]; then
  check_item "4.1.1 Only one firewall utility in use (Debian)" \
    "[ $(systemctl list-units --type=service | grep -E 'ufw|nftables|iptables' | wc -l) -eq 1 ]"
elif [ "$OS_FAMILY" = "rhel" ]; then
  check_item "4.1.1 Only one firewall utility in use (RHEL)" \
    "[ $(systemctl list-units --type=service | grep -E 'firewalld|nftables|iptables' | wc -l) -eq 1 ]"
else
  echo "🔸 Unknown OS family — skipping firewall utility check" | tee -a "$RESULT_FILE"
fi

# === Detect Active Firewall ===
ACTIVE_FIREWALL="none"

if systemctl is-active --quiet ufw; then
  ACTIVE_FIREWALL="ufw"
elif systemctl is-active --quiet nftables; then
  ACTIVE_FIREWALL="nftables"
elif systemctl is-active --quiet iptables; then
  ACTIVE_FIREWALL="iptables"
elif systemctl is-active --quiet firewalld; then
  ACTIVE_FIREWALL="firewalld"
fi


# === 4.2 UFW Configuration (Debian Only) ===
start_section "4.2 - UFW Configuration"

if [ "$OS_FAMILY" = "debian" ] && [ "$ACTIVE_FIREWALL" = "ufw" ]; then
  check_item "4.2.1 UFW is installed" "check_package_installed ufw"
  check_item "4.2.2 iptables-persistent not installed with UFW" "! check_package_installed iptables-persistent"
  check_item "4.2.3 UFW service is enabled" "systemctl is-enabled ufw 2>/dev/null | grep -q enabled"
  check_item "4.2.4 UFW loopback traffic configured" "ufw status | grep -q 'ALLOW IN 127.0.0.1'"
  check_item "4.2.5 UFW outbound connections configured" "ufw status | grep -q 'ALLOW OUT Anywhere'"
  check_item "4.2.6 UFW rules exist for open ports" "ufw status numbered | grep -q 'ALLOW IN'"
  check_item "4.2.7 UFW default deny policy is set" "ufw status | grep -q 'Default: deny (incoming)'"
else
  echo "🔸 Skipping UFW checks — not active or not applicable" | tee -a "$RESULT_FILE"
fi

# === 4.3 nftables Configuration (Both Families) ===
start_section "4.3 - nftables Configuration"

if [ "$ACTIVE_FIREWALL" = "nftables" ]; then
  if [ "$OS_FAMILY" = "debian" ]; then
    check_item "4.3.1 nftables is installed" "check_package_installed nftables"
  elif [ "$OS_FAMILY" = "rhel" ]; then
    check_item "4.3.1 nftables is installed" "rpm -q nftables"
  fi

  check_item "4.3.2 UFW is disabled with nftables" "! systemctl is-active ufw 2>/dev/null | grep -q active"
  check_item "4.3.3 iptables flushed with nftables" "iptables -L | grep -q 'Chain INPUT (policy ACCEPT)'"
  check_item "4.3.4 nftables table exists" "nft list tables | grep -q inet"
  check_item "4.3.5 nftables base chains exist" "nft list chains | grep -q 'type filter'"
  check_item "4.3.6 nftables loopback traffic configured" "nft list ruleset | grep -q 'iif lo accept'"
  check_item "4.3.7 nftables outbound/established configured" "nft list ruleset | grep -q 'ct state established,related accept'"
  check_item "4.3.8 nftables default deny policy" "nft list ruleset | grep -q 'drop'"
  check_item "4.3.9 nftables service enabled" "systemctl is-enabled nftables 2>/dev/null | grep -q enabled"
  check_item "4.3.10 nftables rules are permanent" "[ -f /etc/nftables.conf ]"
else
  echo "🔸 Skipping nftables checks — not active" | tee -a "$RESULT_FILE"
fi

# === 4.4 iptables Configuration (Both Families) ===
start_section "4.4 - iptables Configuration"

if [ "$ACTIVE_FIREWALL" = "iptables" ]; then
  if [ "$OS_FAMILY" = "debian" ]; then
    check_item "4.4.1 iptables is installed" "check_package_installed iptables"
  elif [ "$OS_FAMILY" = "rhel" ]; then
    check_item "4.4.1 iptables is installed" "rpm -q iptables"
  fi

  check_item "4.4.2 nftables not active with iptables" "! systemctl is-active nftables 2>/dev/null | grep -q active"
  check_item "4.4.3 UFW not active with iptables" "! systemctl is-active ufw 2>/dev/null | grep -q active"

  check_item "4.4.4 iptables default deny policy" "iptables -L INPUT | grep -q 'policy DROP'"
  check_item "4.4.5 iptables loopback traffic configured" "iptables -L INPUT | grep -q 'ACCEPT.*lo'"
  check_item "4.4.6 iptables outbound/established configured" "iptables -L OUTPUT | grep -q 'ACCEPT.*state RELATED,ESTABLISHED'"
  check_item "4.4.7 iptables rules exist for open ports" "iptables -L INPUT | grep -q 'ACCEPT.*dpt:'"

  check_item "4.4.8 ip6tables default deny policy" "ip6tables -L INPUT | grep -q 'policy DROP'"
  check_item "4.4.9 ip6tables loopback traffic configured" "ip6tables -L INPUT | grep -q 'ACCEPT.*lo'"
  check_item "4.4.10 ip6tables outbound/established configured" "ip6tables -L OUTPUT | grep -q 'ACCEPT.*state RELATED,ESTABLISHED'"
  check_item "4.4.11 ip6tables rules exist for open ports" "ip6tables -L INPUT | grep -q 'ACCEPT.*dpt:'"
else
  echo "🔸 Skipping iptables checks — not active" | tee -a "$RESULT_FILE"
fi

# === 4.5 firewalld Configuration (RHEL Only) ===
start_section "4.5 - firewalld Configuration"

if [ "$OS_FAMILY" = "rhel" ] && [ "$ACTIVE_FIREWALL" = "firewalld" ]; then
  check_item "4.5.1 firewalld is installed" "rpm -q firewalld"
  check_item "4.5.2 firewalld service is enabled" "systemctl is-enabled firewalld 2>/dev/null | grep -q enabled"
  check_item "4.5.3 firewalld default zone is set" "firewall-cmd --get-default-zone | grep -q public"
  check_item "4.5.4 firewalld loopback traffic allowed" "firewall-cmd --list-all | grep -q 'lo'"
  check_item "4.5.5 firewalld outbound/established allowed" "firewall-cmd --list-all | grep -q 'state RELATED,ESTABLISHED'"
  check_item "4.5.6 firewalld rules exist for open ports" "firewall-cmd --list-ports | grep -q '[0-9]'"
  check_item "4.5.7 firewalld default deny policy enforced" "firewall-cmd --get-default-zone | grep -q public"
else
  echo "🔸 Skipping firewalld checks — not active or not applicable" | tee -a "$RESULT_FILE"
fi




# === 5.1 SSH Server Configuration ===
start_section "5.1 - SSH Server Configuration"

check_item "5.1.1 /etc/ssh/sshd_config permissions = 600" \
  "[ -f /etc/ssh/sshd_config ] && [ $(stat -c '%a' /etc/ssh/sshd_config) -le 600 ]"

check_item "5.1.2 SSH private keys = 600" \
  "find /etc/ssh -type f -name '*_key' -exec stat -c '%a' {} \; | grep -q '^600$'"

check_item "5.1.3 SSH public keys = 644" \
  "find /etc/ssh -type f -name '*.pub' -exec stat -c '%a' {} \; | grep -q '^644$'"

check_item "5.1.4 AllowUsers configured" \
  "grep -q '^AllowUsers' /etc/ssh/sshd_config"

check_item "5.1.5 Banner configured" \
  "grep -q '^Banner' /etc/ssh/sshd_config"

check_item "5.1.6 Ciphers configured" \
  "grep -q '^Ciphers' /etc/ssh/sshd_config"

check_item "5.1.7 ClientAliveInterval set" \
  "grep -q '^ClientAliveInterval' /etc/ssh/sshd_config"

check_item "5.1.8 ClientAliveCountMax set" \
  "grep -q '^ClientAliveCountMax' /etc/ssh/sshd_config"

check_item "5.1.9 DisableForwarding enabled" \
  "grep -q '^DisableForwarding yes' /etc/ssh/sshd_config"

check_item "5.1.10 GSSAPIAuthentication disabled" \
  "grep -q '^GSSAPIAuthentication no' /etc/ssh/sshd_config"

check_item "5.1.11 HostbasedAuthentication disabled" \
  "grep -q '^HostbasedAuthentication no' /etc/ssh/sshd_config"

check_item "5.1.12 IgnoreRhosts enabled" \
  "grep -q '^IgnoreRhosts yes' /etc/ssh/sshd_config"

check_item "5.1.13 KexAlgorithms configured" \
  "grep -q '^KexAlgorithms' /etc/ssh/sshd_config"

check_item "5.1.14 LoginGraceTime configured" \
  "grep -q '^LoginGraceTime' /etc/ssh/sshd_config"

check_item "5.1.15 LogLevel configured" \
  "grep -q '^LogLevel' /etc/ssh/sshd_config"

check_item "5.1.16 MACs configured" \
  "grep -q '^MACs' /etc/ssh/sshd_config"

check_item "5.1.17 MaxAuthTries configured" \
  "grep -q '^MaxAuthTries' /etc/ssh/sshd_config"

check_item "5.1.18 MaxSessions configured" \
  "grep -q '^MaxSessions' /etc/ssh/sshd_config"

check_item "5.1.19 MaxStartups configured" \
  "grep -q '^MaxStartups' /etc/ssh/sshd_config"

check_item "5.1.20 PermitEmptyPasswords disabled" \
  "grep -q '^PermitEmptyPasswords no' /etc/ssh/sshd_config"

check_item "5.1.21 PermitRootLogin disabled" \
  "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config"

check_item "5.1.22 PermitUserEnvironment disabled" \
  "grep -q '^PermitUserEnvironment no' /etc/ssh/sshd_config"

check_item "5.1.23 UsePAM enabled" \
  "grep -q '^UsePAM yes' /etc/ssh/sshd_config"

start_section "5.2 - Privilege Escalation"

check_item "5.2.1 sudo is installed" \
  "check_package_installed sudo"

check_item "5.2.2 sudo uses pty" \
  "grep -q 'Defaults.*use_pty' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"

check_item "5.2.3 sudo log file exists" \
  "[ -f /var/log/sudo.log ]"

check_item "5.2.4 sudo requires password" \
  "! grep -q NOPASSWD /etc/sudoers /etc/sudoers.d/* 2>/dev/null"

check_item "5.2.5 sudo re-authentication not disabled globally" \
  "! grep -q '!authenticate' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"

check_item "5.2.6 sudo timeout configured" \
  "grep -q 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"

check_item "5.2.7 su command restricted to wheel group" \
  "grep -q 'auth required pam_wheel.so' /etc/pam.d/su"


# === 5.3 PAM Configuration ===

# Define PAM file paths based on OS family
if [ "$OS_FAMILY" = "debian" ]; then
  PAM_PASSWORD_FILE="/etc/pam.d/common-password"
  PAM_AUTH_FILE="/etc/pam.d/common-auth"
else
  PAM_PASSWORD_FILE="/etc/pam.d/system-auth"
  PAM_AUTH_FILE="/etc/pam.d/system-auth"
fi

start_section "5.3 - PAM Configuration"

# 5.3.1 Package checks
if [ "$OS_FAMILY" = "debian" ]; then
  check_item "5.3.1.1 libpam0g installed" "check_package_installed libpam0g"
  check_item "5.3.1.2 libpam-modules installed" "check_package_installed libpam-modules"
  check_item "5.3.1.3 libpam-pwquality installed" "check_package_installed libpam-pwquality"
else
  check_item "5.3.1.1 pam installed" "check_package_installed pam"
  check_item "5.3.1.2 pam_pwquality installed" "check_package_installed pam_pwquality"
  check_item "5.3.1.3 pam_pwhistory installed" "check_package_installed pam_pwhistory"
fi

# 5.3.2 Module presence
check_item "5.3.2.1 pam_unix enabled" "grep -q 'pam_unix.so' $PAM_AUTH_FILE"
check_item "5.3.2.2 pam_pwquality enabled" "grep -q 'pam_pwquality.so' $PAM_PASSWORD_FILE"
check_item "5.3.2.3 pam_pwhistory enabled" "grep -q 'pam_pwhistory.so' $PAM_PASSWORD_FILE"

# 5.3.3 faillock (RHEL only)
if [ "$OS_FAMILY" = "rhel" ]; then
  check_item "5.3.3.1 pam_faillock enabled" "grep -q 'pam_faillock.so' $PAM_AUTH_FILE"
  check_item "5.3.3.2 faillock deny configured" "grep -q 'deny=' /etc/security/faillock.conf"
  check_item "5.3.3.3 faillock unlock_time configured" "grep -q 'unlock_time=' /etc/security/faillock.conf"
  check_item "5.3.3.4 faillock includes root" "grep -q 'even_deny_root' /etc/security/faillock.conf"
else
  echo "🔸 Skipping faillock checks — not applicable to Debian systems" | tee -a "$RESULT_FILE"
fi

# 5.3.4 pwquality settings
check_item "5.3.4.1 pwquality minlen configured" "grep -q 'minlen=' /etc/security/pwquality.conf"
check_item "5.3.4.2 pwquality complexity configured" "grep -q 'dcredit=' /etc/security/pwquality.conf"
check_item "5.3.4.3 pwquality consecutive configured" "grep -q 'maxrepeat=' /etc/security/pwquality.conf"
check_item "5.3.4.4 pwquality sequential configured" "grep -q 'maxsequence=' /etc/security/pwquality.conf"
check_item "5.3.4.5 pwquality dictionary check enabled" "grep -q 'dictcheck=' /etc/security/pwquality.conf"
check_item "5.3.4.6 pwquality enforced for root" "grep -q 'enforce_for_root' /etc/security/pwquality.conf"

# 5.3.5 pwhistory settings
check_item "5.3.5.1 pwhistory remember configured" "grep -q 'remember=' /etc/security/pwhistory.conf"
check_item "5.3.5.2 pwhistory enforced for root" "grep -q 'enforce_for_root' /etc/security/pwhistory.conf"
check_item "5.3.5.3 pwhistory use_authtok" "grep -q 'use_authtok' $PAM_PASSWORD_FILE"

# 5.3.6 pam_unix settings
check_item "5.3.6.1 pam_unix no nullok" "! grep -q 'nullok' $PAM_PASSWORD_FILE"
check_item "5.3.6.2 pam_unix no remember" "! grep -q 'remember=' $PAM_PASSWORD_FILE"
check_item "5.3.6.3 pam_unix strong hashing (sha512)" "grep -q 'sha512' $PAM_PASSWORD_FILE"
check_item "5.3.6.4 pam_unix use_authtok" "grep -q 'use_authtok' $PAM_PASSWORD_FILE"


start_section "5.4 - User Accounts and Environment"
check_item "5.4.1 PASS_MAX_DAYS configured" "grep -q '^PASS_MAX_DAYS' /etc/login.defs"
check_item "5.4.2 PASS_WARN_AGE configured" "grep -q '^PASS_WARN_AGE' /etc/login.defs"
check_item "5.4.3 ENCRYPT_METHOD SHA512 configured" "grep -q '^ENCRYPT_METHOD SHA512' /etc/login.defs"
check_item "5.4.4 INACTIVE configured in useradd" "grep -q '^INACTIVE=' /etc/default/useradd"
check_item "5.4.5 All users have password change date" "! awk -F: '$3 >= 1000 && $2 == \"\"' /etc/shadow"
check_item "5.4.6 Only root has UID 0" "[[ $(awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l) -eq 1 ]]"
check_item "5.4.7 Only root has GID 0" "[[ $(awk -F: '$3 == 0 {print $1}' /etc/group | wc -l) -eq 1 ]]"
check_item "5.4.8 Group root is only GID 0 group" "[[ $(grep ':0:' /etc/group | wc -l) -eq 1 ]]"
check_item "5.4.9 Root account is active" "passwd -S root | grep -q 'P'"
check_item "5.4.10 Root PATH has no empty entries" "! echo $PATH | grep -q '::'"
check_item "5.4.11 Root user umask is 077" "grep -q 'umask 077' /root/.profile"
check_item "5.4.12 System accounts have no login shell" "! awk -F: '$3 < 1000 && $7 != \"/usr/sbin/nologin\" && $7 != \"/bin/false\"' /etc/passwd"
check_item "5.4.13 Accounts with nologin/false shell are locked" "awk -F: '$7 == \"/usr/sbin/nologin\" || $7 == \"/bin/false\"' /etc/passwd | grep -q '!'"
check_item "5.4.14 /usr/sbin/nologin not in /etc/shells" "! grep -q '/usr/sbin/nologin' /etc/shells"
check_item "5.4.15 TMOUT configured in /etc/profile" "grep -q 'TMOUT=' /etc/profile"
check_item "5.4.16 Default umask is 077" "grep -q 'umask 077' /etc/login.defs"


start_section "6.1 - System Logging"
check_item "6.1.1 journald service active" "systemctl is-active systemd-journald | grep -q active"
check_item "6.1.2 Only one logging system in use" "[ $(systemctl list-units | grep -E 'rsyslog|systemd-journald' | wc -l) -eq 1 ]"
check_item "6.1.3 systemd-journal-remote installed" "check_package_installed systemd-journal-remote"
check_item "6.1.4 systemd-journal-upload active" "systemctl is-active systemd-journal-upload | grep -q active"
check_item "6.1.5 systemd-journal-remote not in use" "! systemctl is-active systemd-journal-remote | grep -q active"
check_item "6.1.6 journald ForwardToSyslog disabled" "grep -q '^ForwardToSyslog=no' /etc/systemd/journald.conf"
check_item "6.1.7 journald Compress enabled" "grep -q '^Compress=yes' /etc/systemd/journald.conf"
check_item "6.1.8 journald Storage persistent" "grep -q '^Storage=persistent' /etc/systemd/journald.conf"
check_item "6.1.9 rsyslog installed" "check_package_installed rsyslog"
check_item "6.1.10 rsyslog active" "systemctl is-active rsyslog | grep -q active"
check_item "6.1.11 journald forwards to rsyslog" "grep -q '^ForwardToSyslog=yes' /etc/systemd/journald.conf"
check_item "6.1.12 rsyslog not receiving remote logs" "! grep -q 'imtcp' /etc/rsyslog.conf"
check_item "6.1.13 logrotate installed" "check_package_installed logrotate"
check_item "6.1.14 logfile access configured" "find /var/log -type f -exec stat -c '%a' {} \; | grep -vq '^6'"


# === OS Detection ===
if grep -qi "debian" /etc/os-release; then OS_FAMILY="debian"; else OS_FAMILY="rhel"; fi

# === SECTION 6.2 - System Auditing ===
start_section "6.2 - System Auditing"
check_item "6.2.1 auditd installed" "check_package_installed auditd"
check_item "6.2.2 auditd active" "systemctl is-active auditd | grep -q active"
check_item "6.2.3 auditd enabled at boot" "grep -q 'audit=1' /etc/default/grub"
check_item "6.2.4 audit_backlog_limit sufficient" "grep -q 'audit_backlog_limit=' /etc/default/grub"
check_item "6.2.5 audit log size configured" "grep -q '^max_log_file =' /etc/audit/auditd.conf"
check_item "6.2.6 audit logs not auto-deleted" "grep -q '^max_log_file_action = keep_logs' /etc/audit/auditd.conf"
check_item "6.2.7 system disabled when logs full" "grep -q '^space_left_action = email' /etc/audit/auditd.conf"
check_item "6.2.8 warn when logs low on space" "grep -q '^admin_space_left_action = halt' /etc/audit/auditd.conf"

# === SECTION 6.2.3 - Auditd Rules ===
start_section "6.2.3 - Auditd Rules"
if [ "$OS_FAMILY" = "rhel" ]; then AUDIT_RULE_LOADER="augenrules --load"; AUDIT_RULE_FILE="/etc/audit/rules.d/*.rules"; else AUDIT_RULE_LOADER="auditctl -R /etc/audit/audit.rules"; AUDIT_RULE_FILE="/etc/audit/audit.rules"; fi
check_item "6.2.3.1 Audit rules loaded" "$AUDIT_RULE_LOADER"
check_item "6.2.3.2 sudoers changes collected" "auditctl -l | grep -q '/etc/sudoers'"
check_item "6.2.3.3 actions as another user logged" "auditctl -l | grep -q 'execve'"
check_item "6.2.3.4 sudo log file changes collected" "auditctl -l | grep -q '/var/log/sudo.log'"
check_item "6.2.3.5 date/time changes collected" "auditctl -l | grep -q '/etc/localtime'"
check_item "6.2.3.6 network environment changes collected" "auditctl -l | grep -q '/etc/network'"
check_item "6.2.3.7 privileged commands collected" "auditctl -l | grep -q 'chmod'"
check_item "6.2.3.8 unsuccessful file access collected" "auditctl -l | grep -q 'access'"
check_item "6.2.3.9 user/group changes collected" "auditctl -l | grep -q '/etc/passwd'"
check_item "6.2.3.10 DAC permission changes collected" "auditctl -l | grep -q 'chmod'"
check_item "6.2.3.11 filesystem mounts collected" "auditctl -l | grep -q 'mount'"
check_item "6.2.3.12 session initiation collected" "auditctl -l | grep -q 'login'"
check_item "6.2.3.13 login/logout events collected" "auditctl -l | grep -q 'pam_unix'"
check_item "6.2.3.14 file deletions collected" "auditctl -l | grep -q 'unlink'"
check_item "6.2.3.15 MAC changes collected" "auditctl -l | grep -q 'setenforce'"
check_item "6.2.3.16 chcon attempts collected" "auditctl -l | grep -q 'chcon'"
check_item "6.2.3.17 setfacl attempts collected" "auditctl -l | grep -q 'setfacl'"
check_item "6.2.3.18 chacl attempts collected" "auditctl -l | grep -q 'chacl'"
check_item "6.2.3.19 usermod attempts collected" "auditctl -l | grep -q 'usermod'"
check_item "6.2.3.20 kernel module events collected" "auditctl -l | grep -q 'modprobe'"
check_item "6.2.3.21 audit config immutable" "grep -q '^-e 2' $AUDIT_RULE_FILE"

# === SECTION 6.2.4 - Auditd File Access ===
start_section "6.2.4 - Auditd File Access"
AUDITCTL_PATH=$(command -v auditctl)
check_item "6.2.4.1 audit log file mode = 600" "find /var/log/audit -type f -exec stat -c '%a' {} \; | grep -q '^600$'"
check_item "6.2.4.2 audit log file owner = root" "find /var/log/audit -type f -exec stat -c '%U' {} \; | grep -q '^root$'"
check_item "6.2.4.3 audit log file group = root" "find /var/log/audit -type f -exec stat -c '%G' {} \; | grep -q '^root$'"
check_item "6.2.4.4 audit log dir mode = 700" "[ $(stat -c '%a' /var/log/audit) -eq 700 ]"
check_item "6.2.4.5 audit config file mode = 640" "[ $(stat -c '%a' /etc/audit/auditd.conf) -eq 640 ]"
check_item "6.2.4.6 audit config file owner = root" "[ $(stat -c '%U' /etc/audit/auditd.conf) = 'root' ]"
check_item "6.2.4.7 audit config file group = root" "[ $(stat -c '%G' /etc/audit/auditd.conf) = 'root' ]"
check_item "6.2.4.8 audit tools mode = 755" "[ $(stat -c '%a' $AUDITCTL_PATH) -eq 755 ]"
check_item "6.2.4.9 audit tools owner = root" "[ $(stat -c '%U' $AUDITCTL_PATH) = 'root' ]"
check_item "6.2.4.10 audit tools group = root" "[ $(stat -c '%G' $AUDITCTL_PATH) = 'root' ]"

# === SECTION 6.3 - Integrity Checking ===
start_section "6.3 - Integrity Checking"
check_item "6.3.1 AIDE installed" "check_package_installed aide"
check_item "6.3.2 AIDE database exists" "[ -f /var/lib/aide/aide.db ]"
check_item "6.3.3 Audit tools protected by crypto" "check_package_installed gnupg"


# === SECTION 7.1 - System File Permissions ===
start_section "7.1 - System File Permissions"
check_item "7.1.1 /etc/passwd = 644" "[ -f /etc/passwd ] && [ \$(stat -c '%a' /etc/passwd) -eq 644 ]"
check_item "7.1.2 /etc/passwd- = 644" "[ -f /etc/passwd- ] && [ \$(stat -c '%a' /etc/passwd-) -eq 644 ]"
check_item "7.1.3 /etc/group = 644" "[ -f /etc/group ] && [ \$(stat -c '%a' /etc/group) -eq 644 ]"
check_item "7.1.4 /etc/group- = 644" "[ -f /etc/group- ] && [ \$(stat -c '%a' /etc/group-) -eq 644 ]"
check_item "7.1.5 /etc/shadow = 000" "[ -f /etc/shadow ] && [ \$(stat -c '%a' /etc/shadow) -eq 000 ]"
check_item "7.1.6 /etc/shadow- = 000" "[ -f /etc/shadow- ] && [ \$(stat -c '%a' /etc/shadow-) -eq 000 ]"
check_item "7.1.7 /etc/gshadow = 000" "[ -f /etc/gshadow ] && [ \$(stat -c '%a' /etc/gshadow) -eq 000 ]"
check_item "7.1.8 /etc/gshadow- = 000" "[ -f /etc/gshadow- ] && [ \$(stat -c '%a' /etc/gshadow-) -eq 000 ]"
check_item "7.1.9 /etc/shells = 644" "[ -f /etc/shells ] && [ \$(stat -c '%a' /etc/shells) -eq 644 ]"
check_item "7.1.10 /etc/security/opasswd = 600" "[ -f /etc/security/opasswd ] && [ \$(stat -c '%a' /etc/security/opasswd) -eq 600 ]"
check_item "7.1.11 No world-writable files" "! find / -xdev \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o -type f -perm -0002 -print | grep -q ."
check_item "7.1.12 No unowned files" "! find / -xdev -nouser -o -nogroup | grep -q ."
check_item "7.1.13 SUID/SGID files reviewed (manual)" "find / -xdev \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o \\( -perm -4000 -o -perm -2000 \\) -type f -print"


# === SECTION 7.2 - Local User and Group Settings ===
start_section "7.2 - Local User and Group Settings"
check_item "7.2.1 All accounts use shadowed passwords" "! awk -F: '($2 != \"x\") && ($1 != \"\")' /etc/passwd | grep -q ."
check_item "7.2.2 No empty password fields in /etc/shadow" "! awk -F: '($2 == \"\")' /etc/shadow | grep -q ."
check_item "7.2.3 All groups in /etc/passwd exist in /etc/group" "! awk -F: '{print \$4}' /etc/passwd | sort -u | while read gid; do grep -q \":\$gid:\" /etc/group || exit 1; done"
check_item "7.2.4 shadow group is empty" "grep '^shadow:' /etc/group | grep -q ':$'"
check_item "7.2.5 No duplicate UIDs" "[[ -z \$(cut -d: -f3 /etc/passwd | sort | uniq -d) ]]"
check_item "7.2.6 No duplicate GIDs" "[[ -z \$(cut -d: -f3 /etc/group | sort | uniq -d) ]]"
check_item "7.2.7 No duplicate usernames" "[[ -z \$(cut -d: -f1 /etc/passwd | sort | uniq -d) ]]"
check_item "7.2.8 No duplicate group names" "[[ -z \$(cut -d: -f1 /etc/group | sort | uniq -d) ]]"
check_item "7.2.9 Local user home directories exist" "awk -F: '(\$3 >= 1000 && \$7 != \"/usr/sbin/nologin\") {print \$6}' /etc/passwd | while read dir; do [ -d \"\$dir\" ] || exit 1; done"
check_item "7.2.10 Dot files access configured" "find /home -name '.*' -type f -exec stat -c '%a' {} \; | grep -vq '^7'"



# === Final Summary ===
start_section "📊 Compliance Summary"

TOTAL=$((PASS_COUNT + FAIL_COUNT))

# Avoid division by zero
if [ "$TOTAL" -gt 0 ]; then
  PASS_PERCENT=$((100 * PASS_COUNT / TOTAL))
  FAIL_PERCENT=$((100 * FAIL_COUNT / TOTAL))
else
  PASS_PERCENT=0
  FAIL_PERCENT=0
fi

# ANSI color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}✅ Passed: $PASS_COUNT ($PASS_PERCENT%)${NC}" | tee -a "$RESULT_FILE"
echo -e "${RED}❌ Failed: $FAIL_COUNT ($FAIL_PERCENT%)${NC}" | tee -a "$RESULT_FILE"
echo -e "📋 Total Checks: $TOTAL" | tee -a "$RESULT_FILE"
echo -e "\n📁 Full audit log saved to: $RESULT_FILE"
