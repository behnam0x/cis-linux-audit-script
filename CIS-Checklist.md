# 📋 CIS Benchmark Checklist

## 🔧 Section 1: Initial Setup

| Control ID     | Description                                               | Type      | Platform | Status |
|----------------|-----------------------------------------------------------|-----------|----------|--------|
| 1.1.1.1        | Ensure cramfs kernel module is not available              | Automated | All      | ☐      |
| 1.1.1.2        | Ensure freevxfs kernel module is not available            | Automated | All      | ☐      |
| 1.1.1.3        | Ensure hfs kernel module is not available                 | Automated | All      | ☐      |
| 1.1.1.4        | Ensure hfsplus kernel module is not available             | Automated | All      | ☐      |
| 1.1.1.5        | Ensure jffs2 kernel module is not available               | Automated | All      | ☐      |
| 1.1.1.6        | Ensure overlayfs kernel module is not available           | Automated | All      | ☐      |
| 1.1.1.7        | Ensure squashfs kernel module is not available            | Automated | All      | ☐      |
| 1.1.1.8        | Ensure udf kernel module is not available                 | Automated | All      | ☐      |
| 1.1.1.9        | Ensure usb-storage kernel module is not available         | Automated | All      | ☐      |
| 1.1.1.10       | Ensure unused filesystems kernel modules are not available| Manual    | All      | ☐      |
| 1.1.2.1.1      | Ensure /tmp is a separate partition                       | Automated | All      | ☐      |
| 1.1.2.1.2      | Ensure nodev option set on /tmp partition                 | Automated | All      | ☐      |
| 1.1.2.1.3      | Ensure nosuid option set on /tmp partition                | Automated | All      | ☐      |
| 1.1.2.1.4      | Ensure noexec option set on /tmp partition                | Automated | All      | ☐      |
| 1.1.2.2.1      | Ensure /dev/shm is a separate partition                   | Automated | All      | ☐      |
| 1.1.2.2.2      | Ensure nodev option set on /dev/shm partition             | Automated | All      | ☐      |
| 1.1.2.2.3      | Ensure nosuid option set on /dev/shm partition            | Automated | All      | ☐      |
| 1.1.2.2.4      | Ensure noexec option set on /dev/shm partition            | Automated | All      | ☐      |
| 1.1.2.3.1      | Ensure separate partition exists for /home                | Automated | All      | ☐      |
| 1.1.2.3.2      | Ensure nodev option set on /home partition                | Automated | All      | ☐      |
| 1.1.2.3.3      | Ensure nosuid option set on /home partition               | Automated | All      | ☐      |
| 1.1.2.4.1      | Ensure separate partition exists for /var                 | Automated | All      | ☐      |
| 1.1.2.4.2      | Ensure nodev option set on /var partition                 | Automated | All      | ☐      |
| 1.1.2.4.3      | Ensure nosuid option set on /var partition                | Automated | All      | ☐      |
| 1.1.2.5.1      | Ensure separate partition exists for /var/tmp             | Automated | All      | ☐      |
| 1.1.2.5.2      | Ensure nodev option set on /var/tmp partition             | Automated | All      | ☐      |
| 1.1.2.5.3      | Ensure nosuid option set on /var/tmp partition            | Automated | All      | ☐      |
| 1.1.2.5.4      | Ensure noexec option set on /var/tmp partition            | Automated | All      | ☐      |
| 1.1.2.6.1      | Ensure separate partition exists for /var/log             | Automated | All      | ☐      |
| 1.1.2.6.2      | Ensure nodev option set on /var/log partition             | Automated | All      | ☐      |
| 1.1.2.6.3      | Ensure nosuid option set on /var/log partition            | Automated | All      | ☐      |
| 1.1.2.6.4      | Ensure noexec option set on /var/log partition            | Automated | All      | ☐      |
| 1.1.2.7.1      | Ensure separate partition exists for /var/log/audit       | Automated | All      | ☐      |
| 1.1.2.7.2      | Ensure nodev option set on /var/log/audit partition       | Automated | All      | ☐      |
| 1.1.2.7.3      | Ensure nosuid option set on /var/log/audit partition      | Automated | All      | ☐      |
| 1.1.2.7.4      | Ensure noexec option set on /var/log/audit partition      | Automated | All      | ☐      |
| 1.2.1.1        | Ensure GPG keys are configured                            | Manual    | All      | ☐      |
| 1.2.1.2        | Ensure package manager repositories are configured        | Manual    | All      | ☐      |
| 1.2.1.3        | Ensure repo_gpgcheck is globally activated                | Manual    | RHEL     | ☐      |
| 1.2.2.1        | Ensure updates, patches, and additional security software are installed | Manual | All | ☐      |
| 1.3.1.1        | Ensure AppArmor is installed                              | Automated | Debian   | ☐      |
| 1.3.1.2        | Ensure AppArmor is enabled in the bootloader configuration| Automated | Debian   | ☐      |
| 1.3.1.3        | Ensure all AppArmor Profiles are in enforce or complain mode | Automated | Debian | ☐      |
| 1.3.1.4        | Ensure all AppArmor Profiles are enforcing                | Automated | Debian   | ☐      |
| 1.3.1.5        | Ensure the SELinux mode is enforcing                      | Automated | RHEL     | ☐      |
| 1.3.1.6        | Ensure no unconfined services exist                       | Manual    | RHEL     | ☐      |
| 1.3.1.7        | Ensure the MCS Translation Service (mcstrans) is not installed | Automated | RHEL | ☐      |
| 1.3.1.8        | Ensure SETroubleshoot is not installed                    | Automated | RHEL     | ☐      |
| 1.4.1          | Ensure bootloader password is set                         | Automated | All      | ☐      |
| 1.4.2          | Ensure access to bootloader config is configured          | Automated | All      | ☐      |
| 1.5.1          | Ensure address space layout randomization is enabled      | Automated | All      | ☐      |
| 1.5.2          | Ensure ptrace_scope is restricted                         | Automated | All      | ☐      |
| 1.5.3          | Ensure core dumps are restricted                          | Automated | All      | ☐      |
| 1.5.4          | Ensure prelink is not installed                           | Automated | RHEL     | ☐      |
| 1.5.5          | Ensure Automatic Error Reporting is not enabled           | Automated | All      | ☐      |
| 1.6.1          | Ensure message of the day is configured properly          | Automated | All      | ☐      |
| 1.6.2          | Ensure local login warning banner is configured properly  | Automated | All      | ☐      |
| 1.6.3          | Ensure system wide crypto policy disables sha1 hash and signature support | Automated | RHEL | ☐      |
| 1.6.4          | Ensure system wide crypto policy disables macs less than 128 bits | Automated | RHEL | ☐      |
| 1.6.5          | Ensure system wide crypto policy disables cbc for ssh     | Automated | RHEL     | ☐      |
| 1.6.6          | Ensure system wide crypto policy disables chacha20-poly1305 for ssh | Manual | RHEL | ☐      |
| 1.6.7          | Ensure system wide crypto policy disables EtM for ssh     | Manual    | RHEL     | ☐      |
| 1.6.3          | Ensure remote login warning banner is configured properly | Automated | All      | ☐      |
| 1.6.4          | Ensure access to /etc/motd is configured                  | Automated | All      | ☐      |
| 1.6.5          | Ensure access to /etc/issue is configured                 | Automated | All      | ☐      |
| 1.6.6          | Ensure access to /etc/issue.net is configured             | Automated | All      | ☐      |
| 1.7.1          | Ensure GDM is removed                                     | Automated | All      | ☐      |
| 1.7.2          | Ensure GDM login banner is configured                     | Automated | All      | ☐      |
| 1.7.3          | Ensure GDM disable-user-list option is enabled            | Automated | All      | ☐      |
| 1.7.4          | Ensure GDM screen locks when the user is idle             | Automated | All      | ☐      |
| 1.7.5          | Ensure GDM screen locks cannot be overridden              | Automated | All      | ☐      |
| 1.7.6          | Ensure GDM automatic mounting of removable media is disabled | Automated | All   | ☐      |
| 1.7.7          | Ensure GDM disabling automatic mounting of removable media is not overridden | Automated | All | ☐      |
| 1.7.8          | Ensure GDM autorun-never is enabled                       | Automated | All      | ☐      |
| 1.7.9          | Ensure GDM autorun-never is not overridden                | Automated | All      | ☐      |
| 1.7.10         | Ensure XDMCP is not enabled                               | Automated | All      | ☐      |


## ⚙️ Section 2: Services

| Control ID     | Description                                               | Type      | Platform | Status |
|----------------|-----------------------------------------------------------|-----------|----------|--------|
| 2.1.1          | Ensure autofs services are not in use                     | Automated | All      | ☐      |
| 2.1.2          | Ensure avahi daemon services are not in use               | Automated | All      | ☐      |
| 2.1.3          | Ensure dhcp server services are not in use                | Automated | All      | ☐      |
| 2.1.4          | Ensure dns server services are not in use                 | Automated | All      | ☐      |
| 2.1.5          | Ensure dnsmasq services are not in use                    | Automated | All      | ☐      |
| 2.1.6          | Ensure ftp server services are not in use                 | Automated | All      | ☐      |
| 2.1.7          | Ensure ldap server services are not in use                | Automated | All      | ☐      |
| 2.1.8          | Ensure message access server services are not in use      | Automated | All      | ☐      |
| 2.1.9          | Ensure network file system services are not in use        | Automated | All      | ☐      |
| 2.1.10         | Ensure nis server services are not in use                 | Automated | All      | ☐      |
| 2.1.11         | Ensure print server services are not in use               | Automated | All      | ☐      |
| 2.1.12         | Ensure rpcbind services are not in use                    | Automated | All      | ☐      |
| 2.1.13         | Ensure rsync services are not in use                      | Automated | All      | ☐      |
| 2.1.14         | Ensure samba file server services are not in use          | Automated | All      | ☐      |
| 2.1.15         | Ensure snmp services are not in use                       | Automated | All      | ☐      |
| 2.1.15         | Ensure telnet server services are not in use              | Automated | RHEL     | ☐      |
| 2.1.16         | Ensure tftp server services are not in use                | Automated | All      | ☐      |
| 2.1.17         | Ensure web proxy server services are not in use           | Automated | All      | ☐      |
| 2.1.18         | Ensure web server services are not in use                 | Automated | All      | ☐      |
| 2.1.19         | Ensure xinetd services are not in use                     | Automated | All      | ☐      |
| 2.1.20         | Ensure X window server services are not in use            | Automated | All      | ☐      |
| 2.1.21         | Ensure mail transfer agent is configured for local-only mode | Automated | All   | ☐      |
| 2.1.22         | Ensure only approved services are listening on a network interface | Manual | All | ☐      |
| 2.2.1          | Ensure NIS Client is not installed                        | Automated | All      | ☐      |
| 2.2.2          | Ensure rsh client is not installed                        | Automated | All      | ☐      |
| 2.2.3          | Ensure talk client is not installed                       | Automated | All      | ☐      |
| 2.2.4          | Ensure telnet client is not installed                     | Automated | All      | ☐      |
| 2.2.5          | Ensure ldap client is not installed                       | Automated | All      | ☐      |
| 2.2.5          | Ensure tftp client is not installed                       | Automated | RHEL     | ☐      |
| 2.2.6          | Ensure ftp client is not installed                        | Automated | All      | ☐      |
| 2.3.1.1        | Ensure a single time synchronization daemon is in use     | Automated | All      | ☐      |
| 2.3.2.1        | Ensure systemd-timesyncd configured with authorized timeserver | Automated | All | ☐      |
| 2.3.2.2        | Ensure systemd-timesyncd is enabled and running           | Automated | All      | ☐      |
| 2.3.3.1        | Ensure chrony is configured with authorized timeserver    | Automated | All      | ☐      |
| 2.3.3.2        | Ensure chrony is running as user _chrony                  | Automated | All      | ☐      |
| 2.3.3.3        | Ensure chrony is enabled and running                      | Automated | All      | ☐      |
| 2.3.3          | Ensure chrony is not run as the root user                 | Automated | RHEL     | ☐      |
| 2.4.1.1        | Ensure cron daemon is enabled and active                  | Automated | All      | ☐      |
| 2.4.1.2        | Ensure permissions on /etc/crontab are configured         | Automated | All      | ☐      |
| 2.4.1.3        | Ensure permissions on /etc/cron.hourly are configured     | Automated | All      | ☐      |
| 2.4.1.4        | Ensure permissions on /etc/cron.daily are configured      | Automated | All      | ☐      |
| 2.4.1.5        | Ensure permissions on /etc/cron.weekly are configured     | Automated | All      | ☐      |
| 2.4.1.6        | Ensure permissions on /etc/cron.monthly are configured    | Automated | All      | ☐      |
| 2.4.1.7        | Ensure permissions on /etc/cron.d are configured          | Automated | All      | ☐      |
| 2.4.1.8        | Ensure crontab is restricted to authorized users          | Automated | All      | ☐      |
| 2.4.2.1        | Ensure at is restricted to authorized users               | Automated | All      | ☐      |

## 🌐 Section 3: Network

| Control ID | Description                                               | Type      | Platform | Status |
|------------|-----------------------------------------------------------|-----------|----------|--------|
| 3.1.1      | Ensure IPv6 status is identified                          | Manual    | All      | ☐      |
| 3.1.2      | Ensure wireless interfaces are disabled                   | Automated | All      | ☐      |
| 3.1.3      | Ensure bluetooth services are not in use                  | Automated | All      | ☐      |
| 3.2.1      | Ensure dccp kernel module is not available                | Automated | All      | ☐      |
| 3.2.2      | Ensure tipc kernel module is not available                | Automated | All      | ☐      |
| 3.2.3      | Ensure rds kernel module is not available                 | Automated | All      | ☐      |
| 3.2.4      | Ensure sctp kernel module is not available                | Automated | All      | ☐      |
| 3.3.1      | Ensure ip forwarding is disabled                          | Automated | All      | ☐      |
| 3.3.2      | Ensure packet redirect sending is disabled                | Automated | All      | ☐      |
| 3.3.3      | Ensure bogus icmp responses are ignored                   | Automated | All      | ☐      |
| 3.3.4      | Ensure broadcast icmp requests are ignored                | Automated | All      | ☐      |
| 3.3.5      | Ensure icmp redirects are not accepted                    | Automated | All      | ☐      |
| 3.3.6      | Ensure secure icmp redirects are not accepted             | Automated | All      | ☐      |
| 3.3.7      | Ensure reverse path filtering is enabled                  | Automated | All      | ☐      |
| 3.3.8      | Ensure source routed packets are not accepted             | Automated | All      | ☐      |
| 3.3.9      | Ensure suspicious packets are logged                      | Automated | All      | ☐      |
| 3.3.10     | Ensure tcp syn cookies is enabled                         | Automated | All      | ☐      |
| 3.3.11     | Ensure ipv6 router advertisements are not accepted        | Automated | All      | ☐      |

## 🔥 Section 4: Host Based Firewall

| Control ID     | Description                                               | Type      | Platform | Status |
|----------------|-----------------------------------------------------------|-----------|----------|--------|
| 4.1.1          | Ensure a single firewall configuration utility is in use  | Automated | All      | ☐      |
| 4.2.1          | Ensure ufw is installed                                    | Automated | Debian   | ☐      |
| 4.2.2          | Ensure iptables-persistent is not installed with ufw      | Automated | Debian   | ☐      |
| 4.2.1          | Ensure firewalld drops unnecessary services and ports     | Manual    | RHEL     | ☐      |
| 4.2.2          | Ensure firewalld loopback traffic is configured           | Automated | RHEL     | ☐      |
| 4.2.3          | Ensure ufw service is enabled                              | Automated | Debian   | ☐      |
| 4.2.4          | Ensure ufw loopback traffic is configured                  | Automated | Debian   | ☐      |
| 4.2.5          | Ensure ufw outbound connections are configured             | Manual    | Debian   | ☐      |
| 4.2.6          | Ensure ufw firewall rules exist for all open ports         | Automated | Debian   | ☐      |
| 4.2.7          | Ensure ufw default deny firewall policy                    | Automated | Debian   | ☐      |
| 4.3.1          | Ensure nftables is installed                               | Automated | All      | ☐      |
| 4.3.2          | Ensure ufw is uninstalled or disabled with nftables        | Automated | All      | ☐      |
| 4.3.3          | Ensure iptables are flushed with nftables                  | Manual    | All      | ☐      |
| 4.3.4          | Ensure a nftables table exists                             | Automated | All      | ☐      |
| 4.3.5          | Ensure nftables base chains exist                          | Automated | All      | ☐      |
| 4.3.6          | Ensure nftables loopback traffic is configured             | Automated | All      | ☐      |
| 4.3.7          | Ensure nftables outbound and established connections are configured | Manual | All | ☐      |
| 4.3.8          | Ensure nftables default deny firewall policy               | Automated | All      | ☐      |
| 4.3.9          | Ensure nftables service is enabled                         | Automated | All      | ☐      |
| 4.3.10         | Ensure nftables rules are permanent                        | Automated | All      | ☐      |
| 4.4.1.1        | Ensure iptables packages are installed                     | Automated | RHEL     | ☐      |
| 4.4.1.2        | Ensure nftables is not in use with iptables                | Automated | RHEL     | ☐      |
| 4.4.1.3        | Ensure ufw is not in use with iptables                     | Automated | RHEL     | ☐      |
| 4.4.2.1        | Ensure iptables default deny firewall policy               | Automated | RHEL     | ☐      |
| 4.4.2.2        | Ensure iptables loopback traffic is configured             | Automated | RHEL     | ☐      |
| 4.4.2.3        | Ensure iptables outbound and established connections are configured | Manual | RHEL | ☐      |
| 4.4.2.4        | Ensure iptables firewall rules exist for all open ports    | Automated | RHEL     | ☐      |
| 4.4.3.1        | Ensure ip6tables default deny firewall policy              | Automated | RHEL     | ☐      |
| 4.4.3.2        | Ensure ip6tables loopback traffic is configured            | Automated | RHEL     | ☐      |
| 4.4.3.3        | Ensure ip6tables outbound and established connections are configured | Manual | RHEL | ☐      |
| 4.4.3.4        | Ensure ip6tables firewall rules exist for all open ports   | Automated | RHEL     | ☐      |

## 🔐 Section 5: Access Control

| Control ID     | Description                                               | Type      | Platform | Status |
|----------------|-----------------------------------------------------------|-----------|----------|--------|
| 5.1.1          | Ensure permissions on /etc/ssh/sshd_config are configured | Automated | All      | ☐      |
| 5.1.2          | Ensure permissions on SSH private host key files are configured | Automated | All | ☐      |
| 5.1.3          | Ensure permissions on SSH public host key files are configured | Automated | All | ☐      |
| 5.1.4          | Ensure sshd access is configured                          | Automated | All      | ☐      |
| 5.1.5          | Ensure sshd Banner is configured                          | Automated | All      | ☐      |
| 5.1.6          | Ensure sshd Ciphers are configured                        | Automated | All      | ☐      |
| 5.1.7          | Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured | Automated | All | ☐      |
| 5.1.8          | Ensure sshd DisableForwarding is enabled                  | Automated | All      | ☐      |
| 5.1.9          | Ensure sshd GSSAPIAuthentication is disabled              | Automated | All      | ☐      |
| 5.1.10         | Ensure sshd HostbasedAuthentication is disabled           | Automated | All      | ☐      |
| 5.1.11         | Ensure sshd IgnoreRhosts is enabled                       | Automated | All      | ☐      |
| 5.1.12         | Ensure sshd KexAlgorithms is configured                   | Automated | All      | ☐      |
| 5.1.13         | Ensure sshd LoginGraceTime is configured                  | Automated | All      | ☐      |
| 5.1.14         | Ensure sshd LogLevel is configured                        | Automated | All      | ☐      |
| 5.1.15         | Ensure sshd MACs are configured                           | Automated | All      | ☐      |
| 5.1.16         | Ensure sshd MaxAuthTries is configured                    | Automated | All      | ☐      |
| 5.1.17         | Ensure sshd MaxSessions is configured                     | Automated | All      | ☐      |
| 5.1.18         | Ensure sshd MaxStartups is configured                     | Automated | All      | ☐      |
| 5.1.19         | Ensure sshd PermitEmptyPasswords is disabled              | Automated | All      | ☐      |
| 5.1.20         | Ensure sshd PermitRootLogin is disabled                   | Automated | All      | ☐      |
| 5.1.21         | Ensure sshd PermitUserEnvironment is disabled             | Automated | All      | ☐      |
| 5.1.22         | Ensure sshd UsePAM is enabled                             | Automated | All      | ☐      |
| 5.2.1          | Ensure sudo is installed                                  | Automated | All      | ☐      |
| 5.2.2          | Ensure sudo commands use pty                              | Automated | All      | ☐      |
| 5.2.3          | Ensure sudo log file exists                               | Automated | All      | ☐      |
| 5.2.4          | Ensure users must provide password for privilege escalation | Automated | All    | ☐      |
| 5.2.5          | Ensure re-authentication for privilege escalation is not disabled globally | Automated | All | ☐      |
| 5.2.6          | Ensure sudo authentication timeout is configured correctly | Automated | All     | ☐      |
| 5.2.7          | Ensure access to the su command is restricted             | Automated | All      | ☐      |
| 5.3.1.1        | Ensure latest version of pam is installed                 | Automated | All      | ☐      |
| 5.3.1.2        | Ensure libpam-modules is installed                        | Automated | All      | ☐      |
| 5.3.1.3        | Ensure libpam-pwquality is installed                      | Automated | All      | ☐      |
| 5.3.1.2        | Ensure latest version of authselect is installed          | Automated | RHEL     | ☐      |
| 5.3.1.3        | Ensure latest version of libpwquality is installed        | Automated | RHEL     | ☐      |
| 5.3.2.1        | Ensure pam_unix module is enabled                         | Automated | All      | ☐      |
| 5.3.2.1        | Ensure active authselect profile includes pam modules     | Automated | RHEL     | ☐      |
| 5.3.2.2        | Ensure pam_faillock module is enabled                     | Automated | All      | ☐      |
| 5.3.2.3        | Ensure pam_pwquality module is enabled                    | Automated | All      | ☐      |
| 5.3.2.4        | Ensure pam_pwhistory module is enabled                    | Automated | All      | ☐      |
| 5.3.3.1.1      | Ensure password failed attempts lockout is configured     | Automated | All      | ☐      |
| 5.3.3.1.2      | Ensure password unlock time is configured                 | Automated | All      | ☐      |
| 5.3.3.1.3      | Ensure password failed attempts lockout includes root account | Automated | All  | ☐      |
| 5.3.3.2.1      | Ensure password number of changed characters is configured | Automated | All     | ☐      |
| 5.3.3.2.2      | Ensure minimum password length is configured              | Automated | All      | ☐      |
| 5.3.3.2.3      | Ensure password complexity is configured                  | Manual    | All      | ☐      |
| 5.3.3.2.4      | Ensure password same consecutive characters is configured | Automated | All      | ☐      |
| 5.3.3.2.5      | Ensure password maximum sequential characters is configured | Automated | All    | ☐      |
| 5.3.3.2.6      | Ensure password dictionary check is enabled               | Automated | All      | ☐      |
| 5.3.3.2.7      | Ensure password quality checking is enforced              | Automated | All      | ☐      |
| 5.3.3.2.8      | Ensure password quality is enforced for the root user     | Automated | All      | ☐      |
| 5.3.3.3.1      | Ensure password history remember is configured            | Automated | All      | ☐      |
| 5.3.3.3.2      | Ensure password history is enforced for the root user     | Automated | All      | ☐      |
| 5.3.3.3.3      | Ensure pam_pwhistory includes use_authtok                 | Automated | All      | ☐      |
| 5.3.3.4.1      | Ensure pam_unix does not include nullok                   | Automated | All      | ☐      |
| 5.3.3.4.2      | Ensure pam_unix does not include remember                 | Automated | All      | ☐      |
| 5.3.3.4.3      | Ensure pam_unix includes a strong password hashing algorithm | Automated | All  | ☐      |
| 5.3.3.4.4      | Ensure pam_unix includes use_authtok                      | Automated | All      | ☐      |
| 5.4.1.1        | Ensure password expiration is configured                  | Automated | All      | ☐      |
| 5.4.1.2        | Ensure minimum password days is configured                | Manual    | All      | ☐      |
| 5.4.1.3        | Ensure password expiration warning days is configured     | Automated | All      | ☐      |
| 5.4.1.4        | Ensure strong password hashing algorithm is configured    | Automated | All      | ☐      |
| 5.4.1.5        | Ensure inactive password lock is configured               | Automated | All      | ☐      |
| 5.4.1.6        | Ensure all users last password change date is in the past | Automated | All      | ☐      |
| 5.4.2.1        | Ensure root is the only UID 0 account                     | Automated | All      | ☐      |
| 5.4.2.2        | Ensure root is the only GID 0 account                     | Automated | All      | ☐      |
| 5.4.2.3        | Ensure group root is the only GID 0 group                 | Automated | All      | ☐      |
| 5.4.2.4        | Ensure root account access is controlled                  | Automated | All      | ☐      |
| 5.4.2.5        | Ensure root path integrity                                | Automated | All      | ☐      |
| 5.4.2.6        | Ensure root user umask is configured                      | Automated | All      | ☐      |
| 5.4.2.7        | Ensure system accounts do not have a valid login shell    | Automated | All      | ☐      |
| 5.4.2.8        | Ensure accounts without a valid login shell are locked    | Automated | All      | ☐      |
| 5.4.3.1        | Ensure nologin is not listed in /etc/shells               | Automated | All      | ☐      |
| 5.4.3.2        | Ensure default user shell timeout is configured           | Automated | All      | ☐      |
| 5.4.3.3        | Ensure default user umask is configured                   | Automated | All      | ☐      |

## 📝 Section 6: Logging and Auditing

| Control ID     | Description                                               | Type      | Platform | Status |
|----------------|-----------------------------------------------------------|-----------|----------|--------|
| 6.1.1.1        | Ensure journald service is enabled and active             | Automated | All      | ☐      |
| 6.1.1.2        | Ensure journald log file access is configured             | Manual    | All      | ☐      |
| 6.1.1.3        | Ensure journald log file rotation is configured           | Manual    | All      | ☐      |
| 6.1.1.4        | Ensure only one logging system is in use                  | Automated | All      | ☐      |
| 6.1.2.1.1      | Ensure systemd-journal-remote is installed                | Automated | All      | ☐      |
| 6.1.2.1.2      | Ensure systemd-journal-upload authentication is configured| Manual    | All      | ☐      |
| 6.1.2.1.3      | Ensure systemd-journal-upload is enabled and active       | Automated | All      | ☐      |
| 6.1.2.1.4      | Ensure systemd-journal-remote service is not in use       | Automated | All      | ☐      |
| 6.1.2.2        | Ensure journald ForwardToSyslog is disabled               | Automated | All      | ☐      |
| 6.1.2.3        | Ensure journald Compress is configured                    | Automated | All      | ☐      |
| 6.1.2.4        | Ensure journald Storage is configured                     | Automated | All      | ☐      |
| 6.1.3.1        | Ensure rsyslog is installed                               | Automated | All      | ☐      |
| 6.1.3.2        | Ensure rsyslog service is enabled and active              | Automated | All      | ☐      |
| 6.1.3.3        | Ensure journald is configured to send logs to rsyslog     | Automated | All      | ☐      |
| 6.1.3.4        | Ensure rsyslog log file creation mode is configured       | Automated | All      | ☐      |
| 6.1.3.5        | Ensure rsyslog logging is configured                      | Manual    | All      | ☐      |
| 6.1.3.6        | Ensure rsyslog is configured to send logs to a remote host| Manual    | All      | ☐      |
| 6.1.3.7        | Ensure rsyslog is not configured to receive logs from a remote client | Automated | All | ☐      |
| 6.1.3.8        | Ensure logrotate is configured                            | Manual    | All      | ☐      |
| 6.1.4.1        | Ensure access to all logfiles has been configured         | Automated | All      | ☐      |
| 6.2.1.1        | Ensure auditd packages are installed                      | Automated | All      | ☐      |
| 6.2.1.2        | Ensure auditd service is enabled and active               | Automated | All      | ☐      |
| 6.2.1.3        | Ensure auditing for processes that start prior to auditd is enabled | Automated | All | ☐      |
| 6.2.1.4        | Ensure audit_backlog_limit is sufficient                  | Automated | All      | ☐      |
| 6.2.2.1        | Ensure audit log storage size is configured               | Automated | All      | ☐      |
| 6.2.2.2        | Ensure audit logs are not automatically deleted           | Automated | All      | ☐      |
| 6.2.2.3        | Ensure system is disabled when audit logs are full        | Automated | All      | ☐      |
| 6.2.2.4        | Ensure system warns when audit logs are low on space      | Automated | All      | ☐      |
| 6.2.3.1        | Ensure changes to sudoers are collected                   | Automated | All      | ☐      |
| 6.2.3.2        | Ensure actions as another user are always logged          | Automated | All      | ☐      |
| 6.2.3.3        | Ensure events that modify the sudo log file are collected | Automated | All      | ☐      |
| 6.2.3.4        | Ensure events that modify date and time information are collected | Automated | All | ☐      |
| 6.2.3.5        | Ensure events that modify the system's network environment are collected | Automated | All | ☐      |
| 6.2.3.6        | Ensure use of privileged commands are collected           | Automated | All      | ☐      |
| 6.2.3.7        | Ensure unsuccessful file access attempts are collected    | Automated | All      | ☐      |
| 6.2.3.8        | Ensure events that modify user/group information are collected | Automated | All | ☐      |
| 6.2.3.9        | Ensure DAC permission modification events are collected   | Automated | All      | ☐      |
| 6.2.3.10       | Ensure successful file system mounts are collected        | Automated | All      | ☐      |
| 6.2.3.11       | Ensure session initiation information is collected        | Automated | All      | ☐      |
| 6.2.3.12       | Ensure login and logout events are collected              | Automated | All      | ☐      |
| 6.2.3.13       | Ensure file deletion events by users are collected        | Automated | All      | ☐      |
| 6.2.3.14       | Ensure MAC modification events are collected              | Automated | All      | ☐      |
| 6.2.3.15       | Ensure chcon command attempts are collected               | Automated | All      | ☐      |
| 6.2.3.16       | Ensure setfacl command attempts are collected             | Automated | All      | ☐      |
| 6.2.3.17       | Ensure chacl command attempts are collected               | Automated | All      | ☐      |
| 6.2.3.18       | Ensure usermod command attempts are collected             | Automated | All      | ☐      |
| 6.2.3.19       | Ensure kernel module loading/unloading/modification is collected | Automated | All | ☐      |
| 6.2.3.20       | Ensure the audit configuration is immutable               | Automated | All      | ☐      |
| 6.2.3.21       | Ensure running and on-disk audit configuration matches    | Manual    | All      | ☐      |
| 6.2.4.1        | Ensure audit log files mode is configured                 | Automated | All      | ☐      |
| 6.2.4.2        | Ensure audit log files owner is configured                | Automated | All      | ☐      |
| 6.2.4.3        | Ensure audit log files group owner is configured          | Automated | All      | ☐      |
| 6.2.4.4        | Ensure audit log directory mode is configured             | Automated | All      | ☐      |
| 6.2.4.5        | Ensure audit config files mode is configured              | Automated | All      | ☐      |
| 6.2.4.6        | Ensure audit config files owner is configured             | Automated | All      | ☐      |
| 6.2.4.7        | Ensure audit config files group owner is configured       | Automated | All      | ☐      |
| 6.2.4.8        | Ensure audit tools mode is configured                     | Automated | All      | ☐      |
| 6.2.4.9        | Ensure audit tools owner is configured                    | Automated | All      | ☐      |
| 6.2.4.10       | Ensure audit tools group owner is configured              | Automated | All      | ☐      |
| 6.3.1          | Ensure AIDE is installed                                  | Automated | All      | ☐      |
| 6.3.2          | Ensure filesystem integrity is regularly checked          | Automated | All      | ☐      |
| 6.3.3          | Ensure cryptographic mechanisms protect audit tool integrity | Automated | All   | ☐      |

## 🛠️ Section 7: System Maintenance

| Control ID     | Description                                               | Type      | Platform | Status |
|----------------|-----------------------------------------------------------|-----------|----------|--------|
| 7.1.1          | Ensure permissions on /etc/passwd are configured          | Automated | All      | ☐      |
| 7.1.2          | Ensure permissions on /etc/passwd- are configured         | Automated | All      | ☐      |
| 7.1.3          | Ensure permissions on /etc/group are configured           | Automated | All      | ☐      |
| 7.1.4          | Ensure permissions on /etc/group- are configured          | Automated | All      | ☐      |
| 7.1.5          | Ensure permissions on /etc/shadow are configured          | Automated | All      | ☐      |
| 7.1.6          | Ensure permissions on /etc/shadow- are configured         | Automated | All      | ☐      |
| 7.1.7          | Ensure permissions on /etc/gshadow are configured         | Automated | All      | ☐      |
| 7.1.8          | Ensure permissions on /etc/gshadow- are configured        | Automated | All      | ☐      |
| 7.1.9          | Ensure permissions on /etc/shells are configured          | Automated | All      | ☐      |
| 7.1.10         | Ensure permissions on /etc/security/opasswd are configured| Automated | All      | ☐      |
| 7.1.11         | Ensure world writable files and directories are secured   | Automated | All      | ☐      |
| 7.1.12         | Ensure no files or directories without an owner and a group exist | Automated | All | ☐      |
| 7.1.13         | Ensure SUID and SGID files are reviewed                   | Manual    | All      | ☐      |
| 7.2.1          | Ensure accounts in /etc/passwd use shadowed passwords     | Automated | All      | ☐      |
| 7.2.2          | Ensure /etc/shadow password fields are not empty          | Automated | All      | ☐      |
| 7.2.3          | Ensure all groups in /etc/passwd exist in /etc/group      | Automated | All      | ☐      |
| 7.2.4          | Ensure shadow group is empty                              | Automated | All      | ☐      |
| 7.2.5          | Ensure no duplicate UIDs exist                            | Automated | All      | ☐      |
| 7.2.6          | Ensure no duplicate GIDs exist                            | Automated | All      | ☐      |
| 7.2.7          | Ensure no duplicate user names exist                      | Automated | All      | ☐      |
| 7.2.8          | Ensure no duplicate group names exist                     | Automated | All      | ☐      |
| 7.2.9          | Ensure local interactive user home directories are configured | Automated | All  | ☐      |
| 7.2.10         | Ensure local interactive user dot files access is configured | Automated | All   | ☐      |
