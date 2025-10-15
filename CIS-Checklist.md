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
| 1.2.2.1        | Ensure updates, patches, and additional security software are installed | Manual | All | ☐      |
| 1.3.1.1        | Ensure AppArmor is installed                              | Automated | Debian   | ☐      |
| 1.3.1.2        | Ensure AppArmor is enabled in the bootloader configuration| Automated | Debian   | ☐      |
| 1.3.1.3        | Ensure all AppArmor Profiles are in enforce or complain mode | Automated | Debian | ☐      |
| 1.3.1.4        | Ensure all AppArmor Profiles are enforcing                | Automated | Debian   | ☐      |
| 1.4.1          | Ensure bootloader password is set                         | Automated | All      | ☐      |
| 1.4.2          | Ensure access to bootloader config is configured          | Automated | All      | ☐      |
| 1.5.1          | Ensure address space layout randomization is enabled      | Automated | All      | ☐      |
| 1.5.2          | Ensure ptrace_scope is restricted                         | Automated | All      | ☐      |
| 1.5.3          | Ensure core dumps are restricted                          | Automated | All      | ☐      |
| 1.5.4          | Ensure prelink is not installed                           | Automated | RHEL     | ☐      |
| 1.5.5          | Ensure Automatic Error Reporting is not enabled           | Automated | All      | ☐      |
| 1.6.1          | Ensure message of the day is configured properly          | Automated | All      | ☐      |
| 1.6.2          | Ensure local login warning banner is configured properly  | Automated | All      | ☐      |
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
| 2.2.6          | Ensure ftp client is not installed                        | Automated | All      | ☐      |
| 2.3.1.1        | Ensure a single time synchronization daemon is in use     | Automated | All      | ☐      |
| 2.3.2.1        | Ensure systemd-timesyncd configured with authorized timeserver | Automated | All | ☐      |
| 2.3.2.2        | Ensure systemd-timesyncd is enabled and running           | Automated | All      | ☐      |
| 2.3.3.1        | Ensure chrony is configured with authorized timeserver    | Automated | All      | ☐      |
| 2.3.3.2        | Ensure chrony is running as user _chrony                  | Automated | All      | ☐      |
| 2.3.3.3        | Ensure chrony is enabled and running                      | Automated | All      | ☐      |
| 2.4.1.1        | Ensure cron daemon is enabled and active                  | Automated | All      | ☐      |
| 2.4.1.2        | Ensure permissions on /etc/crontab are configured         | Automated | All      | ☐      |
| 2.4.1.3        | Ensure permissions on /etc/cron.hourly are configured     | Automated | All      | ☐      |
| 2.4.1.4        | Ensure permissions on /etc/cron.daily are configured      | Automated | All      | ☐      |
| 2.4.1.5        | Ensure permissions on /etc/cron.weekly are configured     | Automated | All      | ☐      |
| 2.4.1.6        | Ensure permissions on /etc/cron.monthly are configured    | Automated | All      | ☐      |
| 2.4.1.7        | Ensure permissions on /etc/cron.d are configured          | Automated | All      | ☐      |
| 2.4.1.8        | Ensure crontab is restricted to authorized users          | Automated | All      | ☐      |
| 2.4.2.1        | Ensure at is restricted to authorized users               | Automated | All      | ☐      |

