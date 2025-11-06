# CIS Benchmark Implementation Roadmap

## 📊 Übersicht

- **CIS Debian Linux 12 Benchmark:** v1.1.0 (09-26-2024)
- **Gesamt Checks im Benchmark:** 400+
- **Aktuell implementiert:** 270 (~67%)
- **Status:** Phase 2 ABGESCHLOSSEN! ✅ | Phase 3 ABGESCHLOSSEN! ✅ | Phase 4 ABGESCHLOSSEN! ✅ | Phase 5 Sprint 1 ABGESCHLOSSEN! ✅

---

## ✅ Phase 1: Foundation (Abgeschlossen)

**14 Checks implementiert**

### Auditd (4 Checks)
- [x] 6.2.1.1 - Ensure auditd is installed
- [x] 6.2.1.2 - Ensure auditd service is enabled
- [x] 6.2.1.3 - Check auditd.conf for availability issues (Custom)
- [x] 6.2.4.1 - Ensure audit log files mode is configured

### Filesystem (3 Checks)
- [x] 7.1.1 - Ensure permissions on /etc/passwd are configured
- [x] 7.1.5 - Ensure permissions on /etc/shadow are configured
- [x] 7.1.11 - Ensure world writable files are secured

### Services (3 Checks)
- [x] 2.2.1 - Ensure Avahi Server is not installed
- [x] 2.2.4 - Ensure CUPS is not installed
- [x] 2.2.7 - Ensure RPC is not installed

### Network (2 Checks)
- [x] 3.1.1 - Ensure IP forwarding is disabled
- [x] 3.2.2 - Ensure ICMP redirects are not accepted

### User/Group (2 Checks)
- [x] 7.2.2 - Ensure /etc/shadow password fields are not empty
- [x] 7.2.5 - Ensure no duplicate UIDs exist

---

## 🎯 Phase 2: High Priority Checks ✅ ABGESCHLOSSEN

### Kritische Sicherheits-Checks

#### 1. Initial Setup - Filesystem (1.1.x)
**Priorität: HOCH** - 35 Checks

<details>
<summary>Filesystem Kernel Modules (1.1.1.x) - 9 Checks ✅ ABGESCHLOSSEN</summary>

- [x] 1.1.1.1 - Ensure cramfs kernel module is not available
- [x] 1.1.1.2 - Ensure freevxfs kernel module is not available
- [x] 1.1.1.3 - Ensure hfs kernel module is not available
- [x] 1.1.1.4 - Ensure hfsplus kernel module is not available
- [x] 1.1.1.5 - Ensure jffs2 kernel module is not available
- [x] 1.1.1.6 - Ensure overlayfs kernel module is not available
- [x] 1.1.1.7 - Ensure squashfs kernel module is not available
- [x] 1.1.1.8 - Ensure udf kernel module is not available
- [x] 1.1.1.9 - Ensure usb-storage kernel module is not available

**Note:** Check 1.1.1.10 is a summary check covered by the above 9 individual module checks.

</details>

<details>
<summary>Filesystem Partitions (1.1.2.x) - 26 Checks ✅ ABGESCHLOSSEN</summary>

**Configure /tmp (1.1.2.1.x)**
- [x] 1.1.2.1.1 - Ensure /tmp is a separate partition
- [x] 1.1.2.1.2 - Ensure nodev option set on /tmp partition
- [x] 1.1.2.1.3 - Ensure nosuid option set on /tmp partition
- [x] 1.1.2.1.4 - Ensure noexec option set on /tmp partition

**Configure /dev/shm (1.1.2.2.x)**
- [x] 1.1.2.2.1 - Ensure /dev/shm is a separate partition
- [x] 1.1.2.2.2 - Ensure nodev option set on /dev/shm partition
- [x] 1.1.2.2.3 - Ensure nosuid option set on /dev/shm partition
- [x] 1.1.2.2.4 - Ensure noexec option set on /dev/shm partition

**Configure /home (1.1.2.3.x)**
- [x] 1.1.2.3.1 - Ensure separate partition exists for /home
- [x] 1.1.2.3.2 - Ensure nodev option set on /home partition
- [x] 1.1.2.3.3 - Ensure nosuid option set on /home partition

**Configure /var (1.1.2.4.x)**
- [x] 1.1.2.4.1 - Ensure separate partition exists for /var
- [x] 1.1.2.4.2 - Ensure nodev option set on /var partition
- [x] 1.1.2.4.3 - Ensure nosuid option set on /var partition

**Configure /var/tmp (1.1.2.5.x)**
- [x] 1.1.2.5.1 - Ensure separate partition exists for /var/tmp
- [x] 1.1.2.5.2 - Ensure nodev option set on /var/tmp partition
- [x] 1.1.2.5.3 - Ensure nosuid option set on /var/tmp partition
- [x] 1.1.2.5.4 - Ensure noexec option set on /var/tmp partition

**Configure /var/log (1.1.2.6.x)**
- [x] 1.1.2.6.1 - Ensure separate partition exists for /var/log
- [x] 1.1.2.6.2 - Ensure nodev option set on /var/log partition
- [x] 1.1.2.6.3 - Ensure nosuid option set on /var/log partition
- [x] 1.1.2.6.4 - Ensure noexec option set on /var/log partition

**Configure /var/log/audit (1.1.2.7.x)**
- [x] 1.1.2.7.1 - Ensure separate partition exists for /var/log/audit
- [x] 1.1.2.7.2 - Ensure nodev option set on /var/log/audit partition
- [x] 1.1.2.7.3 - Ensure nosuid option set on /var/log/audit partition
- [x] 1.1.2.7.4 - Ensure noexec option set on /var/log/audit partition

</details>

#### 2. SSH Server Configuration (5.1.x) ✅ ABGESCHLOSSEN
**Priorität: KRITISCH** - 22 Checks

<details>
<summary>SSH Configuration Checks - 22 Checks</summary>

- [x] 5.1.1 - Ensure permissions on /etc/ssh/sshd_config are configured
- [x] 5.1.2 - Ensure permissions on SSH private host key files are configured
- [x] 5.1.3 - Ensure permissions on SSH public host key files are configured
- [x] 5.1.4 - Ensure sshd access is configured
- [x] 5.1.5 - Ensure sshd Banner is configured
- [x] 5.1.6 - Ensure sshd Ciphers are configured
- [x] 5.1.7 - Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
- [x] 5.1.8 - Ensure sshd DisableForwarding is enabled
- [x] 5.1.9 - Ensure sshd GSSAPIAuthentication is disabled
- [x] 5.1.10 - Ensure sshd HostbasedAuthentication is disabled
- [x] 5.1.11 - Ensure sshd IgnoreRhosts is enabled
- [x] 5.1.12 - Ensure sshd KexAlgorithms is configured
- [x] 5.1.13 - Ensure sshd LoginGraceTime is configured
- [x] 5.1.14 - Ensure sshd LogLevel is configured
- [x] 5.1.15 - Ensure sshd MACs are configured
- [x] 5.1.16 - Ensure sshd MaxAuthTries is configured
- [x] 5.1.17 - Ensure sshd MaxSessions is configured
- [x] 5.1.18 - Ensure sshd MaxStartups is configured
- [x] 5.1.19 - Ensure sshd PermitEmptyPasswords is disabled
- [x] 5.1.20 - Ensure sshd PermitRootLogin is disabled
- [x] 5.1.21 - Ensure sshd PermitUserEnvironment is disabled
- [x] 5.1.22 - Ensure sshd UsePAM is enabled

</details>

#### 3. Additional Services (2.1.x) ✅ ABGESCHLOSSEN
**Priorität: HOCH** - 22 Checks

<details>
<summary>Server Services - 22 Checks</summary>

- [x] 2.1.1 - Ensure autofs services are not in use
- [x] 2.1.2 - Ensure avahi daemon services are not in use
- [x] 2.1.3 - Ensure dhcp server services are not in use
- [x] 2.1.4 - Ensure dns server services are not in use
- [x] 2.1.5 - Ensure dnsmasq services are not in use
- [x] 2.1.6 - Ensure ftp server services are not in use
- [x] 2.1.7 - Ensure ldap server services are not in use
- [x] 2.1.8 - Ensure message access server services are not in use
- [x] 2.1.9 - Ensure network file system services are not in use
- [x] 2.1.10 - Ensure nis server services are not in use
- [x] 2.1.11 - Ensure print server services are not in use
- [x] 2.1.12 - Ensure rpcbind services are not in use
- [x] 2.1.13 - Ensure rsync services are not in use
- [x] 2.1.14 - Ensure samba file server services are not in use
- [x] 2.1.15 - Ensure snmp services are not in use
- [x] 2.1.16 - Ensure tftp server services are not in use
- [x] 2.1.17 - Ensure web proxy server services are not in use
- [x] 2.1.18 - Ensure web server services are not in use
- [x] 2.1.19 - Ensure xinetd services are not in use
- [x] 2.1.20 - Ensure X window server services are not in use
- [x] 2.1.21 - Ensure mail transfer agent is configured for local-only mode
- [x] 2.1.22 - Ensure only approved services are listening on a network interface

</details>

#### 4. Network Kernel Parameters (3.3.x) ✅ ABGESCHLOSSEN
**Priorität: HOCH** - 11 Checks

<details>
<summary>Network Configuration - 11 Checks</summary>

- [x] 3.3.1 - Ensure ip forwarding is disabled
- [x] 3.3.2 - Ensure packet redirect sending is disabled
- [x] 3.3.3 - Ensure bogus icmp responses are ignored
- [x] 3.3.4 - Ensure broadcast icmp requests are ignored
- [x] 3.3.5 - Ensure icmp redirects are not accepted
- [x] 3.3.6 - Ensure secure icmp redirects are not accepted
- [x] 3.3.7 - Ensure reverse path filtering is enabled
- [x] 3.3.8 - Ensure source routed packets are not accepted
- [x] 3.3.9 - Ensure suspicious packets are logged
- [x] 3.3.10 - Ensure tcp syn cookies is enabled
- [x] 3.3.11 - Ensure ipv6 router advertisements are not accepted

</details>

---

## 🔄 Phase 3: Medium Priority ✅ ABGESCHLOSSEN

**79 Checks implementiert** (System Maintenance, System Logging, Logging & Auditing, PAM & Password Policy)

### System Maintenance (7.x) ✅ ABGESCHLOSSEN
**File Permissions (7.1.x) - 9 Checks**
- [x] 7.1.2 - Ensure permissions on /etc/passwd- are configured
- [x] 7.1.3 - Ensure permissions on /etc/group are configured
- [x] 7.1.4 - Ensure permissions on /etc/group- are configured
- [x] 7.1.6 - Ensure permissions on /etc/shadow- are configured
- [x] 7.1.7 - Ensure permissions on /etc/gshadow are configured
- [x] 7.1.8 - Ensure permissions on /etc/gshadow- are configured
- [x] 7.1.9 - Ensure permissions on /etc/shells are configured
- [x] 7.1.10 - Ensure permissions on /etc/security/opasswd are configured
- [x] 7.1.12 - Ensure no files or directories without an owner and a group exist

**User/Group Configuration (7.2.x) - 8 Checks**
- [x] 7.2.1 - Ensure accounts in /etc/passwd use shadowed passwords
- [x] 7.2.3 - Ensure all groups in /etc/passwd exist in /etc/group
- [x] 7.2.4 - Ensure shadow group is empty
- [x] 7.2.6 - Ensure no duplicate GIDs exist
- [x] 7.2.7 - Ensure no duplicate user names exist
- [x] 7.2.8 - Ensure no duplicate group names exist
- [x] 7.2.9 - Ensure local interactive user home directories are configured
- [x] 7.2.10 - Ensure local interactive user dot files access is configured

### System Logging (6.1.x) ✅ ABGESCHLOSSEN - 11 Checks

**systemd-journald Configuration (6.1.1.x) - 5 Checks**
- [x] 6.1.1.1 - Ensure systemd-journal-remote is installed
- [x] 6.1.1.2 - Ensure journald is configured to send logs to rsyslog
- [x] 6.1.1.3 - Ensure journald is configured to compress large log files
- [x] 6.1.1.4 - Ensure journald is configured to write logfiles to persistent disk
- [x] 6.1.1.5 - Ensure journald is not configured to receive logs from a remote client

**rsyslog Configuration (6.1.2.x) - 6 Checks**
- [x] 6.1.2.1 - Ensure rsyslog is installed
- [x] 6.1.2.2 - Ensure rsyslog service is enabled
- [x] 6.1.2.3 - Ensure rsyslog default file permissions are configured
- [x] 6.1.2.4 - Ensure logging is configured
- [x] 6.1.2.5 - Ensure rsyslog is configured to send logs to a remote log host
- [x] 6.1.2.6 - Ensure remote rsyslog messages are only accepted on designated log hosts

### Logging & Auditing (6.x) - Erweitern
- [x] 6.2.2.x - Audit Data Retention (4 Checks) ✅ ABGESCHLOSSEN
  - [x] 6.2.2.1 - Ensure audit log file size is configured
  - [x] 6.2.2.2 - Ensure audit logs are not automatically deleted
  - [x] 6.2.2.3 - Ensure system is disabled when audit logs are full (space_left_action)
  - [x] 6.2.2.4 - Ensure admin_space_left_action is configured
- [x] 6.2.3.x - Audit Rules (21 Checks) ✅ ABGESCHLOSSEN
  - [x] 6.2.3.1 - Ensure changes to system time are collected
  - [x] 6.2.3.2 - Ensure events that modify user/group information are collected
  - [x] 6.2.3.3 - Ensure events that modify the system's network environment are collected
  - [x] 6.2.3.4 - Ensure events that modify the system's Mandatory Access Controls are collected
  - [x] 6.2.3.5 - Ensure login and logout events are collected
  - [x] 6.2.3.6 - Ensure session initiation information is collected
  - [x] 6.2.3.7 - Ensure discretionary access control permission modification events are collected
  - [x] 6.2.3.8 - Ensure unsuccessful file access attempts are collected
  - [x] 6.2.3.9 - Ensure use of privileged commands are collected
  - [x] 6.2.3.10 - Ensure successful file system mounts are collected
  - [x] 6.2.3.11 - Ensure file deletion events by users are collected
  - [x] 6.2.3.12 - Ensure changes to system administration scope (sudoers) are collected
  - [x] 6.2.3.13 - Ensure system administrator command executions (sudo) are collected
  - [x] 6.2.3.14 - Ensure kernel module loading and unloading is collected
  - [x] 6.2.3.15 - Ensure the audit configuration is immutable
  - [x] 6.2.3.16 - Ensure cron jobs are logged
  - [x] 6.2.3.17 - Ensure password modification events are collected
  - [x] 6.2.3.18 - Ensure modifications to /etc/hosts are collected
  - [x] 6.2.3.19 - Ensure kernel parameters are collected
  - [x] 6.2.3.20 - Ensure modifications to system time zone information are collected
  - [x] 6.2.3.21 - Ensure SSH configuration changes are collected
- [x] 6.2.4.x - Audit File Access (9 Checks) ✅ ABGESCHLOSSEN
  - [x] 6.2.4.1 - Ensure audit log files mode is configured
  - [x] 6.2.4.2 - Ensure audit log directory permissions are configured
  - [x] 6.2.4.3 - Ensure audit configuration files are mode 0640 or more restrictive
  - [x] 6.2.4.4 - Ensure audit configuration files are owned by root
  - [x] 6.2.4.5 - Ensure audit configuration files belong to group root
  - [x] 6.2.4.6 - Ensure audit tools are mode 0755 or more restrictive
  - [x] 6.2.4.7 - Ensure audit tools are owned by root
  - [x] 6.2.4.8 - Ensure audit tools belong to group root
  - [x] 6.2.4.9 - Ensure audit configuration files are mode 0640 or more restrictive
- [x] 6.3.x - Integrity Checking (3 Checks) ✅ ABGESCHLOSSEN
  - [x] 6.3.1 - Ensure AIDE is installed
  - [x] 6.3.2 - Ensure filesystem integrity is regularly checked
  - [x] 6.3.3 - Ensure cryptographic mechanisms are used to protect audit tools

### PAM & Password Policy (5.3.x & 5.4.x) ✅ ABGESCHLOSSEN - 14 Checks

<details>
<summary>PAM Configuration (5.3.x) - 5 Checks ✅</summary>

- [x] 5.3.1.1 - Ensure password creation requirements are configured (libpam-pwquality)
- [x] 5.3.1.2 - Ensure password quality requirements are configured
- [x] 5.3.2.1 - Ensure lockout for failed password attempts is configured
- [x] 5.3.3.1 - Ensure password reuse is limited
- [x] 5.3.3.2 - Ensure password hashing algorithm is SHA-512

</details>

<details>
<summary>User Accounts and Environment (5.4.x) - 9 Checks ✅</summary>

- [x] 5.4.1.1 - Ensure password expiration is 365 days or less
- [x] 5.4.1.2 - Ensure minimum days between password changes is configured
- [x] 5.4.1.3 - Ensure password expiration warning days is 7 or more
- [x] 5.4.1.4 - Ensure inactive password lock is 30 days or less
- [x] 5.4.1.5 - Ensure all users last password change date is in the past
- [x] 5.4.2 - Ensure system accounts are secured
- [x] 5.4.3 - Ensure default group for the root account is GID 0
- [x] 5.4.4 - Ensure default user umask is 027 or more restrictive
- [x] 5.4.5 - Ensure default user shell timeout is 900 seconds or less

</details>

---

## 🚀 Phase 4: Advanced Features ✅ TEILWEISE ABGESCHLOSSEN

### Firewall Configuration (4.x) ✅ ABGESCHLOSSEN - 22 Checks

<details>
<summary>UncomplicatedFirewall (4.2.x) - 7 Checks ✅</summary>

- [x] 4.2.1 - Ensure ufw is installed
- [x] 4.2.2 - Ensure iptables-persistent is not installed with ufw
- [x] 4.2.3 - Ensure ufw service is enabled
- [x] 4.2.4 - Ensure ufw loopback traffic is configured
- [x] 4.2.5 - Ensure ufw outbound connections are configured
- [x] 4.2.6 - Ensure ufw firewall rules exist for all open ports
- [x] 4.2.7 - Ensure ufw default deny firewall policy

</details>

<details>
<summary>nftables (4.3.x) - 10 Checks ✅</summary>

- [x] 4.3.1 - Ensure nftables is installed
- [x] 4.3.2 - Ensure ufw is uninstalled or disabled with nftables
- [x] 4.3.3 - Ensure iptables are flushed with nftables
- [x] 4.3.4 - Ensure a nftables table exists
- [x] 4.3.5 - Ensure nftables base chains exist
- [x] 4.3.6 - Ensure nftables loopback traffic is configured
- [x] 4.3.7 - Ensure nftables outbound and established connections are configured
- [x] 4.3.8 - Ensure nftables default deny firewall policy
- [x] 4.3.9 - Ensure nftables service is enabled
- [x] 4.3.10 - Ensure nftables rules are permanent

</details>

<details>
<summary>iptables (4.4.x) - 5 Checks ✅</summary>

- [x] 4.4.1 - Ensure iptables packages are installed
- [x] 4.4.2 - Ensure nftables is not installed with iptables
- [x] 4.4.3 - Ensure ufw is uninstalled or disabled with iptables
- [x] 4.4.4 - Ensure iptables default deny firewall policy
- [x] 4.4.5 - Ensure iptables loopback traffic is configured

</details>

### AppArmor & Bootloader (1.3.x & 1.4.x) ✅ ABGESCHLOSSEN - 6 Checks

<details>
<summary>AppArmor (1.3.1.x) - 4 Checks ✅</summary>

- [x] 1.3.1.1 - Ensure AppArmor is installed
- [x] 1.3.1.2 - Ensure AppArmor is enabled in the bootloader configuration
- [x] 1.3.1.3 - Ensure all AppArmor Profiles are in enforce or complain mode
- [x] 1.3.1.4 - Ensure all AppArmor Profiles are enforcing

</details>

<details>
<summary>Bootloader (1.4.x) - 2 Checks ✅</summary>

- [x] 1.4.1 - Ensure bootloader password is set
- [x] 1.4.2 - Ensure access to bootloader config is configured

</details>

### GNOME Display Manager (1.7.x) ✅ ABGESCHLOSSEN - 10 Checks

<details>
<summary>GDM Configuration (1.7.x) - 10 Checks ✅</summary>

- [x] 1.7.1 - Ensure GDM is removed or login is configured
- [x] 1.7.2 - Ensure GDM login banner is configured
- [x] 1.7.3 - Ensure GDM disable-user-list option is enabled
- [x] 1.7.4 - Ensure GDM screen locks when the user is idle
- [x] 1.7.5 - Ensure GDM screen locks cannot be overridden
- [x] 1.7.6 - Ensure GDM automatic mounting of removable media is disabled
- [x] 1.7.7 - Ensure GDM disabling automatic mounting is not overridden
- [x] 1.7.8 - Ensure GDM autorun-never is enabled
- [x] 1.7.9 - Ensure GDM autorun-never is not overridden
- [x] 1.7.10 - Ensure XDMCP is not enabled

</details>

### Time Synchronization (2.3.x) ✅ ABGESCHLOSSEN - 7 Checks

<details>
<summary>Time Sync Configuration (2.3.x) - 7 Checks ✅</summary>

- [x] 2.3.1.1 - Ensure systemd-timesyncd is installed
- [x] 2.3.1.2 - Ensure systemd-timesyncd is enabled and running
- [x] 2.3.1.3 - Ensure systemd-timesyncd is configured
- [x] 2.3.2.1 - Ensure chrony is installed
- [x] 2.3.2.2 - Ensure chrony is enabled and running
- [x] 2.3.2.3 - Ensure chrony is configured
- [x] 2.3.3 - Ensure only one time synchronization daemon is in use

</details>

### Job Schedulers (2.4.x) ✅ ABGESCHLOSSEN - 9 Checks

<details>
<summary>Cron & At Configuration (2.4.x) - 9 Checks ✅</summary>

- [x] 2.4.1.1 - Ensure cron daemon is installed
- [x] 2.4.1.2 - Ensure cron daemon is enabled and running
- [x] 2.4.1.3 - Ensure permissions on /etc/crontab are configured
- [x] 2.4.1.4 - Ensure permissions on /etc/cron.hourly are configured
- [x] 2.4.1.5 - Ensure permissions on /etc/cron.daily are configured
- [x] 2.4.1.6 - Ensure permissions on /etc/cron.weekly are configured
- [x] 2.4.1.7 - Ensure permissions on /etc/cron.monthly are configured
- [x] 2.4.1.8 - Ensure permissions on /etc/cron.d are configured
- [x] 2.4.2.1 - Ensure at is restricted to authorized users

</details>

---

## 📈 Implementierungs-Strategie

### ✅ Phase 1: Foundation (v1.0.0) - ABGESCHLOSSEN
**14 Checks** - Grundlegende Auditd, Filesystem, Services, Network, User/Group Checks

### ✅ Phase 2: High Priority (v1.1.0 - v1.3.0) - ABGESCHLOSSEN
**88 Checks** implementiert:
1. **SSH Configuration** (22 Checks) - Kritisch für Security ✅
2. **Filesystem Partitions** (26 Checks) - Wichtig für Availability ✅
3. **Filesystem Kernel Modules** (9 Checks) - Security ✅
4. **Additional Services** (22 Checks) - Attack Surface Reduction ✅
5. **Network Kernel Parameters** (11 Checks) - Network Security ✅

**Checks nach Phase 2:** 102 Checks (~25%)

### ✅ Phase 3: Medium Priority (v1.4.0 - v2.0.0) - ABGESCHLOSSEN
**79 Checks** implementiert:
1. **System Maintenance** (17 Checks) - File Permissions & User/Group ✅
2. **System Logging** (11 Checks) - journald & rsyslog ✅
3. **Logging & Auditing** (37 Checks) - Audit Rules, Retention, File Access, Integrity ✅
4. **PAM & Password Policy** (14 Checks) - PAM Configuration & User Accounts ✅

**Checks nach Phase 3:** 180 Checks (~45%) ✅

### 🎯 Phase 4: Advanced Features (v2.1.0 - v2.4.0) ✅ ABGESCHLOSSEN
**54 Checks implementiert:**
1. **Firewall Configuration (4.x)** (22 Checks) - UFW, nftables, iptables ✅
2. **AppArmor & Bootloader (1.3.x, 1.4.x)** (6 Checks) - MAC & Bootloader Security ✅
3. **GNOME Display Manager (1.7.x)** (10 Checks) - GDM Configuration ✅
4. **Time Synchronization (2.3.x)** (7 Checks) - systemd-timesyncd & chrony ✅
5. **Job Schedulers (2.4.x)** (9 Checks) - cron & at ✅

**Checks nach Phase 4:** 234 Checks (~58%)

### 🚀 Phase 5: High Coverage Goal (v2.6.0 - v3.x) - 🔄 IN ARBEIT
**Ziel:** 300+ Checks (~75% Coverage)

Phase 5 fokussiert sich auf die verbleibenden kritischen CIS-Abschnitte, um 75%+ Coverage zu erreichen.

**Status:** 36 Checks implementiert (270 gesamt / ~67% Coverage)
- **v2.5.0:** 19 Checks (Warning Banners, Software Updates, Network Devices/Protocols, Filesystem Config)
- **v2.6.0:** 17 Checks (sudo Configuration, IPv6 & TCP Wrappers) ✅ Sprint 1 ABGESCHLOSSEN

#### Priorität 1: Remaining Initial Setup (1.x) - ✅ TEILWEISE ABGESCHLOSSEN (5/20 Checks)

<details>
<summary>Filesystem Configuration (1.1.3.x) - 3 Checks ✅</summary>

- [x] 1.1.3.1 - Ensure nodev option set on /var partition
- [x] 1.1.3.2 - Ensure nosuid option set on /var partition
- [x] 1.1.3.3 - Ensure noexec option set on /var partition

</details>

<details>
<summary>Configure Software Updates (1.2.x) - 2 Checks ✅</summary>

- [x] 1.2.1 - Ensure package manager repositories are configured
- [x] 1.2.2 - Ensure GPG keys are configured

</details>

<details>
<summary>Filesystem Integrity (1.5.x) - 4 Checks</summary>

- [ ] 1.5.1 - Ensure bootloader config is not overwritten
- [ ] 1.5.2 - Ensure permissions on bootloader config are configured
- [ ] 1.5.3 - Ensure authentication required for single user mode
- [ ] 1.5.4 - Ensure core dumps are restricted

</details>

<details>
<summary>Mandatory Access Controls (1.6.x) - 11 Checks</summary>

- [ ] 1.6.1.1 - Ensure SELinux is installed
- [ ] 1.6.1.2 - Ensure SELinux is not disabled in bootloader configuration
- [ ] 1.6.1.3 - Ensure SELinux policy is configured
- [ ] 1.6.1.4 - Ensure the SELinux mode is enforcing or permissive
- [ ] 1.6.1.5 - Ensure the SELinux mode is enforcing
- [ ] 1.6.1.6 - Ensure no unconfined services exist
- [ ] 1.6.1.7 - Ensure SETroubleshoot is not installed
- [ ] 1.6.1.8 - Ensure the MCS Translation Service (mcstrans) is not installed
- [ ] 1.6.2.1 - Ensure SELinux or AppArmor is installed
- [ ] 1.6.2.2 - Ensure filesystem integrity checking is configured
- [ ] 1.6.2.3 - Ensure permissions on integrity check DB are configured

**Note:** Checks 1.6.1.x sind SELinux-spezifisch. Für Debian sind 1.3.1.x (AppArmor) bereits implementiert.

</details>

#### Priorität 2: Access Control & Authentication (5.x) - ✅ TEILWEISE ABGESCHLOSSEN (10/25 Checks)

<details>
<summary>sudo Configuration (5.2.x) - 10 Checks ✅ ABGESCHLOSSEN (v2.6.0)</summary>

- [x] 5.2.1 - Ensure sudo is installed
- [x] 5.2.2 - Ensure sudo commands use pty
- [x] 5.2.3 - Ensure sudo log file exists
- [x] 5.2.4 - Ensure users must provide password for privilege escalation
- [x] 5.2.5 - Ensure re-authentication for privilege escalation is not disabled globally
- [x] 5.2.6 - Ensure sudo authentication timeout is configured correctly
- [x] 5.2.7 - Ensure access to the su command is restricted
- [x] 5.2.8 - Ensure sudo log file permissions are configured
- [x] 5.2.9 - Ensure sudoers file is configured
- [x] 5.2.10 - Ensure sudo log file size is configured

</details>

<details>
<summary>Additional User Environment (5.5.x) - 5 Checks</summary>

- [ ] 5.5.1 - Ensure default user shell timeout is configured
- [ ] 5.5.2 - Ensure default user umask is configured
- [ ] 5.5.3 - Ensure tmout is configured
- [ ] 5.5.4 - Ensure default group for the root account is GID 0
- [ ] 5.5.5 - Ensure root is the only UID 0 account

</details>

<details>
<summary>User Accounts (5.6.x) - 10 Checks</summary>

- [ ] 5.6.1 - Ensure accounts in /etc/passwd use shadowed passwords
- [ ] 5.6.2 - Ensure password fields are not empty
- [ ] 5.6.3 - Ensure all groups in /etc/passwd exist in /etc/group
- [ ] 5.6.4 - Ensure shadow group is empty
- [ ] 5.6.5 - Ensure no duplicate UIDs exist
- [ ] 5.6.6 - Ensure no duplicate GIDs exist
- [ ] 5.6.7 - Ensure no duplicate user names exist
- [ ] 5.6.8 - Ensure no duplicate group names exist
- [ ] 5.6.9 - Ensure root PATH Integrity
- [ ] 5.6.10 - Ensure all interactive users home directories exist

**Note:** Viele dieser Checks überschneiden sich mit bereits implementierten 7.2.x Checks.

</details>

#### Priorität 3: Network Configuration (3.x) - ✅ ABGESCHLOSSEN (15/15 Checks)

<details>
<summary>Network Devices (3.1.x) - 3 Checks ✅ (v2.5.0)</summary>

- [x] 3.1.1 - Ensure wireless interfaces are disabled
- [x] 3.1.2 - Ensure Bluetooth is disabled
- [x] 3.1.3 - Ensure packet redirect sending is disabled

</details>

<details>
<summary>Network Protocols (3.2.x) - 5 Checks ✅ (v2.5.0)</summary>

- [x] 3.2.1 - Ensure DCCP is disabled
- [x] 3.2.2 - Ensure SCTP is disabled
- [x] 3.2.3 - Ensure RDS is disabled
- [x] 3.2.4 - Ensure TIPC is disabled
- [x] 3.2.5 - Ensure IPv6 is disabled

</details>

<details>
<summary>IPv6 & TCP Wrappers Configuration (3.4.x) - 7 Checks ✅ ABGESCHLOSSEN (v2.6.0)</summary>

- [x] 3.4.1 - Ensure IPv6 router advertisements are not accepted
- [x] 3.4.2 - Ensure IPv6 redirects are not accepted
- [x] 3.4.3 - Ensure IPv6 is disabled (if not needed)
- [x] 3.4.4 - Ensure TCP Wrappers is installed
- [x] 3.4.5 - Ensure /etc/hosts.allow is configured
- [x] 3.4.6 - Ensure /etc/hosts.deny is configured
- [x] 3.4.7 - Ensure permissions on /etc/hosts.allow are configured

</details>

#### Priorität 4: Warning Banners (1.8.x) - 6 Checks ✅ ABGESCHLOSSEN

<details>
<summary>Command Line Warning Banners - 6 Checks ✅</summary>

- [x] 1.8.1 - Ensure message of the day is configured properly
- [x] 1.8.2 - Ensure local login warning banner is configured properly
- [x] 1.8.3 - Ensure remote login warning banner is configured properly
- [x] 1.8.4 - Ensure permissions on /etc/motd are configured
- [x] 1.8.5 - Ensure permissions on /etc/issue are configured
- [x] 1.8.6 - Ensure permissions on /etc/issue.net are configured

</details>

#### Priorität 5: Additional Services & Daemons (2.2.x) - ~10 Checks

<details>
<summary>Special Purpose Services - 10 Checks</summary>

- [ ] 2.2.1 - Ensure time synchronization is in use (Meta-Check)
- [ ] 2.2.2 - Ensure X Window System is not installed
- [ ] 2.2.3 - Ensure Avahi Server is not installed
- [ ] 2.2.4 - Ensure CUPS is not installed
- [ ] 2.2.5 - Ensure DHCP Server is not installed
- [ ] 2.2.6 - Ensure LDAP server is not installed
- [ ] 2.2.7 - Ensure NFS is not installed
- [ ] 2.2.8 - Ensure DNS Server is not installed
- [ ] 2.2.9 - Ensure FTP Server is not installed
- [ ] 2.2.10 - Ensure HTTP server is not installed

**Note:** Viele dieser Checks überschneiden sich mit 2.1.x (bereits implementiert).

</details>

#### Phase 5 Zusammenfassung:
- **Neue Checks implementiert:** 36 Checks ✅
  - **v2.5.0 (19 Checks):**
    - Warning Banners (1.8.x): 6 Checks ✅
    - Software Updates (1.2.x): 2 Checks ✅
    - Network Devices (3.1.x): 3 Checks ✅
    - Network Protocols (3.2.x): 5 Checks ✅
    - Filesystem Configuration (1.1.3.x): 3 Checks ✅
  - **v2.6.0 (17 Checks) - Sprint 1:**
    - sudo Configuration (5.2.x): 10 Checks ✅
    - IPv6 & TCP Wrappers (3.4.x): 7 Checks ✅
- **Verbleibende Phase 5 Checks:** 30-40 Checks
- **Aktueller Stand:** 270 Checks (~67% Coverage)
- **Ziel nach Phase 5:** 300-310 Checks (~75% Coverage)
- **Fokus:** User Environment (5.5.x), Filesystem Integrity (1.5.x), Additional Services
- **Timeline:** v2.7.0 - v3.0.0

---

## 🎯 Langfristige Ziele

### Phase 6: Full CIS Compliance (v4.0.0+)
**Ziel:** 400+ Checks (~100% Coverage)

Verbleibende Bereiche für vollständige CIS Benchmark Konformität:

1. **Additional Filesystem Checks** (~10 Checks)
   - Erweiterte Mount-Optionen
   - Filesystem-spezifische Konfigurationen

2. **Process Hardening** (~15 Checks)
   - Core dumps
   - Address Space Layout Randomization (ASLR)
   - Prelink

3. **Additional Audit Rules** (~20 Checks)
   - Spezielle Audit-Regeln für kritische Dateien
   - Erweiterte System-Call Überwachung

4. **Remaining Service Checks** (~10 Checks)
   - Spezielle Dienste und Daemons
   - Service-spezifische Konfigurationen

5. **Network Stack Hardening** (~10 Checks)
   - Erweiterte TCP/IP Stack Parameter
   - Netzwerk-Protokoll-spezifische Einstellungen

6. **Documentation & Compliance Checks** (~5 Checks)
   - System-Dokumentation
   - Compliance-Berichte

**Finale Statistik bei 100% Implementierung:**
- Total: 400+ Checks
- Alle CIS Debian 12 Benchmark v1.1.0 Abschnitte abgedeckt
- Vollständige Auditierbarkeit
- Enterprise-ready

---

## 🤝 Mitwirken

Möchtest du bei der Implementierung helfen?

1. **Wähle einen Check-Bereich** aus der Roadmap
2. **Erstelle ein Issue** auf GitHub: "Implement CIS Check X.Y.Z"
3. **Implementiere den Check** nach dem bestehenden Muster
4. **Erstelle einen Pull Request** mit Tests

Siehe [CONTRIBUTING.md](CONTRIBUTING.md) für Details.

---

## 📊 Fortschritts-Tracker

| Kategorie | Implementiert | Gesamt | Prozent |
|-----------|---------------|--------|---------|
| 1. Initial Setup (Filesystems, AppArmor, Bootloader, GDM, Banners) | 62 | 120+ | 52% |
| 2. Services (Services, Time Sync, Job Schedulers) | 41 | 60+ | 68% |
| 3. Network | 19 | 20+ | 95% |
| 4. Firewall | 22 | 40+ | 55% |
| 5. Access Control (SSH & PAM) | 36 | 100+ | 36% |
| 6. Logging/Auditing | 51 | 80+ | 64% |
| 7. System Maintenance | 22 | 30+ | 73% |
| **TOTAL** | **253** | **400+** | **~63%** |

---

## 🎯 Nächste Releases

### v1.1.0 ✅ ABGESCHLOSSEN (2025-11-05)
- SSH Configuration Checks (22 Checks)
- **Gesamt:** 36 Checks

### v1.2.0 ✅ ABGESCHLOSSEN (2025-11-05)
- Filesystem Partition Checks (26 Checks)
- **Gesamt:** 62 Checks

### v1.3.0 ✅ ABGESCHLOSSEN (2025-11-05)
- Additional Services Checks (22 Checks)
- Network Kernel Parameters (11 Checks)
- Filesystem Kernel Modules (9 Checks)
- **Gesamt:** 102 Checks (~25% Coverage)

### v1.4.0 ✅ ABGESCHLOSSEN (2025-11-05)
- System Maintenance File Permissions (9 Checks)
- User/Group Configuration Checks (8 Checks)
- **Gesamt:** 119 Checks (~30% Coverage)

### v1.5.0 ✅ ABGESCHLOSSEN (2025-11-05)
- System Logging - systemd-journald (5 Checks)
- System Logging - rsyslog (6 Checks)
- **Gesamt:** 130 Checks (~32% Coverage)

### v1.6.0 ✅ ABGESCHLOSSEN (2025-11-05)
- Audit Data Retention (6.2.2.x - 4 Checks)
- **Gesamt:** 134 Checks (~33% Coverage)

### v1.7.0 ✅ ABGESCHLOSSEN (2025-11-05)
- Integrity Checking (6.3.x - 3 Checks)
- **Gesamt:** 137 Checks (~34% Coverage)

### v1.8.0 ✅ ABGESCHLOSSEN (2025-11-05)
- Audit File Access (6.2.4.x - 8 weitere Checks)
- **Gesamt:** 145 Checks (~36% Coverage)

### v1.9.0 ✅ ABGESCHLOSSEN (2025-11-05)
- Audit Rules (6.2.3.x - 21 Checks)
- **Gesamt:** 166 Checks (~41% Coverage)

### v2.0.0 ✅ ABGESCHLOSSEN (2025-11-06)
- PAM & Password Policy (5.3.x & 5.4.x - 14 Checks)
- **Gesamt:** 180 Checks (~45% Coverage)

### v2.1.0 ✅ ABGESCHLOSSEN (2025-11-06)
- Firewall Configuration (4.x - 22 Checks)
  - UFW (4.2.x - 7 Checks)
  - nftables (4.3.x - 10 Checks)
  - iptables (4.4.x - 5 Checks)
- **Gesamt:** 202 Checks (~50% Coverage)

### v2.2.0 ✅ ABGESCHLOSSEN (2025-11-06)
- AppArmor Configuration (1.3.1.x - 4 Checks)
- Bootloader Security (1.4.x - 2 Checks)
- **Gesamt:** 208 Checks (~52% Coverage)

### v2.3.0 ✅ ABGESCHLOSSEN (2025-11-06)
- GNOME Display Manager (1.7.x - 10 Checks)
- Time Synchronization (2.3.x - 7 Checks)
- **Gesamt:** 225 Checks (~56% Coverage)

### v2.4.0 ✅ ABGESCHLOSSEN (2025-11-06)
- Job Schedulers (2.4.x - 9 Checks)
- **Gesamt:** 234 Checks (~58% Coverage)

### v2.5.0 ✅ ABGESCHLOSSEN (2025-11-06)
- Warning Banners (1.8.x - 6 Checks)
- Software Updates (1.2.x - 2 Checks)
- Network Devices (3.1.x - 3 Checks)
- Network Protocols (3.2.x - 5 Checks)
- Filesystem Configuration (1.1.3.x - 3 Checks)
- **Gesamt:** 253 Checks (~63% Coverage)

### v2.6.0 ✅ ABGESCHLOSSEN (2025-11-06) - Sprint 1
- sudo Configuration (5.2.x - 10 Checks)
  - Neue SudoAuditor Klasse
  - Privilege Escalation Controls
  - sudo Logging & Audit Konfiguration
  - NOPASSWD Restrictions
  - su Command Access Restrictions
- IPv6 & Network Hardening (3.4.x - 7 Checks)
  - IPv6 Router Advertisements & Redirects
  - TCP Wrappers Configuration
  - hosts.allow/hosts.deny Configuration & Permissions
- **Gesamt:** 270 Checks (~67% Coverage)

### v2.7.0 (In Arbeit) - Sprint 2
- User Environment (5.5.x - 5 Checks)
- Filesystem Integrity (1.5.x - 4 Checks)
- **Geplant gesamt:** 279+ Checks (~70% Coverage)

### v3.0.0 (Geplant)
- Weitere CIS Checks (Phase 5 Abschluss)
- **Geplant gesamt:** 300+ Checks (~75% Coverage)

---

**Status aktualisiert:** 2025-11-06
**Nächstes Update:** Bei jedem neuen Release
