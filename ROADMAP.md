# CIS Benchmark Implementation Roadmap

## 📊 Übersicht

- **CIS Debian Linux 12 Benchmark:** v1.1.0 (09-26-2024)
- **Gesamt Checks im Benchmark:** 400+
- **Aktuell implementiert:** 208 (~52%)
- **Status:** Phase 2 ABGESCHLOSSEN! ✅ | Phase 3 ABGESCHLOSSEN! ✅ | Phase 4 Firewall ABGESCHLOSSEN! ✅ | Phase 4 AppArmor & Bootloader ABGESCHLOSSEN! ✅

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

### GNOME Display Manager (1.7.x)
- [ ] 1.7.x - GDM Configuration (10 Checks)

### Time Synchronization (2.3.x)
- [ ] 2.3.x - Time Sync (7 Checks)

### Job Schedulers (2.4.x)
- [ ] 2.4.x - Cron & At (9 Checks)

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

### 🎯 Phase 4: Advanced Features (v2.1.0+) - TEILWEISE ABGESCHLOSSEN
**28 Checks implementiert:**
1. **Firewall Configuration (4.x)** (22 Checks) - UFW, nftables, iptables ✅
2. **AppArmor & Bootloader (1.3.x, 1.4.x)** (6 Checks) - MAC & Bootloader Security ✅

**Nächste Priorität:**
3. **Time Synchronization (2.3.x)** (7 Checks)
4. **Job Schedulers (2.4.x)** (9 Checks)
5. **GNOME Display Manager (1.7.x)** (10 Checks)
6. **Alle verbleibenden Checks**

**Checks nach Phase 4 (AppArmor & Bootloader):** 208 Checks (~52%)
**Ziel:** 400+ Checks (~100%)

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
| 1. Initial Setup (Filesystems, AppArmor, Bootloader) | 41 | 100+ | 41% |
| 2. Services | 25 | 40+ | 62% |
| 3. Network | 11 | 20+ | 55% |
| 4. Firewall | 22 | 40+ | 55% |
| 5. Access Control (SSH & PAM) | 36 | 100+ | 36% |
| 6. Logging/Auditing | 51 | 80+ | 64% |
| 7. System Maintenance | 22 | 30+ | 73% |
| **TOTAL** | **208** | **400+** | **~52%** |

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

### v2.3.0 (Geplant)
- Time Synchronization (2.3.x - 7 Checks)
- Job Schedulers (2.4.x - 9 Checks)
- **Geplant gesamt:** 224+ Checks

---

**Status aktualisiert:** 2025-11-06
**Nächstes Update:** Bei jedem neuen Release
