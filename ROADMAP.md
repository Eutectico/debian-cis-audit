# CIS Benchmark Implementation Roadmap

## 📊 Übersicht

- **CIS Debian Linux 12 Benchmark:** v1.1.0 (09-26-2024)
- **Gesamt Checks im Benchmark:** 400+
- **Aktuell implementiert:** 134 (~33%)
- **Status:** Phase 2 ABGESCHLOSSEN! ✅ | Phase 3 System Maintenance ABGESCHLOSSEN! ✅ | Phase 3 System Logging ABGESCHLOSSEN! ✅ | Phase 3 Audit Data Retention ABGESCHLOSSEN! ✅

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

## 🔄 Phase 3: Medium Priority ✅ TEILWEISE ABGESCHLOSSEN

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
- [ ] 6.2.3.x - Audit Rules (21 Checks)
- [ ] 6.2.4.x - Audit File Access (erweitern, 9 weitere Checks)
- [ ] 6.3.x - Integrity Checking (3 Checks)

### PAM & Password Policy (5.3.x & 5.4.x)
- [ ] 5.3.x - PAM Configuration (40+ Checks)
- [ ] 5.4.x - User Accounts (20+ Checks)

---

## 🚀 Phase 4: Advanced Features (Zukunft)

### Firewall Configuration (4.x)
- [ ] 4.2.x - UncomplicatedFirewall (7 Checks)
- [ ] 4.3.x - nftables (10 Checks)
- [ ] 4.4.x - iptables (15 Checks)

### AppArmor & Bootloader (1.3.x & 1.4.x)
- [ ] 1.3.1.x - AppArmor (4 Checks)
- [ ] 1.4.x - Bootloader (2 Checks)

### GNOME Display Manager (1.7.x)
- [ ] 1.7.x - GDM Configuration (10 Checks)

### Time Synchronization (2.3.x)
- [ ] 2.3.x - Time Sync (7 Checks)

### Job Schedulers (2.4.x)
- [ ] 2.4.x - Cron & At (9 Checks)

---

## 📈 Implementierungs-Strategie

### Kurzfristig (v1.1.0 - v1.3.0) ✅ ABGESCHLOSSEN
1. **SSH Configuration** (22 Checks) - Kritisch für Security ✅
2. **Filesystem Partitions** (26 Checks) - Wichtig für Availability ✅
3. **Filesystem Kernel Modules** (9 Checks) - Security ✅
4. **Additional Services** (22 Checks) - Attack Surface Reduction ✅
5. **Network Kernel Parameters** (11 Checks) - Network Security ✅

**Checks nach Phase 2:** 102 Checks (~25%)

### Mittelfristig (v1.4.0 - v2.0.0)
1. **System File Permissions** (erweitern auf 13 Checks)
2. **Logging & Auditing** (erweitern auf 80+ Checks)
3. **PAM & Password Policy** (60+ Checks)

**Geschätzte Checks nach Phase 3:** ~180 Checks (~45%)

### Langfristig (v2.1.0+)
1. **Firewall Configuration** (32 Checks)
2. **AppArmor & Bootloader** (6 Checks)
3. **Time Synchronization** (7 Checks)
4. **Job Schedulers** (9 Checks)
5. **GNOME Display Manager** (10 Checks)
6. **Alle verbleibenden Checks**

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
| 1. Initial Setup (Filesystems) | 35 | 100+ | 35% |
| 2. Services | 25 | 40+ | 62% |
| 3. Network | 11 | 20+ | 55% |
| 4. Firewall | 0 | 40+ | 0% |
| 5. Access Control (SSH) | 22 | 100+ | 22% |
| 6. Logging/Auditing | 19 | 80+ | 24% |
| 7. System Maintenance | 22 | 30+ | 73% |
| **TOTAL** | **134** | **400+** | **~33%** |

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

### v2.0.0 (Geplant)
- PAM & Password Policy (5.3.x & 5.4.x)
- Audit Rules (6.2.3.x)
- **Geplant gesamt:** 180+ Checks

---

**Status aktualisiert:** 2025-11-05
**Nächstes Update:** Bei jedem neuen Release
