# CIS Benchmark Implementation Roadmap

## 📊 Übersicht

- **CIS Debian Linux 12 Benchmark:** v1.1.0 (09-26-2024)
- **Gesamt Checks im Benchmark:** 400+
- **Aktuell implementiert:** 62 (~15%)
- **Status:** Aktiv in Entwicklung - Phase 2 läuft

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

## 🎯 Phase 2: High Priority Checks (Geplant)

### Kritische Sicherheits-Checks

#### 1. Initial Setup - Filesystem (1.1.x)
**Priorität: HOCH** - 36+ Checks

<details>
<summary>Filesystem Kernel Modules (1.1.1.x) - 10 Checks (TODO)</summary>

- [ ] 1.1.1.1 - Ensure cramfs kernel module is not available
- [ ] 1.1.1.2 - Ensure freevxfs kernel module is not available
- [ ] 1.1.1.3 - Ensure hfs kernel module is not available
- [ ] 1.1.1.4 - Ensure hfsplus kernel module is not available
- [ ] 1.1.1.5 - Ensure jffs2 kernel module is not available
- [ ] 1.1.1.6 - Ensure overlayfs kernel module is not available
- [ ] 1.1.1.7 - Ensure squashfs kernel module is not available
- [ ] 1.1.1.8 - Ensure udf kernel module is not available
- [ ] 1.1.1.9 - Ensure usb-storage kernel module is not available
- [ ] 1.1.1.10 - Ensure unused filesystems kernel modules are not available

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

#### 3. Additional Services (2.1.x)
**Priorität: HOCH** - 22 Checks

<details>
<summary>Server Services - 22 Checks</summary>

- [ ] 2.1.1 - Ensure autofs services are not in use
- [ ] 2.1.2 - Ensure avahi daemon services are not in use
- [ ] 2.1.3 - Ensure dhcp server services are not in use
- [ ] 2.1.4 - Ensure dns server services are not in use
- [ ] 2.1.5 - Ensure dnsmasq services are not in use
- [ ] 2.1.6 - Ensure ftp server services are not in use
- [ ] 2.1.7 - Ensure ldap server services are not in use
- [ ] 2.1.8 - Ensure message access server services are not in use
- [ ] 2.1.9 - Ensure network file system services are not in use
- [ ] 2.1.10 - Ensure nis server services are not in use
- [ ] 2.1.11 - Ensure print server services are not in use
- [ ] 2.1.12 - Ensure rpcbind services are not in use
- [ ] 2.1.13 - Ensure rsync services are not in use
- [ ] 2.1.14 - Ensure samba file server services are not in use
- [ ] 2.1.15 - Ensure snmp services are not in use
- [ ] 2.1.16 - Ensure tftp server services are not in use
- [ ] 2.1.17 - Ensure web proxy server services are not in use
- [ ] 2.1.18 - Ensure web server services are not in use
- [ ] 2.1.19 - Ensure xinetd services are not in use
- [ ] 2.1.20 - Ensure X window server services are not in use
- [ ] 2.1.21 - Ensure mail transfer agent is configured for local-only mode
- [ ] 2.1.22 - Ensure only approved services are listening on a network interface

</details>

#### 4. Network Kernel Parameters (3.3.x)
**Priorität: HOCH** - 11 Checks

<details>
<summary>Network Configuration - 11 Checks</summary>

- [ ] 3.3.1 - Ensure ip forwarding is disabled
- [ ] 3.3.2 - Ensure packet redirect sending is disabled
- [ ] 3.3.3 - Ensure bogus icmp responses are ignored
- [ ] 3.3.4 - Ensure broadcast icmp requests are ignored
- [ ] 3.3.5 - Ensure icmp redirects are not accepted
- [ ] 3.3.6 - Ensure secure icmp redirects are not accepted
- [ ] 3.3.7 - Ensure reverse path filtering is enabled
- [ ] 3.3.8 - Ensure source routed packets are not accepted
- [ ] 3.3.9 - Ensure suspicious packets are logged
- [ ] 3.3.10 - Ensure tcp syn cookies is enabled
- [ ] 3.3.11 - Ensure ipv6 router advertisements are not accepted

</details>

---

## 🔄 Phase 3: Medium Priority (Zukunft)

### System Maintenance (7.x) - Erweitern
- [ ] 7.1.2 - Ensure permissions on /etc/passwd- are configured
- [ ] 7.1.3 - Ensure permissions on /etc/group are configured
- [ ] 7.1.4 - Ensure permissions on /etc/group- are configured
- [ ] 7.1.6 - Ensure permissions on /etc/shadow- are configured
- [ ] 7.1.7 - Ensure permissions on /etc/gshadow are configured
- [ ] 7.1.8 - Ensure permissions on /etc/gshadow- are configured
- [ ] 7.1.9 - Ensure permissions on /etc/shells are configured
- [ ] 7.1.10 - Ensure permissions on /etc/security/opasswd are configured
- [ ] 7.1.12 - Ensure no files or directories without an owner and a group exist
- [ ] 7.2.1 - Ensure accounts in /etc/passwd use shadowed passwords
- [ ] 7.2.3 - Ensure all groups in /etc/passwd exist in /etc/group
- [ ] 7.2.4 - Ensure shadow group is empty
- [ ] 7.2.6 - Ensure no duplicate GIDs exist
- [ ] 7.2.7 - Ensure no duplicate user names exist
- [ ] 7.2.8 - Ensure no duplicate group names exist
- [ ] 7.2.9 - Ensure local interactive user home directories are configured
- [ ] 7.2.10 - Ensure local interactive user dot files access is configured

### Logging & Auditing (6.x) - Erweitern
- [ ] 6.1.x - System Logging (20+ Checks)
- [ ] 6.2.2.x - Audit Data Retention (4 Checks)
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

### Kurzfristig (v1.1.0 - v1.3.0)
1. **SSH Configuration** (22 Checks) - Kritisch für Security
2. **Filesystem Partitions** (35 Checks) - Wichtig für Availability
3. **Additional Services** (22 Checks) - Attack Surface Reduction

**Geschätzte Checks nach Phase 2:** ~93 Checks (~23%)

### Mittelfristig (v1.4.0 - v2.0.0)
4. **Network Configuration** (erweitern auf 11 Checks)
5. **System File Permissions** (erweitern auf 13 Checks)
6. **Logging & Auditing** (erweitern auf 80+ Checks)

**Geschätzte Checks nach Phase 3:** ~180 Checks (~45%)

### Langfristig (v2.1.0+)
7. **PAM & Password Policy** (60+ Checks)
8. **Firewall Configuration** (32 Checks)
9. **Alle verbleibenden Checks**

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
| 1. Initial Setup (Filesystems) | 26 | 100+ | 26% |
| 2. Services | 3 | 40+ | 7.5% |
| 3. Network | 2 | 20+ | 10% |
| 4. Firewall | 0 | 40+ | 0% |
| 5. Access Control (SSH) | 22 | 100+ | 22% |
| 6. Logging/Auditing | 4 | 80+ | 5% |
| 7. System Maintenance | 5 | 20+ | 25% |
| **TOTAL** | **62** | **400+** | **~15%** |

---

## 🎯 Nächste Releases

### v1.1.0 ✅ ABGESCHLOSSEN (2025-11-05)
- SSH Configuration Checks (22 Checks)
- **Gesamt:** 36 Checks

### v1.2.0 ✅ ABGESCHLOSSEN (2025-11-05)
- Filesystem Partition Checks (26 Checks)
- **Gesamt:** 62 Checks

### v1.3.0 (Geplant)
- Additional Services Checks (22 Checks)
- **Geplant gesamt:** 84 Checks

---

**Status aktualisiert:** 2025-11-05
**Nächstes Update:** Bei jedem neuen Release
