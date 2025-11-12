# Debian CIS Benchmark Audit Script

[![CI](https://github.com/Eutectico/debian-cis-audit/workflows/CI/badge.svg)](https://github.com/Eutectico/debian-cis-audit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-Debian%2012%20v1.1.0-green.svg)](https://www.cisecurity.org/benchmark/debian_linux)

Ein umfassendes Python-Audit-Skript zur Überprüfung der Einhaltung der CIS Debian Linux 12 Benchmark v1.1.0.

**Aktueller Status:** 374 Checks implementiert | 400+ Checks im Benchmark | Phase 6 läuft (~93% Coverage)

> **⚠️ Wichtig:** Dieses Skript erkennt kritische Fehlkonfigurationen in `auditd.conf`, die zu Systemausfällen durch volle Partitionen führen können!

## 🚀 Features

### 🔍 Hauptprüfungen

Das Skript führt folgende Sicherheitsprüfungen durch:

1. **Auditd-Konfiguration**
   - Installation und Aktivierung von auditd
   - Kritische Fehlkonfigurationen in `/etc/audit/auditd.conf`
   - Prüfung auf Verfügbarkeitsprobleme (z.B. volle Partition durch falsche Log-Rotation)
   - Berechtigungen der Audit-Log-Dateien

2. **Dateisystem-Berechtigungen**
   - `/etc/passwd` Berechtigungen
   - `/etc/shadow` Berechtigungen
   - World-writable Dateien
   - SUID/SGID Dateien

3. **System-Services**
   - Unnötige Dienste (Avahi, CUPS, RPC, etc.)
   - Service-Status und Aktivierung

4. **Netzwerk-Konfiguration**
   - IP-Forwarding
   - ICMP-Redirects
   - Weitere Netzwerk-Parameter

5. **Benutzer- und Gruppen-Konfiguration**
   - Leere Passwörter
   - Doppelte UIDs/GIDs
   - Benutzer-Home-Verzeichnisse

### ⚠️ Kritische Auditd-Checks

Das Skript prüft speziell auf Fehlkonfigurationen in `auditd.conf`, die zu Verfügbarkeitsproblemen führen können:

<details>
<summary>Klicken für Details</summary>

- **`max_log_file_action = keep_logs`**: Führt dazu, dass alte Logs NICHT gelöscht werden und die Partition voll läuft
- **Zu kleine `num_logs`**: Zu wenig Log-Rotationen
- **Zu kleiner `max_log_file`**: Kann zu häufiger Rotation führen
- **Zu kleiner `space_left`**: Warnung kommt zu spät
- **`admin_space_left_action = halt`**: System wird angehalten (Verfügbarkeitsproblem)
- **`disk_full_action = halt`**: System wird bei voller Disk angehalten

</details>

## 📦 Installation

### Voraussetzungen

- Python 3.6 oder höher
- Root-Rechte für vollständige Prüfungen
- Debian 12 (Bookworm) oder kompatibles System

### Abhängigkeiten

Das Skript verwendet nur Python-Standardbibliotheken. Keine zusätzlichen Pakete erforderlich.

```bash
# Repository klonen
git clone https://github.com/Eutectico/debian-cis-audit.git
cd debian-cis-audit

# Skript ausführbar machen
chmod +x debian_cis_audit.py

# Optional: Installation mit pip
pip install -e .
```

## 💻 Verwendung

### Basis-Verwendung

```bash
# Mit Root-Rechten ausführen für vollständige Prüfungen
sudo python3 debian_cis_audit.py
```

### Optionen

```bash
# JSON-Report generieren
sudo python3 debian_cis_audit.py --format json --output report.json

# Console-Report in Datei speichern
sudo python3 debian_cis_audit.py --output report.txt

# Hilfe anzeigen
python3 debian_cis_audit.py --help
```

### Ausgabeformate

#### Console (Standard)

Zeigt einen übersichtlichen, farbcodierten Report direkt in der Konsole:

```
================================================================================
DEBIAN CIS BENCHMARK AUDIT REPORT
Generated: 2025-11-04 14:30:00
================================================================================

SUMMARY:
  Total Checks:  20
  ✓ Passed:      15
  ✗ Failed:      3
  ⚠ Warnings:    2
  - Skipped:     0
  ! Errors:      0

--------------------------------------------------------------------------------
FAIL (3 checks)
--------------------------------------------------------------------------------

✗ [6.2.1.3] Check auditd.conf for availability issues
   Severity: CRITICAL
   Kritische Fehlkonfigurationen in auditd.conf gefunden
   Details:
     - max_log_file_action=keep_logs: KRITISCH! Dies führt dazu, dass alte Logs
       NICHT gelöscht werden und die Partition voll laufen kann.
     - disk_full_action=halt: WARNUNG! System wird angehalten wenn Disk voll ist.
   Remediation: Bearbeiten Sie /etc/audit/auditd.conf und passen Sie die
                Konfiguration an
...
```

#### JSON

Maschinenlesbares Format für weitere Verarbeitung:

```json
{
  "generated": "2025-11-04T14:30:00",
  "benchmark": "CIS Debian Linux 12 Benchmark v1.1.0",
  "summary": {
    "total": 20,
    "pass": 15,
    "fail": 3,
    "warning": 2,
    "skip": 0,
    "error": 0
  },
  "results": [
    {
      "check_id": "6.2.1.3",
      "title": "Check auditd.conf for availability issues",
      "status": "FAIL",
      "severity": "CRITICAL",
      "message": "Kritische Fehlkonfigurationen in auditd.conf gefunden",
      "details": "...",
      "remediation": "...",
      "timestamp": "2025-11-04T14:30:00.123456"
    }
  ]
}
```

## 🛠️ Monitoring Integration

Das Skript kann in verschiedene Monitoring-Systeme integriert werden:

```bash
# Prometheus Metrics
python3 monitoring_integration_example.py --format prometheus

# Nagios/Icinga Check
python3 monitoring_integration_example.py --format nagios

# Zabbix LLD
python3 monitoring_integration_example.py --format zabbix
```

## ⚙️ Beispiel: Auditd.conf Problem

Die mitgelieferte `auditd.conf` enthält folgende kritische Fehlkonfiguration:

```ini
max_log_file_action = keep_logs  # ❌ PROBLEM!
disk_full_action = halt           # ❌ PROBLEM!
admin_space_left_action = halt    # ❌ PROBLEM!
```

### Problem-Analyse

1. **`max_log_file_action = keep_logs`**
   - Alte Logs werden NICHT automatisch gelöscht
   - Logs sammeln sich an und füllen die Partition
   - Führt zu Systemausfällen wenn `/var` voll läuft

2. **`disk_full_action = halt`**
   - System wird komplett angehalten wenn Partition voll ist
   - Schwerwiegendes Verfügbarkeitsproblem

3. **`admin_space_left_action = halt`**
   - System wird angehalten wenn `admin_space_left` erreicht wird
   - Kann zu ungeplanten Ausfällen führen

### Empfohlene Lösung

```ini
# Bessere Konfiguration:
max_log_file_action = ROTATE      # ✓ Rotiert automatisch
num_logs = 10                      # ✓ Behält 10 Rotationen
max_log_file = 100                 # ✓ 100 MB pro Log-Datei
space_left = 500                   # ✓ Genug Puffer
space_left_action = syslog         # ✓ Warnung per Syslog
admin_space_left = 100             # ✓ Kritischer Schwellwert
admin_space_left_action = single   # ✓ Single-User Mode statt halt
disk_full_action = rotate          # ✓ Rotiere statt anhalten
```

## 🤝 Contributing

Wir freuen uns über Beiträge! Bitte lesen Sie [CONTRIBUTING.md](CONTRIBUTING.md) für Details.

### Neue Checks hinzufügen

Das Skript ist modular aufgebaut. Um neue Checks hinzuzufügen:

1. Erweitern Sie eine bestehende Auditor-Klasse oder erstellen Sie eine neue:

```python
class MyCustomAuditor(BaseAuditor):
    def check_my_custom_setting(self):
        # Ihre Prüflogik hier
        if condition_failed:
            self.reporter.add_result(AuditResult(
                check_id="X.Y.Z",
                title="My Custom Check",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Check failed",
                remediation="How to fix"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="X.Y.Z",
                title="My Custom Check",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="Check passed"
            ))

    def run_all_checks(self):
        self.check_my_custom_setting()
```

2. Fügen Sie den Auditor in `DebianCISAudit.run_audit()` hinzu:

```python
def run_audit(self):
    # ... existing code ...

    print("[*] Running Custom Checks...")
    custom_auditor = MyCustomAuditor(self.reporter)
    custom_auditor.run_all_checks()
```

Siehe [CONTRIBUTING.md](CONTRIBUTING.md) für weitere Details.

## 📋 CIS Benchmark Konformität

**Status:** 374 von 400+ Checks implementiert (~93%) | **Phase 6 läuft 🚀**

Dieses Skript implementiert aktuell ausgewählte Checks aus folgenden CIS Benchmark-Abschnitten:

<details>
<summary>✅ Implementierte Checks (355) - Klicken zum Anzeigen</summary>

- **1.1.1.x** - Filesystem Kernel Modules (9 Checks)
- **1.1.2.x** - Filesystem Partitions (26 Checks)
- **1.1.3.x** - Filesystem Configuration (3 Checks)
- **1.1.4-18** - Extended Filesystem Security (18 Checks) ✨ ERWEITERT v3.4.0
- **1.2.x** - Software Updates (2 Checks)
- **1.3.1.x** - AppArmor Configuration (4 Checks)
- **1.4.x** - Bootloader Security (2 Checks)
- **1.5.x** - Filesystem Integrity (4 Checks)
- **1.6.1.x** - Process Hardening & Kernel Security (10 Checks) ✨ NEU v3.0.0
- **1.7.x** - GNOME Display Manager (10 Checks)
- **1.8.x** - Warning Banners (6 Checks)
- **2.1.x** - Server Services (24 Checks) ✨ ERWEITERT v3.5.0
- **2.2.1** - Time Synchronization Meta-Check (1 Check) ✨ NEU v2.8.0
- **2.3.x** - Time Synchronization (7 Checks)
- **2.4.x** - Job Schedulers (9 Checks)
- **3.1.x** - Network Devices (3 Checks)
- **3.2.x** - Network Protocols (5 Checks)
- **3.3.x** - Network Kernel Parameters (11 Checks)
- **3.5.x** - Additional Network Hardening (7 Checks) ✨ NEU v3.5.0
- **3.4.x** - IPv6 & TCP Wrappers (7 Checks) ✨ NEU v2.6.0
- **4.2.x** - UncomplicatedFirewall (7 Checks)
- **4.3.x** - nftables (10 Checks)
- **4.4.x** - iptables (5 Checks)
- **5.1.x** - SSH Server Configuration (22 Checks)
- **5.2.x** - sudo Configuration (10 Checks)
- **5.3.x** - PAM Configuration (5 Checks)
- **5.4.x** - User Accounts and Environment (9 Checks)
- **5.5.x** - User Environment & Root Security (5 Checks)
- **5.7.x** - Additional User Security (4 Checks) ✨ NEU v3.5.0
- **5.6.x** - User Account Validation (2 Checks) ✨ NEU v2.8.0
- **6.1.1.x** - systemd-journald Configuration (5 Checks)
- **6.1.2.x** - rsyslog Configuration (6 Checks)
- **6.2.1.x** - Auditd Installation & Service (2 Checks)
- **6.2.2.x** - Audit Data Retention (4 Checks)
- **6.2.3.x** - Audit Rules (36 Checks) ✨ ERWEITERT v3.3.0
- **6.2.4.x** - Audit File Access (9 Checks)
- **6.3.x** - Integrity Checking (3 Checks)
- **7.1.x** - System File Permissions (12 Checks)
- **7.2.x** - Local User and Group Settings (12 Checks) ✨ ERWEITERT v3.5.0
- **8.1.x** - Docker Security (4 Checks) 🆕 v3.6.0
- **8.2.x** - Podman & Container Namespaces (2 Checks) 🆕 v3.6.0
- **8.3.x** - Virtualization Security (libvirt/KVM) (6 Checks) 🆕 v3.6.0
- **Weitere** - Legacy Checks (1 Check)

</details>

> 📝 **Hinweis:** Dies sind die aktuell implementierten Checks. Siehe [ROADMAP.md](ROADMAP.md) für die vollständige Liste aller geplanten 400+ Checks aus dem CIS Benchmark.
>
> 🚀 **Phase 6 läuft - v3.6.0!** 355 Checks implementiert - **89% Coverage erreicht!**
> - **Neu in v3.6.0:** 12 Container & Virtualization Security Checks (8.x)
>   - Docker security (daemon config, socket permissions, content trust)
>   - Podman rootless containers and user namespaces
>   - libvirt/KVM virtualization security (QEMU, SASL, TLS, KVM module)
> - **Neu in v3.5.0:** 15 Service Security & Network Hardening Checks (2.1.23-24, 3.5.x, 5.7.x, 7.2.11-12)
>   - Service security (Postfix, unnecessary packages)
>   - Network hardening (core dumps, packet redirects, TCP SYN cookies, IPv6 RA)
>   - Network protocols (uncommon protocols, wireless interfaces)
>   - User account security (system accounts, default accounts, inactive passwords, shell timeout)
>   - Path and home directory integrity
> - **Phase 6 Priorität 6 abgeschlossen!** Container & Virtualization Security implementiert
> - **Nächster Schritt:** Crypto Policies & Extended Log Monitoring

## 📊 Severity Levels

- **CRITICAL**: Kritische Sicherheits- oder Verfügbarkeitsprobleme
- **HIGH**: Wichtige Sicherheitsprobleme
- **MEDIUM**: Mittlere Sicherheitsprobleme
- **LOW**: Kleinere Konfigurationsprobleme
- **INFO**: Informative Meldungen

## ⚖️ Rechtliche Hinweise

Dieses Skript basiert auf der CIS Debian Linux 12 Benchmark v1.1.0. Die CIS Benchmarks sind urheberrechtlich geschützt durch das Center for Internet Security (CIS).

**Wichtig:**
- Dieses Skript ist ein unabhängiges Werkzeug und wird nicht offiziell von CIS unterstützt oder zertifiziert
- Benutzer sollten die offizielle CIS Benchmark von https://www.cisecurity.org/ beziehen
- CIS Benchmark PDFs dürfen NICHT auf Drittanbieter-Seiten gehostet werden

## 📄 Lizenz

MIT License - Siehe [LICENSE](LICENSE) für Details

## 👥 Contributors

Erstellt basierend auf CIS Debian Linux 12 Benchmark v1.1.0 (09-26-2024)

Siehe [Contributors](https://github.com/Eutectico/debian-cis-audit/graphs/contributors) für alle Mitwirkenden.

## 🐛 Support

- **Bug Reports:** [GitHub Issues](https://github.com/Eutectico/debian-cis-audit/issues)
- **Feature Requests:** [GitHub Issues](https://github.com/Eutectico/debian-cis-audit/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Eutectico/debian-cis-audit/discussions)

## ☕ Support This Project

Wenn dir dieses Projekt hilft, kannst du mir gerne einen Kaffee spendieren!

<a href="https://www.buymeacoffee.com/Eutectico" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

## 📚 Ressourcen

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Debian Security](https://www.debian.org/security/)
- [ROADMAP.md](ROADMAP.md) - 🗺️ **Implementation Roadmap** (400+ Checks geplant)
- [QUICK_START.md](QUICK_START.md) - Schnellstart-Anleitung
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution Guidelines

## ⭐ Star History

Wenn dieses Projekt hilfreich ist, gib ihm einen Stern! ⭐

---

Made with ❤️ by the community
