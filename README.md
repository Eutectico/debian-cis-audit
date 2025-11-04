# Debian CIS Benchmark Audit Script

[![CI](https://github.com/YOUR-USERNAME/debian-cis-audit/workflows/CI/badge.svg)](https://github.com/YOUR-USERNAME/debian-cis-audit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-Debian%2012%20v1.1.0-green.svg)](https://www.cisecurity.org/benchmark/debian_linux)

Ein umfassendes Python-Audit-Skript zur Überprüfung der Einhaltung der CIS Debian Linux 12 Benchmark v1.1.0.

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
git clone https://github.com/YOUR-USERNAME/debian-cis-audit.git
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

Dieses Skript implementiert ausgewählte Checks aus folgenden CIS Benchmark-Abschnitten:

<details>
<summary>Implementierte Checks anzeigen</summary>

- **6.2** - Configure System Accounting (auditd)
  - 6.2.1.1 - Ensure auditd is installed
  - 6.2.1.2 - Ensure auditd service is enabled
  - 6.2.1.3 - Custom: Check auditd.conf for availability issues
  - 6.2.4.1 - Ensure audit log files mode is configured

- **7.1** - System File Permissions
  - 7.1.1 - Ensure permissions on /etc/passwd are configured
  - 7.1.5 - Ensure permissions on /etc/shadow are configured
  - 7.1.11 - Ensure world writable files are secured

- **7.2** - Local User and Group Settings
  - 7.2.2 - Ensure /etc/shadow password fields are not empty
  - 7.2.5 - Ensure no duplicate UIDs exist

- **2.2** - Service Configuration
  - 2.2.1 - Ensure Avahi Server is not installed
  - 2.2.4 - Ensure CUPS is not installed
  - 2.2.7 - Ensure RPC is not installed

- **3.x** - Network Configuration
  - 3.1.1 - Ensure IP forwarding is disabled
  - 3.2.2 - Ensure ICMP redirects are not accepted

</details>

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

Siehe [Contributors](https://github.com/YOUR-USERNAME/debian-cis-audit/graphs/contributors) für alle Mitwirkenden.

## 🐛 Support

- **Bug Reports:** [GitHub Issues](https://github.com/YOUR-USERNAME/debian-cis-audit/issues)
- **Feature Requests:** [GitHub Issues](https://github.com/YOUR-USERNAME/debian-cis-audit/issues)
- **Discussions:** [GitHub Discussions](https://github.com/YOUR-USERNAME/debian-cis-audit/discussions)

## 📚 Ressourcen

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Debian Security](https://www.debian.org/security/)
- [QUICK_START.md](QUICK_START.md) - Schnellstart-Anleitung
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution Guidelines

## ⭐ Star History

Wenn dieses Projekt hilfreich ist, gib ihm einen Stern! ⭐

---

Made with ❤️ by the community
