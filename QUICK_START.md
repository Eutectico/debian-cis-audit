# Quick Start Guide - Debian CIS Audit

## Schnellübersicht

### 🔍 Was ist das Problem?

Die aktuelle `auditd.conf` hat **3 kritische Fehlkonfigurationen**:

1. **`max_log_file_action = keep_logs`** → Logs werden NICHT gelöscht → **Partition läuft voll!**
2. **`disk_full_action = halt`** → System wird angehalten bei voller Disk → **Totalausfall!**
3. **`admin_space_left_action = halt`** → System wird zu früh angehalten → **Verfügbarkeitsproblem!**

### ✅ Die Lösung

Verwenden Sie die `auditd.conf.recommended` Datei oder ändern Sie:

```bash
max_log_file_action = ROTATE    # Automatische Rotation
disk_full_action = rotate        # Rotieren statt System halt
admin_space_left_action = single # Single-User statt halt
```

## 🚀 Verwendung

### 1. Sofort-Test (ohne Installation)

Testen Sie die aktuelle auditd.conf:

```bash
python3 test_auditd_check.py
```

### 2. Vollständiger Audit

Führen Sie alle CIS Checks aus:

```bash
# Mit Root-Rechten für alle Checks
sudo python3 debian_cis_audit.py

# Oder mit JSON-Output
sudo python3 debian_cis_audit.py --format json --output report.json
```

### 3. Auditd.conf reparieren

```bash
# Backup erstellen
sudo cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup

# Empfohlene Konfiguration anwenden
sudo cp auditd.conf.recommended /etc/audit/auditd.conf

# Auditd neu starten
sudo systemctl restart auditd

# Prüfen
sudo systemctl status auditd
```

## 📊 Erstelle Dateien

| Datei | Beschreibung |
|-------|--------------|
| `debian_cis_audit.py` | Haupt-Audit-Skript (vollständiger CIS Check) |
| `test_auditd_check.py` | Schnell-Test für auditd.conf |
| `auditd.conf` | Original-Konfiguration (mit Problemen) |
| `auditd.conf.recommended` | Korrigierte Konfiguration |
| `monitoring_integration_example.py` | Monitoring-Integration (Prometheus, Nagios, Zabbix) |
| `README.md` | Ausführliche Dokumentation |
| `QUICK_START.md` | Diese Datei |

## 🎯 Beispiel-Output

```
🔴 KRITISCHE PROBLEME:

[1] Parameter: max_log_file_action
    Aktueller Wert: keep_logs
    Problem: Dies führt dazu, dass alte Logs NICHT gelöscht werden
             und die Partition voll laufen kann.
    Empfehlung: Setzen Sie auf "ROTATE"

[2] Parameter: disk_full_action
    Aktueller Wert: halt
    Problem: System wird komplett angehalten wenn Disk voll ist.
    Empfehlung: Setzen Sie auf "rotate" oder "single"

[3] Parameter: admin_space_left_action
    Aktueller Wert: halt
    Problem: System wird angehalten bei Speicherwarnung.
    Empfehlung: Setzen Sie auf "single"
```

## 🔧 Monitoring-Integration

### Prometheus

```bash
python3 monitoring_integration_example.py --format prometheus
```

### Nagios/Icinga

```bash
python3 monitoring_integration_example.py --format nagios
```

### Zabbix

```bash
python3 monitoring_integration_example.py --format zabbix
```

## 📝 CIS Benchmark Coverage

Das Skript prüft aktuell:

- ✅ **6.2** - Auditd Configuration (Installation, Service, Config, Permissions)
- ✅ **7.1** - System File Permissions (/etc/passwd, /etc/shadow, etc.)
- ✅ **7.2** - User/Group Settings (Duplicate UIDs, Empty Passwords)
- ✅ **2.2** - Services (Avahi, CUPS, RPC)
- ✅ **3.x** - Network (IP Forwarding, ICMP Redirects)

Weitere Checks können einfach hinzugefügt werden (siehe README.md).

## ⚡ Nächste Schritte

1. Führen Sie `python3 test_auditd_check.py` aus
2. Prüfen Sie die Ausgabe
3. Wenden Sie `auditd.conf.recommended` an
4. Führen Sie den vollständigen Audit aus: `sudo python3 debian_cis_audit.py`
5. Beheben Sie gefundene Probleme

## 🆘 Support

Bei Fragen zur CIS Benchmark:
- https://www.cisecurity.org/

Bei technischen Fragen zum Skript:
- Siehe README.md für Details
- Prüfen Sie die Code-Kommentare
