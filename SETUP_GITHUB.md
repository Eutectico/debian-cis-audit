# GitHub Repository Setup Guide

Diese Anleitung hilft dir, das Repository auf GitHub zu erstellen und zu veröffentlichen.

## 📋 Voraussetzungen

- GitHub Account
- Git installiert (`git --version` zum Prüfen)
- SSH Key oder GitHub Token konfiguriert

## 🚀 Schritt-für-Schritt Anleitung

### 1. GitHub Repository erstellen

1. Gehe zu https://github.com/new
2. Repository Name: **`debian-cis-audit`**
3. Description: `Debian CIS Benchmark Audit Script - Security and compliance auditing tool for Debian 12`
4. Visibility: **Public** (oder Private, je nach Bedarf)
5. **NICHT** initialisieren mit:
   - ❌ README
   - ❌ .gitignore
   - ❌ License
   (Wir haben diese bereits lokal!)
6. Klicke "Create repository"

### 2. Lokales Repository initialisieren

```bash
# Im Projekt-Verzeichnis
cd /home/federico/scripts/TOLTASKS-103

# Git initialisieren
git init

# Alle Dateien zum Staging hinzufügen
git add .

# Ersten Commit erstellen
git commit -m "Initial commit: Debian CIS Benchmark Audit Script

- Implement CIS Debian 12 Benchmark v1.1.0 checks
- Add auditd configuration validation (critical availability checks)
- Add filesystem permission checks
- Add service, network, and user/group checks
- Include monitoring integration examples (Prometheus, Nagios, Zabbix)
- Add comprehensive documentation and GitHub templates
"
```

### 3. Remote Repository verbinden

Ersetze `YOUR-USERNAME` mit deinem GitHub Benutzernamen:

```bash
# Remote hinzufügen (HTTPS)
git remote add origin https://github.com/YOUR-USERNAME/debian-cis-audit.git

# ODER Remote hinzufügen (SSH - empfohlen)
git remote add origin git@github.com:YOUR-USERNAME/debian-cis-audit.git

# Branch auf 'main' umbenennen (falls noch 'master')
git branch -M main

# Zum GitHub pushen
git push -u origin main
```

### 4. Repository-URLs in Dateien aktualisieren

Nach dem Erstellen des Repositories, ersetze `YOUR-USERNAME` in folgenden Dateien mit deinem echten GitHub-Benutzernamen:

```bash
# Dateien die zu aktualisieren sind:
# - README.md (mehrere Stellen)
# - setup.py
# - CONTRIBUTING.md

# Automatisch ersetzen (Linux/macOS):
sed -i 's/YOUR-USERNAME/dein-github-username/g' README.md
sed -i 's/YOUR-USERNAME/dein-github-username/g' setup.py
sed -i 's/YOUR-USERNAME/dein-github-username/g' CONTRIBUTING.md

# Oder manuell in einem Editor öffnen und ersetzen
```

Dann die Änderungen committen:

```bash
git add README.md setup.py CONTRIBUTING.md
git commit -m "Update repository URLs with actual GitHub username"
git push
```

### 5. GitHub Repository konfigurieren

#### 5.1 Beschreibung und Topics

Gehe zu deinem Repository auf GitHub:
- **About** → **Settings** (Zahnrad-Icon)
- **Description**: `Debian CIS Benchmark Audit Script - Security and compliance auditing tool`
- **Website**: `https://www.cisecurity.org/benchmark/debian_linux` (optional)
- **Topics** hinzufügen:
  ```
  security
  audit
  cis-benchmark
  debian
  compliance
  hardening
  devops
  sysadmin
  linux-security
  security-tools
  ```

#### 5.2 GitHub Features aktivieren

In **Settings**:
- ✅ **Issues** aktivieren
- ✅ **Discussions** aktivieren (optional, aber empfohlen)
- ✅ **Projects** (optional)
- ✅ **Preserve this repository** (Archive-Option)

#### 5.3 Branch Protection (optional aber empfohlen)

Für `main` Branch:
- Settings → Branches → Add rule
- Branch name pattern: `main`
- ✅ Require pull request reviews before merging
- ✅ Require status checks to pass before merging
  - Wähle: CI checks
- ✅ Require branches to be up to date before merging

### 6. GitHub Actions überprüfen

Nach dem ersten Push:
1. Gehe zu **Actions** Tab
2. CI Workflow sollte automatisch laufen
3. Prüfe, ob alle Jobs erfolgreich sind (grüner Haken)

### 7. Release erstellen (optional)

Nach erfolgreichem Setup:

```bash
# Tag erstellen
git tag -a v1.0.0 -m "Release v1.0.0

Initial release of Debian CIS Audit Script
- CIS Debian 12 Benchmark v1.1.0 support
- Critical auditd configuration checks
- Filesystem, service, network, and user checks
- Monitoring integration support
"

# Tag pushen
git push origin v1.0.0
```

Dann auf GitHub:
- Releases → Create a new release
- Choose tag: `v1.0.0`
- Release title: `v1.0.0 - Initial Release`
- Beschreibung hinzufügen
- Publish release

### 8. README Badges aktualisieren

Die Badges im README sollten jetzt funktionieren:
- CI Status Badge zeigt den Workflow-Status
- License Badge zeigt MIT License
- Python Version Badge
- CIS Benchmark Badge

## 🎨 Optional: Weitere Verbesserungen

### Social Preview Image

Erstelle ein Social Preview Image (1280x640px):
- Settings → Options → Social preview
- Upload ein Banner-Bild mit Logo/Text

### GitHub Sponsors (optional)

Falls du Spenden akzeptieren möchtest:
- Bearbeite `.github/FUNDING.yml`
- Füge deine Sponsor-Links hinzu

### Wiki (optional)

Aktiviere das Wiki für erweiterte Dokumentation:
- Settings → Features → Wiki
- Erstelle Seiten für:
  - Detaillierte CIS Check-Erklärungen
  - Troubleshooting
  - FAQ
  - Beispiele

## ✅ Checkliste

Bevor du das Repository veröffentlichst:

- [ ] Repository auf GitHub erstellt
- [ ] Lokales Git-Repository initialisiert
- [ ] Erster Commit erstellt
- [ ] Remote origin hinzugefügt
- [ ] Code nach GitHub gepusht
- [ ] `YOUR-USERNAME` in allen Dateien ersetzt
- [ ] Repository-Beschreibung hinzugefügt
- [ ] Topics hinzugefügt
- [ ] Issues und Discussions aktiviert
- [ ] CI Workflow läuft erfolgreich
- [ ] README wird korrekt angezeigt
- [ ] License wird erkannt (MIT)
- [ ] Alle Badges funktionieren

## 🔍 Verifizierung

Prüfe, ob alles funktioniert:

```bash
# Repository klonen (mit deinem Username)
git clone https://github.com/YOUR-USERNAME/debian-cis-audit.git
cd debian-cis-audit

# Skript testen
python3 debian_cis_audit.py --help
python3 test_auditd_check.py

# Prüfen ob alle Dateien vorhanden sind
ls -la
```

## 📢 Repository bewerben

Nach dem Setup kannst du das Repository bewerben:

1. **Reddit**:
   - r/debian
   - r/linuxadmin
   - r/netsec
   - r/sysadmin

2. **LinkedIn/Twitter**:
   - Projekt-Ankündigung mit Link

3. **Dev.to/Medium**:
   - Blog-Post über das Tool schreiben

4. **CIS Community**:
   - Im CIS Forum erwähnen

## 🆘 Hilfe

Bei Problemen:
- Git-Hilfe: `git --help`
- GitHub Docs: https://docs.github.com/
- Issue im Repository öffnen

---

Viel Erfolg mit deinem GitHub Repository! 🚀
