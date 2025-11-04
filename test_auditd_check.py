#!/usr/bin/env python3
"""
Test script to demonstrate auditd.conf checking functionality
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import AuditdAuditor, AuditReporter

def test_local_auditd_config():
    """Test the local auditd.conf file"""
    print("Testing local auditd.conf file...")
    print("=" * 80)

    reporter = AuditReporter()

    # Create a modified auditor that checks the local file
    class LocalAuditdAuditor(AuditdAuditor):
        def check_auditd_config(self):
            """Override to check local file"""
            config_path = './auditd.conf'

            if not self.file_exists(config_path):
                print(f"ERROR: {config_path} not found")
                return

            content = self.read_file(config_path)
            if not content:
                print(f"ERROR: Cannot read {config_path}")
                return

            print(f"\n✓ Found {config_path}")
            print("\nAnalyzing configuration...")
            print("-" * 80)

            issues = []
            warnings = []
            config = {}

            # Parse configuration
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()

            # Check max_log_file_action
            max_log_file_action = config.get('max_log_file_action', '')
            if max_log_file_action == 'keep_logs':
                issues.append({
                    'severity': 'CRITICAL',
                    'param': 'max_log_file_action',
                    'current': max_log_file_action,
                    'issue': 'KRITISCH! Dies führt dazu, dass alte Logs NICHT gelöscht werden und die Partition voll laufen kann.',
                    'recommendation': 'Setzen Sie auf "ROTATE" oder "rotate"'
                })

            # Check num_logs
            num_logs = config.get('num_logs', '0')
            try:
                num_logs_int = int(num_logs)
                if num_logs_int < 5:
                    warnings.append({
                        'severity': 'MEDIUM',
                        'param': 'num_logs',
                        'current': num_logs,
                        'issue': 'Zu wenig Log-Rotationen konfiguriert.',
                        'recommendation': 'Erhöhen Sie auf mindestens 5-10'
                    })
            except ValueError:
                pass

            # Check max_log_file
            max_log_file = config.get('max_log_file', '0')
            try:
                max_log_file_int = int(max_log_file)
                if max_log_file_int < 50:
                    warnings.append({
                        'severity': 'LOW',
                        'param': 'max_log_file',
                        'current': f'{max_log_file} MB',
                        'issue': 'Log-Datei-Größe sehr klein, kann zu häufiger Rotation führen.',
                        'recommendation': 'Erhöhen Sie auf mindestens 50-100 MB'
                    })
            except ValueError:
                pass

            # Check space_left
            space_left = config.get('space_left', '0')
            try:
                space_left_int = int(space_left)
                if space_left_int < 100:
                    warnings.append({
                        'severity': 'MEDIUM',
                        'param': 'space_left',
                        'current': f'{space_left} MB',
                        'issue': 'Zu wenig Speicherplatz-Puffer.',
                        'recommendation': 'Setzen Sie auf mindestens 25% der Partition-Größe oder mindestens 500 MB'
                    })
            except ValueError:
                pass

            # Check admin_space_left_action
            admin_space_left_action = config.get('admin_space_left_action', '')
            if admin_space_left_action == 'halt':
                issues.append({
                    'severity': 'CRITICAL',
                    'param': 'admin_space_left_action',
                    'current': admin_space_left_action,
                    'issue': 'WARNUNG! System wird angehalten wenn admin_space_left erreicht wird. Dies führt zu Verfügbarkeitsproblemen.',
                    'recommendation': 'Setzen Sie auf "single" (Single-User Mode) oder "suspend" (Audit pausieren)'
                })

            # Check disk_full_action
            disk_full_action = config.get('disk_full_action', '')
            if disk_full_action == 'halt':
                issues.append({
                    'severity': 'CRITICAL',
                    'param': 'disk_full_action',
                    'current': disk_full_action,
                    'issue': 'WARNUNG! System wird komplett angehalten wenn Disk voll ist. Schwerwiegendes Verfügbarkeitsproblem!',
                    'recommendation': 'Setzen Sie auf "rotate", "single" oder "suspend"'
                })

            # Print results
            print("\n📊 KONFIGURATIONSPARAMETER:")
            print("-" * 80)
            important_params = [
                'max_log_file_action', 'num_logs', 'max_log_file',
                'space_left', 'space_left_action',
                'admin_space_left', 'admin_space_left_action',
                'disk_full_action', 'disk_error_action'
            ]
            for param in important_params:
                value = config.get(param, 'NOT SET')
                print(f"  {param:30s} = {value}")

            # Print issues
            if issues:
                print("\n\n🔴 KRITISCHE PROBLEME:")
                print("=" * 80)
                for i, issue in enumerate(issues, 1):
                    print(f"\n[{i}] Parameter: {issue['param']}")
                    print(f"    Aktueller Wert: {issue['current']}")
                    print(f"    Schweregrad: {issue['severity']}")
                    print(f"    Problem: {issue['issue']}")
                    print(f"    Empfehlung: {issue['recommendation']}")

            if warnings:
                print("\n\n⚠️  WARNUNGEN:")
                print("=" * 80)
                for i, warn in enumerate(warnings, 1):
                    print(f"\n[{i}] Parameter: {warn['param']}")
                    print(f"    Aktueller Wert: {warn['current']}")
                    print(f"    Schweregrad: {warn['severity']}")
                    print(f"    Problem: {warn['issue']}")
                    print(f"    Empfehlung: {warn['recommendation']}")

            if not issues and not warnings:
                print("\n\n✅ KEINE PROBLEME GEFUNDEN")
                print("=" * 80)
                print("Die auditd.conf Konfiguration sieht gut aus!")

            # Print recommended configuration
            print("\n\n📋 EMPFOHLENE KONFIGURATION:")
            print("=" * 80)
            print("""
# Log-Rotation aktivieren
max_log_file_action = ROTATE

# Genügend Rotationen beibehalten (z.B. 10)
num_logs = 10

# Angemessene Log-Datei-Größe (z.B. 100 MB)
max_log_file = 100

# Genügend Speicherplatz-Puffer (z.B. 500 MB oder 25% der Partition)
space_left = 500
space_left_action = syslog

# Admin-Schwellwert und Aktion
admin_space_left = 100
admin_space_left_action = single  # Single-User Mode statt halt

# Bei voller Disk rotieren statt anhalten
disk_full_action = rotate

# Fehler per Syslog melden
disk_error_action = syslog
            """)

            print("\n" + "=" * 80)
            print(f"Zusammenfassung: {len(issues)} kritische Probleme, {len(warnings)} Warnungen")
            print("=" * 80)

    auditor = LocalAuditdAuditor(reporter)
    auditor.check_auditd_config()

if __name__ == '__main__':
    test_local_auditd_config()
