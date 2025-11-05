#!/usr/bin/env python3
"""
Debian CIS Benchmark Audit Script
Version: 1.0
Based on: CIS Debian Linux 12 Benchmark v1.1.0

This script audits a Debian system against CIS Benchmark requirements
and identifies misconfigurations that could cause availability issues.
"""

import os
import sys
import re
import pwd
import grp
import stat
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(Enum):
    """Severity levels for audit findings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(Enum):
    """Check status"""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class AuditResult:
    """Result of a single audit check"""
    check_id: str
    title: str
    status: Status
    severity: Severity
    message: str
    details: Optional[str] = None
    remediation: Optional[str] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class AuditReporter:
    """Handles reporting of audit results"""

    def __init__(self):
        self.results: List[AuditResult] = []

    def add_result(self, result: AuditResult):
        """Add an audit result"""
        self.results.append(result)

    def get_summary(self) -> Dict[str, int]:
        """Get summary statistics"""
        summary = {
            "total": len(self.results),
            "pass": 0,
            "fail": 0,
            "warning": 0,
            "skip": 0,
            "error": 0
        }
        for result in self.results:
            summary[result.status.value.lower()] += 1
        return summary

    def generate_console_report(self) -> str:
        """Generate a console-friendly report"""
        output = []
        output.append("=" * 80)
        output.append("DEBIAN CIS BENCHMARK AUDIT REPORT")
        output.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append("=" * 80)
        output.append("")

        # Summary
        summary = self.get_summary()
        output.append("SUMMARY:")
        output.append(f"  Total Checks:  {summary['total']}")
        output.append(f"  ✓ Passed:      {summary['pass']}")
        output.append(f"  ✗ Failed:      {summary['fail']}")
        output.append(f"  ⚠ Warnings:    {summary['warning']}")
        output.append(f"  - Skipped:     {summary['skip']}")
        output.append(f"  ! Errors:      {summary['error']}")
        output.append("")

        # Group by status
        for status in [Status.FAIL, Status.WARNING, Status.ERROR, Status.PASS, Status.SKIP]:
            status_results = [r for r in self.results if r.status == status]
            if not status_results:
                continue

            output.append("-" * 80)
            output.append(f"{status.value} ({len(status_results)} checks)")
            output.append("-" * 80)

            for result in status_results:
                icon = {
                    Status.PASS: "✓",
                    Status.FAIL: "✗",
                    Status.WARNING: "⚠",
                    Status.SKIP: "-",
                    Status.ERROR: "!"
                }[result.status]

                output.append(f"\n{icon} [{result.check_id}] {result.title}")
                output.append(f"   Severity: {result.severity.value}")
                output.append(f"   {result.message}")

                if result.details:
                    output.append(f"   Details: {result.details}")

                if result.remediation and result.status in [Status.FAIL, Status.WARNING]:
                    output.append(f"   Remediation: {result.remediation}")

        output.append("")
        output.append("=" * 80)
        return "\n".join(output)

    def generate_json_report(self) -> str:
        """Generate a JSON report"""
        report_data = {
            "generated": datetime.now().isoformat(),
            "benchmark": "CIS Debian Linux 12 Benchmark v1.1.0",
            "summary": self.get_summary(),
            "results": [asdict(r) for r in self.results]
        }
        return json.dumps(report_data, indent=2, default=str)


class BaseAuditor:
    """Base class for all auditors"""

    def __init__(self, reporter: AuditReporter):
        self.reporter = reporter

    def run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Run a shell command and return returncode, stdout, stderr"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timeout"
        except Exception as e:
            return -1, "", str(e)

    def file_exists(self, path: str) -> bool:
        """Check if file exists"""
        return os.path.exists(path)

    def read_file(self, path: str) -> Optional[str]:
        """Read file contents"""
        try:
            with open(path, 'r') as f:
                return f.read()
        except Exception:
            return None

    def get_file_stat(self, path: str) -> Optional[os.stat_result]:
        """Get file statistics"""
        try:
            return os.stat(path)
        except Exception:
            return None


class AuditdAuditor(BaseAuditor):
    """Auditor for auditd configuration"""

    def check_auditd_installed(self):
        """Check if auditd is installed"""
        returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'auditd'])

        if returncode == 0:
            self.reporter.add_result(AuditResult(
                check_id="6.2.1.1",
                title="Ensure auditd is installed",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="auditd package is installed"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.1.1",
                title="Ensure auditd is installed",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="auditd package is not installed",
                remediation="Install auditd: apt install auditd audispd-plugins"
            ))

    def check_auditd_enabled(self):
        """Check if auditd service is enabled"""
        returncode, stdout, stderr = self.run_command(['systemctl', 'is-enabled', 'auditd'])

        if returncode == 0 and stdout.strip() == 'enabled':
            self.reporter.add_result(AuditResult(
                check_id="6.2.1.2",
                title="Ensure auditd service is enabled",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="auditd service is enabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.1.2",
                title="Ensure auditd service is enabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="auditd service is not enabled",
                remediation="Enable auditd: systemctl enable auditd"
            ))

    def check_auditd_config(self):
        """Check auditd.conf for misconfigurations that can cause availability issues"""
        config_path = '/etc/audit/auditd.conf'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="6.2.1.3",
                title="Check auditd.conf configuration",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"{config_path} not found"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="6.2.1.3",
                title="Check auditd.conf configuration",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Cannot read {config_path}"
            ))
            return

        issues = []
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
            issues.append(
                "max_log_file_action=keep_logs: KRITISCH! Dies führt dazu, dass alte Logs "
                "NICHT gelöscht werden und die Partition voll laufen kann. "
                "Empfohlen: 'rotate' oder 'ROTATE'"
            )

        # Check num_logs for rotation
        num_logs = config.get('num_logs', '0')
        try:
            num_logs_int = int(num_logs)
            if num_logs_int < 5:
                issues.append(
                    f"num_logs={num_logs}: Zu wenig Log-Rotationen. "
                    "Empfohlen: mindestens 5-10"
                )
        except ValueError:
            pass

        # Check max_log_file size
        max_log_file = config.get('max_log_file', '0')
        try:
            max_log_file_int = int(max_log_file)
            if max_log_file_int < 50:
                issues.append(
                    f"max_log_file={max_log_file}MB: Sehr klein, kann zu häufiger Rotation führen. "
                    "Empfohlen: mindestens 50-100 MB"
                )
        except ValueError:
            pass

        # Check space_left
        space_left = config.get('space_left', '0')
        try:
            space_left_int = int(space_left)
            if space_left_int < 100:
                issues.append(
                    f"space_left={space_left}MB: Zu niedrig. "
                    "Empfohlen: mindestens 25% der Partition-Größe"
                )
        except ValueError:
            pass

        # Check space_left_action
        space_left_action = config.get('space_left_action', '')
        if space_left_action not in ['email', 'syslog', 'exec', 'rotate']:
            issues.append(
                f"space_left_action={space_left_action}: "
                "Sollte 'email', 'syslog', 'exec' oder 'rotate' sein"
            )

        # Check admin_space_left_action
        admin_space_left_action = config.get('admin_space_left_action', '')
        if admin_space_left_action == 'halt':
            issues.append(
                "admin_space_left_action=halt: WARNUNG! System wird angehalten wenn "
                "admin_space_left erreicht wird. Dies kann zu Verfügbarkeitsproblemen führen. "
                "Erwägen Sie: 'single' oder 'suspend'"
            )

        # Check disk_full_action
        disk_full_action = config.get('disk_full_action', '')
        if disk_full_action == 'halt':
            issues.append(
                "disk_full_action=halt: WARNUNG! System wird angehalten wenn Disk voll ist. "
                "Erwägen Sie: 'rotate', 'single' oder 'suspend'"
            )

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="6.2.1.3",
                title="Check auditd.conf for availability issues",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                message="Kritische Fehlkonfigurationen in auditd.conf gefunden",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="Bearbeiten Sie /etc/audit/auditd.conf und passen Sie die Konfiguration an"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.1.3",
                title="Check auditd.conf for availability issues",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="auditd.conf Konfiguration ist korrekt"
            ))

    def check_audit_log_permissions(self):
        """Check audit log file permissions"""
        log_path = '/var/log/audit/audit.log'

        if not self.file_exists(log_path):
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.1",
                title="Ensure audit log files mode is configured",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message=f"Audit log file {log_path} not found"
            ))
            return

        stat_info = self.get_file_stat(log_path)
        if not stat_info:
            return

        mode = stat.S_IMODE(stat_info.st_mode)
        expected_mode = 0o600  # rw-------

        if mode & 0o077:  # Check if group/other have any permissions
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.1",
                title="Ensure audit log files mode is configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"Audit log file has incorrect permissions: {oct(mode)}",
                details=f"Expected: {oct(expected_mode)} (0600 or more restrictive)",
                remediation=f"chmod 0600 {log_path}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.1",
                title="Ensure audit log files mode is configured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="Audit log file permissions are correct"
            ))

    def check_audit_log_file_size(self):
        """6.2.2.1 - Ensure audit log file size is configured"""
        config_path = '/etc/audit/auditd.conf'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.1",
                title="Ensure audit log file size is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"{config_path} not found"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.1",
                title="Ensure audit log file size is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Cannot read {config_path}"
            ))
            return

        # Parse configuration
        config = {}
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()

        max_log_file = config.get('max_log_file', '')

        if not max_log_file:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.1",
                title="Ensure audit log file size is configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="max_log_file is not configured in auditd.conf",
                remediation="Set max_log_file in /etc/audit/auditd.conf (recommended: at least 8 MB)"
            ))
            return

        try:
            max_log_file_int = int(max_log_file)
            if max_log_file_int < 8:
                self.reporter.add_result(AuditResult(
                    check_id="6.2.2.1",
                    title="Ensure audit log file size is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"max_log_file is too small: {max_log_file} MB",
                    details="CIS recommends at least 8 MB to ensure adequate audit data retention",
                    remediation="Set max_log_file=8 or higher in /etc/audit/auditd.conf"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="6.2.2.1",
                    title="Ensure audit log file size is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message=f"max_log_file is properly configured: {max_log_file} MB"
                ))
        except ValueError:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.1",
                title="Ensure audit log file size is configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"max_log_file has invalid value: {max_log_file}",
                remediation="Set max_log_file to a valid number in /etc/audit/auditd.conf"
            ))

    def check_audit_max_log_file_action(self):
        """6.2.2.2 - Ensure audit logs are not automatically deleted"""
        config_path = '/etc/audit/auditd.conf'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.2",
                title="Ensure audit logs are not automatically deleted",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"{config_path} not found"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.2",
                title="Ensure audit logs are not automatically deleted",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Cannot read {config_path}"
            ))
            return

        # Parse configuration
        config = {}
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()

        max_log_file_action = config.get('max_log_file_action', '')

        if not max_log_file_action:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.2",
                title="Ensure audit logs are not automatically deleted",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="max_log_file_action is not configured",
                remediation="Set max_log_file_action to 'keep_logs' or 'rotate' in /etc/audit/auditd.conf"
            ))
            return

        # Check if set to keep_logs or rotate (both are acceptable per CIS)
        if max_log_file_action.lower() in ['keep_logs', 'rotate']:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.2",
                title="Ensure audit logs are not automatically deleted",
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"max_log_file_action is properly configured: {max_log_file_action}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.2",
                title="Ensure audit logs are not automatically deleted",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"max_log_file_action={max_log_file_action} may cause logs to be deleted",
                details="CIS requires 'keep_logs' or 'rotate' to prevent automatic log deletion",
                remediation="Set max_log_file_action=rotate in /etc/audit/auditd.conf"
            ))

    def check_audit_space_left_action(self):
        """6.2.2.3 - Ensure system is disabled when audit logs are full (space_left_action)"""
        config_path = '/etc/audit/auditd.conf'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.3",
                title="Ensure system is disabled when audit logs are full",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"{config_path} not found"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.3",
                title="Ensure system is disabled when audit logs are full",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Cannot read {config_path}"
            ))
            return

        # Parse configuration
        config = {}
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()

        space_left_action = config.get('space_left_action', '')

        if not space_left_action:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.3",
                title="Ensure system is disabled when audit logs are full",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="space_left_action is not configured",
                remediation="Set space_left_action to 'email', 'exec', 'single', or 'halt' in /etc/audit/auditd.conf"
            ))
            return

        # CIS recommends email, exec, single, or halt
        acceptable_actions = ['email', 'exec', 'single', 'halt']
        if space_left_action.lower() in acceptable_actions:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.3",
                title="Ensure system is disabled when audit logs are full",
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"space_left_action is properly configured: {space_left_action}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.3",
                title="Ensure system is disabled when audit logs are full",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"space_left_action={space_left_action} is not recommended",
                details="CIS recommends 'email', 'exec', 'single', or 'halt'",
                remediation="Set space_left_action=email in /etc/audit/auditd.conf"
            ))

    def check_audit_admin_space_left_action(self):
        """6.2.2.4 - Ensure system is disabled when audit logs are full (admin_space_left_action)"""
        config_path = '/etc/audit/auditd.conf'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.4",
                title="Ensure admin_space_left_action is configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"{config_path} not found"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.4",
                title="Ensure admin_space_left_action is configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Cannot read {config_path}"
            ))
            return

        # Parse configuration
        config = {}
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()

        admin_space_left_action = config.get('admin_space_left_action', '')

        if not admin_space_left_action:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.4",
                title="Ensure admin_space_left_action is configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="admin_space_left_action is not configured",
                remediation="Set admin_space_left_action to 'single' or 'halt' in /etc/audit/auditd.conf"
            ))
            return

        # CIS recommends single or halt
        if admin_space_left_action.lower() in ['single', 'halt']:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.4",
                title="Ensure admin_space_left_action is configured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"admin_space_left_action is properly configured: {admin_space_left_action}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.2.4",
                title="Ensure admin_space_left_action is configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"admin_space_left_action={admin_space_left_action} is not recommended",
                details="CIS recommends 'single' or 'halt' for admin_space_left_action",
                remediation="Set admin_space_left_action=single in /etc/audit/auditd.conf"
            ))

    def run_all_checks(self):
        """Run all auditd checks"""
        self.check_auditd_installed()
        self.check_auditd_enabled()
        self.check_auditd_config()
        self.check_audit_log_permissions()
        # Audit Data Retention checks (6.2.2.x)
        self.check_audit_log_file_size()
        self.check_audit_max_log_file_action()
        self.check_audit_space_left_action()
        self.check_audit_admin_space_left_action()


class SystemLoggingAuditor(BaseAuditor):
    """Auditor for system logging configurations (systemd-journald and rsyslog)"""

    def check_journald_compress(self):
        """Check if journald is configured to compress large log files (6.1.1.3)"""
        journald_conf = self.read_file('/etc/systemd/journald.conf')
        if not journald_conf:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.3",
                title="Ensure journald is configured to compress large log files",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message="Cannot read /etc/systemd/journald.conf"
            ))
            return

        compress_enabled = False
        for line in journald_conf.split('\n'):
            line = line.strip()
            if line.startswith('Compress='):
                value = line.split('=', 1)[1].strip()
                if value.lower() == 'yes':
                    compress_enabled = True
                break

        if compress_enabled:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.3",
                title="Ensure journald is configured to compress large log files",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="journald compression is enabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.3",
                title="Ensure journald is configured to compress large log files",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="journald compression is not enabled",
                remediation="Add 'Compress=yes' to /etc/systemd/journald.conf and restart systemd-journald"
            ))

    def check_journald_persistent(self):
        """Check if journald is configured to write logs to persistent disk (6.1.1.4)"""
        journald_conf = self.read_file('/etc/systemd/journald.conf')
        if not journald_conf:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.4",
                title="Ensure journald is configured to write logfiles to persistent disk",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="Cannot read /etc/systemd/journald.conf"
            ))
            return

        storage_persistent = False
        for line in journald_conf.split('\n'):
            line = line.strip()
            if line.startswith('Storage='):
                value = line.split('=', 1)[1].strip()
                if value.lower() in ['persistent', 'auto']:
                    storage_persistent = True
                break

        if storage_persistent:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.4",
                title="Ensure journald is configured to write logfiles to persistent disk",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="journald is configured for persistent storage"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.4",
                title="Ensure journald is configured to write logfiles to persistent disk",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="journald is not configured for persistent storage",
                remediation="Add 'Storage=persistent' to /etc/systemd/journald.conf and restart systemd-journald"
            ))

    def check_journald_no_remote(self):
        """Check that journald is not configured to receive logs from remote client (6.1.1.5)"""
        returncode, stdout, _ = self.run_command(['systemctl', 'is-enabled', 'systemd-journal-remote.socket'])

        if returncode != 0 or stdout.strip() in ['disabled', 'masked']:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.5",
                title="Ensure journald is not configured to receive logs from a remote client",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="systemd-journal-remote.socket is not enabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.5",
                title="Ensure journald is not configured to receive logs from a remote client",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="systemd-journal-remote.socket is enabled",
                remediation="Run 'systemctl disable systemd-journal-remote.socket' and 'systemctl mask systemd-journal-remote.socket'"
            ))

    def check_journald_forward_to_rsyslog(self):
        """Check if journald forwards to rsyslog (6.1.1.2)"""
        journald_conf = self.read_file('/etc/systemd/journald.conf')
        if not journald_conf:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.2",
                title="Ensure journald is configured to send logs to rsyslog",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message="Cannot read /etc/systemd/journald.conf"
            ))
            return

        forward_enabled = False
        for line in journald_conf.split('\n'):
            line = line.strip()
            if line.startswith('ForwardToSyslog='):
                value = line.split('=', 1)[1].strip()
                if value.lower() == 'yes':
                    forward_enabled = True
                break

        if forward_enabled:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.2",
                title="Ensure journald is configured to send logs to rsyslog",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="journald forwards logs to rsyslog"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.2",
                title="Ensure journald is configured to send logs to rsyslog",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="journald does not forward logs to rsyslog",
                remediation="Add 'ForwardToSyslog=yes' to /etc/systemd/journald.conf and restart systemd-journald"
            ))

    def check_rsyslog_installed(self):
        """Check if rsyslog is installed (6.1.2.1)"""
        returncode, stdout, _ = self.run_command(['dpkg', '-s', 'rsyslog'])

        if returncode == 0:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.1",
                title="Ensure rsyslog is installed",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="rsyslog is installed"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.1",
                title="Ensure rsyslog is installed",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="rsyslog is not installed",
                remediation="Install rsyslog: apt install rsyslog"
            ))

    def check_rsyslog_enabled(self):
        """Check if rsyslog service is enabled (6.1.2.2)"""
        returncode, stdout, _ = self.run_command(['systemctl', 'is-enabled', 'rsyslog'])

        if returncode == 0 and stdout.strip() == 'enabled':
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.2",
                title="Ensure rsyslog service is enabled",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="rsyslog service is enabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.2",
                title="Ensure rsyslog service is enabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="rsyslog service is not enabled",
                remediation="Enable rsyslog: systemctl enable rsyslog"
            ))

    def check_rsyslog_file_permissions(self):
        """Check rsyslog default file permissions configuration (6.1.2.3)"""
        rsyslog_conf = self.read_file('/etc/rsyslog.conf')
        if not rsyslog_conf:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.3",
                title="Ensure rsyslog default file permissions are configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message="Cannot read /etc/rsyslog.conf"
            ))
            return

        file_perms_configured = False
        for line in rsyslog_conf.split('\n'):
            line = line.strip()
            if line.startswith('$FileCreateMode'):
                value = line.split()[1] if len(line.split()) > 1 else ''
                # Should be 0640 or more restrictive
                if value in ['0640', '0600']:
                    file_perms_configured = True
                break

        if file_perms_configured:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.3",
                title="Ensure rsyslog default file permissions are configured",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="rsyslog file permissions are properly configured"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.3",
                title="Ensure rsyslog default file permissions are configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="rsyslog file permissions are not properly configured",
                remediation="Add '$FileCreateMode 0640' to /etc/rsyslog.conf and restart rsyslog"
            ))

    def check_rsyslog_logging_configured(self):
        """Check if logging is configured (6.1.2.4)"""
        rsyslog_conf = self.read_file('/etc/rsyslog.conf')
        if not rsyslog_conf:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.4",
                title="Ensure logging is configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="Cannot read /etc/rsyslog.conf"
            ))
            return

        # Check for basic logging rules (at least some log destinations)
        log_rules = []
        for line in rsyslog_conf.split('\n'):
            line = line.strip()
            # Look for common log rules (*.*, auth.*, kern.*, etc.)
            if not line.startswith('#') and ('*.*' in line or 'auth.' in line or 'kern.' in line or 'cron.' in line):
                if '/var/log/' in line:
                    log_rules.append(line)

        if log_rules:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.4",
                title="Ensure logging is configured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"Logging is configured ({len(log_rules)} rules found)"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.4",
                title="Ensure logging is configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="No logging rules found in rsyslog.conf",
                remediation="Configure appropriate logging rules in /etc/rsyslog.conf"
            ))

    def check_rsyslog_remote_logs(self):
        """Check if rsyslog is configured to send logs to remote host (6.1.2.5)"""
        rsyslog_conf = self.read_file('/etc/rsyslog.conf')
        if not rsyslog_conf:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.5",
                title="Ensure rsyslog is configured to send logs to a remote log host",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message="Cannot read /etc/rsyslog.conf"
            ))
            return

        # Look for remote logging configuration (@@remote-host or @remote-host)
        remote_configured = False
        for line in rsyslog_conf.split('\n'):
            line = line.strip()
            if not line.startswith('#') and ('@@' in line or (line.startswith('*.*') and '@' in line)):
                remote_configured = True
                break

        if remote_configured:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.5",
                title="Ensure rsyslog is configured to send logs to a remote log host",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="rsyslog is configured for remote logging"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.5",
                title="Ensure rsyslog is configured to send logs to a remote log host",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message="rsyslog is not configured for remote logging",
                details="Remote logging is recommended for centralized log management",
                remediation="Add '*.* @@<remote-host>:<port>' to /etc/rsyslog.conf for TCP or '*.* @<remote-host>:<port>' for UDP"
            ))

    def check_rsyslog_remote_messages(self):
        """Check that remote rsyslog messages are only accepted on designated log hosts (6.1.2.6)"""
        rsyslog_conf = self.read_file('/etc/rsyslog.conf')
        if not rsyslog_conf:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.6",
                title="Ensure remote rsyslog messages are only accepted on designated log hosts",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message="Cannot read /etc/rsyslog.conf"
            ))
            return

        # Check if remote input modules are enabled
        remote_enabled = False
        for line in rsyslog_conf.split('\n'):
            line = line.strip()
            if not line.startswith('#'):
                if 'imtcp' in line or 'imudp' in line or 'ModLoad imtcp' in line or 'ModLoad imudp' in line:
                    remote_enabled = True
                    break

        # On non-log-host systems, remote input should be disabled
        if not remote_enabled:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.6",
                title="Ensure remote rsyslog messages are only accepted on designated log hosts",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="rsyslog is not accepting remote messages"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.2.6",
                title="Ensure remote rsyslog messages are only accepted on designated log hosts",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message="rsyslog is configured to accept remote messages",
                details="This is only acceptable on designated log hosts",
                remediation="If this is not a log host, comment out remote input modules (imtcp/imudp) in /etc/rsyslog.conf"
            ))

    def check_systemd_journal_remote_installed(self):
        """Check if systemd-journal-remote is installed for remote journald (6.1.1.1)"""
        returncode, stdout, _ = self.run_command(['dpkg', '-s', 'systemd-journal-remote'])

        if returncode == 0:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.1",
                title="Ensure systemd-journal-remote is installed",
                status=Status.PASS,
                severity=Severity.LOW,
                message="systemd-journal-remote is installed",
                details="Only needed if using remote journal logging"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.1.1.1",
                title="Ensure systemd-journal-remote is installed",
                status=Status.WARNING,
                severity=Severity.LOW,
                message="systemd-journal-remote is not installed",
                details="Only needed if you plan to send journal logs to a remote system",
                remediation="If remote logging is needed: apt install systemd-journal-remote"
            ))

    def run_all_checks(self):
        """Run all system logging checks"""
        # systemd-journald checks
        self.check_systemd_journal_remote_installed()
        self.check_journald_forward_to_rsyslog()
        self.check_journald_compress()
        self.check_journald_persistent()
        self.check_journald_no_remote()

        # rsyslog checks
        self.check_rsyslog_installed()
        self.check_rsyslog_enabled()
        self.check_rsyslog_file_permissions()
        self.check_rsyslog_logging_configured()
        self.check_rsyslog_remote_logs()
        self.check_rsyslog_remote_messages()


class FileSystemAuditor(BaseAuditor):
    """Auditor for filesystem permissions and configurations"""

    def check_passwd_permissions(self):
        """Check /etc/passwd permissions"""
        path = '/etc/passwd'
        expected_mode = 0o644
        expected_owner = 'root'
        expected_group = 'root'

        stat_info = self.get_file_stat(path)
        if not stat_info:
            self.reporter.add_result(AuditResult(
                check_id="7.1.1",
                title="Ensure permissions on /etc/passwd are configured",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Cannot stat {path}"
            ))
            return

        issues = []
        mode = stat.S_IMODE(stat_info.st_mode)

        if mode != expected_mode:
            issues.append(f"Incorrect mode: {oct(mode)}, expected: {oct(expected_mode)}")

        try:
            owner = pwd.getpwuid(stat_info.st_uid).pw_name
            if owner != expected_owner:
                issues.append(f"Incorrect owner: {owner}, expected: {expected_owner}")
        except KeyError:
            issues.append(f"Unknown owner UID: {stat_info.st_uid}")

        try:
            group = grp.getgrgid(stat_info.st_gid).gr_name
            if group != expected_group:
                issues.append(f"Incorrect group: {group}, expected: {expected_group}")
        except KeyError:
            issues.append(f"Unknown group GID: {stat_info.st_gid}")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="7.1.1",
                title="Ensure permissions on /etc/passwd are configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Incorrect permissions on /etc/passwd",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation=f"chown root:root {path} && chmod 644 {path}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.1.1",
                title="Ensure permissions on /etc/passwd are configured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="/etc/passwd permissions are correct"
            ))

    def check_shadow_permissions(self):
        """Check /etc/shadow permissions"""
        path = '/etc/shadow'
        expected_mode = 0o640
        expected_owner = 'root'
        expected_group = 'shadow'

        stat_info = self.get_file_stat(path)
        if not stat_info:
            self.reporter.add_result(AuditResult(
                check_id="7.1.5",
                title="Ensure permissions on /etc/shadow are configured",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Cannot stat {path}"
            ))
            return

        issues = []
        mode = stat.S_IMODE(stat_info.st_mode)

        if mode & 0o077:  # Check if group write or other have any permissions
            issues.append(f"Too permissive mode: {oct(mode)}, expected: {oct(expected_mode)} or more restrictive")

        try:
            owner = pwd.getpwuid(stat_info.st_uid).pw_name
            if owner != expected_owner:
                issues.append(f"Incorrect owner: {owner}, expected: {expected_owner}")
        except KeyError:
            issues.append(f"Unknown owner UID: {stat_info.st_uid}")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="7.1.5",
                title="Ensure permissions on /etc/shadow are configured",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                message="Incorrect permissions on /etc/shadow",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation=f"chown root:shadow {path} && chmod 640 {path}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.1.5",
                title="Ensure permissions on /etc/shadow are configured",
                status=Status.PASS,
                severity=Severity.CRITICAL,
                message="/etc/shadow permissions are correct"
            ))

    def _check_file_permissions_generic(self, check_id: str, title: str, path: str,
                                         expected_mode: int, expected_owner: str,
                                         expected_group: str, severity: Severity,
                                         use_max_mode: bool = False):
        """Generic method to check file permissions"""
        stat_info = self.get_file_stat(path)
        if not stat_info:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.ERROR,
                severity=severity,
                message=f"Cannot stat {path}",
                remediation=f"Ensure {path} exists with correct permissions"
            ))
            return

        issues = []
        mode = stat.S_IMODE(stat_info.st_mode)

        if use_max_mode:
            # Check if permissions are too permissive (e.g., shadow files)
            if mode & ~expected_mode:
                issues.append(f"Too permissive mode: {oct(mode)}, expected: {oct(expected_mode)} or more restrictive")
        else:
            # Exact mode check
            if mode != expected_mode:
                issues.append(f"Incorrect mode: {oct(mode)}, expected: {oct(expected_mode)}")

        try:
            owner = pwd.getpwuid(stat_info.st_uid).pw_name
            if owner != expected_owner:
                issues.append(f"Incorrect owner: {owner}, expected: {expected_owner}")
        except KeyError:
            issues.append(f"Unknown owner UID: {stat_info.st_uid}")

        try:
            group = grp.getgrgid(stat_info.st_gid).gr_name
            if group != expected_group:
                issues.append(f"Incorrect group: {group}, expected: {expected_group}")
        except KeyError:
            issues.append(f"Unknown group GID: {stat_info.st_gid}")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.FAIL,
                severity=severity,
                message=f"Incorrect permissions on {path}",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation=f"chown {expected_owner}:{expected_group} {path} && chmod {oct(expected_mode)[2:]} {path}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.PASS,
                severity=severity,
                message=f"{path} permissions are correct"
            ))

    def check_passwd_backup_permissions(self):
        """Check /etc/passwd- permissions (7.1.2)"""
        self._check_file_permissions_generic(
            check_id="7.1.2",
            title="Ensure permissions on /etc/passwd- are configured",
            path="/etc/passwd-",
            expected_mode=0o644,
            expected_owner="root",
            expected_group="root",
            severity=Severity.HIGH
        )

    def check_group_permissions(self):
        """Check /etc/group permissions (7.1.3)"""
        self._check_file_permissions_generic(
            check_id="7.1.3",
            title="Ensure permissions on /etc/group are configured",
            path="/etc/group",
            expected_mode=0o644,
            expected_owner="root",
            expected_group="root",
            severity=Severity.HIGH
        )

    def check_group_backup_permissions(self):
        """Check /etc/group- permissions (7.1.4)"""
        self._check_file_permissions_generic(
            check_id="7.1.4",
            title="Ensure permissions on /etc/group- are configured",
            path="/etc/group-",
            expected_mode=0o644,
            expected_owner="root",
            expected_group="root",
            severity=Severity.HIGH
        )

    def check_shadow_backup_permissions(self):
        """Check /etc/shadow- permissions (7.1.6)"""
        self._check_file_permissions_generic(
            check_id="7.1.6",
            title="Ensure permissions on /etc/shadow- are configured",
            path="/etc/shadow-",
            expected_mode=0o640,
            expected_owner="root",
            expected_group="shadow",
            severity=Severity.CRITICAL,
            use_max_mode=True
        )

    def check_gshadow_permissions(self):
        """Check /etc/gshadow permissions (7.1.7)"""
        self._check_file_permissions_generic(
            check_id="7.1.7",
            title="Ensure permissions on /etc/gshadow are configured",
            path="/etc/gshadow",
            expected_mode=0o640,
            expected_owner="root",
            expected_group="shadow",
            severity=Severity.CRITICAL,
            use_max_mode=True
        )

    def check_gshadow_backup_permissions(self):
        """Check /etc/gshadow- permissions (7.1.8)"""
        self._check_file_permissions_generic(
            check_id="7.1.8",
            title="Ensure permissions on /etc/gshadow- are configured",
            path="/etc/gshadow-",
            expected_mode=0o640,
            expected_owner="root",
            expected_group="shadow",
            severity=Severity.CRITICAL,
            use_max_mode=True
        )

    def check_shells_permissions(self):
        """Check /etc/shells permissions (7.1.9)"""
        self._check_file_permissions_generic(
            check_id="7.1.9",
            title="Ensure permissions on /etc/shells are configured",
            path="/etc/shells",
            expected_mode=0o644,
            expected_owner="root",
            expected_group="root",
            severity=Severity.MEDIUM
        )

    def check_opasswd_permissions(self):
        """Check /etc/security/opasswd permissions (7.1.10)"""
        self._check_file_permissions_generic(
            check_id="7.1.10",
            title="Ensure permissions on /etc/security/opasswd are configured",
            path="/etc/security/opasswd",
            expected_mode=0o600,
            expected_owner="root",
            expected_group="root",
            severity=Severity.HIGH,
            use_max_mode=True
        )

    def check_unowned_files(self):
        """Check for files without owner or group (7.1.12)"""
        returncode, stdout, stderr = self.run_command([
            'find', '/', '-xdev', '(', '-nouser', '-o', '-nogroup', ')',
            '-type', 'f', '-print'
        ], timeout=60000)

        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="7.1.12",
                title="Ensure no files or directories without an owner and a group exist",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message="Cannot check for unowned files",
                details=stderr
            ))
            return

        unowned_files = stdout.strip()
        if unowned_files:
            # Limit output to avoid overwhelming report
            files_list = unowned_files.split('\n')
            files_count = len(files_list)
            display_files = '\n'.join(files_list[:20])
            if files_count > 20:
                display_files += f"\n... and {files_count - 20} more files"

            self.reporter.add_result(AuditResult(
                check_id="7.1.12",
                title="Ensure no files or directories without an owner and a group exist",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Files without owner or group found ({files_count} files)",
                details=display_files,
                remediation="Review and assign proper ownership to these files"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.1.12",
                title="Ensure no files or directories without an owner and a group exist",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="No files without owner or group found"
            ))

    def check_world_writable_files(self):
        """Check for world-writable files"""
        # This is a simplified check - full check would scan entire filesystem
        returncode, stdout, stderr = self.run_command([
            'find', '/etc', '-type', 'f', '-perm', '-002', '-ls'
        ])

        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="7.1.11",
                title="Ensure world writable files and directories are secured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message="Cannot check for world-writable files",
                details=stderr
            ))
            return

        world_writable = stdout.strip()
        if world_writable:
            self.reporter.add_result(AuditResult(
                check_id="7.1.11",
                title="Ensure world writable files and directories are secured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="World-writable files found in /etc",
                details=world_writable,
                remediation="Review and remove world-write permissions from these files"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.1.11",
                title="Ensure world writable files and directories are secured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="No world-writable files found in /etc"
            ))

    def run_all_checks(self):
        """Run all filesystem checks"""
        self.check_passwd_permissions()
        self.check_passwd_backup_permissions()
        self.check_group_permissions()
        self.check_group_backup_permissions()
        self.check_shadow_permissions()
        self.check_shadow_backup_permissions()
        self.check_gshadow_permissions()
        self.check_gshadow_backup_permissions()
        self.check_shells_permissions()
        self.check_opasswd_permissions()
        self.check_world_writable_files()
        self.check_unowned_files()


class ServiceAuditor(BaseAuditor):
    """Auditor for system services"""

    def check_service_disabled(self, service_name: str, check_id: str, title: str):
        """Check if a service is disabled"""
        returncode, stdout, stderr = self.run_command(['systemctl', 'is-enabled', service_name])

        # Service should be disabled or not exist
        if stdout.strip() in ['disabled', 'masked'] or returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"{service_name} is not enabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"{service_name} is enabled",
                remediation=f"systemctl disable --now {service_name}"
            ))

    def run_all_checks(self):
        """Run all service checks"""
        # 2.1.x - Additional Services (22 checks)
        self.check_service_disabled('autofs', '2.1.1', 'Ensure autofs services are not in use')
        self.check_service_disabled('avahi-daemon', '2.1.2', 'Ensure avahi daemon services are not in use')
        self.check_service_disabled('isc-dhcp-server', '2.1.3', 'Ensure dhcp server services are not in use')
        self.check_service_disabled('bind9', '2.1.4', 'Ensure dns server services are not in use')
        self.check_service_disabled('dnsmasq', '2.1.5', 'Ensure dnsmasq services are not in use')
        self.check_service_disabled('vsftpd', '2.1.6', 'Ensure ftp server services are not in use')
        self.check_service_disabled('slapd', '2.1.7', 'Ensure ldap server services are not in use')
        self.check_service_disabled('dovecot', '2.1.8', 'Ensure message access server services are not in use')
        self.check_service_disabled('nfs-server', '2.1.9', 'Ensure network file system services are not in use')
        self.check_service_disabled('nis', '2.1.10', 'Ensure nis server services are not in use')
        self.check_service_disabled('cups', '2.1.11', 'Ensure print server services are not in use')
        self.check_service_disabled('rpcbind', '2.1.12', 'Ensure rpcbind services are not in use')
        self.check_service_disabled('rsync', '2.1.13', 'Ensure rsync services are not in use')
        self.check_service_disabled('smbd', '2.1.14', 'Ensure samba file server services are not in use')
        self.check_service_disabled('snmpd', '2.1.15', 'Ensure snmp services are not in use')
        self.check_service_disabled('tftpd-hpa', '2.1.16', 'Ensure tftp server services are not in use')
        self.check_service_disabled('squid', '2.1.17', 'Ensure web proxy server services are not in use')
        self.check_service_disabled('apache2', '2.1.18', 'Ensure web server services are not in use')
        self.check_service_disabled('nginx', '2.1.18', 'Ensure web server services are not in use')
        self.check_service_disabled('xinetd', '2.1.19', 'Ensure xinetd services are not in use')
        self.check_service_disabled('xserver-xorg', '2.1.20', 'Ensure X window server services are not in use')
        self.check_mta_local_only()
        self.check_listening_services()

    def check_mta_local_only(self):
        """Check if mail transfer agent is configured for local-only mode"""
        # Check if postfix or exim4 is configured to listen only on localhost
        returncode, stdout, stderr = self.run_command(['ss', '-lntu'])

        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id='2.1.21',
                title='Ensure mail transfer agent is configured for local-only mode',
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message='Cannot check network listeners',
                details=stderr
            ))
            return

        # Look for SMTP ports (25, 465, 587) listening on non-localhost addresses
        smtp_listeners = []
        for line in stdout.split('\n'):
            if ':25 ' in line or ':465 ' in line or ':587 ' in line:
                # Check if it's not listening on localhost only
                if '0.0.0.0:' in line or ':::' in line or '*:' in line:
                    smtp_listeners.append(line.strip())

        if smtp_listeners:
            self.reporter.add_result(AuditResult(
                check_id='2.1.21',
                title='Ensure mail transfer agent is configured for local-only mode',
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message='Mail transfer agent is listening on non-localhost addresses',
                details='\n'.join(f'  - {listener}' for listener in smtp_listeners),
                remediation='Configure MTA (postfix/exim4) to listen only on 127.0.0.1'
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id='2.1.21',
                title='Ensure mail transfer agent is configured for local-only mode',
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message='No mail transfer agent listening on external addresses'
            ))

    def check_listening_services(self):
        """Check that only approved services are listening on network interfaces"""
        returncode, stdout, stderr = self.run_command(['ss', '-lntu'])

        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id='2.1.22',
                title='Ensure only approved services are listening on a network interface',
                status=Status.ERROR,
                severity=Severity.HIGH,
                message='Cannot check network listeners',
                details=stderr
            ))
            return

        # Common approved ports for typical server setups
        approved_ports = ['22', '80', '443']  # SSH, HTTP, HTTPS

        listening_services = []
        for line in stdout.split('\n'):
            if 'LISTEN' in line or 'UNCONN' in line:
                # Parse the line to extract port information
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[4] if len(parts) > 4 else parts[3]
                    # Skip localhost listeners
                    if '127.0.0.1:' not in local_addr and '[::1]:' not in local_addr:
                        listening_services.append(line.strip())

        if listening_services:
            # This is informational - we report what's listening
            self.reporter.add_result(AuditResult(
                check_id='2.1.22',
                title='Ensure only approved services are listening on a network interface',
                status=Status.WARNING,
                severity=Severity.HIGH,
                message=f'Found {len(listening_services)} services listening on network interfaces',
                details='\n'.join(f'  - {svc}' for svc in listening_services[:10]),  # Show first 10
                remediation='Review listening services and disable any unnecessary ones'
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id='2.1.22',
                title='Ensure only approved services are listening on a network interface',
                status=Status.PASS,
                severity=Severity.HIGH,
                message='No services listening on external network interfaces'
            ))


class KernelModuleAuditor(BaseAuditor):
    """Auditor for kernel module configurations"""

    def _check_module_disabled(self, module_name: str, check_id: str, title: str):
        """Check if a kernel module is disabled"""
        issues = []

        # Check if module is currently loaded
        returncode, stdout, stderr = self.run_command(['lsmod'])
        if returncode == 0:
            if module_name in stdout:
                issues.append(f"Module {module_name} is currently loaded")

        # Check if module is configured to be disabled in modprobe
        modprobe_config = f'/etc/modprobe.d/{module_name}.conf'

        # Also check common blacklist files
        check_paths = [
            modprobe_config,
            '/etc/modprobe.d/blacklist.conf',
            '/etc/modprobe.d/CIS.conf'
        ]

        module_disabled = False
        for conf_path in check_paths:
            if self.file_exists(conf_path):
                content = self.read_file(conf_path)
                if content:
                    # Check for install <module> /bin/true or /bin/false
                    if f'install {module_name}' in content and ('/bin/true' in content or '/bin/false' in content):
                        module_disabled = True
                        break
                    # Check for blacklist
                    if f'blacklist {module_name}' in content:
                        module_disabled = True
                        break

        if not module_disabled:
            issues.append(f"Module {module_name} is not disabled in modprobe configuration")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Kernel module {module_name} is not properly disabled",
                details='\n'.join(f'  - {issue}' for issue in issues),
                remediation=f"Create /etc/modprobe.d/{module_name}.conf with:\ninstall {module_name} /bin/true\nblacklist {module_name}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"Kernel module {module_name} is properly disabled"
            ))

    def run_all_checks(self):
        """Run all kernel module checks"""
        # Filesystem Kernel Modules (1.1.1.x - 10 checks)
        self._check_module_disabled('cramfs', '1.1.1.1', 'Ensure cramfs kernel module is not available')
        self._check_module_disabled('freevxfs', '1.1.1.2', 'Ensure freevxfs kernel module is not available')
        self._check_module_disabled('hfs', '1.1.1.3', 'Ensure hfs kernel module is not available')
        self._check_module_disabled('hfsplus', '1.1.1.4', 'Ensure hfsplus kernel module is not available')
        self._check_module_disabled('jffs2', '1.1.1.5', 'Ensure jffs2 kernel module is not available')
        self._check_module_disabled('overlay', '1.1.1.6', 'Ensure overlayfs kernel module is not available')
        self._check_module_disabled('squashfs', '1.1.1.7', 'Ensure squashfs kernel module is not available')
        self._check_module_disabled('udf', '1.1.1.8', 'Ensure udf kernel module is not available')
        self._check_module_disabled('usb_storage', '1.1.1.9', 'Ensure usb-storage kernel module is not available')
        # 1.1.1.10 is covered by the above checks


class NetworkAuditor(BaseAuditor):
    """Auditor for network configurations"""

    def check_ip_forwarding(self):
        """Check if IP forwarding is disabled"""
        ipv4_forward = self.read_file('/proc/sys/net/ipv4/ip_forward')

        if ipv4_forward and ipv4_forward.strip() == '0':
            self.reporter.add_result(AuditResult(
                check_id="3.1.1",
                title="Ensure IP forwarding is disabled",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="IPv4 forwarding is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="3.1.1",
                title="Ensure IP forwarding is disabled",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="IPv4 forwarding is enabled",
                remediation="Set net.ipv4.ip_forward=0 in /etc/sysctl.conf and run sysctl -w net.ipv4.ip_forward=0"
            ))

    def check_icmp_redirects(self):
        """Check if ICMP redirects are disabled"""
        accept_redirects = self.read_file('/proc/sys/net/ipv4/conf/all/accept_redirects')

        if accept_redirects and accept_redirects.strip() == '0':
            self.reporter.add_result(AuditResult(
                check_id="3.2.2",
                title="Ensure ICMP redirects are not accepted",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="ICMP redirects are not accepted"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="3.2.2",
                title="Ensure ICMP redirects are not accepted",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="ICMP redirects are accepted",
                remediation="Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.conf"
            ))

    def _check_sysctl_parameter(self, param_path: str, expected_value: str, check_id: str, title: str, severity: Severity = Severity.MEDIUM):
        """Generic method to check a sysctl parameter"""
        value = self.read_file(param_path)

        if value and value.strip() == expected_value:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.PASS,
                severity=severity,
                message=f"Parameter is correctly set to {expected_value}"
            ))
        else:
            actual = value.strip() if value else "not set"
            param_name = param_path.replace('/proc/sys/', '').replace('/', '.')
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.FAIL,
                severity=severity,
                message=f"Parameter is set to '{actual}', expected '{expected_value}'",
                remediation=f"Set {param_name}={expected_value} in /etc/sysctl.conf and run sysctl -w {param_name}={expected_value}"
            ))

    def run_all_checks(self):
        """Run all network checks"""
        # Legacy checks (3.1.x and 3.2.x)
        self.check_ip_forwarding()
        self.check_icmp_redirects()

        # Network Kernel Parameters (3.3.x - 11 checks)
        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/ip_forward',
            '0',
            '3.3.1',
            'Ensure ip forwarding is disabled'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/conf/all/send_redirects',
            '0',
            '3.3.2',
            'Ensure packet redirect sending is disabled'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses',
            '1',
            '3.3.3',
            'Ensure bogus icmp responses are ignored'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts',
            '1',
            '3.3.4',
            'Ensure broadcast icmp requests are ignored'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/conf/all/accept_redirects',
            '0',
            '3.3.5',
            'Ensure icmp redirects are not accepted'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/conf/all/secure_redirects',
            '0',
            '3.3.6',
            'Ensure secure icmp redirects are not accepted'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/conf/all/rp_filter',
            '1',
            '3.3.7',
            'Ensure reverse path filtering is enabled'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/conf/all/accept_source_route',
            '0',
            '3.3.8',
            'Ensure source routed packets are not accepted'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/conf/all/log_martians',
            '1',
            '3.3.9',
            'Ensure suspicious packets are logged'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv4/tcp_syncookies',
            '1',
            '3.3.10',
            'Ensure tcp syn cookies is enabled'
        )

        self._check_sysctl_parameter(
            '/proc/sys/net/ipv6/conf/all/accept_ra',
            '0',
            '3.3.11',
            'Ensure ipv6 router advertisements are not accepted'
        )


class SSHAuditor(BaseAuditor):
    """Auditor for SSH server configuration"""

    def _parse_sshd_config(self) -> Dict[str, str]:
        """Parse sshd_config file and return configuration dict"""
        config_path = '/etc/ssh/sshd_config'
        config = {}

        content = self.read_file(config_path)
        if not content:
            return config

        for line in content.split('\n'):
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Parse key value pairs
            parts = line.split(None, 1)
            if len(parts) >= 2:
                key = parts[0].lower()
                value = parts[1]
                config[key] = value

        return config

    def check_sshd_config_permissions(self):
        """Check permissions on /etc/ssh/sshd_config"""
        path = '/etc/ssh/sshd_config'
        expected_mode = 0o600
        expected_owner = 'root'
        expected_group = 'root'

        if not self.file_exists(path):
            self.reporter.add_result(AuditResult(
                check_id="5.1.1",
                title="Ensure permissions on /etc/ssh/sshd_config are configured",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"{path} not found"
            ))
            return

        stat_info = self.get_file_stat(path)
        if not stat_info:
            self.reporter.add_result(AuditResult(
                check_id="5.1.1",
                title="Ensure permissions on /etc/ssh/sshd_config are configured",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Cannot stat {path}"
            ))
            return

        issues = []
        mode = stat.S_IMODE(stat_info.st_mode)

        # Should be 0600 or more restrictive
        if mode & 0o177:
            issues.append(f"Too permissive mode: {oct(mode)}, expected: {oct(expected_mode)} or more restrictive")

        try:
            owner = pwd.getpwuid(stat_info.st_uid).pw_name
            if owner != expected_owner:
                issues.append(f"Incorrect owner: {owner}, expected: {expected_owner}")
        except KeyError:
            issues.append(f"Unknown owner UID: {stat_info.st_uid}")

        try:
            group = grp.getgrgid(stat_info.st_gid).gr_name
            if group != expected_group:
                issues.append(f"Incorrect group: {group}, expected: {expected_group}")
        except KeyError:
            issues.append(f"Unknown group GID: {stat_info.st_gid}")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="5.1.1",
                title="Ensure permissions on /etc/ssh/sshd_config are configured",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                message="Incorrect permissions on /etc/ssh/sshd_config",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation=f"chown root:root {path} && chmod 600 {path}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.1",
                title="Ensure permissions on /etc/ssh/sshd_config are configured",
                status=Status.PASS,
                severity=Severity.CRITICAL,
                message="/etc/ssh/sshd_config permissions are correct"
            ))

    def check_ssh_private_keys(self):
        """Check permissions on SSH private host key files"""
        returncode, stdout, stderr = self.run_command([
            'find', '/etc/ssh', '-xdev', '-type', 'f', '-name', 'ssh_host_*_key'
        ])

        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="5.1.2",
                title="Ensure permissions on SSH private host key files are configured",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message="Cannot find SSH private key files",
                details=stderr
            ))
            return

        key_files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
        if not key_files:
            self.reporter.add_result(AuditResult(
                check_id="5.1.2",
                title="Ensure permissions on SSH private host key files are configured",
                status=Status.WARNING,
                severity=Severity.CRITICAL,
                message="No SSH private key files found"
            ))
            return

        issues = []
        for key_file in key_files:
            stat_info = self.get_file_stat(key_file)
            if not stat_info:
                continue

            mode = stat.S_IMODE(stat_info.st_mode)

            # Should be 0600 or more restrictive
            if mode & 0o177:
                issues.append(f"{key_file}: mode {oct(mode)} (expected 0600)")

            try:
                owner = pwd.getpwuid(stat_info.st_uid).pw_name
                if owner != 'root':
                    issues.append(f"{key_file}: owner {owner} (expected root)")
            except KeyError:
                issues.append(f"{key_file}: unknown owner UID {stat_info.st_uid}")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="5.1.2",
                title="Ensure permissions on SSH private host key files are configured",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                message="SSH private key files have incorrect permissions",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="chmod 600 /etc/ssh/ssh_host_*_key && chown root:root /etc/ssh/ssh_host_*_key"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.2",
                title="Ensure permissions on SSH private host key files are configured",
                status=Status.PASS,
                severity=Severity.CRITICAL,
                message="SSH private key file permissions are correct"
            ))

    def check_ssh_public_keys(self):
        """Check permissions on SSH public host key files"""
        returncode, stdout, stderr = self.run_command([
            'find', '/etc/ssh', '-xdev', '-type', 'f', '-name', 'ssh_host_*_key.pub'
        ])

        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="5.1.3",
                title="Ensure permissions on SSH public host key files are configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="Cannot find SSH public key files",
                details=stderr
            ))
            return

        key_files = [f.strip() for f in stdout.strip().split('\n') if f.strip()]
        if not key_files:
            self.reporter.add_result(AuditResult(
                check_id="5.1.3",
                title="Ensure permissions on SSH public host key files are configured",
                status=Status.WARNING,
                severity=Severity.HIGH,
                message="No SSH public key files found"
            ))
            return

        issues = []
        for key_file in key_files:
            stat_info = self.get_file_stat(key_file)
            if not stat_info:
                continue

            mode = stat.S_IMODE(stat_info.st_mode)

            # Should be 0644 or more restrictive
            if mode & 0o133:
                issues.append(f"{key_file}: mode {oct(mode)} (expected 0644)")

            try:
                owner = pwd.getpwuid(stat_info.st_uid).pw_name
                if owner != 'root':
                    issues.append(f"{key_file}: owner {owner} (expected root)")
            except KeyError:
                issues.append(f"{key_file}: unknown owner UID {stat_info.st_uid}")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="5.1.3",
                title="Ensure permissions on SSH public host key files are configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="SSH public key files have incorrect permissions",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="chmod 644 /etc/ssh/ssh_host_*_key.pub && chown root:root /etc/ssh/ssh_host_*_key.pub"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.3",
                title="Ensure permissions on SSH public host key files are configured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="SSH public key file permissions are correct"
            ))

    def check_sshd_access(self):
        """Check if sshd access is configured"""
        config = self._parse_sshd_config()

        has_allow_users = 'allowusers' in config
        has_allow_groups = 'allowgroups' in config
        has_deny_users = 'denyusers' in config
        has_deny_groups = 'denygroups' in config

        if has_allow_users or has_allow_groups or has_deny_users or has_deny_groups:
            details = []
            if has_allow_users:
                details.append(f"AllowUsers: {config['allowusers']}")
            if has_allow_groups:
                details.append(f"AllowGroups: {config['allowgroups']}")
            if has_deny_users:
                details.append(f"DenyUsers: {config['denyusers']}")
            if has_deny_groups:
                details.append(f"DenyGroups: {config['denygroups']}")

            self.reporter.add_result(AuditResult(
                check_id="5.1.4",
                title="Ensure sshd access is configured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="SSH access restrictions are configured",
                details="\n".join(f"  - {d}" for d in details)
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.4",
                title="Ensure sshd access is configured",
                status=Status.WARNING,
                severity=Severity.HIGH,
                message="No SSH access restrictions configured",
                details="Consider using AllowUsers, AllowGroups, DenyUsers, or DenyGroups",
                remediation="Add 'AllowUsers <userlist>' or 'AllowGroups <grouplist>' to /etc/ssh/sshd_config"
            ))

    def check_sshd_banner(self):
        """Check if sshd Banner is configured"""
        config = self._parse_sshd_config()

        banner = config.get('banner', '').lower()

        if banner and banner != 'none':
            self.reporter.add_result(AuditResult(
                check_id="5.1.5",
                title="Ensure sshd Banner is configured",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"SSH banner is configured: {config.get('banner')}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.5",
                title="Ensure sshd Banner is configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="SSH banner is not configured",
                remediation="Add 'Banner /etc/issue.net' to /etc/ssh/sshd_config"
            ))

    def check_sshd_ciphers(self):
        """Check if sshd Ciphers are configured"""
        config = self._parse_sshd_config()

        # Recommended strong ciphers
        recommended_ciphers = [
            'chacha20-poly1305@openssh.com',
            'aes256-gcm@openssh.com',
            'aes128-gcm@openssh.com',
            'aes256-ctr',
            'aes192-ctr',
            'aes128-ctr'
        ]

        ciphers = config.get('ciphers', '')

        if ciphers:
            configured_ciphers = [c.strip() for c in ciphers.split(',')]
            weak_ciphers = [c for c in configured_ciphers if 'cbc' in c.lower() or 'arcfour' in c.lower() or '3des' in c.lower()]

            if weak_ciphers:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.6",
                    title="Ensure sshd Ciphers are configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Weak SSH ciphers are configured",
                    details=f"Weak ciphers found: {', '.join(weak_ciphers)}",
                    remediation=f"Set 'Ciphers {','.join(recommended_ciphers)}' in /etc/ssh/sshd_config"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.6",
                    title="Ensure sshd Ciphers are configured",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="Strong SSH ciphers are configured"
                ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.6",
                title="Ensure sshd Ciphers are configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="SSH ciphers are not explicitly configured",
                remediation=f"Add 'Ciphers {','.join(recommended_ciphers)}' to /etc/ssh/sshd_config"
            ))

    def check_sshd_clientalive(self):
        """Check if sshd ClientAliveInterval and ClientAliveCountMax are configured"""
        config = self._parse_sshd_config()

        interval = config.get('clientaliveinterval', '0')
        count_max = config.get('clientalivecountmax', '3')

        issues = []
        try:
            interval_val = int(interval)
            if interval_val <= 0 or interval_val > 900:
                issues.append(f"ClientAliveInterval={interval} (should be 1-900)")
        except ValueError:
            issues.append(f"ClientAliveInterval={interval} (invalid value)")

        try:
            count_val = int(count_max)
            if count_val < 0 or count_val > 3:
                issues.append(f"ClientAliveCountMax={count_max} (should be 0-3)")
        except ValueError:
            issues.append(f"ClientAliveCountMax={count_max} (invalid value)")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="5.1.7",
                title="Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="SSH client alive settings not properly configured",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="Add 'ClientAliveInterval 300' and 'ClientAliveCountMax 3' to /etc/ssh/sshd_config"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.7",
                title="Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"SSH client alive settings configured correctly (Interval={interval}, CountMax={count_max})"
            ))

    def check_sshd_disableforwarding(self):
        """Check if sshd DisableForwarding is enabled"""
        config = self._parse_sshd_config()

        disable_forwarding = config.get('disableforwarding', 'no').lower()

        if disable_forwarding == 'yes':
            self.reporter.add_result(AuditResult(
                check_id="5.1.8",
                title="Ensure sshd DisableForwarding is enabled",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="SSH forwarding is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.8",
                title="Ensure sshd DisableForwarding is enabled",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="SSH forwarding is not disabled",
                remediation="Add 'DisableForwarding yes' to /etc/ssh/sshd_config"
            ))

    def check_sshd_gssapi(self):
        """Check if sshd GSSAPIAuthentication is disabled"""
        config = self._parse_sshd_config()

        gssapi = config.get('gssapiauthentication', 'no').lower()

        if gssapi == 'no':
            self.reporter.add_result(AuditResult(
                check_id="5.1.9",
                title="Ensure sshd GSSAPIAuthentication is disabled",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="SSH GSSAPI authentication is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.9",
                title="Ensure sshd GSSAPIAuthentication is disabled",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="SSH GSSAPI authentication is enabled",
                remediation="Add 'GSSAPIAuthentication no' to /etc/ssh/sshd_config"
            ))

    def check_sshd_hostbased(self):
        """Check if sshd HostbasedAuthentication is disabled"""
        config = self._parse_sshd_config()

        hostbased = config.get('hostbasedauthentication', 'no').lower()

        if hostbased == 'no':
            self.reporter.add_result(AuditResult(
                check_id="5.1.10",
                title="Ensure sshd HostbasedAuthentication is disabled",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="SSH host-based authentication is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.10",
                title="Ensure sshd HostbasedAuthentication is disabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="SSH host-based authentication is enabled",
                remediation="Add 'HostbasedAuthentication no' to /etc/ssh/sshd_config"
            ))

    def check_sshd_ignorerhosts(self):
        """Check if sshd IgnoreRhosts is enabled"""
        config = self._parse_sshd_config()

        ignore_rhosts = config.get('ignorerhosts', 'yes').lower()

        if ignore_rhosts == 'yes':
            self.reporter.add_result(AuditResult(
                check_id="5.1.11",
                title="Ensure sshd IgnoreRhosts is enabled",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="SSH IgnoreRhosts is enabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.11",
                title="Ensure sshd IgnoreRhosts is enabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="SSH IgnoreRhosts is disabled",
                remediation="Add 'IgnoreRhosts yes' to /etc/ssh/sshd_config"
            ))

    def check_sshd_kexalgorithms(self):
        """Check if sshd KexAlgorithms is configured"""
        config = self._parse_sshd_config()

        # Recommended strong key exchange algorithms
        recommended_kex = [
            'curve25519-sha256',
            'curve25519-sha256@libssh.org',
            'ecdh-sha2-nistp521',
            'ecdh-sha2-nistp384',
            'ecdh-sha2-nistp256',
            'diffie-hellman-group-exchange-sha256'
        ]

        kex = config.get('kexalgorithms', '')

        if kex:
            configured_kex = [k.strip() for k in kex.split(',')]
            weak_kex = [k for k in configured_kex if 'sha1' in k.lower() or 'diffie-hellman-group1' in k.lower() or 'diffie-hellman-group14-sha1' in k.lower()]

            if weak_kex:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.12",
                    title="Ensure sshd KexAlgorithms is configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Weak SSH key exchange algorithms are configured",
                    details=f"Weak algorithms found: {', '.join(weak_kex)}",
                    remediation=f"Set 'KexAlgorithms {','.join(recommended_kex)}' in /etc/ssh/sshd_config"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.12",
                    title="Ensure sshd KexAlgorithms is configured",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="Strong SSH key exchange algorithms are configured"
                ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.12",
                title="Ensure sshd KexAlgorithms is configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="SSH key exchange algorithms are not explicitly configured",
                remediation=f"Add 'KexAlgorithms {','.join(recommended_kex)}' to /etc/ssh/sshd_config"
            ))

    def check_sshd_logingracetime(self):
        """Check if sshd LoginGraceTime is configured"""
        config = self._parse_sshd_config()

        grace_time = config.get('logingracetime', '120')

        try:
            # Remove 's' or 'm' suffix if present
            if grace_time.endswith('s'):
                grace_val = int(grace_time[:-1])
            elif grace_time.endswith('m'):
                grace_val = int(grace_time[:-1]) * 60
            else:
                grace_val = int(grace_time)

            if grace_val > 0 and grace_val <= 60:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.13",
                    title="Ensure sshd LoginGraceTime is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message=f"SSH LoginGraceTime is configured correctly: {grace_time}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.13",
                    title="Ensure sshd LoginGraceTime is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"SSH LoginGraceTime is too high: {grace_time} (should be 1-60 seconds)",
                    remediation="Add 'LoginGraceTime 60' to /etc/ssh/sshd_config"
                ))
        except ValueError:
            self.reporter.add_result(AuditResult(
                check_id="5.1.13",
                title="Ensure sshd LoginGraceTime is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"SSH LoginGraceTime has invalid value: {grace_time}"
            ))

    def check_sshd_loglevel(self):
        """Check if sshd LogLevel is configured"""
        config = self._parse_sshd_config()

        log_level = config.get('loglevel', 'INFO').upper()

        acceptable_levels = ['VERBOSE', 'INFO']

        if log_level in acceptable_levels:
            self.reporter.add_result(AuditResult(
                check_id="5.1.14",
                title="Ensure sshd LogLevel is configured",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"SSH LogLevel is configured correctly: {log_level}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.14",
                title="Ensure sshd LogLevel is configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"SSH LogLevel is not optimal: {log_level} (should be VERBOSE or INFO)",
                remediation="Add 'LogLevel VERBOSE' or 'LogLevel INFO' to /etc/ssh/sshd_config"
            ))

    def check_sshd_macs(self):
        """Check if sshd MACs are configured"""
        config = self._parse_sshd_config()

        # Recommended strong MACs
        recommended_macs = [
            'hmac-sha2-512-etm@openssh.com',
            'hmac-sha2-256-etm@openssh.com',
            'hmac-sha2-512',
            'hmac-sha2-256'
        ]

        macs = config.get('macs', '')

        if macs:
            configured_macs = [m.strip() for m in macs.split(',')]
            weak_macs = [m for m in configured_macs if 'md5' in m.lower() or 'sha1' in m.lower() and 'sha2' not in m.lower()]

            if weak_macs:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.15",
                    title="Ensure sshd MACs are configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Weak SSH MACs are configured",
                    details=f"Weak MACs found: {', '.join(weak_macs)}",
                    remediation=f"Set 'MACs {','.join(recommended_macs)}' in /etc/ssh/sshd_config"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.15",
                    title="Ensure sshd MACs are configured",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="Strong SSH MACs are configured"
                ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.15",
                title="Ensure sshd MACs are configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="SSH MACs are not explicitly configured",
                remediation=f"Add 'MACs {','.join(recommended_macs)}' to /etc/ssh/sshd_config"
            ))

    def check_sshd_maxauthtries(self):
        """Check if sshd MaxAuthTries is configured"""
        config = self._parse_sshd_config()

        max_tries = config.get('maxauthtries', '6')

        try:
            tries_val = int(max_tries)
            if tries_val >= 1 and tries_val <= 4:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.16",
                    title="Ensure sshd MaxAuthTries is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message=f"SSH MaxAuthTries is configured correctly: {max_tries}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.16",
                    title="Ensure sshd MaxAuthTries is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"SSH MaxAuthTries is too high: {max_tries} (should be 1-4)",
                    remediation="Add 'MaxAuthTries 4' to /etc/ssh/sshd_config"
                ))
        except ValueError:
            self.reporter.add_result(AuditResult(
                check_id="5.1.16",
                title="Ensure sshd MaxAuthTries is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"SSH MaxAuthTries has invalid value: {max_tries}"
            ))

    def check_sshd_maxsessions(self):
        """Check if sshd MaxSessions is configured"""
        config = self._parse_sshd_config()

        max_sessions = config.get('maxsessions', '10')

        try:
            sessions_val = int(max_sessions)
            if sessions_val >= 1 and sessions_val <= 10:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.17",
                    title="Ensure sshd MaxSessions is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message=f"SSH MaxSessions is configured correctly: {max_sessions}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.1.17",
                    title="Ensure sshd MaxSessions is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"SSH MaxSessions is too high: {max_sessions} (should be 1-10)",
                    remediation="Add 'MaxSessions 10' to /etc/ssh/sshd_config"
                ))
        except ValueError:
            self.reporter.add_result(AuditResult(
                check_id="5.1.17",
                title="Ensure sshd MaxSessions is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"SSH MaxSessions has invalid value: {max_sessions}"
            ))

    def check_sshd_maxstartups(self):
        """Check if sshd MaxStartups is configured"""
        config = self._parse_sshd_config()

        max_startups = config.get('maxstartups', '10:30:60')

        # MaxStartups format: start:rate:full
        if ':' in max_startups:
            self.reporter.add_result(AuditResult(
                check_id="5.1.18",
                title="Ensure sshd MaxStartups is configured",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"SSH MaxStartups is configured: {max_startups}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.18",
                title="Ensure sshd MaxStartups is configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"SSH MaxStartups may not be optimally configured: {max_startups}",
                remediation="Add 'MaxStartups 10:30:60' to /etc/ssh/sshd_config"
            ))

    def check_sshd_permitemptypasswords(self):
        """Check if sshd PermitEmptyPasswords is disabled"""
        config = self._parse_sshd_config()

        permit_empty = config.get('permitemptypasswords', 'no').lower()

        if permit_empty == 'no':
            self.reporter.add_result(AuditResult(
                check_id="5.1.19",
                title="Ensure sshd PermitEmptyPasswords is disabled",
                status=Status.PASS,
                severity=Severity.CRITICAL,
                message="SSH PermitEmptyPasswords is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.19",
                title="Ensure sshd PermitEmptyPasswords is disabled",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                message="SSH PermitEmptyPasswords is enabled - CRITICAL SECURITY ISSUE",
                remediation="Add 'PermitEmptyPasswords no' to /etc/ssh/sshd_config"
            ))

    def check_sshd_permitrootlogin(self):
        """Check if sshd PermitRootLogin is disabled"""
        config = self._parse_sshd_config()

        permit_root = config.get('permitrootlogin', 'prohibit-password').lower()

        if permit_root == 'no':
            self.reporter.add_result(AuditResult(
                check_id="5.1.20",
                title="Ensure sshd PermitRootLogin is disabled",
                status=Status.PASS,
                severity=Severity.CRITICAL,
                message="SSH PermitRootLogin is disabled"
            ))
        elif permit_root in ['without-password', 'prohibit-password']:
            self.reporter.add_result(AuditResult(
                check_id="5.1.20",
                title="Ensure sshd PermitRootLogin is disabled",
                status=Status.WARNING,
                severity=Severity.CRITICAL,
                message=f"SSH PermitRootLogin is '{permit_root}' (key-based auth allowed)",
                details="Consider setting to 'no' for maximum security",
                remediation="Change 'PermitRootLogin no' in /etc/ssh/sshd_config"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.20",
                title="Ensure sshd PermitRootLogin is disabled",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                message=f"SSH PermitRootLogin is '{permit_root}' - CRITICAL SECURITY ISSUE",
                remediation="Add 'PermitRootLogin no' to /etc/ssh/sshd_config"
            ))

    def check_sshd_permituserenvironment(self):
        """Check if sshd PermitUserEnvironment is disabled"""
        config = self._parse_sshd_config()

        permit_userenv = config.get('permituserenvironment', 'no').lower()

        if permit_userenv == 'no':
            self.reporter.add_result(AuditResult(
                check_id="5.1.21",
                title="Ensure sshd PermitUserEnvironment is disabled",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="SSH PermitUserEnvironment is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.21",
                title="Ensure sshd PermitUserEnvironment is disabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="SSH PermitUserEnvironment is enabled",
                remediation="Add 'PermitUserEnvironment no' to /etc/ssh/sshd_config"
            ))

    def check_sshd_usepam(self):
        """Check if sshd UsePAM is enabled"""
        config = self._parse_sshd_config()

        use_pam = config.get('usepam', 'yes').lower()

        if use_pam == 'yes':
            self.reporter.add_result(AuditResult(
                check_id="5.1.22",
                title="Ensure sshd UsePAM is enabled",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="SSH UsePAM is enabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.1.22",
                title="Ensure sshd UsePAM is enabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="SSH UsePAM is disabled",
                remediation="Add 'UsePAM yes' to /etc/ssh/sshd_config"
            ))

    def run_all_checks(self):
        """Run all SSH checks"""
        # File permission checks
        self.check_sshd_config_permissions()
        self.check_ssh_private_keys()
        self.check_ssh_public_keys()

        # Configuration parameter checks
        self.check_sshd_access()
        self.check_sshd_banner()
        self.check_sshd_ciphers()
        self.check_sshd_clientalive()
        self.check_sshd_disableforwarding()
        self.check_sshd_gssapi()
        self.check_sshd_hostbased()
        self.check_sshd_ignorerhosts()
        self.check_sshd_kexalgorithms()
        self.check_sshd_logingracetime()
        self.check_sshd_loglevel()
        self.check_sshd_macs()
        self.check_sshd_maxauthtries()
        self.check_sshd_maxsessions()
        self.check_sshd_maxstartups()
        self.check_sshd_permitemptypasswords()
        self.check_sshd_permitrootlogin()
        self.check_sshd_permituserenvironment()
        self.check_sshd_usepam()


class FilesystemPartitionAuditor(BaseAuditor):
    """Auditor for filesystem partition configurations"""

    def __init__(self, reporter: AuditReporter):
        super().__init__(reporter)
        self.mounts = self._parse_mounts()

    def _parse_mounts(self) -> Dict[str, Dict[str, str]]:
        """Parse /proc/mounts to get mounted filesystems and their options"""
        mounts = {}

        content = self.read_file('/proc/mounts')
        if not content:
            return mounts

        for line in content.split('\n'):
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) >= 4:
                device = parts[0]
                mount_point = parts[1]
                fs_type = parts[2]
                options = parts[3].split(',')

                mounts[mount_point] = {
                    'device': device,
                    'type': fs_type,
                    'options': options
                }

        return mounts

    def _check_partition_exists(self, mount_point: str, check_id: str, title: str):
        """Generic method to check if a partition exists"""
        if mount_point in self.mounts:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"{mount_point} is mounted as a separate partition"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"{mount_point} is not a separate partition",
                remediation=f"Create a separate partition for {mount_point} and add it to /etc/fstab"
            ))

    def _check_mount_option(self, mount_point: str, option: str, check_id: str, title: str, severity: Severity = Severity.HIGH):
        """Generic method to check if a mount option is set"""
        if mount_point not in self.mounts:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.SKIP,
                severity=severity,
                message=f"{mount_point} is not a separate partition - check skipped"
            ))
            return

        options = self.mounts[mount_point]['options']

        if option in options:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.PASS,
                severity=severity,
                message=f"{option} option is set on {mount_point}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.FAIL,
                severity=severity,
                message=f"{option} option is not set on {mount_point}",
                details=f"Current options: {', '.join(options)}",
                remediation=f"Edit /etc/fstab and add '{option}' to the mount options for {mount_point}, then remount"
            ))

    # /tmp partition checks
    def check_tmp_partition(self):
        """Check if /tmp is a separate partition"""
        self._check_partition_exists('/tmp', '1.1.2.1.1', 'Ensure /tmp is a separate partition')

    def check_tmp_nodev(self):
        """Check if nodev option is set on /tmp"""
        self._check_mount_option('/tmp', 'nodev', '1.1.2.1.2', 'Ensure nodev option set on /tmp partition')

    def check_tmp_nosuid(self):
        """Check if nosuid option is set on /tmp"""
        self._check_mount_option('/tmp', 'nosuid', '1.1.2.1.3', 'Ensure nosuid option set on /tmp partition')

    def check_tmp_noexec(self):
        """Check if noexec option is set on /tmp"""
        self._check_mount_option('/tmp', 'noexec', '1.1.2.1.4', 'Ensure noexec option set on /tmp partition')

    # /dev/shm partition checks
    def check_devshm_partition(self):
        """Check if /dev/shm is a separate partition"""
        self._check_partition_exists('/dev/shm', '1.1.2.2.1', 'Ensure /dev/shm is a separate partition')

    def check_devshm_nodev(self):
        """Check if nodev option is set on /dev/shm"""
        self._check_mount_option('/dev/shm', 'nodev', '1.1.2.2.2', 'Ensure nodev option set on /dev/shm partition')

    def check_devshm_nosuid(self):
        """Check if nosuid option is set on /dev/shm"""
        self._check_mount_option('/dev/shm', 'nosuid', '1.1.2.2.3', 'Ensure nosuid option set on /dev/shm partition')

    def check_devshm_noexec(self):
        """Check if noexec option is set on /dev/shm"""
        self._check_mount_option('/dev/shm', 'noexec', '1.1.2.2.4', 'Ensure noexec option set on /dev/shm partition')

    # /home partition checks
    def check_home_partition(self):
        """Check if /home is a separate partition"""
        self._check_partition_exists('/home', '1.1.2.3.1', 'Ensure separate partition exists for /home')

    def check_home_nodev(self):
        """Check if nodev option is set on /home"""
        self._check_mount_option('/home', 'nodev', '1.1.2.3.2', 'Ensure nodev option set on /home partition')

    def check_home_nosuid(self):
        """Check if nosuid option is set on /home"""
        self._check_mount_option('/home', 'nosuid', '1.1.2.3.3', 'Ensure nosuid option set on /home partition')

    # /var partition checks
    def check_var_partition(self):
        """Check if /var is a separate partition"""
        self._check_partition_exists('/var', '1.1.2.4.1', 'Ensure separate partition exists for /var')

    def check_var_nodev(self):
        """Check if nodev option is set on /var"""
        self._check_mount_option('/var', 'nodev', '1.1.2.4.2', 'Ensure nodev option set on /var partition')

    def check_var_nosuid(self):
        """Check if nosuid option is set on /var"""
        self._check_mount_option('/var', 'nosuid', '1.1.2.4.3', 'Ensure nosuid option set on /var partition')

    # /var/tmp partition checks
    def check_vartmp_partition(self):
        """Check if /var/tmp is a separate partition"""
        self._check_partition_exists('/var/tmp', '1.1.2.5.1', 'Ensure separate partition exists for /var/tmp')

    def check_vartmp_nodev(self):
        """Check if nodev option is set on /var/tmp"""
        self._check_mount_option('/var/tmp', 'nodev', '1.1.2.5.2', 'Ensure nodev option set on /var/tmp partition')

    def check_vartmp_nosuid(self):
        """Check if nosuid option is set on /var/tmp"""
        self._check_mount_option('/var/tmp', 'nosuid', '1.1.2.5.3', 'Ensure nosuid option set on /var/tmp partition')

    def check_vartmp_noexec(self):
        """Check if noexec option is set on /var/tmp"""
        self._check_mount_option('/var/tmp', 'noexec', '1.1.2.5.4', 'Ensure noexec option set on /var/tmp partition')

    # /var/log partition checks
    def check_varlog_partition(self):
        """Check if /var/log is a separate partition"""
        self._check_partition_exists('/var/log', '1.1.2.6.1', 'Ensure separate partition exists for /var/log')

    def check_varlog_nodev(self):
        """Check if nodev option is set on /var/log"""
        self._check_mount_option('/var/log', 'nodev', '1.1.2.6.2', 'Ensure nodev option set on /var/log partition')

    def check_varlog_nosuid(self):
        """Check if nosuid option is set on /var/log"""
        self._check_mount_option('/var/log', 'nosuid', '1.1.2.6.3', 'Ensure nosuid option set on /var/log partition')

    def check_varlog_noexec(self):
        """Check if noexec option is set on /var/log"""
        self._check_mount_option('/var/log', 'noexec', '1.1.2.6.4', 'Ensure noexec option set on /var/log partition')

    # /var/log/audit partition checks
    def check_varlogaudit_partition(self):
        """Check if /var/log/audit is a separate partition"""
        self._check_partition_exists('/var/log/audit', '1.1.2.7.1', 'Ensure separate partition exists for /var/log/audit')

    def check_varlogaudit_nodev(self):
        """Check if nodev option is set on /var/log/audit"""
        self._check_mount_option('/var/log/audit', 'nodev', '1.1.2.7.2', 'Ensure nodev option set on /var/log/audit partition')

    def check_varlogaudit_nosuid(self):
        """Check if nosuid option is set on /var/log/audit"""
        self._check_mount_option('/var/log/audit', 'nosuid', '1.1.2.7.3', 'Ensure nosuid option set on /var/log/audit partition')

    def check_varlogaudit_noexec(self):
        """Check if noexec option is set on /var/log/audit"""
        self._check_mount_option('/var/log/audit', 'noexec', '1.1.2.7.4', 'Ensure noexec option set on /var/log/audit partition')

    def run_all_checks(self):
        """Run all filesystem partition checks"""
        # /tmp checks
        self.check_tmp_partition()
        self.check_tmp_nodev()
        self.check_tmp_nosuid()
        self.check_tmp_noexec()

        # /dev/shm checks
        self.check_devshm_partition()
        self.check_devshm_nodev()
        self.check_devshm_nosuid()
        self.check_devshm_noexec()

        # /home checks
        self.check_home_partition()
        self.check_home_nodev()
        self.check_home_nosuid()

        # /var checks
        self.check_var_partition()
        self.check_var_nodev()
        self.check_var_nosuid()

        # /var/tmp checks
        self.check_vartmp_partition()
        self.check_vartmp_nodev()
        self.check_vartmp_nosuid()
        self.check_vartmp_noexec()

        # /var/log checks
        self.check_varlog_partition()
        self.check_varlog_nodev()
        self.check_varlog_nosuid()
        self.check_varlog_noexec()

        # /var/log/audit checks
        self.check_varlogaudit_partition()
        self.check_varlogaudit_nodev()
        self.check_varlogaudit_nosuid()
        self.check_varlogaudit_noexec()


class UserAuditor(BaseAuditor):
    """Auditor for user and group configurations"""

    def check_empty_passwords(self):
        """Check for accounts with empty passwords"""
        shadow_content = self.read_file('/etc/shadow')
        if not shadow_content:
            self.reporter.add_result(AuditResult(
                check_id="7.2.2",
                title="Ensure /etc/shadow password fields are not empty",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message="Cannot read /etc/shadow"
            ))
            return

        empty_password_accounts = []
        for line in shadow_content.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    password = parts[1]
                    # Empty password field or just !
                    if not password or password in ['', '!', '!!']:
                        # Skip system accounts that should be locked
                        if username not in ['root', 'daemon', 'bin', 'sys', 'sync', 'games',
                                           'man', 'lp', 'mail', 'news', 'uucp', 'proxy',
                                           'www-data', 'backup', 'list', 'irc', 'gnats',
                                           'nobody', '_apt', 'systemd-network', 'systemd-resolve',
                                           'messagebus', 'systemd-timesync', 'sshd']:
                            # Check if it's a regular user account
                            try:
                                user_info = pwd.getpwnam(username)
                                if user_info.pw_uid >= 1000:  # Regular user
                                    empty_password_accounts.append(username)
                            except KeyError:
                                pass

        if empty_password_accounts:
            self.reporter.add_result(AuditResult(
                check_id="7.2.2",
                title="Ensure /etc/shadow password fields are not empty",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                message="User accounts with empty passwords found",
                details=f"Accounts: {', '.join(empty_password_accounts)}",
                remediation="Lock or set passwords for these accounts"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.2.2",
                title="Ensure /etc/shadow password fields are not empty",
                status=Status.PASS,
                severity=Severity.CRITICAL,
                message="No user accounts with empty passwords"
            ))

    def check_duplicate_uids(self):
        """Check for duplicate UIDs"""
        uid_map = {}
        duplicates = []

        try:
            for user in pwd.getpwall():
                if user.pw_uid in uid_map:
                    duplicates.append(f"UID {user.pw_uid}: {uid_map[user.pw_uid]} and {user.pw_name}")
                else:
                    uid_map[user.pw_uid] = user.pw_name
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="7.2.5",
                title="Ensure no duplicate UIDs exist",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Error checking UIDs: {str(e)}"
            ))
            return

        if duplicates:
            self.reporter.add_result(AuditResult(
                check_id="7.2.5",
                title="Ensure no duplicate UIDs exist",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Duplicate UIDs found",
                details="\n".join(f"  - {dup}" for dup in duplicates),
                remediation="Assign unique UIDs to all users"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.2.5",
                title="Ensure no duplicate UIDs exist",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="No duplicate UIDs found"
            ))

    def check_shadowed_passwords(self):
        """Check that all accounts use shadowed passwords (7.2.1)"""
        passwd_content = self.read_file('/etc/passwd')
        if not passwd_content:
            self.reporter.add_result(AuditResult(
                check_id="7.2.1",
                title="Ensure accounts in /etc/passwd use shadowed passwords",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message="Cannot read /etc/passwd"
            ))
            return

        unshadowed_accounts = []
        for line in passwd_content.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    password_field = parts[1]
                    # Check if password is not 'x' (shadowed)
                    if password_field != 'x':
                        unshadowed_accounts.append(f"{username} (password field: '{password_field}')")

        if unshadowed_accounts:
            self.reporter.add_result(AuditResult(
                check_id="7.2.1",
                title="Ensure accounts in /etc/passwd use shadowed passwords",
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                message="Accounts not using shadowed passwords found",
                details="\n".join(f"  - {acc}" for acc in unshadowed_accounts),
                remediation="Run 'pwconv' to convert passwords to shadow format"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.2.1",
                title="Ensure accounts in /etc/passwd use shadowed passwords",
                status=Status.PASS,
                severity=Severity.CRITICAL,
                message="All accounts use shadowed passwords"
            ))

    def check_groups_exist(self):
        """Check that all groups in /etc/passwd exist in /etc/group (7.2.3)"""
        passwd_content = self.read_file('/etc/passwd')
        if not passwd_content:
            self.reporter.add_result(AuditResult(
                check_id="7.2.3",
                title="Ensure all groups in /etc/passwd exist in /etc/group",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="Cannot read /etc/passwd"
            ))
            return

        # Get all GIDs from /etc/passwd
        passwd_gids = set()
        for line in passwd_content.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 4:
                    try:
                        passwd_gids.add(int(parts[3]))
                    except ValueError:
                        pass

        # Check if all GIDs exist in the group database
        missing_groups = []
        for gid in passwd_gids:
            try:
                grp.getgrgid(gid)
            except KeyError:
                missing_groups.append(str(gid))

        if missing_groups:
            self.reporter.add_result(AuditResult(
                check_id="7.2.3",
                title="Ensure all groups in /etc/passwd exist in /etc/group",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Groups referenced in /etc/passwd not found in /etc/group",
                details=f"Missing GIDs: {', '.join(missing_groups)}",
                remediation="Create missing groups or fix GIDs in /etc/passwd"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.2.3",
                title="Ensure all groups in /etc/passwd exist in /etc/group",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="All groups in /etc/passwd exist in /etc/group"
            ))

    def check_shadow_group_empty(self):
        """Check that shadow group is empty (7.2.4)"""
        try:
            shadow_group = grp.getgrnam('shadow')
            if shadow_group.gr_mem:
                self.reporter.add_result(AuditResult(
                    check_id="7.2.4",
                    title="Ensure shadow group is empty",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Shadow group has members",
                    details=f"Members: {', '.join(shadow_group.gr_mem)}",
                    remediation="Remove all users from the shadow group"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="7.2.4",
                    title="Ensure shadow group is empty",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Shadow group is empty"
                ))
        except KeyError:
            self.reporter.add_result(AuditResult(
                check_id="7.2.4",
                title="Ensure shadow group is empty",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message="Shadow group does not exist"
            ))

    def check_duplicate_gids(self):
        """Check for duplicate GIDs (7.2.6)"""
        gid_map = {}
        duplicates = []

        try:
            for group in grp.getgrall():
                if group.gr_gid in gid_map:
                    duplicates.append(f"GID {group.gr_gid}: {gid_map[group.gr_gid]} and {group.gr_name}")
                else:
                    gid_map[group.gr_gid] = group.gr_name
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="7.2.6",
                title="Ensure no duplicate GIDs exist",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Error checking GIDs: {str(e)}"
            ))
            return

        if duplicates:
            self.reporter.add_result(AuditResult(
                check_id="7.2.6",
                title="Ensure no duplicate GIDs exist",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Duplicate GIDs found",
                details="\n".join(f"  - {dup}" for dup in duplicates),
                remediation="Assign unique GIDs to all groups"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.2.6",
                title="Ensure no duplicate GIDs exist",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="No duplicate GIDs found"
            ))

    def check_duplicate_usernames(self):
        """Check for duplicate usernames (7.2.7)"""
        username_map = {}
        duplicates = []

        passwd_content = self.read_file('/etc/passwd')
        if not passwd_content:
            self.reporter.add_result(AuditResult(
                check_id="7.2.7",
                title="Ensure no duplicate user names exist",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="Cannot read /etc/passwd"
            ))
            return

        for line in passwd_content.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 1:
                    username = parts[0]
                    if username in username_map:
                        duplicates.append(f"Username: {username}")
                    else:
                        username_map[username] = True

        if duplicates:
            self.reporter.add_result(AuditResult(
                check_id="7.2.7",
                title="Ensure no duplicate user names exist",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Duplicate usernames found",
                details="\n".join(f"  - {dup}" for dup in duplicates),
                remediation="Ensure all usernames are unique"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.2.7",
                title="Ensure no duplicate user names exist",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="No duplicate usernames found"
            ))

    def check_duplicate_groupnames(self):
        """Check for duplicate group names (7.2.8)"""
        groupname_map = {}
        duplicates = []

        group_content = self.read_file('/etc/group')
        if not group_content:
            self.reporter.add_result(AuditResult(
                check_id="7.2.8",
                title="Ensure no duplicate group names exist",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="Cannot read /etc/group"
            ))
            return

        for line in group_content.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 1:
                    groupname = parts[0]
                    if groupname in groupname_map:
                        duplicates.append(f"Group name: {groupname}")
                    else:
                        groupname_map[groupname] = True

        if duplicates:
            self.reporter.add_result(AuditResult(
                check_id="7.2.8",
                title="Ensure no duplicate group names exist",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Duplicate group names found",
                details="\n".join(f"  - {dup}" for dup in duplicates),
                remediation="Ensure all group names are unique"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.2.8",
                title="Ensure no duplicate group names exist",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="No duplicate group names found"
            ))

    def check_user_home_directories(self):
        """Check local interactive user home directories (7.2.9)"""
        issues = []

        try:
            for user in pwd.getpwall():
                # Check only regular users (UID >= 1000)
                if user.pw_uid >= 1000 and user.pw_uid != 65534:  # Skip nobody
                    home_dir = user.pw_dir

                    # Check if home directory exists
                    if not os.path.exists(home_dir):
                        issues.append(f"User {user.pw_name}: home directory {home_dir} does not exist")
                        continue

                    # Check ownership
                    try:
                        stat_info = os.stat(home_dir)
                        if stat_info.st_uid != user.pw_uid:
                            owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
                            issues.append(f"User {user.pw_name}: home directory {home_dir} owned by {owner_name} (UID {stat_info.st_uid})")
                    except (OSError, KeyError) as e:
                        issues.append(f"User {user.pw_name}: cannot stat {home_dir} ({str(e)})")

        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="7.2.9",
                title="Ensure local interactive user home directories are configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking home directories: {str(e)}"
            ))
            return

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="7.2.9",
                title="Ensure local interactive user home directories are configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="User home directory issues found",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="Ensure all users have valid home directories with proper ownership"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.2.9",
                title="Ensure local interactive user home directories are configured",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="All user home directories are properly configured"
            ))

    def check_user_dot_files(self):
        """Check local interactive user dot files access (7.2.10)"""
        issues = []

        try:
            for user in pwd.getpwall():
                # Check only regular users (UID >= 1000)
                if user.pw_uid >= 1000 and user.pw_uid != 65534:  # Skip nobody
                    home_dir = user.pw_dir

                    # Check if home directory exists
                    if not os.path.exists(home_dir):
                        continue

                    # Check dot files in home directory
                    try:
                        for entry in os.listdir(home_dir):
                            if entry.startswith('.') and entry not in ['.', '..']:
                                file_path = os.path.join(home_dir, entry)
                                try:
                                    stat_info = os.stat(file_path)
                                    mode = stat.S_IMODE(stat_info.st_mode)

                                    # Check if group-writable or world-writable
                                    if mode & 0o022:
                                        issues.append(f"User {user.pw_name}: {file_path} is group or world writable ({oct(mode)})")

                                    # Check ownership
                                    if stat_info.st_uid != user.pw_uid:
                                        owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
                                        issues.append(f"User {user.pw_name}: {file_path} owned by {owner_name}")
                                except (OSError, KeyError):
                                    pass
                    except OSError:
                        pass

        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="7.2.10",
                title="Ensure local interactive user dot files access is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking dot files: {str(e)}"
            ))
            return

        if issues:
            # Limit output to first 20 issues
            display_issues = issues[:20]
            if len(issues) > 20:
                display_issues.append(f"... and {len(issues) - 20} more issues")

            self.reporter.add_result(AuditResult(
                check_id="7.2.10",
                title="Ensure local interactive user dot files access is configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"User dot file issues found ({len(issues)} issues)",
                details="\n".join(f"  - {issue}" for issue in display_issues),
                remediation="Ensure dot files are not group or world writable and owned by the user"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="7.2.10",
                title="Ensure local interactive user dot files access is configured",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="All user dot files are properly configured"
            ))

    def run_all_checks(self):
        """Run all user/group checks"""
        self.check_shadowed_passwords()
        self.check_empty_passwords()
        self.check_groups_exist()
        self.check_shadow_group_empty()
        self.check_duplicate_uids()
        self.check_duplicate_gids()
        self.check_duplicate_usernames()
        self.check_duplicate_groupnames()
        self.check_user_home_directories()
        self.check_user_dot_files()


class DebianCISAudit:
    """Main audit orchestrator"""

    def __init__(self):
        self.reporter = AuditReporter()

    def run_audit(self):
        """Run all audit checks"""
        print("Starting Debian CIS Benchmark Audit...")
        print("=" * 80)

        # Check if running as root
        if os.geteuid() != 0:
            print("WARNING: Not running as root. Some checks may fail or be incomplete.")
            print("=" * 80)

        # Run all auditors
        print("\n[*] Running Auditd Checks...")
        auditd_auditor = AuditdAuditor(self.reporter)
        auditd_auditor.run_all_checks()

        print("[*] Running System Logging Checks...")
        logging_auditor = SystemLoggingAuditor(self.reporter)
        logging_auditor.run_all_checks()

        print("[*] Running Filesystem Checks...")
        filesystem_auditor = FileSystemAuditor(self.reporter)
        filesystem_auditor.run_all_checks()

        print("[*] Running Kernel Module Checks...")
        kernel_module_auditor = KernelModuleAuditor(self.reporter)
        kernel_module_auditor.run_all_checks()

        print("[*] Running Filesystem Partition Checks...")
        partition_auditor = FilesystemPartitionAuditor(self.reporter)
        partition_auditor.run_all_checks()

        print("[*] Running Service Checks...")
        service_auditor = ServiceAuditor(self.reporter)
        service_auditor.run_all_checks()

        print("[*] Running Network Checks...")
        network_auditor = NetworkAuditor(self.reporter)
        network_auditor.run_all_checks()

        print("[*] Running SSH Configuration Checks...")
        ssh_auditor = SSHAuditor(self.reporter)
        ssh_auditor.run_all_checks()

        print("[*] Running User/Group Checks...")
        user_auditor = UserAuditor(self.reporter)
        user_auditor.run_all_checks()

        print("\n[*] Audit complete!")
        print("=" * 80)

    def generate_report(self, output_format: str = 'console', output_file: Optional[str] = None):
        """Generate and save report"""
        if output_format == 'json':
            report = self.reporter.generate_json_report()
        else:
            report = self.reporter.generate_console_report()

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                print(f"\nReport saved to: {output_file}")
            except Exception as e:
                print(f"\nError saving report: {e}")
                print("\n" + report)
        else:
            print("\n" + report)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Debian CIS Benchmark Audit Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run audit and display console report
  sudo python3 debian_cis_audit.py

  # Run audit and save JSON report
  sudo python3 debian_cis_audit.py --format json --output report.json

  # Run audit and save both console and JSON reports
  sudo python3 debian_cis_audit.py --output report.txt
  sudo python3 debian_cis_audit.py --format json --output report.json
        """
    )

    parser.add_argument(
        '--format',
        choices=['console', 'json'],
        default='console',
        help='Output format (default: console)'
    )

    parser.add_argument(
        '--output',
        '-o',
        help='Output file path (default: print to console)'
    )

    args = parser.parse_args()

    # Create and run audit
    audit = DebianCISAudit()
    audit.run_audit()
    audit.generate_report(output_format=args.format, output_file=args.output)


if __name__ == '__main__':
    main()
