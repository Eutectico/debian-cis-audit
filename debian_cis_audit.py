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

    def run_command(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """Run a shell command and return returncode, stdout, stderr"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
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

    def check_audit_log_directory_permissions(self):
        """6.2.4.2 - Ensure audit log directory permissions are configured"""
        log_dir = '/var/log/audit'

        if not self.file_exists(log_dir):
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.2",
                title="Ensure audit log directory permissions are configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"Audit log directory {log_dir} does not exist"
            ))
            return

        stat_info = self.get_file_stat(log_dir)
        if not stat_info:
            return

        mode = stat.S_IMODE(stat_info.st_mode)
        expected_mode = 0o750  # rwxr-x---

        # Check if permissions are 0750 or more restrictive
        if mode & 0o027:  # Check if group write or other has any permissions
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.2",
                title="Ensure audit log directory permissions are configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"Audit log directory has incorrect permissions: {oct(mode)}",
                details=f"Expected: {oct(expected_mode)} (0750 or more restrictive)",
                remediation=f"chmod 0750 {log_dir}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.2",
                title="Ensure audit log directory permissions are configured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"Audit log directory permissions are correct: {oct(mode)}"
            ))

    def check_audit_config_file_permissions(self):
        """6.2.4.3 - Ensure audit configuration files are mode 0640 or more restrictive"""
        config_file = '/etc/audit/auditd.conf'

        if not self.file_exists(config_file):
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.3",
                title="Ensure audit configuration files are mode 0640 or more restrictive",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Audit config file {config_file} does not exist"
            ))
            return

        stat_info = self.get_file_stat(config_file)
        if not stat_info:
            return

        mode = stat.S_IMODE(stat_info.st_mode)
        expected_mode = 0o640  # rw-r-----

        # Check if permissions are too permissive
        if mode & 0o137:  # Check for owner execute, group write/execute, or other permissions
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.3",
                title="Ensure audit configuration files are mode 0640 or more restrictive",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Audit config file has incorrect permissions: {oct(mode)}",
                details=f"Expected: {oct(expected_mode)} (0640 or more restrictive)",
                remediation=f"chmod 0640 {config_file}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.3",
                title="Ensure audit configuration files are mode 0640 or more restrictive",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"Audit config file permissions are correct: {oct(mode)}"
            ))

    def check_audit_config_file_ownership(self):
        """6.2.4.4 - Ensure audit configuration files are owned by root"""
        config_file = '/etc/audit/auditd.conf'

        if not self.file_exists(config_file):
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.4",
                title="Ensure audit configuration files are owned by root",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Audit config file {config_file} does not exist"
            ))
            return

        stat_info = self.get_file_stat(config_file)
        if not stat_info:
            return

        # Check if owned by root (UID 0)
        if stat_info.st_uid != 0:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.4",
                title="Ensure audit configuration files are owned by root",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Audit config file is not owned by root (UID: {stat_info.st_uid})",
                remediation=f"chown root:root {config_file}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.4",
                title="Ensure audit configuration files are owned by root",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="Audit config file is owned by root"
            ))

    def check_audit_config_file_group_ownership(self):
        """6.2.4.5 - Ensure audit configuration files belong to group root"""
        config_file = '/etc/audit/auditd.conf'

        if not self.file_exists(config_file):
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.5",
                title="Ensure audit configuration files belong to group root",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Audit config file {config_file} does not exist"
            ))
            return

        stat_info = self.get_file_stat(config_file)
        if not stat_info:
            return

        # Check if group is root (GID 0)
        if stat_info.st_gid != 0:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.5",
                title="Ensure audit configuration files belong to group root",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Audit config file does not belong to group root (GID: {stat_info.st_gid})",
                remediation=f"chgrp root {config_file}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.5",
                title="Ensure audit configuration files belong to group root",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="Audit config file belongs to group root"
            ))

    def check_audit_tools_permissions(self):
        """6.2.4.6 - Ensure audit tools are mode 0755 or more restrictive"""
        audit_tools = [
            '/sbin/auditctl',
            '/sbin/aureport',
            '/sbin/ausearch',
            '/sbin/autrace',
            '/sbin/auditd',
            '/sbin/augenrules'
        ]

        issues = []
        passed = []

        for tool in audit_tools:
            if not self.file_exists(tool):
                issues.append(f"{tool} does not exist")
                continue

            stat_info = self.get_file_stat(tool)
            if not stat_info:
                continue

            mode = stat.S_IMODE(stat_info.st_mode)
            expected_mode = 0o755  # rwxr-xr-x

            # Check if permissions are too permissive (e.g., group/other write)
            if mode & 0o022:  # Check for group write or other write
                issues.append(f"{tool} has incorrect permissions: {oct(mode)}")
            else:
                passed.append(tool)

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.6",
                title="Ensure audit tools are mode 0755 or more restrictive",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Some audit tools have incorrect permissions",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="Run: chmod 0755 /sbin/audit{ctl,d,report,search,trace} /sbin/augenrules"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.6",
                title="Ensure audit tools are mode 0755 or more restrictive",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"All audit tools have correct permissions ({len(passed)} tools checked)"
            ))

    def check_audit_tools_ownership(self):
        """6.2.4.7 - Ensure audit tools are owned by root"""
        audit_tools = [
            '/sbin/auditctl',
            '/sbin/aureport',
            '/sbin/ausearch',
            '/sbin/autrace',
            '/sbin/auditd',
            '/sbin/augenrules'
        ]

        issues = []
        passed = []

        for tool in audit_tools:
            if not self.file_exists(tool):
                issues.append(f"{tool} does not exist")
                continue

            stat_info = self.get_file_stat(tool)
            if not stat_info:
                continue

            # Check if owned by root (UID 0)
            if stat_info.st_uid != 0:
                issues.append(f"{tool} is not owned by root (UID: {stat_info.st_uid})")
            else:
                passed.append(tool)

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.7",
                title="Ensure audit tools are owned by root",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Some audit tools are not owned by root",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="Run: chown root /sbin/audit{ctl,d,report,search,trace} /sbin/augenrules"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.7",
                title="Ensure audit tools are owned by root",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"All audit tools are owned by root ({len(passed)} tools checked)"
            ))

    def check_audit_tools_group_ownership(self):
        """6.2.4.8 - Ensure audit tools belong to group root"""
        audit_tools = [
            '/sbin/auditctl',
            '/sbin/aureport',
            '/sbin/ausearch',
            '/sbin/autrace',
            '/sbin/auditd',
            '/sbin/augenrules'
        ]

        issues = []
        passed = []

        for tool in audit_tools:
            if not self.file_exists(tool):
                issues.append(f"{tool} does not exist")
                continue

            stat_info = self.get_file_stat(tool)
            if not stat_info:
                continue

            # Check if group is root (GID 0)
            if stat_info.st_gid != 0:
                issues.append(f"{tool} does not belong to group root (GID: {stat_info.st_gid})")
            else:
                passed.append(tool)

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.8",
                title="Ensure audit tools belong to group root",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Some audit tools do not belong to group root",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="Run: chgrp root /sbin/audit{ctl,d,report,search,trace} /sbin/augenrules"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.8",
                title="Ensure audit tools belong to group root",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"All audit tools belong to group root ({len(passed)} tools checked)"
            ))

    def check_audit_rules_permissions(self):
        """6.2.4.9 - Ensure audit configuration files are mode 0640 or more restrictive"""
        rules_files = [
            '/etc/audit/audit.rules',
            '/etc/audit/rules.d/audit.rules'
        ]

        issues = []
        passed = []
        all_missing = True

        for rules_file in rules_files:
            if not self.file_exists(rules_file):
                continue

            all_missing = False
            stat_info = self.get_file_stat(rules_file)
            if not stat_info:
                continue

            mode = stat.S_IMODE(stat_info.st_mode)
            expected_mode = 0o640  # rw-r-----

            # Check if permissions are too permissive
            if mode & 0o137:  # Check for owner execute, group write/execute, or other permissions
                issues.append(f"{rules_file} has incorrect permissions: {oct(mode)}")
            else:
                passed.append(rules_file)

        if all_missing:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.9",
                title="Ensure audit configuration files are mode 0640 or more restrictive",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message="No audit rules files found",
                details="This may be expected if audit rules are not yet configured"
            ))
        elif issues:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.9",
                title="Ensure audit configuration files are mode 0640 or more restrictive",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Some audit rules files have incorrect permissions",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="Run: chmod 0640 /etc/audit/audit.rules /etc/audit/rules.d/*.rules"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.2.4.9",
                title="Ensure audit configuration files are mode 0640 or more restrictive",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"All audit rules files have correct permissions ({len(passed)} files checked)"
            ))

    def _check_audit_rule(self, check_id: str, title: str, pattern: str, severity=Severity.MEDIUM):
        """Helper method to check if an audit rule exists"""
        # Check in /etc/audit/rules.d/*.rules files
        rules_dir = '/etc/audit/rules.d'
        audit_rules_file = '/etc/audit/audit.rules'

        found = False

        # Check rules.d directory
        if self.file_exists(rules_dir):
            try:
                for filename in os.listdir(rules_dir):
                    if filename.endswith('.rules'):
                        filepath = os.path.join(rules_dir, filename)
                        content = self.read_file(filepath)
                        if content and pattern in content:
                            found = True
                            break
            except Exception:
                pass

        # Also check audit.rules
        if not found and self.file_exists(audit_rules_file):
            content = self.read_file(audit_rules_file)
            if content and pattern in content:
                found = True

        # Alternative: Check running rules with auditctl -l
        if not found:
            returncode, stdout, _ = self.run_command(['auditctl', '-l'])
            if returncode == 0 and pattern in stdout:
                found = True

        if found:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.PASS,
                severity=severity,
                message="Audit rule is configured"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.FAIL,
                severity=severity,
                message="Audit rule is not configured",
                details=f"Expected pattern: {pattern}",
                remediation=f"Add the following rule to /etc/audit/rules.d/50-*.rules:\n{pattern}"
            ))

    def check_audit_time_rules(self):
        """6.2.3.1 - Ensure changes to system time are collected"""
        self._check_audit_rule(
            check_id="6.2.3.1",
            title="Ensure changes to system time are collected",
            pattern="-a always,exit -F arch=b64 -S adjtimex,settimeofday",
            severity=Severity.MEDIUM
        )

    def check_audit_user_group_rules(self):
        """6.2.3.2 - Ensure events that modify user/group information are collected"""
        self._check_audit_rule(
            check_id="6.2.3.2",
            title="Ensure events that modify user/group information are collected",
            pattern="-w /etc/group -p wa",
            severity=Severity.MEDIUM
        )

    def check_audit_network_env_rules(self):
        """6.2.3.3 - Ensure events that modify the system's network environment are collected"""
        self._check_audit_rule(
            check_id="6.2.3.3",
            title="Ensure events that modify the system's network environment are collected",
            pattern="-w /etc/issue -p wa",
            severity=Severity.MEDIUM
        )

    def check_audit_apparmor_rules(self):
        """6.2.3.4 - Ensure events that modify the system's Mandatory Access Controls are collected"""
        self._check_audit_rule(
            check_id="6.2.3.4",
            title="Ensure events that modify the system's Mandatory Access Controls are collected",
            pattern="-w /etc/apparmor/ -p wa",
            severity=Severity.MEDIUM
        )

    def check_audit_login_logout_rules(self):
        """6.2.3.5 - Ensure login and logout events are collected"""
        self._check_audit_rule(
            check_id="6.2.3.5",
            title="Ensure login and logout events are collected",
            pattern="-w /var/log/lastlog -p wa",
            severity=Severity.MEDIUM
        )

    def check_audit_session_rules(self):
        """6.2.3.6 - Ensure session initiation information is collected"""
        self._check_audit_rule(
            check_id="6.2.3.6",
            title="Ensure session initiation information is collected",
            pattern="-w /var/run/utmp -p wa",
            severity=Severity.MEDIUM
        )

    def check_audit_perm_mod_rules(self):
        """6.2.3.7 - Ensure discretionary access control permission modification events are collected"""
        self._check_audit_rule(
            check_id="6.2.3.7",
            title="Ensure discretionary access control permission modification events are collected",
            pattern="-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat",
            severity=Severity.MEDIUM
        )

    def check_audit_access_rules(self):
        """6.2.3.8 - Ensure unsuccessful file access attempts are collected"""
        self._check_audit_rule(
            check_id="6.2.3.8",
            title="Ensure unsuccessful file access attempts are collected",
            pattern="-a always,exit -F arch=b64 -S open,openat,openat2,open_by_handle_at,truncate,ftruncate -F exit=-EACCES",
            severity=Severity.MEDIUM
        )

    def check_audit_privileged_commands_rules(self):
        """6.2.3.9 - Ensure use of privileged commands are collected"""
        # This is a complex check - we need to find all SUID/SGID programs
        # For simplicity, we check for a common pattern
        self._check_audit_rule(
            check_id="6.2.3.9",
            title="Ensure use of privileged commands are collected",
            pattern="-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset",
            severity=Severity.HIGH
        )

    def check_audit_mounts_rules(self):
        """6.2.3.10 - Ensure successful file system mounts are collected"""
        self._check_audit_rule(
            check_id="6.2.3.10",
            title="Ensure successful file system mounts are collected",
            pattern="-a always,exit -F arch=b64 -S mount",
            severity=Severity.MEDIUM
        )

    def check_audit_file_deletion_rules(self):
        """6.2.3.11 - Ensure file deletion events by users are collected"""
        self._check_audit_rule(
            check_id="6.2.3.11",
            title="Ensure file deletion events by users are collected",
            pattern="-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat",
            severity=Severity.MEDIUM
        )

    def check_audit_sudoers_rules(self):
        """6.2.3.12 - Ensure changes to system administration scope (sudoers) are collected"""
        self._check_audit_rule(
            check_id="6.2.3.12",
            title="Ensure changes to system administration scope (sudoers) are collected",
            pattern="-w /etc/sudoers -p wa",
            severity=Severity.HIGH
        )

    def check_audit_sudolog_rules(self):
        """6.2.3.13 - Ensure system administrator command executions (sudo) are collected"""
        self._check_audit_rule(
            check_id="6.2.3.13",
            title="Ensure system administrator command executions (sudo) are collected",
            pattern="-w /var/log/sudo.log -p wa",
            severity=Severity.HIGH
        )

    def check_audit_kernel_modules_rules(self):
        """6.2.3.14 - Ensure kernel module loading and unloading is collected"""
        self._check_audit_rule(
            check_id="6.2.3.14",
            title="Ensure kernel module loading and unloading is collected",
            pattern="-a always,exit -F arch=b64 -S init_module,finit_module,delete_module",
            severity=Severity.HIGH
        )

    def check_audit_immutable_rules(self):
        """6.2.3.15 - Ensure the audit configuration is immutable"""
        self._check_audit_rule(
            check_id="6.2.3.15",
            title="Ensure the audit configuration is immutable",
            pattern="-e 2",
            severity=Severity.MEDIUM
        )

    def check_audit_cron_rules(self):
        """6.2.3.16 - Ensure cron jobs are logged"""
        self._check_audit_rule(
            check_id="6.2.3.16",
            title="Ensure cron jobs are logged",
            pattern="-w /etc/cron",
            severity=Severity.LOW
        )

    def check_audit_passwd_rules(self):
        """6.2.3.17 - Ensure password modification events are collected"""
        self._check_audit_rule(
            check_id="6.2.3.17",
            title="Ensure password modification events are collected",
            pattern="-w /etc/security/opasswd -p wa",
            severity=Severity.MEDIUM
        )

    def check_audit_hosts_rules(self):
        """6.2.3.18 - Ensure modifications to /etc/hosts are collected"""
        self._check_audit_rule(
            check_id="6.2.3.18",
            title="Ensure modifications to /etc/hosts are collected",
            pattern="-w /etc/hosts -p wa",
            severity=Severity.MEDIUM
        )

    def check_audit_sysctl_rules(self):
        """6.2.3.19 - Ensure kernel parameters are collected"""
        self._check_audit_rule(
            check_id="6.2.3.19",
            title="Ensure kernel parameters are collected",
            pattern="-w /etc/sysctl.conf -p wa",
            severity=Severity.MEDIUM
        )

    def check_audit_localtime_rules(self):
        """6.2.3.20 - Ensure modifications to system time zone information are collected"""
        self._check_audit_rule(
            check_id="6.2.3.20",
            title="Ensure modifications to system time zone information are collected",
            pattern="-w /etc/localtime -p wa",
            severity=Severity.LOW
        )

    def check_audit_ssh_rules(self):
        """6.2.3.21 - Ensure SSH configuration changes are collected"""
        self._check_audit_rule(
            check_id="6.2.3.21",
            title="Ensure SSH configuration changes are collected",
            pattern="-w /etc/ssh/sshd_config -p wa",
            severity=Severity.MEDIUM
        )

    def run_all_checks(self):
        """Run all auditd checks"""
        self.check_auditd_installed()
        self.check_auditd_enabled()
        self.check_auditd_config()
        # Audit Data Retention checks (6.2.2.x)
        self.check_audit_log_file_size()
        self.check_audit_max_log_file_action()
        self.check_audit_space_left_action()
        self.check_audit_admin_space_left_action()
        # Audit Rules checks (6.2.3.x)
        self.check_audit_time_rules()
        self.check_audit_user_group_rules()
        self.check_audit_network_env_rules()
        self.check_audit_apparmor_rules()
        self.check_audit_login_logout_rules()
        self.check_audit_session_rules()
        self.check_audit_perm_mod_rules()
        self.check_audit_access_rules()
        self.check_audit_privileged_commands_rules()
        self.check_audit_mounts_rules()
        self.check_audit_file_deletion_rules()
        self.check_audit_sudoers_rules()
        self.check_audit_sudolog_rules()
        self.check_audit_kernel_modules_rules()
        self.check_audit_immutable_rules()
        self.check_audit_cron_rules()
        self.check_audit_passwd_rules()
        self.check_audit_hosts_rules()
        self.check_audit_sysctl_rules()
        self.check_audit_localtime_rules()
        self.check_audit_ssh_rules()
        # Audit File Access checks (6.2.4.x)
        self.check_audit_log_permissions()
        self.check_audit_log_directory_permissions()
        self.check_audit_config_file_permissions()
        self.check_audit_config_file_ownership()
        self.check_audit_config_file_group_ownership()
        self.check_audit_tools_permissions()
        self.check_audit_tools_ownership()
        self.check_audit_tools_group_ownership()
        self.check_audit_rules_permissions()


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


class IntegrityAuditor(BaseAuditor):
    """Auditor for filesystem integrity checks (AIDE)"""

    def check_aide_installed(self):
        """6.3.1 - Ensure AIDE is installed"""
        # Check if either aide or aide-common is installed
        aide_installed = False
        package_name = None

        # Try aide first
        returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'aide'])
        if returncode == 0:
            aide_installed = True
            package_name = 'aide'
        else:
            # Try aide-common
            returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'aide-common'])
            if returncode == 0:
                aide_installed = True
                package_name = 'aide-common'

        if aide_installed:
            self.reporter.add_result(AuditResult(
                check_id="6.3.1",
                title="Ensure AIDE is installed",
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"AIDE package is installed ({package_name})"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.3.1",
                title="Ensure AIDE is installed",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="AIDE is not installed",
                details="AIDE (Advanced Intrusion Detection Environment) is required for file integrity monitoring",
                remediation="apt install aide aide-common && aideinit"
            ))

    def check_filesystem_integrity_checked(self):
        """6.3.2 - Ensure filesystem integrity is regularly checked"""
        # Check if AIDE is installed first
        aide_installed = False
        returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'aide'])
        if returncode == 0:
            aide_installed = True
        else:
            returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'aide-common'])
            if returncode == 0:
                aide_installed = True

        if not aide_installed:
            self.reporter.add_result(AuditResult(
                check_id="6.3.2",
                title="Ensure filesystem integrity is regularly checked",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="AIDE is not installed, cannot check for scheduled integrity checks",
                remediation="First install AIDE: apt install aide aide-common"
            ))
            return

        # Check for cron job or systemd timer
        cron_configured = False
        timer_configured = False

        # Check cron directories
        cron_paths = [
            '/etc/cron.daily/aide',
            '/etc/cron.weekly/aide',
            '/etc/cron.monthly/aide',
            '/etc/crontab',
            '/etc/cron.d/'
        ]

        for path in cron_paths:
            if self.file_exists(path):
                if path.endswith('/'):
                    # It's a directory, check for aide-related files
                    returncode, stdout, stderr = self.run_command(['ls', path])
                    if 'aide' in stdout.lower():
                        cron_configured = True
                        break
                else:
                    # It's a file, check its contents
                    content = self.read_file(path)
                    if content and 'aide' in content.lower():
                        cron_configured = True
                        break

        # Check systemd timer
        returncode, stdout, stderr = self.run_command(['systemctl', 'is-enabled', 'aide.timer'])
        if returncode == 0 and stdout.strip() == 'enabled':
            timer_configured = True

        if cron_configured or timer_configured:
            method = "cron" if cron_configured else "systemd timer"
            self.reporter.add_result(AuditResult(
                check_id="6.3.2",
                title="Ensure filesystem integrity is regularly checked",
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"AIDE filesystem integrity checks are scheduled via {method}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.3.2",
                title="Ensure filesystem integrity is regularly checked",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="AIDE is installed but no regular integrity check is configured",
                details="Filesystem integrity should be checked regularly (daily or weekly recommended)",
                remediation="Configure a cron job or systemd timer to run 'aide --check' regularly"
            ))

    def check_audit_tools_integrity(self):
        """6.3.3 - Ensure cryptographic mechanisms are used to protect the integrity of audit tools"""
        # This check verifies that AIDE is configured to monitor audit tools
        aide_conf_paths = ['/etc/aide/aide.conf', '/etc/aide.conf']
        aide_conf_path = None

        for path in aide_conf_paths:
            if self.file_exists(path):
                aide_conf_path = path
                break

        if not aide_conf_path:
            self.reporter.add_result(AuditResult(
                check_id="6.3.3",
                title="Ensure cryptographic mechanisms are used to protect audit tools",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="AIDE configuration file not found",
                details="Cannot verify if audit tools are monitored",
                remediation="Install and configure AIDE: apt install aide aide-common && aideinit"
            ))
            return

        content = self.read_file(aide_conf_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="6.3.3",
                title="Ensure cryptographic mechanisms are used to protect audit tools",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Cannot read AIDE configuration file: {aide_conf_path}"
            ))
            return

        # Check if key audit tools are monitored
        audit_tools = [
            '/sbin/auditctl',
            '/sbin/aureport',
            '/sbin/ausearch',
            '/sbin/autrace',
            '/sbin/auditd',
            '/sbin/augenrules'
        ]

        monitored_tools = []
        missing_tools = []

        for tool in audit_tools:
            # Check if the tool path is mentioned in the config
            # AIDE config can use regex patterns like /sbin/ or specific paths
            if tool in content or '/sbin/' in content or '/sbin' in content:
                monitored_tools.append(tool)
            else:
                missing_tools.append(tool)

        # Also check if /sbin is generally monitored
        sbin_monitored = '/sbin' in content

        if sbin_monitored or len(monitored_tools) >= 3:
            self.reporter.add_result(AuditResult(
                check_id="6.3.3",
                title="Ensure cryptographic mechanisms are used to protect audit tools",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="AIDE is configured to monitor audit tools",
                details=f"Configuration file: {aide_conf_path}"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="6.3.3",
                title="Ensure cryptographic mechanisms are used to protect audit tools",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="AIDE is not properly configured to monitor audit tools",
                details=f"Audit tools should be monitored in {aide_conf_path}",
                remediation=f"Add audit tool paths to {aide_conf_path}, e.g.: /sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512"
            ))

    def run_all_checks(self):
        """Run all integrity checking checks"""
        self.check_aide_installed()
        self.check_filesystem_integrity_checked()
        self.check_audit_tools_integrity()


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

    def check_time_synchronization(self):
        """2.2.1 - Ensure time synchronization is in use (Meta-Check)"""
        # Check if any time synchronization service is active
        time_sync_services = [
            'systemd-timesyncd.service',
            'chrony.service',
            'ntp.service'
        ]

        active_services = []
        for service in time_sync_services:
            returncode, stdout, _ = self.run_command(['systemctl', 'is-active', service])
            if returncode == 0 and stdout.strip() == 'active':
                active_services.append(service)

        if active_services:
            self.reporter.add_result(AuditResult(
                check_id='2.2.1',
                title='Ensure time synchronization is in use',
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f'Time synchronization is active: {", ".join(active_services)}'
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id='2.2.1',
                title='Ensure time synchronization is in use',
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message='No time synchronization service is active',
                remediation='Install and enable systemd-timesyncd, chrony, or ntp'
            ))

    def run_all_checks(self):
        """Run all service checks"""
        # 2.2.1 - Time Synchronization Meta-Check (1 check)
        self.check_time_synchronization()

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


class TimeSyncAuditor(BaseAuditor):
    """Auditor for time synchronization configuration (2.3.x)"""

    def check_systemd_timesyncd_installed(self):
        """2.3.1.1 - Ensure systemd-timesyncd is installed"""
        returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'systemd-timesyncd'])

        if returncode == 0:
            self.reporter.add_result(AuditResult(
                check_id="2.3.1.1",
                title="Ensure systemd-timesyncd is installed",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="systemd-timesyncd is installed"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="2.3.1.1",
                title="Ensure systemd-timesyncd is installed",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="systemd-timesyncd is not installed",
                details="Time synchronization is critical for logs, authentication, and security",
                remediation="apt install systemd-timesyncd"
            ))

    def check_systemd_timesyncd_enabled(self):
        """2.3.1.2 - Ensure systemd-timesyncd is enabled and running"""
        # Check if enabled
        returncode_enabled, stdout_enabled, _ = self.run_command(['systemctl', 'is-enabled', 'systemd-timesyncd.service'])
        # Check if active
        returncode_active, stdout_active, _ = self.run_command(['systemctl', 'is-active', 'systemd-timesyncd.service'])

        enabled = stdout_enabled.strip() == 'enabled'
        active = stdout_active.strip() == 'active'

        if enabled and active:
            self.reporter.add_result(AuditResult(
                check_id="2.3.1.2",
                title="Ensure systemd-timesyncd is enabled and running",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="systemd-timesyncd is enabled and running"
            ))
        else:
            issues = []
            if not enabled:
                issues.append("not enabled")
            if not active:
                issues.append("not active")

            self.reporter.add_result(AuditResult(
                check_id="2.3.1.2",
                title="Ensure systemd-timesyncd is enabled and running",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"systemd-timesyncd is {', '.join(issues)}",
                remediation="systemctl enable systemd-timesyncd.service && systemctl start systemd-timesyncd.service"
            ))

    def check_systemd_timesyncd_configured(self):
        """2.3.1.3 - Ensure systemd-timesyncd is configured"""
        config_path = '/etc/systemd/timesyncd.conf'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="2.3.1.3",
                title="Ensure systemd-timesyncd is configured",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message=f"Configuration file {config_path} not found",
                details="Using default configuration",
                remediation=f"Create {config_path} and configure NTP servers"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="2.3.1.3",
                title="Ensure systemd-timesyncd is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Cannot read {config_path}"
            ))
            return

        # Check for NTP or FallbackNTP configuration
        has_ntp = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('NTP=') or line.startswith('FallbackNTP='):
                if not line.startswith('#'):
                    has_ntp = True
                    break

        if has_ntp:
            self.reporter.add_result(AuditResult(
                check_id="2.3.1.3",
                title="Ensure systemd-timesyncd is configured",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="systemd-timesyncd is configured with NTP servers"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="2.3.1.3",
                title="Ensure systemd-timesyncd is configured",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message="No NTP servers configured",
                details="Using default NTP servers",
                remediation=f"Edit {config_path} and configure NTP= or FallbackNTP="
            ))

    def check_chrony_installed(self):
        """2.3.2.1 - Ensure chrony is installed"""
        returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'chrony'])

        if returncode == 0:
            self.reporter.add_result(AuditResult(
                check_id="2.3.2.1",
                title="Ensure chrony is installed",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="chrony is installed"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="2.3.2.1",
                title="Ensure chrony is installed",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="chrony is not installed",
                details="chrony is an alternative NTP client that may be preferred over systemd-timesyncd",
                remediation="apt install chrony"
            ))

    def check_chrony_enabled(self):
        """2.3.2.2 - Ensure chrony is enabled and running"""
        # Check if chrony is installed first
        returncode_installed, _, _ = self.run_command(['dpkg', '-s', 'chrony'])
        if returncode_installed != 0:
            self.reporter.add_result(AuditResult(
                check_id="2.3.2.2",
                title="Ensure chrony is enabled and running",
                status=Status.SKIP,
                severity=Severity.MEDIUM,
                message="chrony is not installed"
            ))
            return

        # Check if enabled
        returncode_enabled, stdout_enabled, _ = self.run_command(['systemctl', 'is-enabled', 'chrony.service'])
        # Check if active
        returncode_active, stdout_active, _ = self.run_command(['systemctl', 'is-active', 'chrony.service'])

        enabled = stdout_enabled.strip() == 'enabled'
        active = stdout_active.strip() == 'active'

        if enabled and active:
            self.reporter.add_result(AuditResult(
                check_id="2.3.2.2",
                title="Ensure chrony is enabled and running",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="chrony is enabled and running"
            ))
        else:
            issues = []
            if not enabled:
                issues.append("not enabled")
            if not active:
                issues.append("not active")

            self.reporter.add_result(AuditResult(
                check_id="2.3.2.2",
                title="Ensure chrony is enabled and running",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"chrony is {', '.join(issues)}",
                remediation="systemctl enable chrony.service && systemctl start chrony.service"
            ))

    def check_chrony_configured(self):
        """2.3.2.3 - Ensure chrony is configured"""
        # Check if chrony is installed first
        returncode_installed, _, _ = self.run_command(['dpkg', '-s', 'chrony'])
        if returncode_installed != 0:
            self.reporter.add_result(AuditResult(
                check_id="2.3.2.3",
                title="Ensure chrony is configured",
                status=Status.SKIP,
                severity=Severity.MEDIUM,
                message="chrony is not installed"
            ))
            return

        config_path = '/etc/chrony/chrony.conf'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="2.3.2.3",
                title="Ensure chrony is configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Configuration file {config_path} not found",
                remediation=f"Create {config_path} and configure NTP servers"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="2.3.2.3",
                title="Ensure chrony is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Cannot read {config_path}"
            ))
            return

        # Check for server or pool configuration
        has_server = False
        for line in content.splitlines():
            line = line.strip()
            if (line.startswith('server ') or line.startswith('pool ')) and not line.startswith('#'):
                has_server = True
                break

        if has_server:
            self.reporter.add_result(AuditResult(
                check_id="2.3.2.3",
                title="Ensure chrony is configured",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="chrony is configured with NTP servers"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="2.3.2.3",
                title="Ensure chrony is configured",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="No NTP servers configured in chrony",
                remediation=f"Edit {config_path} and add 'server' or 'pool' directives"
            ))

    def check_single_time_sync_daemon(self):
        """2.3.3 - Ensure only one time synchronization daemon is in use"""
        # Check which time sync daemons are active
        daemons = {
            'systemd-timesyncd': False,
            'chrony': False,
            'ntpd': False
        }

        for daemon in daemons.keys():
            service_name = f"{daemon}.service" if daemon != 'ntpd' else 'ntp.service'
            returncode, stdout, _ = self.run_command(['systemctl', 'is-active', service_name])
            if stdout.strip() == 'active':
                daemons[daemon] = True

        active_daemons = [name for name, active in daemons.items() if active]

        if len(active_daemons) == 1:
            self.reporter.add_result(AuditResult(
                check_id="2.3.3",
                title="Ensure only one time synchronization daemon is in use",
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"Only one time sync daemon is active: {active_daemons[0]}"
            ))
        elif len(active_daemons) == 0:
            self.reporter.add_result(AuditResult(
                check_id="2.3.3",
                title="Ensure only one time synchronization daemon is in use",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="No time synchronization daemon is active",
                details="System time will drift without time synchronization",
                remediation="Enable either systemd-timesyncd or chrony"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="2.3.3",
                title="Ensure only one time synchronization daemon is in use",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"Multiple time sync daemons are active: {', '.join(active_daemons)}",
                details="Having multiple time sync daemons can cause conflicts",
                remediation=f"Disable all but one: systemctl disable {active_daemons[1]}.service"
            ))

    def run_all_checks(self):
        """Run all time synchronization checks"""
        self.check_systemd_timesyncd_installed()
        self.check_systemd_timesyncd_enabled()
        self.check_systemd_timesyncd_configured()
        self.check_chrony_installed()
        self.check_chrony_enabled()
        self.check_chrony_configured()
        self.check_single_time_sync_daemon()


class JobSchedulerAuditor(BaseAuditor):
    """Auditor for cron and at job scheduler configuration (2.4.x)"""

    def check_cron_installed(self):
        """2.4.1.1 - Ensure cron daemon is installed"""
        returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'cron'])

        if returncode == 0:
            self.reporter.add_result(AuditResult(
                check_id="2.4.1.1",
                title="Ensure cron daemon is installed",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="cron daemon is installed"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="2.4.1.1",
                title="Ensure cron daemon is installed",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="cron daemon is not installed",
                details="cron is required for scheduled system tasks",
                remediation="apt install cron"
            ))

    def check_cron_enabled(self):
        """2.4.1.2 - Ensure cron daemon is enabled and running"""
        # Check if enabled
        returncode_enabled, stdout_enabled, _ = self.run_command(['systemctl', 'is-enabled', 'cron.service'])
        # Check if active
        returncode_active, stdout_active, _ = self.run_command(['systemctl', 'is-active', 'cron.service'])

        enabled = stdout_enabled.strip() == 'enabled'
        active = stdout_active.strip() == 'active'

        if enabled and active:
            self.reporter.add_result(AuditResult(
                check_id="2.4.1.2",
                title="Ensure cron daemon is enabled and running",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="cron daemon is enabled and running"
            ))
        else:
            issues = []
            if not enabled:
                issues.append("not enabled")
            if not active:
                issues.append("not active")

            self.reporter.add_result(AuditResult(
                check_id="2.4.1.2",
                title="Ensure cron daemon is enabled and running",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"cron daemon is {', '.join(issues)}",
                remediation="systemctl enable cron.service && systemctl start cron.service"
            ))

    def _check_cron_permissions(self, path: str, check_id: str, title: str):
        """Helper method to check cron directory/file permissions"""
        if not self.file_exists(path):
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message=f"{path} does not exist"
            ))
            return

        stat_info = self.get_file_stat(path)
        if not stat_info:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Cannot get file statistics for {path}"
            ))
            return

        mode = stat.S_IMODE(stat_info.st_mode)
        owner_uid = stat_info.st_uid
        group_gid = stat_info.st_gid

        issues = []

        # Check owner is root (UID 0)
        if owner_uid != 0:
            issues.append(f"Owner is not root (UID {owner_uid})")

        # Check group is root (GID 0)
        if group_gid != 0:
            issues.append(f"Group is not root (GID {group_gid})")

        # Check permissions are 0700 or more restrictive (no group/other access)
        if mode & 0o077:
            issues.append(f"Permissions {oct(mode)} are too permissive (should be 0700 or more restrictive)")

        if len(issues) == 0:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message=f"{path} has correct permissions ({oct(mode)})"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id=check_id,
                title=title,
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"{path} has incorrect permissions",
                details="\n".join(issues),
                remediation=f"chown root:root {path} && chmod 0700 {path}"
            ))

    def check_crontab_permissions(self):
        """2.4.1.3 - Ensure permissions on /etc/crontab are configured"""
        self._check_cron_permissions('/etc/crontab', '2.4.1.3', 'Ensure permissions on /etc/crontab are configured')

    def check_cron_hourly_permissions(self):
        """2.4.1.4 - Ensure permissions on /etc/cron.hourly are configured"""
        self._check_cron_permissions('/etc/cron.hourly', '2.4.1.4', 'Ensure permissions on /etc/cron.hourly are configured')

    def check_cron_daily_permissions(self):
        """2.4.1.5 - Ensure permissions on /etc/cron.daily are configured"""
        self._check_cron_permissions('/etc/cron.daily', '2.4.1.5', 'Ensure permissions on /etc/cron.daily are configured')

    def check_cron_weekly_permissions(self):
        """2.4.1.6 - Ensure permissions on /etc/cron.weekly are configured"""
        self._check_cron_permissions('/etc/cron.weekly', '2.4.1.6', 'Ensure permissions on /etc/cron.weekly are configured')

    def check_cron_monthly_permissions(self):
        """2.4.1.7 - Ensure permissions on /etc/cron.monthly are configured"""
        self._check_cron_permissions('/etc/cron.monthly', '2.4.1.7', 'Ensure permissions on /etc/cron.monthly are configured')

    def check_cron_d_permissions(self):
        """2.4.1.8 - Ensure permissions on /etc/cron.d are configured"""
        self._check_cron_permissions('/etc/cron.d', '2.4.1.8', 'Ensure permissions on /etc/cron.d are configured')

    def check_at_restricted(self):
        """2.4.2.1 - Ensure at is restricted to authorized users"""
        # Check for /etc/at.deny and /etc/at.allow
        at_deny_exists = self.file_exists('/etc/at.deny')
        at_allow_exists = self.file_exists('/etc/at.allow')

        # Best practice: /etc/at.allow exists and /etc/at.deny does not exist
        if at_allow_exists and not at_deny_exists:
            self.reporter.add_result(AuditResult(
                check_id="2.4.2.1",
                title="Ensure at is restricted to authorized users",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="/etc/at.allow exists and /etc/at.deny does not exist"
            ))
        elif at_allow_exists and at_deny_exists:
            self.reporter.add_result(AuditResult(
                check_id="2.4.2.1",
                title="Ensure at is restricted to authorized users",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message="Both /etc/at.allow and /etc/at.deny exist",
                details="/etc/at.allow takes precedence, but /etc/at.deny should be removed",
                remediation="rm /etc/at.deny"
            ))
        elif at_deny_exists and not at_allow_exists:
            self.reporter.add_result(AuditResult(
                check_id="2.4.2.1",
                title="Ensure at is restricted to authorized users",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Only /etc/at.deny exists (allow-by-default)",
                details="Using deny-list approach is less secure than allow-list",
                remediation="Create /etc/at.allow with authorized users and remove /etc/at.deny"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="2.4.2.1",
                title="Ensure at is restricted to authorized users",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Neither /etc/at.allow nor /etc/at.deny exists",
                details="at is unrestricted (all users can schedule jobs)",
                remediation="Create /etc/at.allow with authorized users"
            ))

    def run_all_checks(self):
        """Run all job scheduler checks"""
        self.check_cron_installed()
        self.check_cron_enabled()
        self.check_crontab_permissions()
        self.check_cron_hourly_permissions()
        self.check_cron_daily_permissions()
        self.check_cron_weekly_permissions()
        self.check_cron_monthly_permissions()
        self.check_cron_d_permissions()
        self.check_at_restricted()


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

    def check_wireless_interfaces_disabled(self):
        """3.1.1 - Ensure wireless interfaces are disabled"""
        try:
            # Check for wireless interfaces
            returncode, stdout, _ = self.run_command(['find', '/sys/class/net', '-type', 'l', '-name', 'wlan*'])

            wireless_found = False
            if returncode == 0 and stdout.strip():
                wireless_found = True

            # Also check with iwconfig if available
            returncode2, stdout2, _ = self.run_command(['which', 'iwconfig'])
            if returncode2 == 0:
                returncode3, stdout3, _ = self.run_command(['iwconfig'])
                if returncode3 == 0 and stdout3.strip() and 'no wireless extensions' not in stdout3.lower():
                    wireless_found = True

            if wireless_found:
                self.reporter.add_result(AuditResult(
                    check_id="3.1.1",
                    title="Ensure wireless interfaces are disabled",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="WLAN-Interfaces gefunden",
                    remediation="Deaktivieren Sie WLAN-Interfaces wenn nicht benötigt"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.1.1",
                    title="Ensure wireless interfaces are disabled",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Keine WLAN-Interfaces gefunden"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.1.1",
                title="Ensure wireless interfaces are disabled",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_bluetooth_disabled(self):
        """3.1.2 - Ensure Bluetooth is disabled"""
        try:
            # Check if bluetooth service is running
            returncode, stdout, _ = self.run_command(['systemctl', 'is-enabled', 'bluetooth.service'])

            if returncode == 0 and stdout.strip() in ['enabled']:
                self.reporter.add_result(AuditResult(
                    check_id="3.1.2",
                    title="Ensure Bluetooth is disabled",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="Bluetooth ist aktiviert",
                    remediation="Führen Sie aus: systemctl disable bluetooth.service"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.1.2",
                    title="Ensure Bluetooth is disabled",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="Bluetooth ist deaktiviert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.1.2",
                title="Ensure Bluetooth is disabled",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_packet_redirect_sending_disabled(self):
        """3.1.3 - Ensure packet redirect sending is disabled"""
        try:
            all_send_redirects = self.read_file('/proc/sys/net/ipv4/conf/all/send_redirects')
            default_send_redirects = self.read_file('/proc/sys/net/ipv4/conf/default/send_redirects')

            issues = []
            if not all_send_redirects or all_send_redirects.strip() != '0':
                issues.append("net.ipv4.conf.all.send_redirects ist nicht 0")
            if not default_send_redirects or default_send_redirects.strip() != '0':
                issues.append("net.ipv4.conf.default.send_redirects ist nicht 0")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="3.1.3",
                    title="Ensure packet redirect sending is disabled",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Packet redirect sending ist nicht korrekt konfiguriert",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie net.ipv4.conf.all.send_redirects=0 und net.ipv4.conf.default.send_redirects=0 in /etc/sysctl.conf"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.1.3",
                    title="Ensure packet redirect sending is disabled",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Packet redirect sending ist deaktiviert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.1.3",
                title="Ensure packet redirect sending is disabled",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_dccp_disabled(self):
        """3.2.1 - Ensure DCCP is disabled"""
        try:
            returncode, stdout, _ = self.run_command(['modprobe', '-n', '-v', 'dccp'])

            if 'install /bin/true' in stdout or 'install /bin/false' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="3.2.1",
                    title="Ensure DCCP is disabled",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="DCCP-Modul ist deaktiviert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.2.1",
                    title="Ensure DCCP is disabled",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="DCCP-Modul ist nicht deaktiviert",
                    remediation="Fügen Sie 'install dccp /bin/true' zu /etc/modprobe.d/dccp.conf hinzu"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.2.1",
                title="Ensure DCCP is disabled",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_sctp_disabled(self):
        """3.2.2 - Ensure SCTP is disabled"""
        try:
            returncode, stdout, _ = self.run_command(['modprobe', '-n', '-v', 'sctp'])

            if 'install /bin/true' in stdout or 'install /bin/false' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="3.2.2",
                    title="Ensure SCTP is disabled",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="SCTP-Modul ist deaktiviert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.2.2",
                    title="Ensure SCTP is disabled",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="SCTP-Modul ist nicht deaktiviert",
                    remediation="Fügen Sie 'install sctp /bin/true' zu /etc/modprobe.d/sctp.conf hinzu"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.2.2",
                title="Ensure SCTP is disabled",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_rds_disabled(self):
        """3.2.3 - Ensure RDS is disabled"""
        try:
            returncode, stdout, _ = self.run_command(['modprobe', '-n', '-v', 'rds'])

            if 'install /bin/true' in stdout or 'install /bin/false' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="3.2.3",
                    title="Ensure RDS is disabled",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="RDS-Modul ist deaktiviert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.2.3",
                    title="Ensure RDS is disabled",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="RDS-Modul ist nicht deaktiviert",
                    remediation="Fügen Sie 'install rds /bin/true' zu /etc/modprobe.d/rds.conf hinzu"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.2.3",
                title="Ensure RDS is disabled",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_tipc_disabled(self):
        """3.2.4 - Ensure TIPC is disabled"""
        try:
            returncode, stdout, _ = self.run_command(['modprobe', '-n', '-v', 'tipc'])

            if 'install /bin/true' in stdout or 'install /bin/false' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="3.2.4",
                    title="Ensure TIPC is disabled",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="TIPC-Modul ist deaktiviert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.2.4",
                    title="Ensure TIPC is disabled",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="TIPC-Modul ist nicht deaktiviert",
                    remediation="Fügen Sie 'install tipc /bin/true' zu /etc/modprobe.d/tipc.conf hinzu"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.2.4",
                title="Ensure TIPC is disabled",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ipv6_disabled(self):
        """3.2.5 - Ensure IPv6 is disabled (if not needed)"""
        try:
            # Check if IPv6 is disabled via sysctl
            ipv6_disabled = self.read_file('/proc/sys/net/ipv6/conf/all/disable_ipv6')

            if ipv6_disabled and ipv6_disabled.strip() == '1':
                self.reporter.add_result(AuditResult(
                    check_id="3.2.5",
                    title="Ensure IPv6 is disabled",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="IPv6 ist deaktiviert"
                ))
            else:
                # IPv6 is enabled - this might be intentional
                self.reporter.add_result(AuditResult(
                    check_id="3.2.5",
                    title="Ensure IPv6 is disabled",
                    status=Status.WARNING,
                    severity=Severity.LOW,
                    message="IPv6 ist aktiviert (deaktivieren Sie es falls nicht benötigt)",
                    remediation="Setzen Sie net.ipv6.conf.all.disable_ipv6=1 in /etc/sysctl.conf falls IPv6 nicht benötigt wird"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.2.5",
                title="Ensure IPv6 is disabled",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ipv6_router_advertisements(self):
        """3.4.1 - Ensure IPv6 router advertisements are not accepted"""
        try:
            all_accept_ra = self.read_file('/proc/sys/net/ipv6/conf/all/accept_ra')
            default_accept_ra = self.read_file('/proc/sys/net/ipv6/conf/default/accept_ra')

            issues = []
            if not all_accept_ra or all_accept_ra.strip() != '0':
                issues.append("net.ipv6.conf.all.accept_ra ist nicht 0")
            if not default_accept_ra or default_accept_ra.strip() != '0':
                issues.append("net.ipv6.conf.default.accept_ra ist nicht 0")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.1",
                    title="Ensure IPv6 router advertisements are not accepted",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="IPv6 Router Advertisements werden akzeptiert",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie net.ipv6.conf.all.accept_ra=0 und net.ipv6.conf.default.accept_ra=0 in /etc/sysctl.conf"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.1",
                    title="Ensure IPv6 router advertisements are not accepted",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="IPv6 Router Advertisements werden nicht akzeptiert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.4.1",
                title="Ensure IPv6 router advertisements are not accepted",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ipv6_redirects(self):
        """3.4.2 - Ensure IPv6 redirects are not accepted"""
        try:
            all_accept_redirects = self.read_file('/proc/sys/net/ipv6/conf/all/accept_redirects')
            default_accept_redirects = self.read_file('/proc/sys/net/ipv6/conf/default/accept_redirects')

            issues = []
            if not all_accept_redirects or all_accept_redirects.strip() != '0':
                issues.append("net.ipv6.conf.all.accept_redirects ist nicht 0")
            if not default_accept_redirects or default_accept_redirects.strip() != '0':
                issues.append("net.ipv6.conf.default.accept_redirects ist nicht 0")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.2",
                    title="Ensure IPv6 redirects are not accepted",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="IPv6 Redirects werden akzeptiert",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie net.ipv6.conf.all.accept_redirects=0 und net.ipv6.conf.default.accept_redirects=0 in /etc/sysctl.conf"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.2",
                    title="Ensure IPv6 redirects are not accepted",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="IPv6 Redirects werden nicht akzeptiert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.4.2",
                title="Ensure IPv6 redirects are not accepted",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ipv6_completely_disabled(self):
        """3.4.3 - Ensure IPv6 is disabled (comprehensive check)"""
        try:
            # Check if IPv6 is disabled via grub configuration
            grub_config = self.read_file('/etc/default/grub')
            ipv6_disabled_in_grub = False

            if grub_config:
                for line in grub_config.splitlines():
                    if 'GRUB_CMDLINE_LINUX' in line and 'ipv6.disable=1' in line:
                        ipv6_disabled_in_grub = True
                        break

            # Also check sysctl
            ipv6_disabled_sysctl = self.read_file('/proc/sys/net/ipv6/conf/all/disable_ipv6')
            ipv6_disabled_via_sysctl = ipv6_disabled_sysctl and ipv6_disabled_sysctl.strip() == '1'

            if ipv6_disabled_in_grub or ipv6_disabled_via_sysctl:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.3",
                    title="Ensure IPv6 is disabled",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="IPv6 ist deaktiviert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.3",
                    title="Ensure IPv6 is disabled",
                    status=Status.WARNING,
                    severity=Severity.LOW,
                    message="IPv6 ist aktiviert (deaktivieren Sie es falls nicht benötigt)",
                    remediation="Fügen Sie 'ipv6.disable=1' zu GRUB_CMDLINE_LINUX in /etc/default/grub hinzu und führen Sie 'update-grub' aus, oder setzen Sie net.ipv6.conf.all.disable_ipv6=1 in /etc/sysctl.conf"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.4.3",
                title="Ensure IPv6 is disabled",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_tcp_wrappers_installed(self):
        """3.4.4 - Ensure TCP Wrappers is installed"""
        try:
            returncode, stdout, _ = self.run_command(['dpkg', '-s', 'tcpd'])

            if returncode == 0 and 'install ok installed' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.4",
                    title="Ensure TCP Wrappers is installed",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="TCP Wrappers (tcpd) ist installiert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.4",
                    title="Ensure TCP Wrappers is installed",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="TCP Wrappers (tcpd) ist nicht installiert",
                    remediation="Führen Sie aus: apt install tcpd"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.4.4",
                title="Ensure TCP Wrappers is installed",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_hosts_allow_configured(self):
        """3.4.5 - Ensure /etc/hosts.allow is configured"""
        try:
            hosts_allow_path = '/etc/hosts.allow'

            if not self.file_exists(hosts_allow_path):
                self.reporter.add_result(AuditResult(
                    check_id="3.4.5",
                    title="Ensure /etc/hosts.allow is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="/etc/hosts.allow existiert nicht",
                    remediation="Erstellen Sie /etc/hosts.allow und konfigurieren Sie erlaubte Hosts"
                ))
                return

            content = self.read_file(hosts_allow_path)
            if not content or content.strip() == '':
                self.reporter.add_result(AuditResult(
                    check_id="3.4.5",
                    title="Ensure /etc/hosts.allow is configured",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    message="/etc/hosts.allow ist leer",
                    remediation="Konfigurieren Sie /etc/hosts.allow mit erlaubten Hosts (z.B. 'ALL: 192.168.1.0/24')"
                ))
            else:
                # Check for at least one non-comment line
                has_config = False
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        has_config = True
                        break

                if has_config:
                    self.reporter.add_result(AuditResult(
                        check_id="3.4.5",
                        title="Ensure /etc/hosts.allow is configured",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="/etc/hosts.allow ist konfiguriert"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="3.4.5",
                        title="Ensure /etc/hosts.allow is configured",
                        status=Status.WARNING,
                        severity=Severity.MEDIUM,
                        message="/etc/hosts.allow enthält keine aktive Konfiguration",
                        remediation="Fügen Sie erlaubte Hosts zu /etc/hosts.allow hinzu"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.4.5",
                title="Ensure /etc/hosts.allow is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_hosts_deny_configured(self):
        """3.4.6 - Ensure /etc/hosts.deny is configured"""
        try:
            hosts_deny_path = '/etc/hosts.deny'

            if not self.file_exists(hosts_deny_path):
                self.reporter.add_result(AuditResult(
                    check_id="3.4.6",
                    title="Ensure /etc/hosts.deny is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="/etc/hosts.deny existiert nicht",
                    remediation="Erstellen Sie /etc/hosts.deny mit 'ALL: ALL' als Standard-Deny-Regel"
                ))
                return

            content = self.read_file(hosts_deny_path)
            if not content or content.strip() == '':
                self.reporter.add_result(AuditResult(
                    check_id="3.4.6",
                    title="Ensure /etc/hosts.deny is configured",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    message="/etc/hosts.deny ist leer",
                    remediation="Fügen Sie 'ALL: ALL' zu /etc/hosts.deny hinzu für Default-Deny"
                ))
            else:
                # Check for deny-all rule
                has_deny_all = False
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if 'ALL' in line and ':' in line:
                            has_deny_all = True
                            break

                if has_deny_all:
                    self.reporter.add_result(AuditResult(
                        check_id="3.4.6",
                        title="Ensure /etc/hosts.deny is configured",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="/etc/hosts.deny ist konfiguriert"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="3.4.6",
                        title="Ensure /etc/hosts.deny is configured",
                        status=Status.WARNING,
                        severity=Severity.MEDIUM,
                        message="/etc/hosts.deny enthält keine Default-Deny-Regel",
                        remediation="Fügen Sie 'ALL: ALL' zu /etc/hosts.deny hinzu"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.4.6",
                title="Ensure /etc/hosts.deny is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_hosts_allow_permissions(self):
        """3.4.7 - Ensure permissions on /etc/hosts.allow are configured"""
        try:
            hosts_allow_path = '/etc/hosts.allow'

            if not self.file_exists(hosts_allow_path):
                self.reporter.add_result(AuditResult(
                    check_id="3.4.7",
                    title="Ensure permissions on /etc/hosts.allow are configured",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    message="/etc/hosts.allow existiert nicht"
                ))
                return

            stat_info = self.get_file_stat(hosts_allow_path)
            if not stat_info:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.7",
                    title="Ensure permissions on /etc/hosts.allow are configured",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message=f"Kann {hosts_allow_path} nicht prüfen"
                ))
                return

            issues = []
            mode = stat.S_IMODE(stat_info.st_mode)

            # Should be 0644 or more restrictive
            if mode & 0o133:  # Check if others have write/execute or group has write/execute
                issues.append(f"Zu permissive Rechte: {oct(mode)}, erwartet: 0644 oder restriktiver")

            try:
                owner = pwd.getpwuid(stat_info.st_uid).pw_name
                if owner != 'root':
                    issues.append(f"Falscher Besitzer: {owner}, erwartet: root")
            except KeyError:
                issues.append(f"Unbekannte UID: {stat_info.st_uid}")

            try:
                group = grp.getgrgid(stat_info.st_gid).gr_name
                if group != 'root':
                    issues.append(f"Falsche Gruppe: {group}, erwartet: root")
            except KeyError:
                issues.append(f"Unbekannte GID: {stat_info.st_gid}")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.7",
                    title="Ensure permissions on /etc/hosts.allow are configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Falsche Berechtigungen auf /etc/hosts.allow",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Führen Sie aus: chown root:root /etc/hosts.allow && chmod 644 /etc/hosts.allow"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="3.4.7",
                    title="Ensure permissions on /etc/hosts.allow are configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="/etc/hosts.allow Berechtigungen sind korrekt"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="3.4.7",
                title="Ensure permissions on /etc/hosts.allow are configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def run_all_checks(self):
        """Run all network checks"""
        # Legacy checks (3.1.x and 3.2.x)
        self.check_ip_forwarding()
        self.check_icmp_redirects()

        # Network Devices (3.1.x - 3 checks)
        self.check_wireless_interfaces_disabled()
        self.check_bluetooth_disabled()
        self.check_packet_redirect_sending_disabled()

        # Network Protocols (3.2.x - 5 checks)
        self.check_dccp_disabled()
        self.check_sctp_disabled()
        self.check_rds_disabled()
        self.check_tipc_disabled()
        self.check_ipv6_disabled()

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

        # IPv6 & Network Hardening (3.4.x - 7 checks)
        self.check_ipv6_router_advertisements()
        self.check_ipv6_redirects()
        self.check_ipv6_completely_disabled()
        self.check_tcp_wrappers_installed()
        self.check_hosts_allow_configured()
        self.check_hosts_deny_configured()
        self.check_hosts_allow_permissions()


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

    # Additional /var configuration checks (1.1.3.x)
    def check_var_nodev_1_1_3_1(self):
        """1.1.3.1 - Ensure nodev option set on /var partition"""
        self._check_mount_option('/var', 'nodev', '1.1.3.1', 'Ensure nodev option set on /var partition', Severity.MEDIUM)

    def check_var_nosuid_1_1_3_2(self):
        """1.1.3.2 - Ensure nosuid option set on /var partition"""
        self._check_mount_option('/var', 'nosuid', '1.1.3.2', 'Ensure nosuid option set on /var partition', Severity.MEDIUM)

    def check_var_noexec(self):
        """1.1.3.3 - Ensure noexec option set on /var partition"""
        self._check_mount_option('/var', 'noexec', '1.1.3.3', 'Ensure noexec option set on /var partition', Severity.MEDIUM)

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

        # /var checks (1.1.2.4.x)
        self.check_var_partition()
        self.check_var_nodev()
        self.check_var_nosuid()

        # Additional /var configuration checks (1.1.3.x)
        self.check_var_nodev_1_1_3_1()
        self.check_var_nosuid_1_1_3_2()
        self.check_var_noexec()

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


class AppArmorAuditor(BaseAuditor):
    """Auditor for AppArmor configuration checks (1.3.1.x)"""

    def check_apparmor_installed(self):
        """1.3.1.1 - Ensure AppArmor is installed"""
        # Check if apparmor package is installed
        apparmor_installed = False
        apparmor_utils_installed = False

        returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'apparmor'])
        if returncode == 0:
            apparmor_installed = True

        returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'apparmor-utils'])
        if returncode == 0:
            apparmor_utils_installed = True

        if apparmor_installed and apparmor_utils_installed:
            self.reporter.add_result(AuditResult(
                check_id="1.3.1.1",
                title="Ensure AppArmor is installed",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="AppArmor and apparmor-utils are installed"
            ))
        else:
            missing = []
            if not apparmor_installed:
                missing.append("apparmor")
            if not apparmor_utils_installed:
                missing.append("apparmor-utils")

            self.reporter.add_result(AuditResult(
                check_id="1.3.1.1",
                title="Ensure AppArmor is installed",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message=f"Missing packages: {', '.join(missing)}",
                details="AppArmor provides Mandatory Access Control (MAC) to restrict program capabilities",
                remediation=f"apt install {' '.join(missing)}"
            ))

    def check_apparmor_bootloader(self):
        """1.3.1.2 - Ensure AppArmor is enabled in the bootloader configuration"""
        # Check GRUB configuration for AppArmor
        grub_config_paths = [
            '/boot/grub/grub.cfg',
            '/boot/grub2/grub.cfg'
        ]

        grub_default_path = '/etc/default/grub'
        apparmor_enabled = False

        # First check /etc/default/grub for the setting
        if self.file_exists(grub_default_path):
            content = self.read_file(grub_default_path)
            if content:
                # Check if apparmor=1 and security=apparmor are in GRUB_CMDLINE_LINUX
                for line in content.splitlines():
                    if line.strip().startswith('GRUB_CMDLINE_LINUX'):
                        if 'apparmor=1' in line and 'security=apparmor' in line:
                            apparmor_enabled = True
                            break

        # Also check the actual grub.cfg
        if not apparmor_enabled:
            for grub_path in grub_config_paths:
                if self.file_exists(grub_path):
                    content = self.read_file(grub_path)
                    if content:
                        # Check kernel command lines
                        for line in content.splitlines():
                            if 'linux' in line.lower() and '/boot/vmlinuz' in line:
                                if 'apparmor=1' in line and 'security=apparmor' in line:
                                    apparmor_enabled = True
                                    break
                    if apparmor_enabled:
                        break

        if apparmor_enabled:
            self.reporter.add_result(AuditResult(
                check_id="1.3.1.2",
                title="Ensure AppArmor is enabled in the bootloader configuration",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="AppArmor is enabled in bootloader configuration"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.3.1.2",
                title="Ensure AppArmor is enabled in the bootloader configuration",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="AppArmor is not enabled in bootloader configuration",
                details="AppArmor must be enabled at boot time to provide MAC",
                remediation="Edit /etc/default/grub and add 'apparmor=1 security=apparmor' to GRUB_CMDLINE_LINUX, then run 'update-grub'"
            ))

    def check_apparmor_profiles_mode(self):
        """1.3.1.3 - Ensure all AppArmor Profiles are in enforce or complain mode"""
        # Check that no profiles are unconfined
        returncode, stdout, stderr = self.run_command(['aa-status', '--json'])

        if returncode != 0:
            # aa-status not available or error
            self.reporter.add_result(AuditResult(
                check_id="1.3.1.3",
                title="Ensure all AppArmor Profiles are in enforce or complain mode",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="Cannot check AppArmor profile status",
                details="aa-status command failed or AppArmor not running",
                remediation="Ensure AppArmor is installed and running: systemctl status apparmor"
            ))
            return

        try:
            import json as json_module
            status_data = json_module.loads(stdout)

            # Count profiles in different modes
            enforce_count = len(status_data.get('profiles', {}).get('enforce', []))
            complain_count = len(status_data.get('profiles', {}).get('complain', []))
            unconfined_count = len(status_data.get('processes', {}).get('unconfined', []))

            total_profiles = enforce_count + complain_count

            if total_profiles > 0 and unconfined_count == 0:
                self.reporter.add_result(AuditResult(
                    check_id="1.3.1.3",
                    title="Ensure all AppArmor Profiles are in enforce or complain mode",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message=f"All profiles are in enforce or complain mode ({enforce_count} enforcing, {complain_count} complaining)"
                ))
            elif total_profiles == 0:
                self.reporter.add_result(AuditResult(
                    check_id="1.3.1.3",
                    title="Ensure all AppArmor Profiles are in enforce or complain mode",
                    status=Status.WARNING,
                    severity=Severity.HIGH,
                    message="No AppArmor profiles are loaded",
                    details="AppArmor is installed but no profiles are active",
                    remediation="Load AppArmor profiles for critical services"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.3.1.3",
                    title="Ensure all AppArmor Profiles are in enforce or complain mode",
                    status=Status.WARNING,
                    severity=Severity.HIGH,
                    message=f"Some processes are unconfined ({unconfined_count} unconfined)",
                    details=f"Profiles: {enforce_count} enforcing, {complain_count} complaining",
                    remediation="Review unconfined processes with 'aa-status' and create/enable profiles"
                ))
        except Exception as e:
            # Fallback to text parsing if JSON parsing fails
            returncode, stdout, stderr = self.run_command(['aa-status'])
            if returncode == 0:
                lines = stdout.splitlines()
                has_profiles = False
                for line in lines:
                    if 'profiles are in enforce mode' in line or 'profiles are in complain mode' in line:
                        has_profiles = True
                        break

                if has_profiles:
                    self.reporter.add_result(AuditResult(
                        check_id="1.3.1.3",
                        title="Ensure all AppArmor Profiles are in enforce or complain mode",
                        status=Status.PASS,
                        severity=Severity.HIGH,
                        message="AppArmor profiles are loaded (check output for details)",
                        details="Run 'aa-status' for detailed profile information"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="1.3.1.3",
                        title="Ensure all AppArmor Profiles are in enforce or complain mode",
                        status=Status.WARNING,
                        severity=Severity.HIGH,
                        message="Cannot determine AppArmor profile status",
                        details=f"Error parsing aa-status output: {str(e)}"
                    ))

    def check_apparmor_profiles_enforcing(self):
        """1.3.1.4 - Ensure all AppArmor Profiles are enforcing"""
        # Check that all profiles are in enforce mode (not complain mode)
        returncode, stdout, stderr = self.run_command(['aa-status', '--json'])

        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.3.1.4",
                title="Ensure all AppArmor Profiles are enforcing",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message="Cannot check AppArmor profile enforcement status",
                details="aa-status command failed or AppArmor not running",
                remediation="Ensure AppArmor is installed and running"
            ))
            return

        try:
            import json as json_module
            status_data = json_module.loads(stdout)

            enforce_count = len(status_data.get('profiles', {}).get('enforce', []))
            complain_count = len(status_data.get('profiles', {}).get('complain', []))
            complain_profiles = status_data.get('profiles', {}).get('complain', [])

            if complain_count == 0 and enforce_count > 0:
                self.reporter.add_result(AuditResult(
                    check_id="1.3.1.4",
                    title="Ensure all AppArmor Profiles are enforcing",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message=f"All {enforce_count} profiles are in enforce mode"
                ))
            elif enforce_count == 0 and complain_count == 0:
                self.reporter.add_result(AuditResult(
                    check_id="1.3.1.4",
                    title="Ensure all AppArmor Profiles are enforcing",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    message="No AppArmor profiles are loaded",
                    remediation="Load and enforce AppArmor profiles for critical services"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.3.1.4",
                    title="Ensure all AppArmor Profiles are enforcing",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"{complain_count} profiles are in complain mode (should be enforcing)",
                    details=f"Complaining profiles: {', '.join(complain_profiles[:5])}{'...' if len(complain_profiles) > 5 else ''}",
                    remediation="Set profiles to enforce mode: aa-enforce /etc/apparmor.d/*"
                ))
        except Exception as e:
            # Fallback to text parsing
            returncode, stdout, stderr = self.run_command(['aa-status'])
            if returncode == 0:
                complain_match = re.search(r'(\d+)\s+profiles are in complain mode', stdout)
                enforce_match = re.search(r'(\d+)\s+profiles are in enforce mode', stdout)

                complain_count = int(complain_match.group(1)) if complain_match else 0
                enforce_count = int(enforce_match.group(1)) if enforce_match else 0

                if complain_count == 0 and enforce_count > 0:
                    self.reporter.add_result(AuditResult(
                        check_id="1.3.1.4",
                        title="Ensure all AppArmor Profiles are enforcing",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message=f"All {enforce_count} profiles are in enforce mode"
                    ))
                elif complain_count > 0:
                    self.reporter.add_result(AuditResult(
                        check_id="1.3.1.4",
                        title="Ensure all AppArmor Profiles are enforcing",
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        message=f"{complain_count} profiles in complain mode",
                        remediation="Set profiles to enforce mode: aa-enforce /etc/apparmor.d/*"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="1.3.1.4",
                        title="Ensure all AppArmor Profiles are enforcing",
                        status=Status.WARNING,
                        severity=Severity.MEDIUM,
                        message="Cannot determine enforcement status"
                    ))

    def run_all_checks(self):
        """Run all AppArmor checks"""
        self.check_apparmor_installed()
        self.check_apparmor_bootloader()
        self.check_apparmor_profiles_mode()
        self.check_apparmor_profiles_enforcing()


class BootloaderAuditor(BaseAuditor):
    """Auditor for bootloader security configuration (1.4.x)"""

    def check_bootloader_password(self):
        """1.4.1 - Ensure bootloader password is set"""
        # Check GRUB configuration for password protection
        grub_config_paths = [
            '/boot/grub/grub.cfg',
            '/boot/grub2/grub.cfg'
        ]

        grub_user_cfg = '/boot/grub/user.cfg'
        password_set = False

        # Check for password in grub.cfg
        for grub_path in grub_config_paths:
            if self.file_exists(grub_path):
                content = self.read_file(grub_path)
                if content:
                    # Look for password_pbkdf2 or password entries
                    if 'password_pbkdf2' in content or 'set superusers' in content:
                        password_set = True
                        break

        # Also check user.cfg which is sometimes used for passwords
        if not password_set and self.file_exists(grub_user_cfg):
            content = self.read_file(grub_user_cfg)
            if content and ('password_pbkdf2' in content or 'GRUB2_PASSWORD' in content):
                password_set = True

        if password_set:
            self.reporter.add_result(AuditResult(
                check_id="1.4.1",
                title="Ensure bootloader password is set",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="Bootloader password is configured"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.4.1",
                title="Ensure bootloader password is set",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Bootloader password is not set",
                details="Setting a bootloader password prevents unauthorized users from modifying boot parameters or accessing single-user mode",
                remediation="Create encrypted password with 'grub-mkpasswd-pbkdf2' and add to /etc/grub.d/40_custom, then run 'update-grub'"
            ))

    def check_bootloader_config_permissions(self):
        """1.4.2 - Ensure access to bootloader config is configured"""
        # Check permissions on GRUB configuration files
        grub_config_paths = [
            '/boot/grub/grub.cfg',
            '/boot/grub2/grub.cfg'
        ]

        issues = []
        checked_files = []

        for grub_path in grub_config_paths:
            if self.file_exists(grub_path):
                checked_files.append(grub_path)
                stat_info = self.get_file_stat(grub_path)

                if stat_info:
                    mode = stat.S_IMODE(stat_info.st_mode)
                    owner_uid = stat_info.st_uid
                    group_gid = stat_info.st_gid

                    # Check owner is root (UID 0)
                    if owner_uid != 0:
                        issues.append(f"{grub_path}: Owner is not root (UID {owner_uid})")

                    # Check group is root (GID 0)
                    if group_gid != 0:
                        issues.append(f"{grub_path}: Group is not root (GID {group_gid})")

                    # Check permissions are 0400 or 0600 (read-only for owner, no access for others)
                    # Mode should be 0o400 (r--------) or 0o600 (rw-------)
                    if mode & 0o077:  # Check if group or others have any permissions
                        issues.append(f"{grub_path}: Permissions {oct(mode)} are too permissive (should be 0400 or 0600)")

                    if mode & 0o200 and mode != 0o600:  # If writable but not exactly 0600
                        issues.append(f"{grub_path}: File is writable but permissions {oct(mode)} are not 0600")

        # Also check /boot/grub/ directory permissions
        grub_dir = '/boot/grub'
        if self.file_exists(grub_dir):
            checked_files.append(grub_dir)
            stat_info = self.get_file_stat(grub_dir)
            if stat_info:
                mode = stat.S_IMODE(stat_info.st_mode)
                if mode & 0o077:  # Check if group or others have write/execute
                    if mode & 0o022:  # Others have write permission
                        issues.append(f"{grub_dir}: Directory permissions {oct(mode)} allow group/other write access")

        if len(checked_files) == 0:
            self.reporter.add_result(AuditResult(
                check_id="1.4.2",
                title="Ensure access to bootloader config is configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="No bootloader configuration files found",
                details="Cannot verify permissions on non-existent files"
            ))
        elif len(issues) == 0:
            self.reporter.add_result(AuditResult(
                check_id="1.4.2",
                title="Ensure access to bootloader config is configured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message=f"Bootloader configuration files have correct permissions ({len(checked_files)} files checked)"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.4.2",
                title="Ensure access to bootloader config is configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Bootloader configuration files have incorrect permissions",
                details="\n".join(issues),
                remediation="Fix permissions: chown root:root /boot/grub/grub.cfg && chmod 0400 /boot/grub/grub.cfg"
            ))

    def check_bootloader_not_overwritten(self):
        """1.5.1 - Ensure bootloader config is not overwritten"""
        # Check if grub.cfg is regenerated or if custom entries exist
        grub_config_paths = [
            '/boot/grub/grub.cfg',
            '/boot/grub2/grub.cfg'
        ]

        issues = []
        for grub_path in grub_config_paths:
            if self.file_exists(grub_path):
                content = self.read_file(grub_path)
                if content:
                    # Check for warning about manual editing
                    if '### BEGIN /etc/grub.d' in content or 'DO NOT EDIT THIS FILE' in content:
                        # This is auto-generated - good
                        pass
                    else:
                        issues.append(f"{grub_path} erscheint manuell editiert zu sein")

        # Check /etc/default/grub for update-grub usage
        grub_default = '/etc/default/grub'
        if self.file_exists(grub_default):
            self.reporter.add_result(AuditResult(
                check_id="1.5.1",
                title="Ensure bootloader config is not overwritten",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="Bootloader-Konfiguration verwendet update-grub Mechanismus",
                details="Änderungen sollten in /etc/default/grub oder /etc/grub.d/* vorgenommen werden"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.5.1",
                title="Ensure bootloader config is not overwritten",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message="/etc/default/grub nicht gefunden",
                remediation="Stellen Sie sicher, dass Bootloader-Änderungen über update-grub erfolgen"
            ))

    def check_bootloader_permissions_configured(self):
        """1.5.2 - Ensure permissions on bootloader config are configured"""
        # This is similar to 1.4.2 but with focus on /etc/grub.d and /etc/default/grub
        issues = []

        # Check /etc/default/grub
        grub_default = '/etc/default/grub'
        if self.file_exists(grub_default):
            stat_info = self.get_file_stat(grub_default)
            if stat_info:
                mode = stat.S_IMODE(stat_info.st_mode)
                if mode & 0o077:  # Group or others have permissions
                    issues.append(f"{grub_default}: Berechtigungen {oct(mode)} sind zu permissiv (sollte 0644 oder restriktiver sein)")
                if stat_info.st_uid != 0:
                    issues.append(f"{grub_default}: Besitzer ist nicht root")

        # Check /etc/grub.d directory
        grub_d_dir = '/etc/grub.d'
        if self.file_exists(grub_d_dir):
            stat_info = self.get_file_stat(grub_d_dir)
            if stat_info:
                mode = stat.S_IMODE(stat_info.st_mode)
                if mode & 0o022:  # Others have write access
                    issues.append(f"{grub_d_dir}: Verzeichnis-Berechtigungen {oct(mode)} erlauben anderen Schreibzugriff")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="1.5.2",
                title="Ensure permissions on bootloader config are configured",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Bootloader-Konfigurations-Berechtigungen sind inkorrekt",
                details="\n".join([f"  - {issue}" for issue in issues]),
                remediation="Führen Sie aus: chown root:root /etc/default/grub /etc/grub.d && chmod 0644 /etc/default/grub"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.5.2",
                title="Ensure permissions on bootloader config are configured",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="Bootloader-Konfigurations-Berechtigungen sind korrekt"
            ))

    def check_single_user_authentication(self):
        """1.5.3 - Ensure authentication required for single user mode"""
        # Check if systemd rescue/emergency mode requires authentication
        rescue_service = '/lib/systemd/system/rescue.service'
        emergency_service = '/lib/systemd/system/emergency.service'

        issues = []

        for service_file in [rescue_service, emergency_service]:
            if self.file_exists(service_file):
                content = self.read_file(service_file)
                if content:
                    # Check for ExecStart with sulogin
                    if 'ExecStart=' in content:
                        if 'sulogin' not in content and 'sushell' not in content:
                            service_name = service_file.split('/')[-1]
                            issues.append(f"{service_name}: ExecStart verwendet nicht sulogin")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="1.5.3",
                title="Ensure authentication required for single user mode",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Single-User-Mode erfordert keine Authentifizierung",
                details="\n".join([f"  - {issue}" for issue in issues]),
                remediation="Bearbeiten Sie rescue.service und emergency.service um 'ExecStart=-/bin/sh' durch 'ExecStart=-/lib/systemd/systemd-sulogin-shell rescue' zu ersetzen"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.5.3",
                title="Ensure authentication required for single user mode",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="Single-User-Mode erfordert Authentifizierung"
            ))

    def check_core_dumps_restricted(self):
        """1.5.4 - Ensure core dumps are restricted"""
        # Check multiple aspects of core dump configuration
        issues = []

        # 1. Check sysctl fs.suid_dumpable
        suid_dumpable = self.read_file('/proc/sys/fs/suid_dumpable')
        if suid_dumpable and suid_dumpable.strip() != '0':
            issues.append(f"fs.suid_dumpable ist {suid_dumpable.strip()} (sollte 0 sein)")

        # 2. Check systemd coredump configuration
        coredump_conf = '/etc/systemd/coredump.conf'
        if self.file_exists(coredump_conf):
            content = self.read_file(coredump_conf)
            if content:
                # Check for Storage=none
                if 'Storage=none' not in content and '#Storage=' not in content:
                    # Default is usually external, which might be ok, but CIS recommends none
                    pass  # Don't fail on this alone

        # 3. Check limits.conf for hard core limit
        limits_conf = '/etc/security/limits.conf'
        found_core_limit = False
        if self.file_exists(limits_conf):
            content = self.read_file(limits_conf)
            if content:
                # Look for "* hard core 0"
                for line in content.splitlines():
                    if line.strip() and not line.strip().startswith('#'):
                        if 'hard' in line and 'core' in line and '0' in line:
                            found_core_limit = True
                            break

        if not found_core_limit:
            issues.append("Core dump limit nicht in /etc/security/limits.conf konfiguriert")

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="1.5.4",
                title="Ensure core dumps are restricted",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Core dumps sind nicht ausreichend eingeschränkt",
                details="\n".join([f"  - {issue}" for issue in issues]),
                remediation="Setzen Sie fs.suid_dumpable=0 in /etc/sysctl.conf und fügen Sie '* hard core 0' zu /etc/security/limits.conf hinzu"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.5.4",
                title="Ensure core dumps are restricted",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="Core dumps sind korrekt eingeschränkt"
            ))

    def run_all_checks(self):
        """Run all bootloader security and filesystem integrity checks"""
        # 1.4.x - Bootloader Security
        self.check_bootloader_password()
        self.check_bootloader_config_permissions()

        # 1.5.x - Filesystem Integrity
        self.check_bootloader_not_overwritten()
        self.check_bootloader_permissions_configured()
        self.check_single_user_authentication()
        self.check_core_dumps_restricted()


class GDMAuditor(BaseAuditor):
    """Auditor for GNOME Display Manager configuration (1.7.x)"""

    def check_gdm_removed_or_configured(self):
        """1.7.1 - Ensure GDM is removed or login is configured"""
        # Check if GDM3 is installed
        returncode, stdout, stderr = self.run_command(['dpkg', '-s', 'gdm3'])

        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.1",
                title="Ensure GDM is removed or login is configured",
                status=Status.PASS,
                severity=Severity.LOW,
                message="GDM3 is not installed (server system)"
            ))
            return

        # GDM3 is installed, check if it's configured
        # This is informational - configuration is checked in subsequent tests
        self.reporter.add_result(AuditResult(
            check_id="1.7.1",
            title="Ensure GDM is removed or login is configured",
            status=Status.PASS,
            severity=Severity.LOW,
            message="GDM3 is installed (check subsequent GDM configuration tests)",
            details="GDM3 detected - ensure it is properly configured"
        ))

    def check_gdm_banner(self):
        """1.7.2 - Ensure GDM login banner is configured"""
        # Check if GDM3 is installed
        returncode, _, _ = self.run_command(['dpkg', '-s', 'gdm3'])
        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.2",
                title="Ensure GDM login banner is configured",
                status=Status.SKIP,
                severity=Severity.LOW,
                message="GDM3 is not installed"
            ))
            return

        # Check for banner configuration in GDM dconf profile
        banner_paths = [
            '/etc/dconf/db/gdm.d/01-banner-message',
            '/etc/gdm3/greeter.dconf-defaults'
        ]

        banner_configured = False
        for path in banner_paths:
            if self.file_exists(path):
                content = self.read_file(path)
                if content and 'banner-message-enable=true' in content.replace(' ', ''):
                    banner_configured = True
                    break

        if banner_configured:
            self.reporter.add_result(AuditResult(
                check_id="1.7.2",
                title="Ensure GDM login banner is configured",
                status=Status.PASS,
                severity=Severity.LOW,
                message="GDM login banner is configured"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.7.2",
                title="Ensure GDM login banner is configured",
                status=Status.FAIL,
                severity=Severity.LOW,
                message="GDM login banner is not configured",
                details="Login banners can display security warnings or acceptable use policies",
                remediation="Create /etc/dconf/db/gdm.d/01-banner-message with banner-message-enable=true"
            ))

    def check_gdm_disable_user_list(self):
        """1.7.3 - Ensure GDM disable-user-list option is enabled"""
        returncode, _, _ = self.run_command(['dpkg', '-s', 'gdm3'])
        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.3",
                title="Ensure GDM disable-user-list option is enabled",
                status=Status.SKIP,
                severity=Severity.MEDIUM,
                message="GDM3 is not installed"
            ))
            return

        config_paths = [
            '/etc/dconf/db/gdm.d/00-login-screen',
            '/etc/gdm3/greeter.dconf-defaults'
        ]

        user_list_disabled = False
        for path in config_paths:
            if self.file_exists(path):
                content = self.read_file(path)
                if content and 'disable-user-list=true' in content.replace(' ', ''):
                    user_list_disabled = True
                    break

        if user_list_disabled:
            self.reporter.add_result(AuditResult(
                check_id="1.7.3",
                title="Ensure GDM disable-user-list option is enabled",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="GDM user list is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.7.3",
                title="Ensure GDM disable-user-list option is enabled",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="GDM user list is not disabled",
                details="Disabling the user list prevents user enumeration",
                remediation="Create /etc/dconf/db/gdm.d/00-login-screen with disable-user-list=true"
            ))

    def check_gdm_screen_lock_idle(self):
        """1.7.4 - Ensure GDM screen locks when the user is idle"""
        returncode, _, _ = self.run_command(['dpkg', '-s', 'gdm3'])
        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.4",
                title="Ensure GDM screen locks when the user is idle",
                status=Status.SKIP,
                severity=Severity.MEDIUM,
                message="GDM3 is not installed"
            ))
            return

        config_path = '/etc/dconf/db/local.d/00-screensaver'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="1.7.4",
                title="Ensure GDM screen locks when the user is idle",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Screen lock configuration not found",
                remediation=f"Create {config_path} with idle-delay and lock-enabled settings"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="1.7.4",
                title="Ensure GDM screen locks when the user is idle",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Cannot read {config_path}"
            ))
            return

        # Check for idle-delay and lock-enabled settings
        has_idle_delay = 'idle-delay' in content
        has_lock_enabled = 'lock-enabled=true' in content.replace(' ', '')

        if has_idle_delay and has_lock_enabled:
            self.reporter.add_result(AuditResult(
                check_id="1.7.4",
                title="Ensure GDM screen locks when the user is idle",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="Screen lock on idle is configured"
            ))
        else:
            missing = []
            if not has_idle_delay:
                missing.append("idle-delay")
            if not has_lock_enabled:
                missing.append("lock-enabled")

            self.reporter.add_result(AuditResult(
                check_id="1.7.4",
                title="Ensure GDM screen locks when the user is idle",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message=f"Screen lock configuration incomplete: missing {', '.join(missing)}",
                remediation=f"Edit {config_path} and add idle-delay and lock-enabled=true"
            ))

    def check_gdm_screen_lock_override(self):
        """1.7.5 - Ensure GDM screen locks cannot be overridden"""
        returncode, _, _ = self.run_command(['dpkg', '-s', 'gdm3'])
        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.5",
                title="Ensure GDM screen locks cannot be overridden",
                status=Status.SKIP,
                severity=Severity.MEDIUM,
                message="GDM3 is not installed"
            ))
            return

        locks_path = '/etc/dconf/db/local.d/locks/00-screensaver'

        if not self.file_exists(locks_path):
            self.reporter.add_result(AuditResult(
                check_id="1.7.5",
                title="Ensure GDM screen locks cannot be overridden",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Screen lock settings are not locked (can be overridden by users)",
                remediation=f"Create {locks_path} to lock screen saver settings"
            ))
            return

        content = self.read_file(locks_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="1.7.5",
                title="Ensure GDM screen locks cannot be overridden",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Cannot read {locks_path}"
            ))
            return

        # Check for locked settings
        has_locks = '/org/gnome/desktop/screensaver/' in content or '/org/gnome/desktop/session/' in content

        if has_locks:
            self.reporter.add_result(AuditResult(
                check_id="1.7.5",
                title="Ensure GDM screen locks cannot be overridden",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="Screen lock settings are locked"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.7.5",
                title="Ensure GDM screen locks cannot be overridden",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Screen lock settings file exists but appears incomplete",
                remediation=f"Edit {locks_path} to lock screensaver settings"
            ))

    def check_gdm_automount_disabled(self):
        """1.7.6 - Ensure GDM automatic mounting of removable media is disabled"""
        returncode, _, _ = self.run_command(['dpkg', '-s', 'gdm3'])
        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.6",
                title="Ensure GDM automatic mounting of removable media is disabled",
                status=Status.SKIP,
                severity=Severity.MEDIUM,
                message="GDM3 is not installed"
            ))
            return

        config_path = '/etc/dconf/db/local.d/00-media-automount'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="1.7.6",
                title="Ensure GDM automatic mounting of removable media is disabled",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Automount configuration not found",
                remediation=f"Create {config_path} with automount settings disabled"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="1.7.6",
                title="Ensure GDM automatic mounting of removable media is disabled",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Cannot read {config_path}"
            ))
            return

        # Check for automount disabled settings
        automount_disabled = 'automount=false' in content.replace(' ', '')
        automount_open_disabled = 'automount-open=false' in content.replace(' ', '')

        if automount_disabled and automount_open_disabled:
            self.reporter.add_result(AuditResult(
                check_id="1.7.6",
                title="Ensure GDM automatic mounting of removable media is disabled",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="Automatic mounting is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.7.6",
                title="Ensure GDM automatic mounting of removable media is disabled",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Automatic mounting is not properly disabled",
                remediation=f"Edit {config_path} with automount=false and automount-open=false"
            ))

    def check_gdm_automount_override(self):
        """1.7.7 - Ensure GDM disabling automatic mounting is not overridden"""
        returncode, _, _ = self.run_command(['dpkg', '-s', 'gdm3'])
        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.7",
                title="Ensure GDM disabling automatic mounting is not overridden",
                status=Status.SKIP,
                severity=Severity.MEDIUM,
                message="GDM3 is not installed"
            ))
            return

        locks_path = '/etc/dconf/db/local.d/locks/00-media-automount'

        if not self.file_exists(locks_path):
            self.reporter.add_result(AuditResult(
                check_id="1.7.7",
                title="Ensure GDM disabling automatic mounting is not overridden",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Automount settings are not locked",
                remediation=f"Create {locks_path} to lock automount settings"
            ))
            return

        content = self.read_file(locks_path)
        if content and '/org/gnome/desktop/media-handling/' in content:
            self.reporter.add_result(AuditResult(
                check_id="1.7.7",
                title="Ensure GDM disabling automatic mounting is not overridden",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="Automount settings are locked"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.7.7",
                title="Ensure GDM disabling automatic mounting is not overridden",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Automount lock file incomplete",
                remediation=f"Edit {locks_path} to lock media-handling settings"
            ))

    def check_gdm_autorun_never(self):
        """1.7.8 - Ensure GDM autorun-never is enabled"""
        returncode, _, _ = self.run_command(['dpkg', '-s', 'gdm3'])
        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.8",
                title="Ensure GDM autorun-never is enabled",
                status=Status.SKIP,
                severity=Severity.HIGH,
                message="GDM3 is not installed"
            ))
            return

        config_path = '/etc/dconf/db/local.d/00-media-autorun'

        if not self.file_exists(config_path):
            self.reporter.add_result(AuditResult(
                check_id="1.7.8",
                title="Ensure GDM autorun-never is enabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Autorun configuration not found",
                details="Autorun can automatically execute malicious code from removable media",
                remediation=f"Create {config_path} with autorun-never=true"
            ))
            return

        content = self.read_file(config_path)
        if content and 'autorun-never=true' in content.replace(' ', ''):
            self.reporter.add_result(AuditResult(
                check_id="1.7.8",
                title="Ensure GDM autorun-never is enabled",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="Autorun is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.7.8",
                title="Ensure GDM autorun-never is enabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Autorun is not disabled",
                details="Autorun can execute malicious code",
                remediation=f"Edit {config_path} with autorun-never=true"
            ))

    def check_gdm_autorun_override(self):
        """1.7.9 - Ensure GDM autorun-never is not overridden"""
        returncode, _, _ = self.run_command(['dpkg', '-s', 'gdm3'])
        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.9",
                title="Ensure GDM autorun-never is not overridden",
                status=Status.SKIP,
                severity=Severity.HIGH,
                message="GDM3 is not installed"
            ))
            return

        locks_path = '/etc/dconf/db/local.d/locks/00-media-autorun'

        if not self.file_exists(locks_path):
            self.reporter.add_result(AuditResult(
                check_id="1.7.9",
                title="Ensure GDM autorun-never is not overridden",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Autorun settings are not locked",
                remediation=f"Create {locks_path} to lock autorun settings"
            ))
            return

        content = self.read_file(locks_path)
        if content and '/org/gnome/desktop/media-handling/autorun-never' in content:
            self.reporter.add_result(AuditResult(
                check_id="1.7.9",
                title="Ensure GDM autorun-never is not overridden",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="Autorun settings are locked"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.7.9",
                title="Ensure GDM autorun-never is not overridden",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Autorun lock file incomplete",
                remediation=f"Edit {locks_path} to lock autorun-never setting"
            ))

    def check_xdmcp_disabled(self):
        """1.7.10 - Ensure XDMCP is not enabled"""
        # Check if GDM3 is installed
        returncode, _, _ = self.run_command(['dpkg', '-s', 'gdm3'])
        if returncode != 0:
            self.reporter.add_result(AuditResult(
                check_id="1.7.10",
                title="Ensure XDMCP is not enabled",
                status=Status.SKIP,
                severity=Severity.HIGH,
                message="GDM3 is not installed"
            ))
            return

        config_path = '/etc/gdm3/custom.conf'

        if not self.file_exists(config_path):
            # No custom config means XDMCP is disabled by default
            self.reporter.add_result(AuditResult(
                check_id="1.7.10",
                title="Ensure XDMCP is not enabled",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="XDMCP is disabled (no custom configuration)"
            ))
            return

        content = self.read_file(config_path)
        if not content:
            self.reporter.add_result(AuditResult(
                check_id="1.7.10",
                title="Ensure XDMCP is not enabled",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Cannot read {config_path}"
            ))
            return

        # Check if XDMCP is enabled
        xdmcp_enabled = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('Enable=true') or line.startswith('Enable = true'):
                # Check if this is in the [xdmcp] section (need to track sections)
                if '[xdmcp]' in content.lower():
                    xdmcp_enabled = True
                    break

        if not xdmcp_enabled:
            self.reporter.add_result(AuditResult(
                check_id="1.7.10",
                title="Ensure XDMCP is not enabled",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="XDMCP is disabled"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="1.7.10",
                title="Ensure XDMCP is not enabled",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="XDMCP is enabled",
                details="XDMCP is an insecure protocol that sends authentication in cleartext",
                remediation=f"Edit {config_path} and set Enable=false in [xdmcp] section or remove the section"
            ))

    def run_all_checks(self):
        """Run all GDM configuration checks"""
        self.check_gdm_removed_or_configured()
        self.check_gdm_banner()
        self.check_gdm_disable_user_list()
        self.check_gdm_screen_lock_idle()
        self.check_gdm_screen_lock_override()
        self.check_gdm_automount_disabled()
        self.check_gdm_automount_override()
        self.check_gdm_autorun_never()
        self.check_gdm_autorun_override()
        self.check_xdmcp_disabled()


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

    def check_root_path_integrity(self):
        """5.6.9 - Ensure root PATH Integrity"""
        issues = []

        try:
            # Get root's PATH
            root_path = os.environ.get('PATH', '')
            if not root_path:
                # Try to get from root's shell environment
                returncode, stdout, _ = self.run_command(['su', '-', 'root', '-c', 'echo $PATH'])
                if returncode == 0:
                    root_path = stdout.strip()

            if not root_path:
                self.reporter.add_result(AuditResult(
                    check_id="5.6.9",
                    title="Ensure root PATH Integrity",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="Cannot determine root's PATH"
                ))
                return

            # Check each directory in PATH
            path_dirs = root_path.split(':')
            for path_dir in path_dirs:
                # Check for empty directory (.)
                if not path_dir or path_dir == '.':
                    issues.append("PATH contains empty directory or '.'")
                    continue

                # Check if directory exists
                if not os.path.exists(path_dir):
                    issues.append(f"PATH contains non-existent directory: {path_dir}")
                    continue

                # Check directory ownership and permissions
                try:
                    stat_info = os.stat(path_dir)

                    # Check ownership (should be root)
                    if stat_info.st_uid != 0:
                        owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
                        issues.append(f"PATH directory {path_dir} owned by {owner_name} (not root)")

                    # Check permissions (should not be group or world writable)
                    mode = stat.S_IMODE(stat_info.st_mode)
                    if mode & 0o022:
                        issues.append(f"PATH directory {path_dir} is group or world writable ({oct(mode)})")

                except (OSError, KeyError) as e:
                    issues.append(f"Cannot stat PATH directory {path_dir}: {str(e)}")

        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.6.9",
                title="Ensure root PATH Integrity",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Error checking root PATH: {str(e)}"
            ))
            return

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="5.6.9",
                title="Ensure root PATH Integrity",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="Root PATH integrity issues found",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="Ensure root's PATH only contains secure directories owned by root"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.6.9",
                title="Ensure root PATH Integrity",
                status=Status.PASS,
                severity=Severity.HIGH,
                message="Root PATH integrity verified"
            ))

    def check_all_users_have_home_dirs(self):
        """5.6.10 - Ensure all interactive users' home directories exist"""
        issues = []

        try:
            for user in pwd.getpwall():
                # Check only interactive users (UID >= 1000, has valid shell)
                if user.pw_uid >= 1000 and user.pw_uid != 65534:  # Skip nobody
                    # Check if user has a valid shell (not /usr/sbin/nologin or /bin/false)
                    if user.pw_shell not in ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin']:
                        home_dir = user.pw_dir

                        # Check if home directory is defined
                        if not home_dir or home_dir == '/':
                            issues.append(f"User {user.pw_name}: no valid home directory defined")
                            continue

                        # Check if home directory exists
                        if not os.path.exists(home_dir):
                            issues.append(f"User {user.pw_name}: home directory {home_dir} does not exist")

        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.6.10",
                title="Ensure all interactive users home directories exist",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking home directories: {str(e)}"
            ))
            return

        if issues:
            self.reporter.add_result(AuditResult(
                check_id="5.6.10",
                title="Ensure all interactive users home directories exist",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="Interactive users without home directories found",
                details="\n".join(f"  - {issue}" for issue in issues),
                remediation="Create missing home directories: mkhomedir_helper <username>"
            ))
        else:
            self.reporter.add_result(AuditResult(
                check_id="5.6.10",
                title="Ensure all interactive users home directories exist",
                status=Status.PASS,
                severity=Severity.MEDIUM,
                message="All interactive users have valid home directories"
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
        self.check_root_path_integrity()
        self.check_all_users_have_home_dirs()


class PAMAuditor(BaseAuditor):
    """PAM and Password Policy auditor for CIS checks 5.3.x and 5.4.x"""

    def check_pam_pwquality_installed(self):
        """5.3.1.1 - Ensure password creation requirements are configured (libpam-pwquality)"""
        try:
            returncode, stdout, _ = self.run_command(['dpkg', '-s', 'libpam-pwquality'])

            if returncode == 0 and 'Status: install ok installed' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.1.1",
                    title="Ensure password creation requirements are configured",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="libpam-pwquality ist installiert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.1.1",
                    title="Ensure password creation requirements are configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="libpam-pwquality ist nicht installiert",
                    remediation="apt install libpam-pwquality"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.3.1.1",
                title="Ensure password creation requirements are configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_pwquality_config(self):
        """5.3.1.2 - Ensure password quality requirements are configured"""
        try:
            config_file = '/etc/security/pwquality.conf'

            if not self.file_exists(config_file):
                self.reporter.add_result(AuditResult(
                    check_id="5.3.1.2",
                    title="Ensure password quality requirements are configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message=f"{config_file} nicht gefunden",
                    remediation="apt install libpam-pwquality"
                ))
                return

            config = self.read_file(config_file)
            if not config:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.1.2",
                    title="Ensure password quality requirements are configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message=f"{config_file} konnte nicht gelesen werden",
                    remediation="Überprüfen Sie die Dateiberechtigungen"
                ))
                return

            # Check for required password quality settings
            required_settings = {
                'minlen': 14,
                'minclass': 4,
                'dcredit': -1,
                'ucredit': -1,
                'lcredit': -1,
                'ocredit': -1
            }

            issues = []
            for setting, min_value in required_settings.items():
                pattern = rf'^\s*{setting}\s*=\s*(-?\d+)'
                match = re.search(pattern, config, re.MULTILINE)

                if not match:
                    issues.append(f"{setting} nicht konfiguriert (empfohlen: {min_value})")
                else:
                    value = int(match.group(1))
                    if setting == 'minlen' and value < min_value:
                        issues.append(f"{setting}={value} ist zu klein (empfohlen: >= {min_value})")
                    elif setting != 'minlen' and value > min_value:
                        issues.append(f"{setting}={value} sollte <= {min_value} sein")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.1.2",
                    title="Ensure password quality requirements are configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Password-Qualitätsanforderungen nicht ausreichend konfiguriert",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation=f"Bearbeiten Sie {config_file} und passen Sie die Einstellungen an"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.1.2",
                    title="Ensure password quality requirements are configured",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="Password-Qualitätsanforderungen sind korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.3.1.2",
                title="Ensure password quality requirements are configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_pam_faillock(self):
        """5.3.2.1 - Ensure lockout for failed password attempts is configured"""
        try:
            pam_files = ['/etc/pam.d/common-auth', '/etc/pam.d/common-account']
            issues = []

            for pam_file in pam_files:
                if not self.file_exists(pam_file):
                    issues.append(f"{pam_file} nicht gefunden")
                    continue

                content = self.read_file(pam_file)
                if not content:
                    issues.append(f"{pam_file} konnte nicht gelesen werden")
                    continue

                if 'pam_faillock' in pam_file and 'common-auth' in pam_file:
                    if 'pam_faillock.so' not in content:
                        issues.append(f"pam_faillock.so nicht in {pam_file} konfiguriert")

                if 'common-account' in pam_file:
                    if 'pam_faillock.so' not in content:
                        issues.append(f"pam_faillock.so nicht in {pam_file} konfiguriert")

            # Check faillock.conf
            faillock_conf = '/etc/security/faillock.conf'
            if self.file_exists(faillock_conf):
                config = self.read_file(faillock_conf)
                if config:
                    # Check for deny, unlock_time settings
                    if not re.search(r'^\s*deny\s*=\s*[1-5]\s*$', config, re.MULTILINE):
                        issues.append("deny-Einstellung nicht korrekt konfiguriert (empfohlen: <= 5)")
                    if not re.search(r'^\s*unlock_time\s*=\s*9\d{2,}', config, re.MULTILINE):
                        issues.append("unlock_time nicht korrekt konfiguriert (empfohlen: >= 900)")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.2.1",
                    title="Ensure lockout for failed password attempts is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Account-Lockout nicht korrekt konfiguriert",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Konfigurieren Sie pam_faillock in /etc/pam.d/ und /etc/security/faillock.conf"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.2.1",
                    title="Ensure lockout for failed password attempts is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Account-Lockout ist korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.3.2.1",
                title="Ensure lockout for failed password attempts is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_pam_pwhistory(self):
        """5.3.3.1 - Ensure password reuse is limited"""
        try:
            pam_file = '/etc/pam.d/common-password'

            if not self.file_exists(pam_file):
                self.reporter.add_result(AuditResult(
                    check_id="5.3.3.1",
                    title="Ensure password reuse is limited",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"{pam_file} nicht gefunden",
                    remediation="Stellen Sie sicher, dass PAM korrekt installiert ist"
                ))
                return

            content = self.read_file(pam_file)
            if not content:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.3.1",
                    title="Ensure password reuse is limited",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"{pam_file} konnte nicht gelesen werden"
                ))
                return

            # Check for pam_pwhistory with remember parameter
            pwhistory_match = re.search(r'pam_pwhistory\.so.*remember=(\d+)', content)

            if not pwhistory_match:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.3.1",
                    title="Ensure password reuse is limited",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="pam_pwhistory nicht konfiguriert",
                    remediation=f"Fügen Sie 'password required pam_pwhistory.so remember=5' zu {pam_file} hinzu"
                ))
            else:
                remember_value = int(pwhistory_match.group(1))
                if remember_value < 5:
                    self.reporter.add_result(AuditResult(
                        check_id="5.3.3.1",
                        title="Ensure password reuse is limited",
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        message=f"Password-History zu niedrig: remember={remember_value}",
                        details="Empfohlen: remember >= 5",
                        remediation=f"Erhöhen Sie den remember-Wert in {pam_file} auf mindestens 5"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.3.3.1",
                        title="Ensure password reuse is limited",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message=f"Password-History korrekt konfiguriert (remember={remember_value})"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.3.3.1",
                title="Ensure password reuse is limited",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_pam_unix_sha512(self):
        """5.3.3.2 - Ensure password hashing algorithm is SHA-512"""
        try:
            pam_file = '/etc/pam.d/common-password'

            if not self.file_exists(pam_file):
                self.reporter.add_result(AuditResult(
                    check_id="5.3.3.2",
                    title="Ensure password hashing algorithm is SHA-512",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message=f"{pam_file} nicht gefunden"
                ))
                return

            content = self.read_file(pam_file)
            if not content:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.3.2",
                    title="Ensure password hashing algorithm is SHA-512",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message=f"{pam_file} konnte nicht gelesen werden"
                ))
                return

            # Check for pam_unix.so with sha512
            if re.search(r'pam_unix\.so.*sha512', content):
                self.reporter.add_result(AuditResult(
                    check_id="5.3.3.2",
                    title="Ensure password hashing algorithm is SHA-512",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="Password-Hashing verwendet SHA-512"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.3.3.2",
                    title="Ensure password hashing algorithm is SHA-512",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="SHA-512 nicht für Password-Hashing konfiguriert",
                    remediation=f"Fügen Sie 'sha512' zu pam_unix.so in {pam_file} hinzu"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.3.3.2",
                title="Ensure password hashing algorithm is SHA-512",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_password_max_days(self):
        """5.4.1.1 - Ensure password expiration is 365 days or less"""
        try:
            login_defs = '/etc/login.defs'

            if not self.file_exists(login_defs):
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.1",
                    title="Ensure password expiration is 365 days or less",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"{login_defs} nicht gefunden"
                ))
                return

            content = self.read_file(login_defs)
            if not content:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.1",
                    title="Ensure password expiration is 365 days or less",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"{login_defs} konnte nicht gelesen werden"
                ))
                return

            match = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)

            if not match:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.1",
                    title="Ensure password expiration is 365 days or less",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="PASS_MAX_DAYS nicht konfiguriert",
                    remediation=f"Setzen Sie PASS_MAX_DAYS auf 365 oder weniger in {login_defs}"
                ))
            else:
                max_days = int(match.group(1))
                if max_days > 365:
                    self.reporter.add_result(AuditResult(
                        check_id="5.4.1.1",
                        title="Ensure password expiration is 365 days or less",
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        message=f"PASS_MAX_DAYS zu hoch: {max_days} Tage",
                        details="Empfohlen: <= 365 Tage",
                        remediation=f"Setzen Sie PASS_MAX_DAYS auf 365 oder weniger in {login_defs}"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.4.1.1",
                        title="Ensure password expiration is 365 days or less",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message=f"PASS_MAX_DAYS korrekt konfiguriert ({max_days} Tage)"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.4.1.1",
                title="Ensure password expiration is 365 days or less",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_password_min_days(self):
        """5.4.1.2 - Ensure minimum days between password changes is configured"""
        try:
            login_defs = '/etc/login.defs'

            if not self.file_exists(login_defs):
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.2",
                    title="Ensure minimum days between password changes is configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message=f"{login_defs} nicht gefunden"
                ))
                return

            content = self.read_file(login_defs)
            if not content:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.2",
                    title="Ensure minimum days between password changes is configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message=f"{login_defs} konnte nicht gelesen werden"
                ))
                return

            match = re.search(r'^\s*PASS_MIN_DAYS\s+(\d+)', content, re.MULTILINE)

            if not match:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.2",
                    title="Ensure minimum days between password changes is configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="PASS_MIN_DAYS nicht konfiguriert",
                    remediation=f"Setzen Sie PASS_MIN_DAYS auf 1 oder mehr in {login_defs}"
                ))
            else:
                min_days = int(match.group(1))
                if min_days < 1:
                    self.reporter.add_result(AuditResult(
                        check_id="5.4.1.2",
                        title="Ensure minimum days between password changes is configured",
                        status=Status.FAIL,
                        severity=Severity.LOW,
                        message=f"PASS_MIN_DAYS zu niedrig: {min_days}",
                        details="Empfohlen: >= 1 Tag",
                        remediation=f"Setzen Sie PASS_MIN_DAYS auf 1 oder mehr in {login_defs}"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.4.1.2",
                        title="Ensure minimum days between password changes is configured",
                        status=Status.PASS,
                        severity=Severity.LOW,
                        message=f"PASS_MIN_DAYS korrekt konfiguriert ({min_days} Tag(e))"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.4.1.2",
                title="Ensure minimum days between password changes is configured",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_password_warn_age(self):
        """5.4.1.3 - Ensure password expiration warning days is 7 or more"""
        try:
            login_defs = '/etc/login.defs'

            if not self.file_exists(login_defs):
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.3",
                    title="Ensure password expiration warning days is 7 or more",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message=f"{login_defs} nicht gefunden"
                ))
                return

            content = self.read_file(login_defs)
            if not content:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.3",
                    title="Ensure password expiration warning days is 7 or more",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message=f"{login_defs} konnte nicht gelesen werden"
                ))
                return

            match = re.search(r'^\s*PASS_WARN_AGE\s+(\d+)', content, re.MULTILINE)

            if not match:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.3",
                    title="Ensure password expiration warning days is 7 or more",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="PASS_WARN_AGE nicht konfiguriert",
                    remediation=f"Setzen Sie PASS_WARN_AGE auf 7 oder mehr in {login_defs}"
                ))
            else:
                warn_age = int(match.group(1))
                if warn_age < 7:
                    self.reporter.add_result(AuditResult(
                        check_id="5.4.1.3",
                        title="Ensure password expiration warning days is 7 or more",
                        status=Status.FAIL,
                        severity=Severity.LOW,
                        message=f"PASS_WARN_AGE zu niedrig: {warn_age}",
                        details="Empfohlen: >= 7 Tage",
                        remediation=f"Setzen Sie PASS_WARN_AGE auf 7 oder mehr in {login_defs}"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.4.1.3",
                        title="Ensure password expiration warning days is 7 or more",
                        status=Status.PASS,
                        severity=Severity.LOW,
                        message=f"PASS_WARN_AGE korrekt konfiguriert ({warn_age} Tage)"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.4.1.3",
                title="Ensure password expiration warning days is 7 or more",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_inactive_password_lock(self):
        """5.4.1.4 - Ensure inactive password lock is 30 days or less"""
        try:
            returncode, stdout, _ = self.run_command(['useradd', '-D'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.4",
                    title="Ensure inactive password lock is 30 days or less",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="useradd -D Befehl fehlgeschlagen"
                ))
                return

            match = re.search(r'INACTIVE=(\d+|-1)', stdout)

            if not match:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.4",
                    title="Ensure inactive password lock is 30 days or less",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="INACTIVE nicht konfiguriert",
                    remediation="useradd -D -f 30"
                ))
            else:
                inactive_days = int(match.group(1))
                if inactive_days == -1 or inactive_days > 30:
                    self.reporter.add_result(AuditResult(
                        check_id="5.4.1.4",
                        title="Ensure inactive password lock is 30 days or less",
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        message=f"INACTIVE nicht korrekt: {inactive_days}",
                        details="Empfohlen: <= 30 Tage",
                        remediation="useradd -D -f 30"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.4.1.4",
                        title="Ensure inactive password lock is 30 days or less",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message=f"INACTIVE korrekt konfiguriert ({inactive_days} Tage)"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.4.1.4",
                title="Ensure inactive password lock is 30 days or less",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_user_password_expiry(self):
        """5.4.1.5 - Ensure all users last password change date is in the past"""
        try:
            returncode, stdout, _ = self.run_command(['cat', '/etc/shadow'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.5",
                    title="Ensure all users last password change date is in the past",
                    status=Status.SKIP,
                    severity=Severity.MEDIUM,
                    message="Kann /etc/shadow nicht lesen (Root-Rechte erforderlich)"
                ))
                return

            import time
            current_days = int(time.time() / 86400)
            issues = []

            for line in stdout.splitlines():
                if not line or line.startswith('#'):
                    continue

                fields = line.split(':')
                if len(fields) < 3:
                    continue

                username = fields[0]
                password_change_date = fields[2]

                # Skip system accounts
                if username in ['root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man',
                               'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data',
                               'backup', 'list', 'irc', 'gnats', 'nobody']:
                    continue

                if password_change_date and password_change_date.isdigit():
                    change_days = int(password_change_date)
                    if change_days > current_days:
                        issues.append(f"Benutzer {username}: Passwort-Änderungsdatum in der Zukunft")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.5",
                    title="Ensure all users last password change date is in the past",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Benutzer mit zukünftigem Passwort-Änderungsdatum gefunden",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Korrigieren Sie die Passwort-Änderungsdaten mit chage"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.1.5",
                    title="Ensure all users last password change date is in the past",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Alle Passwort-Änderungsdaten sind korrekt"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.4.1.5",
                title="Ensure all users last password change date is in the past",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_system_accounts_nologin(self):
        """5.4.2 - Ensure system accounts are secured"""
        try:
            passwd_content = self.read_file('/etc/passwd')
            if not passwd_content:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.2",
                    title="Ensure system accounts are secured",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="/etc/passwd konnte nicht gelesen werden"
                ))
                return

            issues = []

            for line in passwd_content.splitlines():
                if not line or line.startswith('#'):
                    continue

                fields = line.split(':')
                if len(fields) < 7:
                    continue

                username = fields[0]
                uid = int(fields[2])
                shell = fields[6]

                # System accounts have UID < 1000 (excluding root)
                if uid < 1000 and username != 'root':
                    # Check if shell is not nologin or false
                    if shell not in ['/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/usr/bin/false']:
                        issues.append(f"System-Account {username} (UID {uid}) hat Login-Shell: {shell}")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.2",
                    title="Ensure system accounts are secured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="System-Accounts mit Login-Shell gefunden",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie die Shell für System-Accounts auf /usr/sbin/nologin oder /bin/false"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.2",
                    title="Ensure system accounts are secured",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="Alle System-Accounts sind gesichert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.4.2",
                title="Ensure system accounts are secured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_default_group_root(self):
        """5.4.3 - Ensure default group for the root account is GID 0"""
        try:
            passwd_content = self.read_file('/etc/passwd')
            if not passwd_content:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.3",
                    title="Ensure default group for the root account is GID 0",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="/etc/passwd konnte nicht gelesen werden"
                ))
                return

            for line in passwd_content.splitlines():
                if line.startswith('root:'):
                    fields = line.split(':')
                    if len(fields) >= 4:
                        gid = fields[3]
                        if gid == '0':
                            self.reporter.add_result(AuditResult(
                                check_id="5.4.3",
                                title="Ensure default group for the root account is GID 0",
                                status=Status.PASS,
                                severity=Severity.HIGH,
                                message="Root-Account hat GID 0"
                            ))
                        else:
                            self.reporter.add_result(AuditResult(
                                check_id="5.4.3",
                                title="Ensure default group for the root account is GID 0",
                                status=Status.FAIL,
                                severity=Severity.HIGH,
                                message=f"Root-Account hat falsche GID: {gid}",
                                remediation="usermod -g 0 root"
                            ))
                    return

            self.reporter.add_result(AuditResult(
                check_id="5.4.3",
                title="Ensure default group for the root account is GID 0",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="Root-Account nicht in /etc/passwd gefunden"
            ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.4.3",
                title="Ensure default group for the root account is GID 0",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_default_umask(self):
        """5.4.4 - Ensure default user umask is 027 or more restrictive"""
        try:
            files_to_check = ['/etc/bash.bashrc', '/etc/profile']
            issues = []
            found_umask = False

            for file_path in files_to_check:
                if not self.file_exists(file_path):
                    continue

                content = self.read_file(file_path)
                if not content:
                    continue

                # Look for umask settings
                umask_matches = re.findall(r'^\s*umask\s+(\d+)', content, re.MULTILINE)

                for umask_value in umask_matches:
                    found_umask = True
                    umask_int = int(umask_value, 8)
                    required_umask = int('027', 8)

                    if umask_int < required_umask:
                        issues.append(f"{file_path}: umask {umask_value} ist zu permissiv (empfohlen: 027)")

            if not found_umask:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.4",
                    title="Ensure default user umask is 027 or more restrictive",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Kein umask in den Standard-Konfigurationsdateien gefunden",
                    remediation="Fügen Sie 'umask 027' zu /etc/bash.bashrc und /etc/profile hinzu"
                ))
            elif issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.4",
                    title="Ensure default user umask is 027 or more restrictive",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="umask nicht ausreichend restriktiv",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie umask auf 027 oder restriktiver"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.4",
                    title="Ensure default user umask is 027 or more restrictive",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Default umask ist ausreichend restriktiv"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.4.4",
                title="Ensure default user umask is 027 or more restrictive",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_root_timeout(self):
        """5.4.5 - Ensure default user shell timeout is 900 seconds or less"""
        try:
            files_to_check = ['/etc/bash.bashrc', '/etc/profile', '/etc/profile.d/*.sh']
            found_timeout = False
            issues = []

            # Check main files
            for file_path in ['/etc/bash.bashrc', '/etc/profile']:
                if not self.file_exists(file_path):
                    continue

                content = self.read_file(file_path)
                if not content:
                    continue

                # Look for TMOUT settings
                timeout_match = re.search(r'^\s*(?:readonly\s+)?TMOUT=(\d+)', content, re.MULTILINE)

                if timeout_match:
                    found_timeout = True
                    timeout_value = int(timeout_match.group(1))

                    if timeout_value > 900 or timeout_value == 0:
                        issues.append(f"{file_path}: TMOUT={timeout_value} ist zu hoch (empfohlen: <= 900)")

            # Check profile.d directory
            profile_d = '/etc/profile.d'
            if self.file_exists(profile_d):
                returncode, stdout, _ = self.run_command(['find', profile_d, '-name', '*.sh'])
                if returncode == 0:
                    for profile_file in stdout.splitlines():
                        if not profile_file:
                            continue
                        content = self.read_file(profile_file)
                        if content and 'TMOUT=' in content:
                            found_timeout = True
                            timeout_match = re.search(r'^\s*(?:readonly\s+)?TMOUT=(\d+)', content, re.MULTILINE)
                            if timeout_match:
                                timeout_value = int(timeout_match.group(1))
                                if timeout_value > 900 or timeout_value == 0:
                                    issues.append(f"{profile_file}: TMOUT={timeout_value} ist zu hoch")

            if not found_timeout:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.5",
                    title="Ensure default user shell timeout is 900 seconds or less",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="TMOUT nicht konfiguriert",
                    remediation="Fügen Sie 'TMOUT=900' und 'readonly TMOUT' zu /etc/bash.bashrc oder /etc/profile hinzu"
                ))
            elif issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.5",
                    title="Ensure default user shell timeout is 900 seconds or less",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Shell-Timeout nicht korrekt konfiguriert",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie TMOUT auf 900 Sekunden oder weniger"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.4.5",
                    title="Ensure default user shell timeout is 900 seconds or less",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Shell-Timeout ist korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.4.5",
                title="Ensure default user shell timeout is 900 seconds or less",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_default_user_shell_timeout(self):
        """5.5.1 - Ensure default user shell timeout is configured"""
        try:
            profile_files = ['/etc/bash.bashrc', '/etc/profile', '/etc/profile.d/*.sh']
            found_timeout = False
            issues = []

            for pattern in profile_files:
                if '*' in pattern:
                    # Glob pattern
                    returncode, stdout, _ = self.run_command(['find', '/etc/profile.d', '-name', '*.sh'])
                    if returncode == 0 and stdout.strip():
                        files = stdout.strip().split('\n')
                        for f in files:
                            content = self.read_file(f)
                            if content and 'TMOUT=' in content:
                                found_timeout = True
                                match = re.search(r'TMOUT=(\d+)', content)
                                if match:
                                    timeout_value = int(match.group(1))
                                    if timeout_value > 900:
                                        issues.append(f"{f}: TMOUT={timeout_value} ist zu hoch (max 900)")
                else:
                    content = self.read_file(pattern)
                    if content and 'TMOUT=' in content:
                        found_timeout = True
                        match = re.search(r'TMOUT=(\d+)', content)
                        if match:
                            timeout_value = int(match.group(1))
                            if timeout_value > 900:
                                issues.append(f"{pattern}: TMOUT={timeout_value} ist zu hoch (max 900)")

            if not found_timeout:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.1",
                    title="Ensure default user shell timeout is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="TMOUT nicht konfiguriert",
                    remediation="Fügen Sie 'TMOUT=900' und 'readonly TMOUT' zu /etc/bash.bashrc oder /etc/profile hinzu"
                ))
            elif issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.1",
                    title="Ensure default user shell timeout is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Shell-Timeout nicht korrekt konfiguriert",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie TMOUT auf 900 Sekunden oder weniger"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.1",
                    title="Ensure default user shell timeout is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Shell-Timeout ist korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.5.1",
                title="Ensure default user shell timeout is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_default_user_umask(self):
        """5.5.2 - Ensure default user umask is configured"""
        try:
            profile_files = ['/etc/bash.bashrc', '/etc/profile', '/etc/login.defs']
            found_umask = False
            issues = []

            for profile_file in profile_files:
                content = self.read_file(profile_file)
                if not content:
                    continue

                # Look for umask setting
                match = re.search(r'^\s*umask\s+([0-7]{3,4})', content, re.MULTILINE)
                if match:
                    found_umask = True
                    umask_value = match.group(1)
                    # CIS requires umask 027 or more restrictive (e.g., 077)
                    umask_int = int(umask_value, 8)
                    required = int('027', 8)
                    if umask_int < required:
                        issues.append(f"{profile_file}: umask {umask_value} ist zu permissiv (minimum 027)")

            if not found_umask:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.2",
                    title="Ensure default user umask is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="umask nicht konfiguriert",
                    remediation="Fügen Sie 'umask 027' zu /etc/bash.bashrc oder /etc/profile hinzu"
                ))
            elif issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.2",
                    title="Ensure default user umask is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="umask nicht ausreichend restriktiv",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie umask auf 027 oder restriktiver"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.2",
                    title="Ensure default user umask is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="umask ist korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.5.2",
                title="Ensure default user umask is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_tmout_configured(self):
        """5.5.3 - Ensure tmout is configured"""
        # This is essentially the same as 5.5.1, but with more emphasis on readonly
        try:
            profile_files = ['/etc/bash.bashrc', '/etc/profile']
            found_tmout = False
            found_readonly = False
            issues = []

            for profile_file in profile_files:
                content = self.read_file(profile_file)
                if not content:
                    continue

                if 'TMOUT=' in content:
                    found_tmout = True
                    match = re.search(r'TMOUT=(\d+)', content)
                    if match:
                        timeout_value = int(match.group(1))
                        if timeout_value > 900:
                            issues.append(f"{profile_file}: TMOUT={timeout_value} ist zu hoch (max 900)")

                if 'readonly TMOUT' in content or 'readonly -f TMOUT' in content:
                    found_readonly = True

            if not found_tmout:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.3",
                    title="Ensure tmout is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="TMOUT nicht konfiguriert",
                    remediation="Fügen Sie 'TMOUT=900' und 'readonly TMOUT' zu /etc/bash.bashrc hinzu"
                ))
            elif not found_readonly:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.3",
                    title="Ensure tmout is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="TMOUT nicht als readonly konfiguriert",
                    remediation="Fügen Sie 'readonly TMOUT' nach der TMOUT-Deklaration hinzu"
                ))
            elif issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.3",
                    title="Ensure tmout is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="TMOUT nicht korrekt konfiguriert",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie TMOUT auf 900 Sekunden oder weniger"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.3",
                    title="Ensure tmout is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="TMOUT ist korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.5.3",
                title="Ensure tmout is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_root_default_group_gid0(self):
        """5.5.4 - Ensure default group for the root account is GID 0"""
        try:
            passwd_content = self.read_file('/etc/passwd')
            if not passwd_content:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.4",
                    title="Ensure default group for the root account is GID 0",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="Kann /etc/passwd nicht lesen"
                ))
                return

            for line in passwd_content.splitlines():
                if line.startswith('root:'):
                    parts = line.split(':')
                    if len(parts) >= 4:
                        gid = parts[3]
                        if gid == '0':
                            self.reporter.add_result(AuditResult(
                                check_id="5.5.4",
                                title="Ensure default group for the root account is GID 0",
                                status=Status.PASS,
                                severity=Severity.HIGH,
                                message="root-Account hat GID 0"
                            ))
                        else:
                            self.reporter.add_result(AuditResult(
                                check_id="5.5.4",
                                title="Ensure default group for the root account is GID 0",
                                status=Status.FAIL,
                                severity=Severity.HIGH,
                                message=f"root-Account hat falsche GID: {gid}",
                                remediation="Setzen Sie GID für root auf 0 in /etc/passwd"
                            ))
                        return

            self.reporter.add_result(AuditResult(
                check_id="5.5.4",
                title="Ensure default group for the root account is GID 0",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message="root-Account nicht in /etc/passwd gefunden"
            ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.5.4",
                title="Ensure default group for the root account is GID 0",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_root_only_uid0(self):
        """5.5.5 - Ensure root is the only UID 0 account"""
        try:
            passwd_content = self.read_file('/etc/passwd')
            if not passwd_content:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.5",
                    title="Ensure root is the only UID 0 account",
                    status=Status.ERROR,
                    severity=Severity.CRITICAL,
                    message="Kann /etc/passwd nicht lesen"
                ))
                return

            uid0_accounts = []
            for line in passwd_content.splitlines():
                if line.strip() and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        uid = parts[2]
                        if uid == '0' and username != 'root':
                            uid0_accounts.append(username)

            if uid0_accounts:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.5",
                    title="Ensure root is the only UID 0 account",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    message="Andere Accounts mit UID 0 gefunden",
                    details=f"Accounts: {', '.join(uid0_accounts)}",
                    remediation="Entfernen Sie alle Accounts mit UID 0 außer root"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.5.5",
                    title="Ensure root is the only UID 0 account",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    message="Nur root hat UID 0"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.5.5",
                title="Ensure root is the only UID 0 account",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def run_all_checks(self):
        """Run all PAM and password policy checks"""
        # 5.3.x - PAM Configuration
        self.check_pam_pwquality_installed()
        self.check_pwquality_config()
        self.check_pam_faillock()
        self.check_pam_pwhistory()
        self.check_pam_unix_sha512()

        # 5.4.x - User Accounts and Environment
        self.check_password_max_days()
        self.check_password_min_days()
        self.check_password_warn_age()
        self.check_inactive_password_lock()
        self.check_user_password_expiry()
        self.check_system_accounts_nologin()
        self.check_default_group_root()
        self.check_default_umask()
        self.check_root_timeout()

        # 5.5.x - User Environment & Root Security
        self.check_default_user_shell_timeout()
        self.check_default_user_umask()
        self.check_tmout_configured()
        self.check_root_default_group_gid0()
        self.check_root_only_uid0()


class FirewallAuditor(BaseAuditor):
    """Firewall configuration auditor for CIS checks 4.x"""

    # UFW Checks (4.2.x)
    def check_ufw_installed(self):
        """4.2.1 - Ensure ufw is installed"""
        try:
            returncode, stdout, _ = self.run_command(['dpkg', '-s', 'ufw'])

            if returncode == 0 and 'Status: install ok installed' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.1",
                    title="Ensure ufw is installed",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="ufw ist installiert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.1",
                    title="Ensure ufw is installed",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="ufw ist nicht installiert",
                    remediation="apt install ufw"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.2.1",
                title="Ensure ufw is installed",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_iptables_persistent_not_installed(self):
        """4.2.2 - Ensure iptables-persistent is not installed with ufw"""
        try:
            # Check if ufw is installed first
            returncode_ufw, _, _ = self.run_command(['dpkg', '-s', 'ufw'])

            if returncode_ufw != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.2",
                    title="Ensure iptables-persistent is not installed with ufw",
                    status=Status.SKIP,
                    severity=Severity.MEDIUM,
                    message="ufw ist nicht installiert, Check nicht relevant"
                ))
                return

            # Check if iptables-persistent is installed
            returncode, stdout, _ = self.run_command(['dpkg', '-s', 'iptables-persistent'])

            if returncode == 0 and 'Status: install ok installed' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.2",
                    title="Ensure iptables-persistent is not installed with ufw",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="iptables-persistent ist installiert (Konflikt mit ufw)",
                    remediation="apt purge iptables-persistent"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.2",
                    title="Ensure iptables-persistent is not installed with ufw",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="iptables-persistent ist nicht installiert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.2.2",
                title="Ensure iptables-persistent is not installed with ufw",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ufw_service_enabled(self):
        """4.2.3 - Ensure ufw service is enabled"""
        try:
            returncode, stdout, _ = self.run_command(['systemctl', 'is-enabled', 'ufw'])

            if stdout.strip() == 'enabled':
                self.reporter.add_result(AuditResult(
                    check_id="4.2.3",
                    title="Ensure ufw service is enabled",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="ufw service ist aktiviert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.3",
                    title="Ensure ufw service is enabled",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message=f"ufw service ist nicht aktiviert: {stdout.strip()}",
                    remediation="systemctl enable ufw"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.2.3",
                title="Ensure ufw service is enabled",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ufw_loopback_configured(self):
        """4.2.4 - Ensure ufw loopback traffic is configured"""
        try:
            returncode, stdout, _ = self.run_command(['ufw', 'status', 'verbose'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.4",
                    title="Ensure ufw loopback traffic is configured",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="ufw status konnte nicht abgerufen werden"
                ))
                return

            issues = []

            # Check for loopback allow rules
            if 'Anywhere on lo' not in stdout and 'ALLOW IN' not in stdout:
                issues.append("Loopback ALLOW IN Regel fehlt")

            if 'Anywhere' not in stdout or 'ALLOW OUT' not in stdout or 'on lo' not in stdout:
                issues.append("Loopback ALLOW OUT Regel fehlt")

            # Check for deny from loopback network
            if '127.0.0.0/8' not in stdout or 'DENY IN' not in stdout:
                issues.append("DENY Regel für 127.0.0.0/8 fehlt")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.4",
                    title="Ensure ufw loopback traffic is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Loopback-Konfiguration unvollständig",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="ufw allow in on lo && ufw allow out on lo && ufw deny in from 127.0.0.0/8"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.4",
                    title="Ensure ufw loopback traffic is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Loopback-Traffic ist korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.2.4",
                title="Ensure ufw loopback traffic is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ufw_outbound_connections(self):
        """4.2.5 - Ensure ufw outbound connections are configured"""
        try:
            returncode, stdout, _ = self.run_command(['ufw', 'status', 'verbose'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.5",
                    title="Ensure ufw outbound connections are configured",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="ufw status konnte nicht abgerufen werden"
                ))
                return

            # Check for default outbound policy or specific rules
            has_outbound_rules = False

            if 'Default: deny (outgoing)' in stdout or 'Default: reject (outgoing)' in stdout:
                # If default is deny/reject, there should be explicit allow rules
                if 'ALLOW OUT' in stdout:
                    has_outbound_rules = True
            elif 'Default: allow (outgoing)' in stdout:
                # Default allow is acceptable but should be noted
                has_outbound_rules = True

            if has_outbound_rules:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.5",
                    title="Ensure ufw outbound connections are configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Ausgehende Verbindungen sind konfiguriert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.5",
                    title="Ensure ufw outbound connections are configured",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    message="Keine spezifischen Regeln für ausgehende Verbindungen gefunden",
                    remediation="Konfigurieren Sie ufw-Regeln für ausgehende Verbindungen"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.2.5",
                title="Ensure ufw outbound connections are configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ufw_firewall_rules(self):
        """4.2.6 - Ensure ufw firewall rules exist for all open ports"""
        try:
            # Get listening ports
            returncode_ss, stdout_ss, _ = self.run_command(['ss', '-4tuln'])

            if returncode_ss != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.6",
                    title="Ensure ufw firewall rules exist for all open ports",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="Konnte offene Ports nicht ermitteln"
                ))
                return

            # Get UFW rules
            returncode_ufw, stdout_ufw, _ = self.run_command(['ufw', 'status', 'numbered'])

            if returncode_ufw != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.6",
                    title="Ensure ufw firewall rules exist for all open ports",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="ufw status konnte nicht abgerufen werden"
                ))
                return

            # Parse listening ports (simplified check)
            listening_ports = set()
            for line in stdout_ss.splitlines():
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) > 4:
                        addr_port = parts[4]
                        if ':' in addr_port:
                            port = addr_port.split(':')[-1]
                            if port.isdigit():
                                listening_ports.add(port)

            # Check if UFW has rules (simplified check)
            if listening_ports and ('ALLOW' in stdout_ufw or 'Status: active' in stdout_ufw):
                self.reporter.add_result(AuditResult(
                    check_id="4.2.6",
                    title="Ensure ufw firewall rules exist for all open ports",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message=f"Firewall-Regeln vorhanden ({len(listening_ports)} offene Ports gefunden)",
                    details=f"Offene Ports: {', '.join(sorted(listening_ports))}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.6",
                    title="Ensure ufw firewall rules exist for all open ports",
                    status=Status.WARNING,
                    severity=Severity.HIGH,
                    message="Überprüfen Sie, ob alle offenen Ports Firewall-Regeln haben",
                    details=f"Offene Ports: {', '.join(sorted(listening_ports))}",
                    remediation="Erstellen Sie ufw-Regeln für alle erforderlichen offenen Ports"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.2.6",
                title="Ensure ufw firewall rules exist for all open ports",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ufw_default_deny(self):
        """4.2.7 - Ensure ufw default deny firewall policy"""
        try:
            returncode, stdout, _ = self.run_command(['ufw', 'status', 'verbose'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.7",
                    title="Ensure ufw default deny firewall policy",
                    status=Status.ERROR,
                    severity=Severity.CRITICAL,
                    message="ufw status konnte nicht abgerufen werden"
                ))
                return

            issues = []

            # Check default incoming policy
            if 'Default: deny (incoming)' not in stdout and 'Default: reject (incoming)' not in stdout:
                issues.append("Default-Policy für eingehende Verbindungen ist nicht deny/reject")

            # Check default forward policy
            if 'Default: deny (routed)' not in stdout and 'Default: reject (routed)' not in stdout:
                issues.append("Default-Policy für weitergeleitete Verbindungen ist nicht deny/reject")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.7",
                    title="Ensure ufw default deny firewall policy",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    message="Default-Policy ist nicht auf deny gesetzt",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="ufw default deny incoming && ufw default deny routed"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.2.7",
                    title="Ensure ufw default deny firewall policy",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    message="Default-Policy ist korrekt auf deny gesetzt"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.2.7",
                title="Ensure ufw default deny firewall policy",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    # nftables Checks (4.3.x)
    def check_nftables_installed(self):
        """4.3.1 - Ensure nftables is installed"""
        try:
            returncode, stdout, _ = self.run_command(['dpkg', '-s', 'nftables'])

            if returncode == 0 and 'Status: install ok installed' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.1",
                    title="Ensure nftables is installed",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="nftables ist installiert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.1",
                    title="Ensure nftables is installed",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="nftables ist nicht installiert",
                    remediation="apt install nftables"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.1",
                title="Ensure nftables is installed",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ufw_uninstalled_with_nftables(self):
        """4.3.2 - Ensure ufw is uninstalled or disabled with nftables"""
        try:
            # Check if nftables is installed
            returncode_nft, _, _ = self.run_command(['dpkg', '-s', 'nftables'])

            if returncode_nft != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.2",
                    title="Ensure ufw is uninstalled or disabled with nftables",
                    status=Status.SKIP,
                    severity=Severity.MEDIUM,
                    message="nftables ist nicht installiert, Check nicht relevant"
                ))
                return

            # Check if ufw is installed
            returncode_ufw, stdout_ufw, _ = self.run_command(['dpkg', '-s', 'ufw'])

            if returncode_ufw == 0 and 'Status: install ok installed' in stdout_ufw:
                # Check if ufw is disabled
                returncode_status, stdout_status, _ = self.run_command(['ufw', 'status'])
                if 'inactive' in stdout_status.lower():
                    self.reporter.add_result(AuditResult(
                        check_id="4.3.2",
                        title="Ensure ufw is uninstalled or disabled with nftables",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="ufw ist installiert aber deaktiviert"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="4.3.2",
                        title="Ensure ufw is uninstalled or disabled with nftables",
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        message="ufw ist installiert und aktiv (Konflikt mit nftables)",
                        remediation="ufw disable oder apt purge ufw"
                    ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.2",
                    title="Ensure ufw is uninstalled or disabled with nftables",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="ufw ist nicht installiert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.2",
                title="Ensure ufw is uninstalled or disabled with nftables",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_iptables_flushed_with_nftables(self):
        """4.3.3 - Ensure iptables are flushed with nftables"""
        try:
            # Check if nftables is active
            returncode_nft, _, _ = self.run_command(['systemctl', 'is-active', 'nftables'])

            if returncode_nft != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.3",
                    title="Ensure iptables are flushed with nftables",
                    status=Status.SKIP,
                    severity=Severity.MEDIUM,
                    message="nftables ist nicht aktiv, Check nicht relevant"
                ))
                return

            # Check iptables rules
            returncode_v4, stdout_v4, _ = self.run_command(['iptables', '-L'])
            returncode_v6, stdout_v6, _ = self.run_command(['ip6tables', '-L'])

            issues = []

            # Check if iptables has rules (besides default chains)
            if returncode_v4 == 0:
                lines_v4 = [l for l in stdout_v4.splitlines() if l and not l.startswith('Chain') and not l.startswith('target')]
                if len(lines_v4) > 0:
                    issues.append(f"iptables hat {len(lines_v4)} Regeln")

            if returncode_v6 == 0:
                lines_v6 = [l for l in stdout_v6.splitlines() if l and not l.startswith('Chain') and not l.startswith('target')]
                if len(lines_v6) > 0:
                    issues.append(f"ip6tables hat {len(lines_v6)} Regeln")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.3",
                    title="Ensure iptables are flushed with nftables",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="iptables-Regeln sollten geleert werden bei Verwendung von nftables",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="iptables -F && ip6tables -F"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.3",
                    title="Ensure iptables are flushed with nftables",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="iptables-Regeln sind geleert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.3",
                title="Ensure iptables are flushed with nftables",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_nftables_table_exists(self):
        """4.3.4 - Ensure a nftables table exists"""
        try:
            returncode, stdout, _ = self.run_command(['nft', 'list', 'tables'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.4",
                    title="Ensure a nftables table exists",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="nft list tables fehlgeschlagen"
                ))
                return

            if stdout.strip():
                tables = stdout.strip().splitlines()
                self.reporter.add_result(AuditResult(
                    check_id="4.3.4",
                    title="Ensure a nftables table exists",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message=f"nftables-Tabellen vorhanden ({len(tables)} Tabelle(n))",
                    details=f"Tabellen: {', '.join(tables)}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.4",
                    title="Ensure a nftables table exists",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Keine nftables-Tabellen definiert",
                    remediation="Erstellen Sie eine nftables-Tabelle: nft create table inet filter"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.4",
                title="Ensure a nftables table exists",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_nftables_base_chains(self):
        """4.3.5 - Ensure nftables base chains exist"""
        try:
            returncode, stdout, _ = self.run_command(['nft', 'list', 'ruleset'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.5",
                    title="Ensure nftables base chains exist",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="nft list ruleset fehlgeschlagen"
                ))
                return

            # Check for base chains
            required_chains = ['input', 'forward', 'output']
            found_chains = []

            for chain in required_chains:
                if f'chain {chain}' in stdout.lower():
                    found_chains.append(chain)

            missing_chains = [c for c in required_chains if c not in found_chains]

            if missing_chains:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.5",
                    title="Ensure nftables base chains exist",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Nicht alle Base-Chains vorhanden",
                    details=f"Fehlende Chains: {', '.join(missing_chains)}",
                    remediation="Erstellen Sie die Base-Chains: input, forward, output"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.5",
                    title="Ensure nftables base chains exist",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="Alle Base-Chains vorhanden (input, forward, output)"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.5",
                title="Ensure nftables base chains exist",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_nftables_loopback_configured(self):
        """4.3.6 - Ensure nftables loopback traffic is configured"""
        try:
            returncode, stdout, _ = self.run_command(['nft', 'list', 'ruleset'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.6",
                    title="Ensure nftables loopback traffic is configured",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="nft list ruleset fehlgeschlagen"
                ))
                return

            issues = []

            # Check for loopback interface rules
            if 'iif "lo"' not in stdout and 'iifname "lo"' not in stdout:
                issues.append("Loopback-Interface-Regel fehlt")

            # Check for loopback IP rules
            if '127.0.0.0/8' not in stdout and 'ip saddr' not in stdout:
                issues.append("Loopback-IP-Regel fehlt")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.6",
                    title="Ensure nftables loopback traffic is configured",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    message="Loopback-Konfiguration möglicherweise unvollständig",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Konfigurieren Sie Loopback-Regeln in nftables"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.6",
                    title="Ensure nftables loopback traffic is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Loopback-Traffic ist konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.6",
                title="Ensure nftables loopback traffic is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_nftables_outbound_established(self):
        """4.3.7 - Ensure nftables outbound and established connections are configured"""
        try:
            returncode, stdout, _ = self.run_command(['nft', 'list', 'ruleset'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.7",
                    title="Ensure nftables outbound and established connections are configured",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="nft list ruleset fehlgeschlagen"
                ))
                return

            # Check for established/related rules
            has_established = 'ct state' in stdout and ('established' in stdout or 'related' in stdout)
            has_outbound = 'chain output' in stdout.lower()

            if has_established and has_outbound:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.7",
                    title="Ensure nftables outbound and established connections are configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Ausgehende und etablierte Verbindungen sind konfiguriert"
                ))
            else:
                issues = []
                if not has_established:
                    issues.append("Keine established/related-Regeln gefunden")
                if not has_outbound:
                    issues.append("Keine output-Chain gefunden")

                self.reporter.add_result(AuditResult(
                    check_id="4.3.7",
                    title="Ensure nftables outbound and established connections are configured",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    message="Konfiguration möglicherweise unvollständig",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Konfigurieren Sie nftables-Regeln für ausgehende Verbindungen"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.7",
                title="Ensure nftables outbound and established connections are configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_nftables_default_deny(self):
        """4.3.8 - Ensure nftables default deny firewall policy"""
        try:
            returncode, stdout, _ = self.run_command(['nft', 'list', 'ruleset'])

            if returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.8",
                    title="Ensure nftables default deny firewall policy",
                    status=Status.ERROR,
                    severity=Severity.CRITICAL,
                    message="nft list ruleset fehlgeschlagen"
                ))
                return

            issues = []

            # Check for drop/reject policies on base chains
            for chain in ['input', 'forward']:
                if f'chain {chain}' in stdout.lower():
                    # Look for policy drop or policy reject
                    chain_section = stdout.lower()
                    if f'policy drop' not in chain_section and f'policy reject' not in chain_section and 'drop' not in chain_section:
                        issues.append(f"{chain}-Chain hat keine drop/reject-Policy")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.8",
                    title="Ensure nftables default deny firewall policy",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    message="Default-Policy ist nicht auf drop/reject gesetzt",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Setzen Sie die Policy auf drop für input und forward chains"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.8",
                    title="Ensure nftables default deny firewall policy",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    message="Default-Policy ist auf drop/reject gesetzt"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.8",
                title="Ensure nftables default deny firewall policy",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_nftables_service_enabled(self):
        """4.3.9 - Ensure nftables service is enabled"""
        try:
            returncode, stdout, _ = self.run_command(['systemctl', 'is-enabled', 'nftables'])

            if stdout.strip() == 'enabled':
                self.reporter.add_result(AuditResult(
                    check_id="4.3.9",
                    title="Ensure nftables service is enabled",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="nftables service ist aktiviert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.9",
                    title="Ensure nftables service is enabled",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message=f"nftables service ist nicht aktiviert: {stdout.strip()}",
                    remediation="systemctl enable nftables"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.9",
                title="Ensure nftables service is enabled",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_nftables_rules_permanent(self):
        """4.3.10 - Ensure nftables rules are permanent"""
        try:
            # Check if nftables config file exists
            config_file = '/etc/nftables.conf'

            if not self.file_exists(config_file):
                self.reporter.add_result(AuditResult(
                    check_id="4.3.10",
                    title="Ensure nftables rules are permanent",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message=f"{config_file} nicht gefunden",
                    remediation=f"Erstellen Sie {config_file} und speichern Sie Ihre Regeln"
                ))
                return

            content = self.read_file(config_file)

            if content and len(content.strip()) > 0:
                # Check if it has actual rules
                if 'table' in content or 'chain' in content:
                    self.reporter.add_result(AuditResult(
                        check_id="4.3.10",
                        title="Ensure nftables rules are permanent",
                        status=Status.PASS,
                        severity=Severity.HIGH,
                        message="nftables-Regeln sind persistent konfiguriert"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="4.3.10",
                        title="Ensure nftables rules are permanent",
                        status=Status.WARNING,
                        severity=Severity.HIGH,
                        message=f"{config_file} existiert aber enthält keine Regeln",
                        remediation="Speichern Sie Ihre nftables-Regeln in der Konfigurationsdatei"
                    ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.3.10",
                    title="Ensure nftables rules are permanent",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message=f"{config_file} ist leer",
                    remediation="Speichern Sie Ihre nftables-Regeln: nft list ruleset > /etc/nftables.conf"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.3.10",
                title="Ensure nftables rules are permanent",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    # iptables Checks (4.4.x) - Simplified versions
    def check_iptables_installed(self):
        """4.4.1 - Ensure iptables packages are installed"""
        try:
            packages = ['iptables', 'iptables-persistent']
            missing = []

            for package in packages:
                returncode, stdout, _ = self.run_command(['dpkg', '-s', package])
                if returncode != 0 or 'Status: install ok installed' not in stdout:
                    missing.append(package)

            if missing:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.1",
                    title="Ensure iptables packages are installed",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message=f"Fehlende Pakete: {', '.join(missing)}",
                    remediation=f"apt install {' '.join(missing)}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.1",
                    title="Ensure iptables packages are installed",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="iptables-Pakete sind installiert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.4.1",
                title="Ensure iptables packages are installed",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_nftables_uninstalled_with_iptables(self):
        """4.4.2 - Ensure nftables is not installed with iptables"""
        try:
            # Check if iptables is being used
            returncode_ipt, _, _ = self.run_command(['dpkg', '-s', 'iptables'])

            if returncode_ipt != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.2",
                    title="Ensure nftables is not installed with iptables",
                    status=Status.SKIP,
                    severity=Severity.MEDIUM,
                    message="iptables ist nicht installiert, Check nicht relevant"
                ))
                return

            # Check if nftables is installed
            returncode_nft, stdout_nft, _ = self.run_command(['dpkg', '-s', 'nftables'])

            if returncode_nft == 0 and 'Status: install ok installed' in stdout_nft:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.2",
                    title="Ensure nftables is not installed with iptables",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="nftables ist installiert (Konflikt mit iptables)",
                    remediation="apt purge nftables"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.2",
                    title="Ensure nftables is not installed with iptables",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="nftables ist nicht installiert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.4.2",
                title="Ensure nftables is not installed with iptables",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_ufw_uninstalled_with_iptables(self):
        """4.4.3 - Ensure ufw is uninstalled or disabled with iptables"""
        try:
            # Check if iptables is being used
            returncode_ipt, _, _ = self.run_command(['dpkg', '-s', 'iptables'])

            if returncode_ipt != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.3",
                    title="Ensure ufw is uninstalled or disabled with iptables",
                    status=Status.SKIP,
                    severity=Severity.MEDIUM,
                    message="iptables ist nicht installiert, Check nicht relevant"
                ))
                return

            # Check if ufw is installed and active
            returncode_ufw, stdout_ufw, _ = self.run_command(['dpkg', '-s', 'ufw'])

            if returncode_ufw == 0 and 'Status: install ok installed' in stdout_ufw:
                returncode_status, stdout_status, _ = self.run_command(['ufw', 'status'])
                if 'inactive' not in stdout_status.lower():
                    self.reporter.add_result(AuditResult(
                        check_id="4.4.3",
                        title="Ensure ufw is uninstalled or disabled with iptables",
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        message="ufw ist installiert und aktiv (Konflikt mit iptables)",
                        remediation="ufw disable oder apt purge ufw"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="4.4.3",
                        title="Ensure ufw is uninstalled or disabled with iptables",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="ufw ist deaktiviert"
                    ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.3",
                    title="Ensure ufw is uninstalled or disabled with iptables",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="ufw ist nicht installiert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.4.3",
                title="Ensure ufw is uninstalled or disabled with iptables",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_iptables_default_deny(self):
        """4.4.4 - Ensure iptables default deny firewall policy"""
        try:
            # Check IPv4
            returncode_v4, stdout_v4, _ = self.run_command(['iptables', '-L'])
            # Check IPv6
            returncode_v6, stdout_v6, _ = self.run_command(['ip6tables', '-L'])

            if returncode_v4 != 0 and returncode_v6 != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.4",
                    title="Ensure iptables default deny firewall policy",
                    status=Status.ERROR,
                    severity=Severity.CRITICAL,
                    message="iptables-Befehle fehlgeschlagen"
                ))
                return

            issues = []

            # Check IPv4 policies
            if returncode_v4 == 0:
                if 'Chain INPUT (policy ACCEPT)' in stdout_v4:
                    issues.append("IPv4 INPUT policy ist ACCEPT (sollte DROP sein)")
                if 'Chain FORWARD (policy ACCEPT)' in stdout_v4:
                    issues.append("IPv4 FORWARD policy ist ACCEPT (sollte DROP sein)")

            # Check IPv6 policies
            if returncode_v6 == 0:
                if 'Chain INPUT (policy ACCEPT)' in stdout_v6:
                    issues.append("IPv6 INPUT policy ist ACCEPT (sollte DROP sein)")
                if 'Chain FORWARD (policy ACCEPT)' in stdout_v6:
                    issues.append("IPv6 FORWARD policy ist ACCEPT (sollte DROP sein)")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.4",
                    title="Ensure iptables default deny firewall policy",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    message="Default-Policy ist nicht auf DROP gesetzt",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="iptables -P INPUT DROP && iptables -P FORWARD DROP && ip6tables -P INPUT DROP && ip6tables -P FORWARD DROP"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.4",
                    title="Ensure iptables default deny firewall policy",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    message="Default-Policy ist korrekt auf DROP gesetzt"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.4.4",
                title="Ensure iptables default deny firewall policy",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_iptables_loopback_configured(self):
        """4.4.5 - Ensure iptables loopback traffic is configured"""
        try:
            returncode_v4, stdout_v4, _ = self.run_command(['iptables', '-L', 'INPUT', '-v', '-n'])
            returncode_v6, stdout_v6, _ = self.run_command(['ip6tables', '-L', 'INPUT', '-v', '-n'])

            if returncode_v4 != 0 and returncode_v6 != 0:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.5",
                    title="Ensure iptables loopback traffic is configured",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="iptables-Befehle fehlgeschlagen"
                ))
                return

            issues = []

            # Check for loopback rules in IPv4
            if returncode_v4 == 0:
                if 'lo' not in stdout_v4 or 'ACCEPT' not in stdout_v4:
                    issues.append("IPv4 Loopback-Regeln möglicherweise unvollständig")

            # Check for loopback rules in IPv6
            if returncode_v6 == 0:
                if 'lo' not in stdout_v6 or 'ACCEPT' not in stdout_v6:
                    issues.append("IPv6 Loopback-Regeln möglicherweise unvollständig")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.5",
                    title="Ensure iptables loopback traffic is configured",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    message="Loopback-Konfiguration möglicherweise unvollständig",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Konfigurieren Sie Loopback-Regeln für iptables"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="4.4.5",
                    title="Ensure iptables loopback traffic is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="Loopback-Traffic ist konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="4.4.5",
                title="Ensure iptables loopback traffic is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def run_all_checks(self):
        """Run all firewall checks"""
        # UFW Checks (4.2.x)
        self.check_ufw_installed()
        self.check_iptables_persistent_not_installed()
        self.check_ufw_service_enabled()
        self.check_ufw_loopback_configured()
        self.check_ufw_outbound_connections()
        self.check_ufw_firewall_rules()
        self.check_ufw_default_deny()

        # nftables Checks (4.3.x)
        self.check_nftables_installed()
        self.check_ufw_uninstalled_with_nftables()
        self.check_iptables_flushed_with_nftables()
        self.check_nftables_table_exists()
        self.check_nftables_base_chains()
        self.check_nftables_loopback_configured()
        self.check_nftables_outbound_established()
        self.check_nftables_default_deny()
        self.check_nftables_service_enabled()
        self.check_nftables_rules_permanent()

        # iptables Checks (4.4.x)
        self.check_iptables_installed()
        self.check_nftables_uninstalled_with_iptables()
        self.check_ufw_uninstalled_with_iptables()
        self.check_iptables_default_deny()
        self.check_iptables_loopback_configured()


class WarningBannerAuditor(BaseAuditor):
    """Auditor for warning banner configuration (1.8.x)"""

    def check_motd_configured(self):
        """1.8.1 - Ensure message of the day is configured properly"""
        try:
            motd_file = '/etc/motd'

            if not self.file_exists(motd_file):
                self.reporter.add_result(AuditResult(
                    check_id="1.8.1",
                    title="Ensure message of the day is configured properly",
                    status=Status.WARNING,
                    severity=Severity.LOW,
                    message="/etc/motd existiert nicht",
                    remediation="Erstellen Sie /etc/motd mit angemessenem Inhalt"
                ))
                return

            content = self.read_file(motd_file)
            if content:
                # Check for inappropriate content (OS info, kernel version, etc.)
                inappropriate_patterns = [r'\\m', r'\\r', r'\\s', r'\\v']
                issues = []

                for pattern in inappropriate_patterns:
                    if pattern in content:
                        issues.append(f"Enthält {pattern} (Systeminformationen)")

                if issues:
                    self.reporter.add_result(AuditResult(
                        check_id="1.8.1",
                        title="Ensure message of the day is configured properly",
                        status=Status.FAIL,
                        severity=Severity.LOW,
                        message="/etc/motd enthält unangemessenen Inhalt",
                        details="\n".join([f"  - {issue}" for issue in issues]),
                        remediation="Entfernen Sie Systeminformationen aus /etc/motd"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="1.8.1",
                        title="Ensure message of the day is configured properly",
                        status=Status.PASS,
                        severity=Severity.LOW,
                        message="/etc/motd ist angemessen konfiguriert"
                    ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.1",
                    title="Ensure message of the day is configured properly",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="/etc/motd ist leer (akzeptabel)"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.8.1",
                title="Ensure message of the day is configured properly",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_issue_configured(self):
        """1.8.2 - Ensure local login warning banner is configured properly"""
        try:
            issue_file = '/etc/issue'

            if not self.file_exists(issue_file):
                self.reporter.add_result(AuditResult(
                    check_id="1.8.2",
                    title="Ensure local login warning banner is configured properly",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="/etc/issue existiert nicht",
                    remediation="Erstellen Sie /etc/issue mit einem Warnhinweis"
                ))
                return

            content = self.read_file(issue_file)
            if not content or len(content.strip()) == 0:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.2",
                    title="Ensure local login warning banner is configured properly",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="/etc/issue ist leer",
                    remediation="Fügen Sie einen Warnhinweis zu /etc/issue hinzu"
                ))
                return

            # Check for inappropriate content
            inappropriate_patterns = [r'\\m', r'\\r', r'\\s', r'\\v']
            issues = []

            for pattern in inappropriate_patterns:
                if pattern in content:
                    issues.append(f"Enthält {pattern} (Systeminformationen)")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.2",
                    title="Ensure local login warning banner is configured properly",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="/etc/issue enthält unangemessenen Inhalt",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Entfernen Sie Systeminformationen aus /etc/issue"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.2",
                    title="Ensure local login warning banner is configured properly",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="/etc/issue ist korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.8.2",
                title="Ensure local login warning banner is configured properly",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_issue_net_configured(self):
        """1.8.3 - Ensure remote login warning banner is configured properly"""
        try:
            issue_net_file = '/etc/issue.net'

            if not self.file_exists(issue_net_file):
                self.reporter.add_result(AuditResult(
                    check_id="1.8.3",
                    title="Ensure remote login warning banner is configured properly",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="/etc/issue.net existiert nicht",
                    remediation="Erstellen Sie /etc/issue.net mit einem Warnhinweis"
                ))
                return

            content = self.read_file(issue_net_file)
            if not content or len(content.strip()) == 0:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.3",
                    title="Ensure remote login warning banner is configured properly",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="/etc/issue.net ist leer",
                    remediation="Fügen Sie einen Warnhinweis zu /etc/issue.net hinzu"
                ))
                return

            # Check for inappropriate content
            inappropriate_patterns = [r'\\m', r'\\r', r'\\s', r'\\v']
            issues = []

            for pattern in inappropriate_patterns:
                if pattern in content:
                    issues.append(f"Enthält {pattern} (Systeminformationen)")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.3",
                    title="Ensure remote login warning banner is configured properly",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="/etc/issue.net enthält unangemessenen Inhalt",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Entfernen Sie Systeminformationen aus /etc/issue.net"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.3",
                    title="Ensure remote login warning banner is configured properly",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="/etc/issue.net ist korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.8.3",
                title="Ensure remote login warning banner is configured properly",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_motd_permissions(self):
        """1.8.4 - Ensure permissions on /etc/motd are configured"""
        try:
            motd_file = '/etc/motd'

            if not self.file_exists(motd_file):
                self.reporter.add_result(AuditResult(
                    check_id="1.8.4",
                    title="Ensure permissions on /etc/motd are configured",
                    status=Status.SKIP,
                    severity=Severity.LOW,
                    message="/etc/motd existiert nicht"
                ))
                return

            stat_info = self.get_file_stat(motd_file)
            if not stat_info:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.4",
                    title="Ensure permissions on /etc/motd are configured",
                    status=Status.ERROR,
                    severity=Severity.LOW,
                    message="Konnte Dateiinformationen nicht abrufen"
                ))
                return

            mode = stat.S_IMODE(stat_info.st_mode)
            owner = stat_info.st_uid
            group = stat_info.st_gid

            issues = []

            # Should be 0644 or more restrictive
            if mode & 0o022:  # Check if group/other can write
                issues.append(f"Berechtigungen zu offen: {oct(mode)}")

            if owner != 0:
                issues.append(f"Owner ist nicht root: UID {owner}")

            if group != 0:
                issues.append(f"Group ist nicht root: GID {group}")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.4",
                    title="Ensure permissions on /etc/motd are configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="Berechtigungen auf /etc/motd sind falsch",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Führen Sie aus: chown root:root /etc/motd && chmod 0644 /etc/motd"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.4",
                    title="Ensure permissions on /etc/motd are configured",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="Berechtigungen auf /etc/motd sind korrekt"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.8.4",
                title="Ensure permissions on /etc/motd are configured",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_issue_permissions(self):
        """1.8.5 - Ensure permissions on /etc/issue are configured"""
        try:
            issue_file = '/etc/issue'

            if not self.file_exists(issue_file):
                self.reporter.add_result(AuditResult(
                    check_id="1.8.5",
                    title="Ensure permissions on /etc/issue are configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="/etc/issue existiert nicht"
                ))
                return

            stat_info = self.get_file_stat(issue_file)
            if not stat_info:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.5",
                    title="Ensure permissions on /etc/issue are configured",
                    status=Status.ERROR,
                    severity=Severity.LOW,
                    message="Konnte Dateiinformationen nicht abrufen"
                ))
                return

            mode = stat.S_IMODE(stat_info.st_mode)
            owner = stat_info.st_uid
            group = stat_info.st_gid

            issues = []

            # Should be 0644 or more restrictive
            if mode & 0o022:  # Check if group/other can write
                issues.append(f"Berechtigungen zu offen: {oct(mode)}")

            if owner != 0:
                issues.append(f"Owner ist nicht root: UID {owner}")

            if group != 0:
                issues.append(f"Group ist nicht root: GID {group}")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.5",
                    title="Ensure permissions on /etc/issue are configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="Berechtigungen auf /etc/issue sind falsch",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Führen Sie aus: chown root:root /etc/issue && chmod 0644 /etc/issue"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.5",
                    title="Ensure permissions on /etc/issue are configured",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="Berechtigungen auf /etc/issue sind korrekt"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.8.5",
                title="Ensure permissions on /etc/issue are configured",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_issue_net_permissions(self):
        """1.8.6 - Ensure permissions on /etc/issue.net are configured"""
        try:
            issue_net_file = '/etc/issue.net'

            if not self.file_exists(issue_net_file):
                self.reporter.add_result(AuditResult(
                    check_id="1.8.6",
                    title="Ensure permissions on /etc/issue.net are configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="/etc/issue.net existiert nicht"
                ))
                return

            stat_info = self.get_file_stat(issue_net_file)
            if not stat_info:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.6",
                    title="Ensure permissions on /etc/issue.net are configured",
                    status=Status.ERROR,
                    severity=Severity.LOW,
                    message="Konnte Dateiinformationen nicht abrufen"
                ))
                return

            mode = stat.S_IMODE(stat_info.st_mode)
            owner = stat_info.st_uid
            group = stat_info.st_gid

            issues = []

            # Should be 0644 or more restrictive
            if mode & 0o022:  # Check if group/other can write
                issues.append(f"Berechtigungen zu offen: {oct(mode)}")

            if owner != 0:
                issues.append(f"Owner ist nicht root: UID {owner}")

            if group != 0:
                issues.append(f"Group ist nicht root: GID {group}")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.6",
                    title="Ensure permissions on /etc/issue.net are configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="Berechtigungen auf /etc/issue.net sind falsch",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Führen Sie aus: chown root:root /etc/issue.net && chmod 0644 /etc/issue.net"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.8.6",
                    title="Ensure permissions on /etc/issue.net are configured",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="Berechtigungen auf /etc/issue.net sind korrekt"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.8.6",
                title="Ensure permissions on /etc/issue.net are configured",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def run_all_checks(self):
        """Run all warning banner checks"""
        self.check_motd_configured()
        self.check_issue_configured()
        self.check_issue_net_configured()
        self.check_motd_permissions()
        self.check_issue_permissions()
        self.check_issue_net_permissions()


class SoftwareUpdatesAuditor(BaseAuditor):
    """Auditor for software updates configuration (1.2.x)"""

    def check_apt_repositories_configured(self):
        """1.2.1 - Ensure package manager repositories are configured"""
        try:
            sources_file = '/etc/apt/sources.list'
            sources_d = '/etc/apt/sources.list.d'

            if not self.file_exists(sources_file) and not self.file_exists(sources_d):
                self.reporter.add_result(AuditResult(
                    check_id="1.2.1",
                    title="Ensure package manager repositories are configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Keine APT-Repositories konfiguriert",
                    remediation="Konfigurieren Sie /etc/apt/sources.list"
                ))
                return

            # Check if sources.list has content
            has_repos = False

            if self.file_exists(sources_file):
                content = self.read_file(sources_file)
                if content:
                    # Count non-comment, non-empty lines
                    repo_lines = [line for line in content.splitlines()
                                 if line.strip() and not line.strip().startswith('#')]
                    if repo_lines:
                        has_repos = True

            # Check sources.list.d directory
            if self.file_exists(sources_d):
                returncode, stdout, _ = self.run_command(['find', sources_d, '-name', '*.list', '-type', 'f'])
                if returncode == 0 and stdout.strip():
                    has_repos = True

            if not has_repos:
                self.reporter.add_result(AuditResult(
                    check_id="1.2.1",
                    title="Ensure package manager repositories are configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Keine aktiven APT-Repositories gefunden",
                    remediation="Fügen Sie Debian-Repositories zu /etc/apt/sources.list hinzu"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.2.1",
                    title="Ensure package manager repositories are configured",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="APT-Repositories sind konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.2.1",
                title="Ensure package manager repositories are configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_gpg_keys_configured(self):
        """1.2.2 - Ensure GPG keys are configured"""
        try:
            # Check for GPG keys
            returncode, stdout, _ = self.run_command(['apt-key', 'list'])

            if returncode != 0:
                # apt-key might be deprecated, try alternative
                returncode2, stdout2, _ = self.run_command(['ls', '/etc/apt/trusted.gpg.d/'])
                if returncode2 == 0 and stdout2.strip():
                    self.reporter.add_result(AuditResult(
                        check_id="1.2.2",
                        title="Ensure GPG keys are configured",
                        status=Status.PASS,
                        severity=Severity.HIGH,
                        message="GPG-Keys sind konfiguriert"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="1.2.2",
                        title="Ensure GPG keys are configured",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        message="Keine GPG-Keys gefunden",
                        remediation="Installieren Sie GPG-Keys für Ihre Repositories"
                    ))
            elif not stdout.strip() or 'pub' not in stdout.lower():
                self.reporter.add_result(AuditResult(
                    check_id="1.2.2",
                    title="Ensure GPG keys are configured",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Keine GPG-Keys gefunden",
                    remediation="Installieren Sie GPG-Keys für Ihre Repositories"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.2.2",
                    title="Ensure GPG keys are configured",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="GPG-Keys sind konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.2.2",
                title="Ensure GPG keys are configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def run_all_checks(self):
        """Run all software updates checks"""
        self.check_apt_repositories_configured()
        self.check_gpg_keys_configured()


class SudoAuditor(BaseAuditor):
    """Auditor for sudo configuration (5.2.x)"""

    def check_sudo_installed(self):
        """5.2.1 - Ensure sudo is installed"""
        try:
            returncode, stdout, _ = self.run_command(['dpkg', '-s', 'sudo'])

            if returncode == 0 and 'install ok installed' in stdout.lower():
                self.reporter.add_result(AuditResult(
                    check_id="5.2.1",
                    title="Ensure sudo is installed",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="sudo ist installiert"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.1",
                    title="Ensure sudo is installed",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="sudo ist nicht installiert",
                    remediation="Installieren Sie sudo: apt install sudo"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.1",
                title="Ensure sudo is installed",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_sudo_use_pty(self):
        """5.2.2 - Ensure sudo commands use pty"""
        try:
            # Check for use_pty in sudoers configuration
            returncode, stdout, _ = self.run_command(['grep', '-r', 'use_pty', '/etc/sudoers', '/etc/sudoers.d/'])

            if returncode == 0 and 'use_pty' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.2",
                    title="Ensure sudo commands use pty",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="sudo ist konfiguriert um pty zu verwenden"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.2",
                    title="Ensure sudo commands use pty",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="use_pty ist nicht in sudoers konfiguriert",
                    remediation="Fügen Sie 'Defaults use_pty' zu /etc/sudoers hinzu"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.2",
                title="Ensure sudo commands use pty",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_sudo_logfile(self):
        """5.2.3 - Ensure sudo log file exists"""
        try:
            # Check for logfile directive in sudoers
            returncode, stdout, _ = self.run_command(['grep', '-r', '^Defaults.*logfile', '/etc/sudoers', '/etc/sudoers.d/'])

            if returncode == 0 and 'logfile' in stdout:
                # Extract log file path
                logfile_match = re.search(r'logfile[=\s]+"?([^"\s]+)', stdout)
                if logfile_match:
                    logfile = logfile_match.group(1)
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.3",
                        title="Ensure sudo log file exists",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message=f"sudo Logfile ist konfiguriert: {logfile}"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.3",
                        title="Ensure sudo log file exists",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="sudo Logfile ist konfiguriert"
                    ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.3",
                    title="Ensure sudo log file exists",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="Kein sudo Logfile konfiguriert",
                    remediation="Fügen Sie 'Defaults logfile=\"/var/log/sudo.log\"' zu /etc/sudoers hinzu"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.3",
                title="Ensure sudo log file exists",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_sudo_password_required(self):
        """5.2.4 - Ensure users must provide password for privilege escalation"""
        try:
            # Check for NOPASSWD in sudoers
            returncode, stdout, _ = self.run_command(['grep', '-r', 'NOPASSWD', '/etc/sudoers', '/etc/sudoers.d/'])

            if returncode != 0 or not stdout.strip():
                self.reporter.add_result(AuditResult(
                    check_id="5.2.4",
                    title="Ensure users must provide password for privilege escalation",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    message="Keine NOPASSWD-Einträge gefunden"
                ))
            else:
                # Filter out commented lines
                nopasswd_lines = [line for line in stdout.splitlines() if line.strip() and not line.strip().startswith('#')]
                if nopasswd_lines:
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.4",
                        title="Ensure users must provide password for privilege escalation",
                        status=Status.FAIL,
                        severity=Severity.CRITICAL,
                        message="NOPASSWD-Einträge in sudoers gefunden",
                        details="\n".join([f"  - {line.strip()}" for line in nopasswd_lines[:5]]),
                        remediation="Entfernen Sie NOPASSWD aus /etc/sudoers und /etc/sudoers.d/"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.4",
                        title="Ensure users must provide password for privilege escalation",
                        status=Status.PASS,
                        severity=Severity.CRITICAL,
                        message="Keine aktiven NOPASSWD-Einträge gefunden"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.4",
                title="Ensure users must provide password for privilege escalation",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_sudo_reauthentication(self):
        """5.2.5 - Ensure re-authentication for privilege escalation is not disabled globally"""
        try:
            # Check for !authenticate in sudoers
            returncode, stdout, _ = self.run_command(['grep', '-r', '!authenticate', '/etc/sudoers', '/etc/sudoers.d/'])

            if returncode != 0 or not stdout.strip():
                self.reporter.add_result(AuditResult(
                    check_id="5.2.5",
                    title="Ensure re-authentication for privilege escalation is not disabled globally",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="Re-Authentifizierung ist nicht global deaktiviert"
                ))
            else:
                # Filter out commented lines
                noauth_lines = [line for line in stdout.splitlines() if line.strip() and not line.strip().startswith('#')]
                if noauth_lines:
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.5",
                        title="Ensure re-authentication for privilege escalation is not disabled globally",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        message="!authenticate gefunden - Re-Authentifizierung ist deaktiviert",
                        details="\n".join([f"  - {line.strip()}" for line in noauth_lines[:5]]),
                        remediation="Entfernen Sie !authenticate aus /etc/sudoers"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.5",
                        title="Ensure re-authentication for privilege escalation is not disabled globally",
                        status=Status.PASS,
                        severity=Severity.HIGH,
                        message="Re-Authentifizierung ist nicht global deaktiviert"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.5",
                title="Ensure re-authentication for privilege escalation is not disabled globally",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_sudo_timeout(self):
        """5.2.6 - Ensure sudo authentication timeout is configured correctly"""
        try:
            # Check for timestamp_timeout in sudoers
            returncode, stdout, _ = self.run_command(['grep', '-r', 'timestamp_timeout', '/etc/sudoers', '/etc/sudoers.d/'])

            if returncode == 0 and stdout.strip():
                # Extract timeout value
                timeout_match = re.search(r'timestamp_timeout[=\s]+(\d+)', stdout)
                if timeout_match:
                    timeout = int(timeout_match.group(1))
                    if timeout <= 15:
                        self.reporter.add_result(AuditResult(
                            check_id="5.2.6",
                            title="Ensure sudo authentication timeout is configured correctly",
                            status=Status.PASS,
                            severity=Severity.MEDIUM,
                            message=f"sudo timeout ist korrekt konfiguriert: {timeout} Minuten"
                        ))
                    else:
                        self.reporter.add_result(AuditResult(
                            check_id="5.2.6",
                            title="Ensure sudo authentication timeout is configured correctly",
                            status=Status.FAIL,
                            severity=Severity.MEDIUM,
                            message=f"sudo timeout ist zu hoch: {timeout} Minuten (sollte ≤ 15 sein)",
                            remediation="Setzen Sie 'Defaults timestamp_timeout=15' in /etc/sudoers"
                        ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.6",
                        title="Ensure sudo authentication timeout is configured correctly",
                        status=Status.WARNING,
                        severity=Severity.MEDIUM,
                        message="timestamp_timeout gefunden, aber Wert konnte nicht geparst werden"
                    ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.6",
                    title="Ensure sudo authentication timeout is configured correctly",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="sudo timeout ist nicht explizit konfiguriert (Standard: 15 Minuten)",
                    remediation="Fügen Sie 'Defaults timestamp_timeout=15' zu /etc/sudoers hinzu"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.6",
                title="Ensure sudo authentication timeout is configured correctly",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_su_restricted(self):
        """5.2.7 - Ensure access to the su command is restricted"""
        try:
            # Check if pam_wheel.so is configured for su
            pam_su = self.read_file('/etc/pam.d/su')

            if pam_su:
                # Look for pam_wheel.so use_uid
                if 'pam_wheel.so' in pam_su and 'use_uid' in pam_su:
                    # Check if it's not commented out
                    active_wheel = [line for line in pam_su.splitlines()
                                   if 'pam_wheel.so' in line and 'use_uid' in line
                                   and not line.strip().startswith('#')]
                    if active_wheel:
                        self.reporter.add_result(AuditResult(
                            check_id="5.2.7",
                            title="Ensure access to the su command is restricted",
                            status=Status.PASS,
                            severity=Severity.HIGH,
                            message="pam_wheel.so ist für su aktiviert"
                        ))
                    else:
                        self.reporter.add_result(AuditResult(
                            check_id="5.2.7",
                            title="Ensure access to the su command is restricted",
                            status=Status.FAIL,
                            severity=Severity.HIGH,
                            message="pam_wheel.so ist nicht aktiv in /etc/pam.d/su",
                            remediation="Fügen Sie 'auth required pam_wheel.so use_uid' zu /etc/pam.d/su hinzu"
                        ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.7",
                        title="Ensure access to the su command is restricted",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        message="pam_wheel.so ist nicht in /etc/pam.d/su konfiguriert",
                        remediation="Fügen Sie 'auth required pam_wheel.so use_uid' zu /etc/pam.d/su hinzu"
                    ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.7",
                    title="Ensure access to the su command is restricted",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="/etc/pam.d/su konnte nicht gelesen werden"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.7",
                title="Ensure access to the su command is restricted",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_sudo_logfile_permissions(self):
        """5.2.8 - Ensure sudo log file permissions are configured"""
        try:
            # First, check if logfile is configured
            returncode, stdout, _ = self.run_command(['grep', '-r', '^Defaults.*logfile', '/etc/sudoers', '/etc/sudoers.d/'])

            if returncode != 0 or not stdout.strip():
                self.reporter.add_result(AuditResult(
                    check_id="5.2.8",
                    title="Ensure sudo log file permissions are configured",
                    status=Status.SKIP,
                    severity=Severity.LOW,
                    message="Kein sudo Logfile konfiguriert - Check übersprungen"
                ))
                return

            # Extract logfile path
            logfile_match = re.search(r'logfile[=\s]+"?([^"\s]+)', stdout)
            if not logfile_match:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.8",
                    title="Ensure sudo log file permissions are configured",
                    status=Status.WARNING,
                    severity=Severity.LOW,
                    message="sudo Logfile konfiguriert, aber Pfad konnte nicht extrahiert werden"
                ))
                return

            logfile = logfile_match.group(1)

            # Check if file exists
            if not self.file_exists(logfile):
                self.reporter.add_result(AuditResult(
                    check_id="5.2.8",
                    title="Ensure sudo log file permissions are configured",
                    status=Status.WARNING,
                    severity=Severity.LOW,
                    message=f"sudo Logfile existiert noch nicht: {logfile}"
                ))
                return

            # Check permissions
            stat_info = self.get_file_stat(logfile)
            if not stat_info:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.8",
                    title="Ensure sudo log file permissions are configured",
                    status=Status.ERROR,
                    severity=Severity.LOW,
                    message="Konnte Dateiinformationen nicht abrufen"
                ))
                return

            mode = stat.S_IMODE(stat_info.st_mode)
            owner = stat_info.st_uid
            group = stat_info.st_gid

            issues = []

            # Should be 0640 or more restrictive
            if mode & 0o027:  # Check if group/other have excessive permissions
                issues.append(f"Berechtigungen zu offen: {oct(mode)}")

            if owner != 0:
                issues.append(f"Owner ist nicht root: UID {owner}")

            if group not in [0, 4]:  # root or adm group
                issues.append(f"Group ist nicht root/adm: GID {group}")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.8",
                    title="Ensure sudo log file permissions are configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message=f"Berechtigungen auf {logfile} sind falsch",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation=f"Führen Sie aus: chown root:adm {logfile} && chmod 0640 {logfile}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.8",
                    title="Ensure sudo log file permissions are configured",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message=f"Berechtigungen auf {logfile} sind korrekt"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.8",
                title="Ensure sudo log file permissions are configured",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_sudoers_file_configured(self):
        """5.2.9 - Ensure sudoers file is configured"""
        try:
            # Check /etc/sudoers permissions
            sudoers_file = '/etc/sudoers'

            if not self.file_exists(sudoers_file):
                self.reporter.add_result(AuditResult(
                    check_id="5.2.9",
                    title="Ensure sudoers file is configured",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    message="/etc/sudoers existiert nicht"
                ))
                return

            stat_info = self.get_file_stat(sudoers_file)
            if not stat_info:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.9",
                    title="Ensure sudoers file is configured",
                    status=Status.ERROR,
                    severity=Severity.CRITICAL,
                    message="Konnte Dateiinformationen nicht abrufen"
                ))
                return

            mode = stat.S_IMODE(stat_info.st_mode)
            owner = stat_info.st_uid
            group = stat_info.st_gid

            issues = []

            # Should be 0440 or 0400
            if mode not in [0o440, 0o400]:
                issues.append(f"Berechtigungen nicht optimal: {oct(mode)} (sollte 0440 oder 0400 sein)")

            if owner != 0:
                issues.append(f"Owner ist nicht root: UID {owner}")

            if group != 0:
                issues.append(f"Group ist nicht root: GID {group}")

            # Verify syntax with visudo
            returncode, stdout, stderr = self.run_command(['visudo', '-c', '-f', sudoers_file])
            if returncode != 0:
                issues.append(f"Syntaxfehler in sudoers: {stderr.strip()}")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.9",
                    title="Ensure sudoers file is configured",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    message="Probleme mit /etc/sudoers gefunden",
                    details="\n".join([f"  - {issue}" for issue in issues]),
                    remediation="Führen Sie aus: chown root:root /etc/sudoers && chmod 0440 /etc/sudoers"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.9",
                    title="Ensure sudoers file is configured",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    message="/etc/sudoers ist korrekt konfiguriert"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.9",
                title="Ensure sudoers file is configured",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def check_sudo_logfile_size(self):
        """5.2.10 - Ensure sudo log file size is configured"""
        try:
            # Check if logrotate is configured for sudo logs
            logrotate_sudo = '/etc/logrotate.d/sudo'

            if self.file_exists(logrotate_sudo):
                content = self.read_file(logrotate_sudo)
                if content and ('rotate' in content or 'size' in content):
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.10",
                        title="Ensure sudo log file size is configured",
                        status=Status.PASS,
                        severity=Severity.LOW,
                        message="logrotate ist für sudo Logs konfiguriert"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="5.2.10",
                        title="Ensure sudo log file size is configured",
                        status=Status.FAIL,
                        severity=Severity.LOW,
                        message="logrotate-Konfiguration für sudo ist unvollständig",
                        remediation="Konfigurieren Sie logrotate in /etc/logrotate.d/sudo"
                    ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="5.2.10",
                    title="Ensure sudo log file size is configured",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="Keine logrotate-Konfiguration für sudo vorhanden",
                    remediation="Erstellen Sie /etc/logrotate.d/sudo mit sinnvoller Rotation"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="5.2.10",
                title="Ensure sudo log file size is configured",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Fehler bei der Prüfung: {str(e)}"
            ))

    def run_all_checks(self):
        """Run all sudo configuration checks"""
        self.check_sudo_installed()
        self.check_sudo_use_pty()
        self.check_sudo_logfile()
        self.check_sudo_password_required()
        self.check_sudo_reauthentication()
        self.check_sudo_timeout()
        self.check_su_restricted()
        self.check_sudo_logfile_permissions()
        self.check_sudoers_file_configured()
        self.check_sudo_logfile_size()


class ProcessHardeningAuditor(BaseAuditor):
    """Process Hardening and Kernel Security auditor for CIS checks 1.6.x"""

    def check_aslr_enabled(self):
        """1.6.1.1 - Ensure address space layout randomization (ASLR) is enabled"""
        try:
            aslr_value = self.read_file('/proc/sys/kernel/randomize_va_space')

            if not aslr_value:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.1",
                    title="Ensure address space layout randomization (ASLR) is enabled",
                    status=Status.ERROR,
                    severity=Severity.CRITICAL,
                    message="Cannot read /proc/sys/kernel/randomize_va_space"
                ))
                return

            aslr_value = aslr_value.strip()

            if aslr_value == '2':
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.1",
                    title="Ensure address space layout randomization (ASLR) is enabled",
                    status=Status.PASS,
                    severity=Severity.CRITICAL,
                    message="ASLR is fully enabled (value: 2)"
                ))
            elif aslr_value == '1':
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.1",
                    title="Ensure address space layout randomization (ASLR) is enabled",
                    status=Status.WARNING,
                    severity=Severity.CRITICAL,
                    message="ASLR is partially enabled (value: 1)",
                    details="Conservative randomization enabled, but full randomization recommended",
                    remediation="Set kernel.randomize_va_space = 2 in /etc/sysctl.conf"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.1",
                    title="Ensure address space layout randomization (ASLR) is enabled",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    message=f"ASLR is disabled (value: {aslr_value})",
                    remediation="Set kernel.randomize_va_space = 2 in /etc/sysctl.conf and run sysctl -p"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.1",
                title="Ensure address space layout randomization (ASLR) is enabled",
                status=Status.ERROR,
                severity=Severity.CRITICAL,
                message=f"Error checking ASLR: {str(e)}"
            ))

    def check_prelink_not_installed(self):
        """1.6.1.2 - Ensure prelink is not installed"""
        try:
            returncode, stdout, _ = self.run_command(['dpkg', '-s', 'prelink'])

            if returncode != 0 or 'Status: install ok installed' not in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.2",
                    title="Ensure prelink is not installed",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="prelink is not installed"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.2",
                    title="Ensure prelink is not installed",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="prelink is installed",
                    details="prelink can interfere with ASLR and security features",
                    remediation="apt purge prelink"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.2",
                title="Ensure prelink is not installed",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Error checking prelink: {str(e)}"
            ))

    def check_kernel_yama_ptrace_scope(self):
        """1.6.1.3 - Ensure Yama ptrace_scope is configured"""
        try:
            ptrace_value = self.read_file('/proc/sys/kernel/yama/ptrace_scope')

            if not ptrace_value:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.3",
                    title="Ensure Yama ptrace_scope is configured",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="Cannot read /proc/sys/kernel/yama/ptrace_scope (Yama LSM may not be enabled)"
                ))
                return

            ptrace_value = ptrace_value.strip()

            if ptrace_value in ['1', '2', '3']:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.3",
                    title="Ensure Yama ptrace_scope is configured",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message=f"ptrace_scope is properly restricted (value: {ptrace_value})"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.3",
                    title="Ensure Yama ptrace_scope is configured",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"ptrace_scope is not restricted (value: {ptrace_value})",
                    details="Value 0 allows any process to ptrace any other process (security risk)",
                    remediation="Set kernel.yama.ptrace_scope = 1 in /etc/sysctl.conf"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.3",
                title="Ensure Yama ptrace_scope is configured",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking ptrace_scope: {str(e)}"
            ))

    def check_kernel_dmesg_restrict(self):
        """1.6.1.4 - Ensure kernel.dmesg_restrict is set"""
        try:
            dmesg_value = self.read_file('/proc/sys/kernel/dmesg_restrict')

            if not dmesg_value:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.4",
                    title="Ensure kernel.dmesg_restrict is set",
                    status=Status.ERROR,
                    severity=Severity.LOW,
                    message="Cannot read /proc/sys/kernel/dmesg_restrict"
                ))
                return

            dmesg_value = dmesg_value.strip()

            if dmesg_value == '1':
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.4",
                    title="Ensure kernel.dmesg_restrict is set",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="dmesg_restrict is enabled"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.4",
                    title="Ensure kernel.dmesg_restrict is set",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="dmesg_restrict is not enabled",
                    details="Unprivileged users can read kernel ring buffer messages",
                    remediation="Set kernel.dmesg_restrict = 1 in /etc/sysctl.conf"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.4",
                title="Ensure kernel.dmesg_restrict is set",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Error checking dmesg_restrict: {str(e)}"
            ))

    def check_kernel_kptr_restrict(self):
        """1.6.1.5 - Ensure kernel.kptr_restrict is set"""
        try:
            kptr_value = self.read_file('/proc/sys/kernel/kptr_restrict')

            if not kptr_value:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.5",
                    title="Ensure kernel.kptr_restrict is set",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="Cannot read /proc/sys/kernel/kptr_restrict"
                ))
                return

            kptr_value = kptr_value.strip()

            if kptr_value in ['1', '2']:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.5",
                    title="Ensure kernel.kptr_restrict is set",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message=f"kptr_restrict is properly set (value: {kptr_value})"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.5",
                    title="Ensure kernel.kptr_restrict is set",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message=f"kptr_restrict is not set (value: {kptr_value})",
                    details="Kernel pointer addresses are exposed to all users",
                    remediation="Set kernel.kptr_restrict = 2 in /etc/sysctl.conf"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.5",
                title="Ensure kernel.kptr_restrict is set",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking kptr_restrict: {str(e)}"
            ))

    def check_kernel_unprivileged_bpf_disabled(self):
        """1.6.1.6 - Ensure kernel.unprivileged_bpf_disabled is set"""
        try:
            bpf_value = self.read_file('/proc/sys/kernel/unprivileged_bpf_disabled')

            if not bpf_value:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.6",
                    title="Ensure kernel.unprivileged_bpf_disabled is set",
                    status=Status.SKIP,
                    severity=Severity.MEDIUM,
                    message="/proc/sys/kernel/unprivileged_bpf_disabled not available (kernel < 4.4)"
                ))
                return

            bpf_value = bpf_value.strip()

            if bpf_value == '1':
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.6",
                    title="Ensure kernel.unprivileged_bpf_disabled is set",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="unprivileged_bpf_disabled is enabled"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.6",
                    title="Ensure kernel.unprivileged_bpf_disabled is set",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="unprivileged_bpf_disabled is not enabled",
                    details="Unprivileged users can use BPF system call",
                    remediation="Set kernel.unprivileged_bpf_disabled = 1 in /etc/sysctl.conf"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.6",
                title="Ensure kernel.unprivileged_bpf_disabled is set",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking unprivileged_bpf_disabled: {str(e)}"
            ))

    def check_kernel_unprivileged_userns_clone_disabled(self):
        """1.6.1.7 - Ensure kernel.unprivileged_userns_clone is disabled"""
        try:
            userns_value = self.read_file('/proc/sys/kernel/unprivileged_userns_clone')

            if not userns_value:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.7",
                    title="Ensure kernel.unprivileged_userns_clone is disabled",
                    status=Status.SKIP,
                    severity=Severity.MEDIUM,
                    message="/proc/sys/kernel/unprivileged_userns_clone not available (Debian-specific)"
                ))
                return

            userns_value = userns_value.strip()

            if userns_value == '0':
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.7",
                    title="Ensure kernel.unprivileged_userns_clone is disabled",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="unprivileged_userns_clone is disabled"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.7",
                    title="Ensure kernel.unprivileged_userns_clone is disabled",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    message="unprivileged_userns_clone is enabled",
                    details="Unprivileged users can create user namespaces (potential privilege escalation)",
                    remediation="Set kernel.unprivileged_userns_clone = 0 in /etc/sysctl.conf"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.7",
                title="Ensure kernel.unprivileged_userns_clone is disabled",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking unprivileged_userns_clone: {str(e)}"
            ))

    def check_kernel_perf_event_paranoid(self):
        """1.6.1.8 - Ensure kernel.perf_event_paranoid is set"""
        try:
            perf_value = self.read_file('/proc/sys/kernel/perf_event_paranoid')

            if not perf_value:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.8",
                    title="Ensure kernel.perf_event_paranoid is set",
                    status=Status.ERROR,
                    severity=Severity.LOW,
                    message="Cannot read /proc/sys/kernel/perf_event_paranoid"
                ))
                return

            perf_value = perf_value.strip()
            perf_int = int(perf_value)

            if perf_int >= 2:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.8",
                    title="Ensure kernel.perf_event_paranoid is set",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message=f"perf_event_paranoid is properly restricted (value: {perf_value})"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.8",
                    title="Ensure kernel.perf_event_paranoid is set",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message=f"perf_event_paranoid is not sufficiently restricted (value: {perf_value})",
                    details="Unprivileged users may have excessive access to performance monitoring",
                    remediation="Set kernel.perf_event_paranoid = 2 in /etc/sysctl.conf"
                ))
        except (ValueError, Exception) as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.8",
                title="Ensure kernel.perf_event_paranoid is set",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Error checking perf_event_paranoid: {str(e)}"
            ))

    def check_kernel_kexec_load_disabled(self):
        """1.6.1.9 - Ensure kernel.kexec_load_disabled is set"""
        try:
            kexec_value = self.read_file('/proc/sys/kernel/kexec_load_disabled')

            if not kexec_value:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.9",
                    title="Ensure kernel.kexec_load_disabled is set",
                    status=Status.SKIP,
                    severity=Severity.LOW,
                    message="/proc/sys/kernel/kexec_load_disabled not available (kernel may not support it)"
                ))
                return

            kexec_value = kexec_value.strip()

            if kexec_value == '1':
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.9",
                    title="Ensure kernel.kexec_load_disabled is set",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="kexec_load_disabled is enabled"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.9",
                    title="Ensure kernel.kexec_load_disabled is set",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="kexec_load_disabled is not enabled",
                    details="kexec allows loading and executing a different kernel",
                    remediation="Set kernel.kexec_load_disabled = 1 in /etc/sysctl.conf"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.9",
                title="Ensure kernel.kexec_load_disabled is set",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Error checking kexec_load_disabled: {str(e)}"
            ))

    def check_dev_mem_restricted(self):
        """1.6.1.10 - Ensure /dev/mem and /dev/kmem are restricted"""
        try:
            issues = []

            # Check /dev/mem
            if self.file_exists('/dev/mem'):
                stat_info = self.get_file_stat('/dev/mem')
                if stat_info:
                    mode = stat.S_IMODE(stat_info.st_mode)
                    if mode & 0o044:  # Check if group or other have read access
                        issues.append("/dev/mem is readable by group or others")

            # Check /dev/kmem (usually not present in modern kernels)
            if self.file_exists('/dev/kmem'):
                stat_info = self.get_file_stat('/dev/kmem')
                if stat_info:
                    mode = stat.S_IMODE(stat_info.st_mode)
                    if mode & 0o044:
                        issues.append("/dev/kmem is readable by group or others")

            if issues:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.10",
                    title="Ensure /dev/mem and /dev/kmem are restricted",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="Physical memory devices have excessive permissions",
                    details="\n".join(f"  - {issue}" for issue in issues),
                    remediation="chmod 600 /dev/mem /dev/kmem (if exists)"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.1.10",
                    title="Ensure /dev/mem and /dev/kmem are restricted",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message="Physical memory devices are properly restricted"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.1.10",
                title="Ensure /dev/mem and /dev/kmem are restricted",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Error checking memory device permissions: {str(e)}"
            ))

    def run_all_checks(self):
        """Run all process hardening checks"""
        self.check_aslr_enabled()
        self.check_prelink_not_installed()
        self.check_kernel_yama_ptrace_scope()
        self.check_kernel_dmesg_restrict()
        self.check_kernel_kptr_restrict()
        self.check_kernel_unprivileged_bpf_disabled()
        self.check_kernel_unprivileged_userns_clone_disabled()
        self.check_kernel_perf_event_paranoid()
        self.check_kernel_kexec_load_disabled()
        self.check_dev_mem_restricted()


class MandatoryAccessControlAuditor(BaseAuditor):
    """Mandatory Access Control (MAC) auditor for CIS checks 1.6.2.x"""

    def check_mac_installed(self):
        """1.6.2.1 - Ensure a MAC system is installed (AppArmor or SELinux)"""
        try:
            # Check for AppArmor
            apparmor_installed = False
            returncode, stdout, _ = self.run_command(['dpkg', '-s', 'apparmor'])
            if returncode == 0 and 'Status: install ok installed' in stdout:
                apparmor_installed = True

            # Check for SELinux
            selinux_installed = False
            returncode, stdout, _ = self.run_command(['dpkg', '-s', 'selinux-basics'])
            if returncode == 0 and 'Status: install ok installed' in stdout:
                selinux_installed = True

            if apparmor_installed or selinux_installed:
                macs = []
                if apparmor_installed:
                    macs.append("AppArmor")
                if selinux_installed:
                    macs.append("SELinux")

                self.reporter.add_result(AuditResult(
                    check_id="1.6.2.1",
                    title="Ensure a Mandatory Access Control system is installed",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message=f"MAC system(s) installed: {', '.join(macs)}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.2.1",
                    title="Ensure a Mandatory Access Control system is installed",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="No MAC system (AppArmor or SELinux) is installed",
                    remediation="Install AppArmor: apt install apparmor apparmor-utils"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.2.1",
                title="Ensure a Mandatory Access Control system is installed",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Error checking MAC installation: {str(e)}"
            ))

    def check_mac_enabled(self):
        """1.6.2.2 - Ensure a MAC system is enabled"""
        try:
            # Check if AppArmor is enabled
            apparmor_enabled = False
            returncode, stdout, _ = self.run_command(['aa-enabled'])
            if returncode == 0 or 'Yes' in stdout:
                apparmor_enabled = True

            # Check if SELinux is enabled
            selinux_enabled = False
            if self.file_exists('/usr/sbin/getenforce'):
                returncode, stdout, _ = self.run_command(['getenforce'])
                if returncode == 0 and stdout.strip() in ['Enforcing', 'Permissive']:
                    selinux_enabled = True

            if apparmor_enabled or selinux_enabled:
                macs = []
                if apparmor_enabled:
                    macs.append("AppArmor")
                if selinux_enabled:
                    macs.append("SELinux")

                self.reporter.add_result(AuditResult(
                    check_id="1.6.2.2",
                    title="Ensure a Mandatory Access Control system is enabled",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message=f"MAC system(s) enabled: {', '.join(macs)}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.2.2",
                    title="Ensure a Mandatory Access Control system is enabled",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    message="No MAC system is enabled",
                    details="Neither AppArmor nor SELinux is active",
                    remediation="Enable AppArmor: systemctl enable apparmor && systemctl start apparmor"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.2.2",
                title="Ensure a Mandatory Access Control system is enabled",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Error checking MAC status: {str(e)}"
            ))

    def check_mac_enforcing(self):
        """1.6.2.3 - Ensure MAC is in enforcing mode"""
        try:
            # Check AppArmor mode
            apparmor_enforcing = False
            returncode, stdout, _ = self.run_command(['aa-status', '--enabled'])
            if returncode == 0:
                # Check if profiles are in enforce mode
                returncode, stdout, _ = self.run_command(['aa-status'])
                if 'profiles are in enforce mode' in stdout:
                    # Parse number of enforcing profiles
                    import re
                    match = re.search(r'(\d+)\s+profiles are in enforce mode', stdout)
                    if match and int(match.group(1)) > 0:
                        apparmor_enforcing = True

            # Check SELinux mode
            selinux_enforcing = False
            if self.file_exists('/usr/sbin/getenforce'):
                returncode, stdout, _ = self.run_command(['getenforce'])
                if returncode == 0 and stdout.strip() == 'Enforcing':
                    selinux_enforcing = True

            if apparmor_enforcing or selinux_enforcing:
                macs = []
                if apparmor_enforcing:
                    macs.append("AppArmor (enforcing)")
                if selinux_enforcing:
                    macs.append("SELinux (enforcing)")

                self.reporter.add_result(AuditResult(
                    check_id="1.6.2.3",
                    title="Ensure Mandatory Access Control is in enforcing mode",
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    message=f"MAC in enforcing mode: {', '.join(macs)}"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.6.2.3",
                    title="Ensure Mandatory Access Control is in enforcing mode",
                    status=Status.WARNING,
                    severity=Severity.HIGH,
                    message="No MAC system is in enforcing mode",
                    details="AppArmor may be in complain mode or SELinux in permissive mode",
                    remediation="Set AppArmor profiles to enforce mode: aa-enforce /etc/apparmor.d/*"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.6.2.3",
                title="Ensure Mandatory Access Control is in enforcing mode",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Error checking MAC enforcement: {str(e)}"
            ))

    def run_all_checks(self):
        """Run all MAC checks"""
        self.check_mac_installed()
        self.check_mac_enabled()
        self.check_mac_enforcing()


class ExtendedFilesystemAuditor(BaseAuditor):
    """Extended Filesystem Security auditor for additional CIS filesystem checks"""

    def check_tmp_noexec_configured(self):
        """1.1.4.1 - Ensure /tmp mount has noexec option set"""
        try:
            mount_output = self.read_file('/proc/mounts')
            if not mount_output:
                self.reporter.add_result(AuditResult(
                    check_id="1.1.4.1",
                    title="Ensure /tmp has noexec option",
                    status=Status.ERROR,
                    severity=Severity.HIGH,
                    message="Cannot read /proc/mounts"
                ))
                return

            for line in mount_output.splitlines():
                if ' /tmp ' in line and 'noexec' in line:
                    self.reporter.add_result(AuditResult(
                        check_id="1.1.4.1",
                        title="Ensure /tmp has noexec option",
                        status=Status.PASS,
                        severity=Severity.HIGH,
                        message="/tmp is mounted with noexec option"
                    ))
                    return

            self.reporter.add_result(AuditResult(
                check_id="1.1.4.1",
                title="Ensure /tmp has noexec option",
                status=Status.FAIL,
                severity=Severity.HIGH,
                message="/tmp is not mounted with noexec option",
                remediation="Add noexec to /tmp mount options in /etc/fstab"
            ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.1.4.1",
                title="Ensure /tmp has noexec option",
                status=Status.ERROR,
                severity=Severity.HIGH,
                message=f"Error checking /tmp noexec: {str(e)}"
            ))

    def check_var_tmp_bind_mount(self):
        """1.1.4.2 - Ensure /var/tmp is bound to /tmp"""
        try:
            mount_output = self.read_file('/proc/mounts')
            if not mount_output:
                self.reporter.add_result(AuditResult(
                    check_id="1.1.4.2",
                    title="Ensure /var/tmp is bound to /tmp",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="Cannot read /proc/mounts"
                ))
                return

            for line in mount_output.splitlines():
                if ' /var/tmp ' in line and '/tmp' in line and 'bind' in line:
                    self.reporter.add_result(AuditResult(
                        check_id="1.1.4.2",
                        title="Ensure /var/tmp is bound to /tmp",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="/var/tmp is bound to /tmp"
                    ))
                    return

            self.reporter.add_result(AuditResult(
                check_id="1.1.4.2",
                title="Ensure /var/tmp is bound to /tmp",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                message="/var/tmp is not bound to /tmp",
                details="Binding /var/tmp to /tmp ensures consistent security settings",
                remediation="Add '/tmp /var/tmp none bind 0 0' to /etc/fstab"
            ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.1.4.2",
                title="Ensure /var/tmp is bound to /tmp",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking /var/tmp bind mount: {str(e)}"
            ))

    def check_dev_shm_noexec(self):
        """1.1.5.1 - Ensure /dev/shm has noexec option"""
        try:
            mount_output = self.read_file('/proc/mounts')
            if not mount_output:
                self.reporter.add_result(AuditResult(
                    check_id="1.1.5.1",
                    title="Ensure /dev/shm has noexec option",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="Cannot read /proc/mounts"
                ))
                return

            for line in mount_output.splitlines():
                if ' /dev/shm ' in line and 'noexec' in line:
                    self.reporter.add_result(AuditResult(
                        check_id="1.1.5.1",
                        title="Ensure /dev/shm has noexec option",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="/dev/shm is mounted with noexec option"
                    ))
                    return

            self.reporter.add_result(AuditResult(
                check_id="1.1.5.1",
                title="Ensure /dev/shm has noexec option",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="/dev/shm is not mounted with noexec option",
                remediation="Add noexec to /dev/shm mount options in /etc/fstab"
            ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.1.5.1",
                title="Ensure /dev/shm has noexec option",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking /dev/shm noexec: {str(e)}"
            ))

    def check_dev_shm_nodev(self):
        """1.1.5.2 - Ensure /dev/shm has nodev option"""
        try:
            mount_output = self.read_file('/proc/mounts')
            if not mount_output:
                self.reporter.add_result(AuditResult(
                    check_id="1.1.5.2",
                    title="Ensure /dev/shm has nodev option",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="Cannot read /proc/mounts"
                ))
                return

            for line in mount_output.splitlines():
                if ' /dev/shm ' in line and 'nodev' in line:
                    self.reporter.add_result(AuditResult(
                        check_id="1.1.5.2",
                        title="Ensure /dev/shm has nodev option",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="/dev/shm is mounted with nodev option"
                    ))
                    return

            self.reporter.add_result(AuditResult(
                check_id="1.1.5.2",
                title="Ensure /dev/shm has nodev option",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="/dev/shm is not mounted with nodev option",
                remediation="Add nodev to /dev/shm mount options in /etc/fstab"
            ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.1.5.2",
                title="Ensure /dev/shm has nodev option",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking /dev/shm nodev: {str(e)}"
            ))

    def check_dev_shm_nosuid(self):
        """1.1.5.3 - Ensure /dev/shm has nosuid option"""
        try:
            mount_output = self.read_file('/proc/mounts')
            if not mount_output:
                self.reporter.add_result(AuditResult(
                    check_id="1.1.5.3",
                    title="Ensure /dev/shm has nosuid option",
                    status=Status.ERROR,
                    severity=Severity.MEDIUM,
                    message="Cannot read /proc/mounts"
                ))
                return

            for line in mount_output.splitlines():
                if ' /dev/shm ' in line and 'nosuid' in line:
                    self.reporter.add_result(AuditResult(
                        check_id="1.1.5.3",
                        title="Ensure /dev/shm has nosuid option",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="/dev/shm is mounted with nosuid option"
                    ))
                    return

            self.reporter.add_result(AuditResult(
                check_id="1.1.5.3",
                title="Ensure /dev/shm has nosuid option",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                message="/dev/shm is not mounted with nosuid option",
                remediation="Add nosuid to /dev/shm mount options in /etc/fstab"
            ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.1.5.3",
                title="Ensure /dev/shm has nosuid option",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking /dev/shm nosuid: {str(e)}"
            ))

    def check_sticky_bit_world_writable(self):
        """1.1.6 - Ensure sticky bit is set on world-writable directories"""
        try:
            # Check common world-writable directories
            returncode, stdout, _ = self.run_command([
                'find', '/', '-xdev', '-type', 'd',
                '\\(', '-perm', '-0002', '-a', '!', '-perm', '-1000', '\\)',
                '-ls', '2>/dev/null'
            ], timeout=30)

            if returncode == 0:
                if stdout.strip():
                    # Found directories without sticky bit
                    dirs = stdout.strip().split('\n')[:10]  # Limit to first 10
                    self.reporter.add_result(AuditResult(
                        check_id="1.1.6",
                        title="Ensure sticky bit is set on world-writable directories",
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        message=f"Found {len(dirs)} world-writable directories without sticky bit",
                        details="\n".join(f"  - {d}" for d in dirs),
                        remediation="Set sticky bit: chmod +t <directory>"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="1.1.6",
                        title="Ensure sticky bit is set on world-writable directories",
                        status=Status.PASS,
                        severity=Severity.MEDIUM,
                        message="All world-writable directories have sticky bit set"
                    ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.1.6",
                    title="Ensure sticky bit is set on world-writable directories",
                    status=Status.SKIP,
                    severity=Severity.MEDIUM,
                    message="Cannot search for world-writable directories (requires root)"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.1.6",
                title="Ensure sticky bit is set on world-writable directories",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking sticky bit: {str(e)}"
            ))

    def check_automounting_disabled(self):
        """1.1.7 - Ensure autofs services are not in use"""
        try:
            returncode, stdout, _ = self.run_command(['systemctl', 'is-enabled', 'autofs'])

            if stdout.strip() in ['disabled', 'masked'] or returncode != 0:
                self.reporter.add_result(AuditResult(
                    check_id="1.1.7",
                    title="Ensure autofs services are not in use",
                    status=Status.PASS,
                    severity=Severity.LOW,
                    message="autofs service is not enabled"
                ))
            else:
                self.reporter.add_result(AuditResult(
                    check_id="1.1.7",
                    title="Ensure autofs services are not in use",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    message="autofs service is enabled",
                    remediation="systemctl disable --now autofs"
                ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.1.7",
                title="Ensure autofs services are not in use",
                status=Status.ERROR,
                severity=Severity.LOW,
                message=f"Error checking autofs: {str(e)}"
            ))

    def check_usb_storage_disabled(self):
        """1.1.8 - Ensure USB storage is disabled"""
        try:
            # Check if usb-storage module is disabled
            returncode, stdout, _ = self.run_command(['modprobe', '-n', '-v', 'usb-storage'])

            if 'install /bin/true' in stdout or 'install /bin/false' in stdout:
                self.reporter.add_result(AuditResult(
                    check_id="1.1.8",
                    title="Ensure USB storage is disabled",
                    status=Status.PASS,
                    severity=Severity.MEDIUM,
                    message="USB storage module is disabled"
                ))
            else:
                # Check if module is currently loaded
                returncode2, stdout2, _ = self.run_command(['lsmod'])
                if 'usb_storage' in stdout2:
                    self.reporter.add_result(AuditResult(
                        check_id="1.1.8",
                        title="Ensure USB storage is disabled",
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        message="USB storage module is loaded",
                        details="usb_storage module is currently active",
                        remediation="Add 'install usb-storage /bin/true' to /etc/modprobe.d/usb-storage.conf"
                    ))
                else:
                    self.reporter.add_result(AuditResult(
                        check_id="1.1.8",
                        title="Ensure USB storage is disabled",
                        status=Status.WARNING,
                        severity=Severity.MEDIUM,
                        message="USB storage module is not disabled but not loaded",
                        remediation="Add 'install usb-storage /bin/true' to /etc/modprobe.d/usb-storage.conf"
                    ))
        except Exception as e:
            self.reporter.add_result(AuditResult(
                check_id="1.1.8",
                title="Ensure USB storage is disabled",
                status=Status.ERROR,
                severity=Severity.MEDIUM,
                message=f"Error checking USB storage: {str(e)}"
            ))

    def run_all_checks(self):
        """Run all extended filesystem checks"""
        self.check_tmp_noexec_configured()
        self.check_var_tmp_bind_mount()
        self.check_dev_shm_noexec()
        self.check_dev_shm_nodev()
        self.check_dev_shm_nosuid()
        self.check_sticky_bit_world_writable()
        self.check_automounting_disabled()
        self.check_usb_storage_disabled()


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

        print("[*] Running Integrity Checks...")
        integrity_auditor = IntegrityAuditor(self.reporter)
        integrity_auditor.run_all_checks()

        print("[*] Running Filesystem Checks...")
        filesystem_auditor = FileSystemAuditor(self.reporter)
        filesystem_auditor.run_all_checks()

        print("[*] Running Extended Filesystem Checks...")
        extended_fs_auditor = ExtendedFilesystemAuditor(self.reporter)
        extended_fs_auditor.run_all_checks()

        print("[*] Running Kernel Module Checks...")
        kernel_module_auditor = KernelModuleAuditor(self.reporter)
        kernel_module_auditor.run_all_checks()

        print("[*] Running Filesystem Partition Checks...")
        partition_auditor = FilesystemPartitionAuditor(self.reporter)
        partition_auditor.run_all_checks()

        print("[*] Running Software Updates Checks...")
        software_updates_auditor = SoftwareUpdatesAuditor(self.reporter)
        software_updates_auditor.run_all_checks()

        print("[*] Running Warning Banner Checks...")
        warning_banner_auditor = WarningBannerAuditor(self.reporter)
        warning_banner_auditor.run_all_checks()

        print("[*] Running AppArmor Configuration Checks...")
        apparmor_auditor = AppArmorAuditor(self.reporter)
        apparmor_auditor.run_all_checks()

        print("[*] Running Bootloader Security Checks...")
        bootloader_auditor = BootloaderAuditor(self.reporter)
        bootloader_auditor.run_all_checks()

        print("[*] Running Process Hardening Checks...")
        process_hardening_auditor = ProcessHardeningAuditor(self.reporter)
        process_hardening_auditor.run_all_checks()

        print("[*] Running Mandatory Access Control Checks...")
        mac_auditor = MandatoryAccessControlAuditor(self.reporter)
        mac_auditor.run_all_checks()

        print("[*] Running GNOME Display Manager Checks...")
        gdm_auditor = GDMAuditor(self.reporter)
        gdm_auditor.run_all_checks()

        print("[*] Running Service Checks...")
        service_auditor = ServiceAuditor(self.reporter)
        service_auditor.run_all_checks()

        print("[*] Running Time Synchronization Checks...")
        timesync_auditor = TimeSyncAuditor(self.reporter)
        timesync_auditor.run_all_checks()

        print("[*] Running Job Scheduler Checks...")
        jobscheduler_auditor = JobSchedulerAuditor(self.reporter)
        jobscheduler_auditor.run_all_checks()

        print("[*] Running Network Checks...")
        network_auditor = NetworkAuditor(self.reporter)
        network_auditor.run_all_checks()

        print("[*] Running SSH Configuration Checks...")
        ssh_auditor = SSHAuditor(self.reporter)
        ssh_auditor.run_all_checks()

        print("[*] Running sudo Configuration Checks...")
        sudo_auditor = SudoAuditor(self.reporter)
        sudo_auditor.run_all_checks()

        print("[*] Running User/Group Checks...")
        user_auditor = UserAuditor(self.reporter)
        user_auditor.run_all_checks()

        print("[*] Running PAM and Password Policy Checks...")
        pam_auditor = PAMAuditor(self.reporter)
        pam_auditor.run_all_checks()

        print("[*] Running Firewall Configuration Checks...")
        firewall_auditor = FirewallAuditor(self.reporter)
        firewall_auditor.run_all_checks()

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
