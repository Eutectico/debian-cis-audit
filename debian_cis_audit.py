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

    def run_all_checks(self):
        """Run all auditd checks"""
        self.check_auditd_installed()
        self.check_auditd_enabled()
        self.check_auditd_config()
        self.check_audit_log_permissions()


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
        self.check_shadow_permissions()
        self.check_world_writable_files()


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
        # Check some common unnecessary services
        self.check_service_disabled('avahi-daemon', '2.2.1', 'Ensure Avahi Server is not installed')
        self.check_service_disabled('cups', '2.2.4', 'Ensure CUPS is not installed')
        self.check_service_disabled('rpcbind', '2.2.7', 'Ensure RPC is not installed')


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

    def run_all_checks(self):
        """Run all network checks"""
        self.check_ip_forwarding()
        self.check_icmp_redirects()


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

    def run_all_checks(self):
        """Run all user/group checks"""
        self.check_empty_passwords()
        self.check_duplicate_uids()


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

        print("[*] Running Filesystem Checks...")
        filesystem_auditor = FileSystemAuditor(self.reporter)
        filesystem_auditor.run_all_checks()

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
