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
