#!/usr/bin/env python3
"""
Test script for Audit Rules checks (6.2.3.x)

This script demonstrates the audit rules checking functionality
by testing against the local system's audit configuration.

CIS Debian Linux 12 Benchmark v1.1.0
Section 6.2.3 - Audit Rules
"""

import sys
import os

# Add parent directory to path to import the main module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    AuditdAuditor,
    AuditReporter,
    Status
)


def main():
    """Run Audit Rules checks"""
    print("=" * 80)
    print("AUDIT RULES CHECKS TEST (6.2.3.x)")
    print("=" * 80)
    print()

    print("This test checks if the following system events are being audited:")
    print("  6.2.3.1  - System time changes")
    print("  6.2.3.2  - User/group information modifications")
    print("  6.2.3.3  - Network environment changes")
    print("  6.2.3.4  - Mandatory Access Control changes")
    print("  6.2.3.5  - Login/logout events")
    print("  6.2.3.6  - Session initiation")
    print("  6.2.3.7  - Permission modifications")
    print("  6.2.3.8  - Unsuccessful file access attempts")
    print("  6.2.3.9  - Privileged commands usage")
    print("  6.2.3.10 - File system mounts")
    print("  6.2.3.11 - File deletion events")
    print("  6.2.3.12 - Sudoers changes")
    print("  6.2.3.13 - Sudo command executions")
    print("  6.2.3.14 - Kernel module loading/unloading")
    print("  6.2.3.15 - Audit configuration immutability")
    print("  6.2.3.16 - Cron jobs")
    print("  6.2.3.17 - Password modifications")
    print("  6.2.3.18 - /etc/hosts modifications")
    print("  6.2.3.19 - Kernel parameter changes")
    print("  6.2.3.20 - Time zone changes")
    print("  6.2.3.21 - SSH configuration changes")
    print()
    print("=" * 80)
    print()

    # Create reporter and auditor
    reporter = AuditReporter()
    auditor = AuditdAuditor(reporter)

    # Run only the audit rules checks
    print("[*] Running Audit Rules Checks...\n")
    auditor.check_audit_time_rules()
    auditor.check_audit_user_group_rules()
    auditor.check_audit_network_env_rules()
    auditor.check_audit_apparmor_rules()
    auditor.check_audit_login_logout_rules()
    auditor.check_audit_session_rules()
    auditor.check_audit_perm_mod_rules()
    auditor.check_audit_access_rules()
    auditor.check_audit_privileged_commands_rules()
    auditor.check_audit_mounts_rules()
    auditor.check_audit_file_deletion_rules()
    auditor.check_audit_sudoers_rules()
    auditor.check_audit_sudolog_rules()
    auditor.check_audit_kernel_modules_rules()
    auditor.check_audit_immutable_rules()
    auditor.check_audit_cron_rules()
    auditor.check_audit_passwd_rules()
    auditor.check_audit_hosts_rules()
    auditor.check_audit_sysctl_rules()
    auditor.check_audit_localtime_rules()
    auditor.check_audit_ssh_rules()

    # Generate report
    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80 + "\n")

    print(reporter.generate_console_report())

    # Check if any critical issues found
    results = reporter.results
    critical_failures = [r for r in results if r.status == Status.FAIL and r.severity.value in ['CRITICAL', 'HIGH']]

    if critical_failures:
        print("\n" + "!" * 80)
        print(f"WARNING: {len(critical_failures)} critical audit rules are not configured!")
        print("!" * 80)
        print("\nThese rules are essential for security monitoring and compliance.")
        print("Consider implementing the recommended audit rules.")
        return 1
    else:
        print("\n" + "=" * 80)
        print("All audit rules checks completed successfully!")
        print("=" * 80)
        return 0


if __name__ == '__main__':
    sys.exit(main())
