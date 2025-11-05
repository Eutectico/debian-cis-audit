#!/usr/bin/env python3
"""
Test script for Audit File Access checks (6.2.4.x)

This script demonstrates the audit file access checking functionality
by testing against the local system's audit configuration.

CIS Debian Linux 12 Benchmark v1.1.0
Section 6.2.4 - Audit File Access
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
    """Run Audit File Access checks"""
    print("=" * 80)
    print("AUDIT FILE ACCESS CHECKS TEST (6.2.4.x)")
    print("=" * 80)
    print()

    print("This test checks the following:")
    print("  6.2.4.1 - Audit log files mode")
    print("  6.2.4.2 - Audit log directory permissions")
    print("  6.2.4.3 - Audit configuration file permissions")
    print("  6.2.4.4 - Audit configuration file ownership")
    print("  6.2.4.5 - Audit configuration file group ownership")
    print("  6.2.4.6 - Audit tools permissions")
    print("  6.2.4.7 - Audit tools ownership")
    print("  6.2.4.8 - Audit tools group ownership")
    print("  6.2.4.9 - Audit rules file permissions")
    print()
    print("=" * 80)
    print()

    # Create reporter and auditor
    reporter = AuditReporter()
    auditor = AuditdAuditor(reporter)

    # Run only the audit file access checks
    print("[*] Running Audit File Access Checks...\n")
    auditor.check_audit_log_permissions()
    auditor.check_audit_log_directory_permissions()
    auditor.check_audit_config_file_permissions()
    auditor.check_audit_config_file_ownership()
    auditor.check_audit_config_file_group_ownership()
    auditor.check_audit_tools_permissions()
    auditor.check_audit_tools_ownership()
    auditor.check_audit_tools_group_ownership()
    auditor.check_audit_rules_permissions()

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
        print("WARNING: Critical audit file access issues found!")
        print("!" * 80)
        return 1
    else:
        print("\n" + "=" * 80)
        print("All audit file access checks completed successfully!")
        print("=" * 80)
        return 0


if __name__ == '__main__':
    sys.exit(main())
