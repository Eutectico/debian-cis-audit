#!/usr/bin/env python3
"""
Test script for Advanced Audit Rules (6.2.3.22 - 6.2.3.36)

This script tests the 15 additional advanced audit rules implemented in Phase 6 Priority 2.
These rules extend the basic audit rules with monitoring for critical system configurations.

Usage:
    python3 test_advanced_audit_rules.py
"""

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import AuditdAuditor, AuditReporter


def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 80)
    print(text)
    print("=" * 80 + "\n")


def test_advanced_audit_rules():
    """Test all advanced audit rules"""
    print_header("Testing Advanced Audit Rules (6.2.3.22 - 6.2.3.36)")
    print("These tests check for advanced audit rules that monitor critical system files")
    print("and configurations beyond the basic CIS requirements.\n")

    reporter = AuditReporter()
    auditor = AuditdAuditor(reporter)

    # Test each advanced audit rule individually
    print("[*] Testing advanced audit rules...\n")

    # 6.2.3.22 - PAM configuration monitoring
    print("  [1/15] Testing PAM configuration monitoring (6.2.3.22)...")
    auditor.check_audit_pam_rules()

    # 6.2.3.23 - Security limits monitoring
    print("  [2/15] Testing security limits monitoring (6.2.3.23)...")
    auditor.check_audit_security_limits_rules()

    # 6.2.3.24 - Syslog configuration monitoring
    print("  [3/15] Testing syslog configuration monitoring (6.2.3.24)...")
    auditor.check_audit_syslog_rules()

    # 6.2.3.25 - Systemd configuration monitoring
    print("  [4/15] Testing systemd configuration monitoring (6.2.3.25)...")
    auditor.check_audit_systemd_rules()

    # 6.2.3.26 - Firewall configuration monitoring
    print("  [5/15] Testing firewall configuration monitoring (6.2.3.26)...")
    auditor.check_audit_firewall_rules()

    # 6.2.3.27 - iptables configuration monitoring
    print("  [6/15] Testing iptables configuration monitoring (6.2.3.27)...")
    auditor.check_audit_iptables_rules()

    # 6.2.3.28 - CA certificates monitoring
    print("  [7/15] Testing CA certificates monitoring (6.2.3.28)...")
    auditor.check_audit_ca_certificates_rules()

    # 6.2.3.29 - APT sources monitoring
    print("  [8/15] Testing APT sources monitoring (6.2.3.29)...")
    auditor.check_audit_apt_sources_rules()

    # 6.2.3.30 - Package management monitoring
    print("  [9/15] Testing package management monitoring (6.2.3.30)...")
    auditor.check_audit_dpkg_rules()

    # 6.2.3.31 - Unsuccessful access attempts (EACCES)
    print(" [10/15] Testing unsuccessful access attempts - EACCES (6.2.3.31)...")
    auditor.check_audit_unsuccessful_access_rules()

    # 6.2.3.32 - Unsuccessful access attempts (EPERM)
    print(" [11/15] Testing unsuccessful access attempts - EPERM (6.2.3.32)...")
    auditor.check_audit_unsuccessful_access_eperm_rules()

    # 6.2.3.33 - Ownership changes
    print(" [12/15] Testing ownership changes monitoring (6.2.3.33)...")
    auditor.check_audit_chown_rules()

    # 6.2.3.34 - Permission changes
    print(" [13/15] Testing permission changes monitoring (6.2.3.34)...")
    auditor.check_audit_chmod_rules()

    # 6.2.3.35 - Extended attribute changes
    print(" [14/15] Testing extended attribute changes (6.2.3.35)...")
    auditor.check_audit_setxattr_rules()

    # 6.2.3.36 - Process creation events
    print(" [15/15] Testing process creation events (6.2.3.36)...")
    auditor.check_audit_process_creation_rules()

    print("\n[*] All advanced audit rule tests completed!\n")

    # Generate and display report
    print_header("Test Results Summary")

    results = reporter.results
    total = len(results)
    passed = sum(1 for r in results if r.status.value == "PASS")
    failed = sum(1 for r in results if r.status.value == "FAIL")
    warnings = sum(1 for r in results if r.status.value == "WARNING")
    errors = sum(1 for r in results if r.status.value == "ERROR")
    skipped = sum(1 for r in results if r.status.value == "SKIP")

    print(f"Total Advanced Audit Rules Tested: {total}")
    print(f"  ✓ Passed:   {passed}")
    print(f"  ✗ Failed:   {failed}")
    print(f"  ⚠ Warnings: {warnings}")
    print(f"  ! Errors:   {errors}")
    print(f"  - Skipped:  {skipped}")
    print()

    # Show detailed results
    if failed > 0 or warnings > 0:
        print_header("Detailed Results")

        # Show failures first
        if failed > 0:
            print("FAILED CHECKS:")
            print("-" * 80)
            for result in results:
                if result.status.value == "FAIL":
                    print(f"✗ [{result.check_id}] {result.title}")
                    print(f"  Message: {result.message}")
                    if result.details:
                        print(f"  Details: {result.details}")
                    if result.remediation:
                        print(f"  Remediation: {result.remediation}")
                    print()

        # Show warnings
        if warnings > 0:
            print("WARNINGS:")
            print("-" * 80)
            for result in results:
                if result.status.value == "WARNING":
                    print(f"⚠ [{result.check_id}] {result.title}")
                    print(f"  Message: {result.message}")
                    print()

    # Summary message
    print_header("Test Completion")
    if failed == 0 and errors == 0:
        print("✅ All advanced audit rules are configured correctly!")
    elif failed > 0:
        print(f"⚠️  {failed} advanced audit rule(s) are not configured.")
        print("   This is expected if auditd is not installed or rules are not set up.")
        print("   These checks validate advanced monitoring beyond basic CIS requirements.")

    print("\n" + "=" * 80)
    print("Advanced Audit Rules Test Complete")
    print("=" * 80 + "\n")

    return 0 if errors == 0 else 1


def main():
    """Main function"""
    print("\n" + "=" * 80)
    print("Debian CIS Audit - Advanced Audit Rules Test")
    print("Phase 6 Priority 2 Implementation (6.2.3.22 - 6.2.3.36)")
    print("=" * 80)
    print()
    print("This test validates 15 advanced audit rules that extend the basic CIS")
    print("requirements with additional monitoring for:")
    print("  • PAM and authentication configurations")
    print("  • System logging and monitoring")
    print("  • Firewall and network security")
    print("  • Certificate management")
    print("  • Package management")
    print("  • Unsuccessful access attempts")
    print("  • File ownership and permission changes")
    print("  • Process creation events")
    print()

    try:
        return test_advanced_audit_rules()
    except KeyboardInterrupt:
        print("\n\n[!] Test interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
