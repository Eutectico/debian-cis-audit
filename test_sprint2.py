#!/usr/bin/env python3
"""
Test script for Sprint 2: User Environment (5.5.x) + Filesystem Integrity (1.5.x)

This script tests the newly implemented checks from Sprint 2 of Phase 5.
Tests can be run with or without sudo privileges.

Sprint 2 Implementation:
- User Environment & Root Security (5.5.x): 5 checks
- Filesystem Integrity & Bootloader (1.5.x): 4 checks

Total new checks: 9

Usage:
    # Test without sudo (limited checks)
    python3 test_sprint2.py

    # Test with sudo (full checks)
    sudo python3 test_sprint2.py
"""

import sys
import os

# Add current directory to path to import debian_cis_audit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    PAMAuditor,
    BootloaderAuditor,
    AuditReporter
)


def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def test_user_environment():
    """Test the User Environment checks (5.5.x - 5 checks)"""
    print_section("TESTING USER ENVIRONMENT & ROOT SECURITY (5.5.x - 5 checks)")

    reporter = AuditReporter()
    auditor = PAMAuditor(reporter)

    print("\nRunning User Environment checks...")
    # Run only the new 5.5.x checks
    auditor.check_default_user_shell_timeout()
    auditor.check_default_user_umask()
    auditor.check_tmout_configured()
    auditor.check_root_default_group_gid0()
    auditor.check_root_only_uid0()

    # Generate report
    report = reporter.generate_console_report()
    print(report)

    return reporter


def test_filesystem_integrity():
    """Test the Filesystem Integrity checks (1.5.x - 4 checks)"""
    print_section("TESTING FILESYSTEM INTEGRITY & BOOTLOADER (1.5.x - 4 checks)")

    reporter = AuditReporter()
    auditor = BootloaderAuditor(reporter)

    print("\nRunning Filesystem Integrity checks...")
    # Run only the new 1.5.x checks
    auditor.check_bootloader_not_overwritten()
    auditor.check_bootloader_permissions_configured()
    auditor.check_single_user_authentication()
    auditor.check_core_dumps_restricted()

    # Generate report
    report = reporter.generate_console_report()
    print(report)

    return reporter


def main():
    """Main test function"""
    print("=" * 80)
    print("SPRINT 2 TEST SUITE - v2.7.0")
    print("User Environment (5.5.x) + Filesystem Integrity (1.5.x)")
    print("=" * 80)

    # Check if running as root
    if os.geteuid() != 0:
        print("\n⚠️  WARNING: Not running as root!")
        print("Some checks may fail or be incomplete.")
        print("For full test coverage, run with: sudo python3 test_sprint2.py")
    else:
        print("\n✓ Running as root - full test coverage available")

    # Test User Environment checks
    user_env_reporter = test_user_environment()

    # Test Filesystem Integrity checks
    fs_integrity_reporter = test_filesystem_integrity()

    # Combined summary
    print_section("SPRINT 2 COMBINED SUMMARY")

    user_env_results = user_env_reporter.results
    fs_integrity_results = fs_integrity_reporter.results

    total_checks = len(user_env_results) + len(fs_integrity_results)

    user_pass = sum(1 for r in user_env_results if r.status.value == 'PASS')
    user_fail = sum(1 for r in user_env_results if r.status.value == 'FAIL')
    user_warn = sum(1 for r in user_env_results if r.status.value == 'WARNING')
    user_error = sum(1 for r in user_env_results if r.status.value == 'ERROR')

    fs_pass = sum(1 for r in fs_integrity_results if r.status.value == 'PASS')
    fs_fail = sum(1 for r in fs_integrity_results if r.status.value == 'FAIL')
    fs_warn = sum(1 for r in fs_integrity_results if r.status.value == 'WARNING')
    fs_error = sum(1 for r in fs_integrity_results if r.status.value == 'ERROR')

    total_pass = user_pass + fs_pass
    total_fail = user_fail + fs_fail
    total_warn = user_warn + fs_warn
    total_error = user_error + fs_error

    print(f"\nTotal Checks Run: {total_checks}")
    print(f"  ✓ Passed:   {total_pass}")
    print(f"  ✗ Failed:   {total_fail}")
    print(f"  ⚠ Warnings: {total_warn}")
    print(f"  ! Errors:   {total_error}")

    print("\nBreakdown by Auditor:")
    print(f"  User Environment (5.5.x):          {len(user_env_results)} checks ({user_pass}P/{user_fail}F/{user_warn}W/{user_error}E)")
    print(f"  Filesystem Integrity (1.5.x):      {len(fs_integrity_results)} checks ({fs_pass}P/{fs_fail}F/{fs_warn}W/{fs_error}E)")

    print("\n" + "=" * 80)
    print("Sprint 2 Implementation Complete!")
    print("New checks: 9 (5 User Environment + 4 Filesystem Integrity)")
    print("Total project checks: 279 (~70% of CIS Benchmark)")
    print("=" * 80)


if __name__ == '__main__':
    main()
