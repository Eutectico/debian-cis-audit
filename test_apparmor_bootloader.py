#!/usr/bin/env python3
"""
Test script for AppArmor and Bootloader Security Checks

This script demonstrates and tests the AppArmor (1.3.1.x) and
Bootloader (1.4.x) checks from the CIS Debian 12 Benchmark.

Usage:
    python3 test_apparmor_bootloader.py

    # With sudo for complete checks:
    sudo python3 test_apparmor_bootloader.py
"""

import sys
import os

# Add parent directory to path to import from debian_cis_audit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    AppArmorAuditor, BootloaderAuditor, AuditReporter,
    Status, Severity
)


def print_separator(title=""):
    """Print a visual separator"""
    if title:
        print(f"\n{'=' * 80}")
        print(f"  {title}")
        print('=' * 80)
    else:
        print('=' * 80)


def print_result(result):
    """Print a single audit result in a readable format"""
    status_symbols = {
        Status.PASS: "✓",
        Status.FAIL: "✗",
        Status.WARNING: "⚠",
        Status.SKIP: "-",
        Status.ERROR: "!"
    }

    symbol = status_symbols.get(result.status, "?")
    print(f"\n{symbol} [{result.check_id}] {result.title}")
    print(f"   Status: {result.status.value}")
    print(f"   Severity: {result.severity.value}")
    print(f"   Message: {result.message}")

    if result.details:
        print(f"   Details: {result.details}")

    if result.remediation:
        print(f"   Remediation: {result.remediation}")


def main():
    """Main test function"""
    print_separator("AppArmor & Bootloader Security Checks Test")

    # Check if running as root
    if os.geteuid() != 0:
        print("\n⚠ WARNING: Not running as root!")
        print("Some checks may fail or return incomplete results.")
        print("Run with 'sudo' for complete testing.\n")

    # Create reporter
    reporter = AuditReporter()

    # Test AppArmor Checks
    print_separator("AppArmor Configuration Checks (1.3.1.x)")
    print("\nTesting 4 AppArmor checks...\n")

    apparmor_auditor = AppArmorAuditor(reporter)

    print("→ Running 1.3.1.1 - Ensure AppArmor is installed")
    apparmor_auditor.check_apparmor_installed()

    print("→ Running 1.3.1.2 - Ensure AppArmor is enabled in bootloader")
    apparmor_auditor.check_apparmor_bootloader()

    print("→ Running 1.3.1.3 - Ensure all profiles are in enforce or complain mode")
    apparmor_auditor.check_apparmor_profiles_mode()

    print("→ Running 1.3.1.4 - Ensure all profiles are enforcing")
    apparmor_auditor.check_apparmor_profiles_enforcing()

    # Test Bootloader Checks
    print_separator("Bootloader Security Checks (1.4.x)")
    print("\nTesting 2 Bootloader security checks...\n")

    bootloader_auditor = BootloaderAuditor(reporter)

    print("→ Running 1.4.1 - Ensure bootloader password is set")
    bootloader_auditor.check_bootloader_password()

    print("→ Running 1.4.2 - Ensure bootloader config permissions are correct")
    bootloader_auditor.check_bootloader_config_permissions()

    # Print all results
    print_separator("Test Results")

    for result in reporter.results:
        print_result(result)

    # Print summary
    print_separator("Summary")
    summary = reporter.get_summary()

    print(f"\nTotal Checks: {summary['total']}")
    print(f"  ✓ Passed:   {summary['pass']}")
    print(f"  ✗ Failed:   {summary['fail']}")
    print(f"  ⚠ Warnings: {summary['warning']}")
    print(f"  - Skipped:  {summary['skip']}")
    print(f"  ! Errors:   {summary['error']}")

    print_separator()

    # Return exit code based on results
    if summary['fail'] > 0:
        print("\n⚠ Some checks failed. Review the results above.")
        return 1
    elif summary['warning'] > 0:
        print("\n⚠ Some checks have warnings. Review the results above.")
        return 0
    else:
        print("\n✓ All checks passed!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
