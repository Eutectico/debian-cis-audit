#!/usr/bin/env python3
"""
Test script for Sprint 1: sudo Configuration (5.2.x) + IPv6 & Network Hardening (3.4.x)

This script tests the newly implemented checks from Sprint 1 of Phase 5.
Tests can be run with or without sudo privileges.

Sprint 1 Implementation:
- SudoAuditor (5.2.x): 10 checks for sudo configuration
- NetworkAuditor IPv6 extension (3.4.x): 7 checks for IPv6 and TCP Wrappers

Total new checks: 17

Usage:
    # Test without sudo (limited checks)
    python3 test_sprint1.py

    # Test with sudo (full checks)
    sudo python3 test_sprint1.py
"""

import sys
import os

# Add current directory to path to import debian_cis_audit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    SudoAuditor,
    NetworkAuditor,
    AuditReporter
)


def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def test_sudo_auditor():
    """Test the SudoAuditor class (5.2.x - 10 checks)"""
    print_section("TESTING SUDO AUDITOR (5.2.x - 10 checks)")

    reporter = AuditReporter()
    auditor = SudoAuditor(reporter)

    print("\nRunning all sudo configuration checks...")
    auditor.run_all_checks()

    # Generate report
    report = reporter.generate_console_report()
    print(report)

    return reporter


def test_network_auditor_ipv6():
    """Test the NetworkAuditor IPv6 checks (3.4.x - 7 checks)"""
    print_section("TESTING NETWORK AUDITOR - IPv6 & TCP WRAPPERS (3.4.x - 7 checks)")

    reporter = AuditReporter()
    auditor = NetworkAuditor(reporter)

    print("\nRunning IPv6 and TCP Wrappers checks...")
    # Run only the new 3.4.x checks
    auditor.check_ipv6_router_advertisements()
    auditor.check_ipv6_redirects()
    auditor.check_ipv6_completely_disabled()
    auditor.check_tcp_wrappers_installed()
    auditor.check_hosts_allow_configured()
    auditor.check_hosts_deny_configured()
    auditor.check_hosts_allow_permissions()

    # Generate report
    report = reporter.generate_console_report()
    print(report)

    return reporter


def main():
    """Main test function"""
    print("=" * 80)
    print("SPRINT 1 TEST SUITE - v2.6.0")
    print("sudo Configuration (5.2.x) + IPv6 & Network Hardening (3.4.x)")
    print("=" * 80)

    # Check if running as root
    if os.geteuid() != 0:
        print("\n⚠️  WARNING: Not running as root!")
        print("Some checks may fail or be incomplete.")
        print("For full test coverage, run with: sudo python3 test_sprint1.py")
    else:
        print("\n✓ Running as root - full test coverage available")

    # Test sudo configuration checks
    sudo_reporter = test_sudo_auditor()

    # Test IPv6 and TCP Wrappers checks
    network_reporter = test_network_auditor_ipv6()

    # Combined summary
    print_section("SPRINT 1 COMBINED SUMMARY")

    sudo_results = sudo_reporter.results
    network_results = network_reporter.results

    total_checks = len(sudo_results) + len(network_results)

    sudo_pass = sum(1 for r in sudo_results if r.status.value == 'PASS')
    sudo_fail = sum(1 for r in sudo_results if r.status.value == 'FAIL')
    sudo_warn = sum(1 for r in sudo_results if r.status.value == 'WARNING')
    sudo_error = sum(1 for r in sudo_results if r.status.value == 'ERROR')

    network_pass = sum(1 for r in network_results if r.status.value == 'PASS')
    network_fail = sum(1 for r in network_results if r.status.value == 'FAIL')
    network_warn = sum(1 for r in network_results if r.status.value == 'WARNING')
    network_error = sum(1 for r in network_results if r.status.value == 'ERROR')

    total_pass = sudo_pass + network_pass
    total_fail = sudo_fail + network_fail
    total_warn = sudo_warn + network_warn
    total_error = sudo_error + network_error

    print(f"\nTotal Checks Run: {total_checks}")
    print(f"  ✓ Passed:   {total_pass}")
    print(f"  ✗ Failed:   {total_fail}")
    print(f"  ⚠ Warnings: {total_warn}")
    print(f"  ! Errors:   {total_error}")

    print("\nBreakdown by Auditor:")
    print(f"  sudo Configuration (5.2.x):      {len(sudo_results)} checks ({sudo_pass}P/{sudo_fail}F/{sudo_warn}W/{sudo_error}E)")
    print(f"  IPv6 & TCP Wrappers (3.4.x):     {len(network_results)} checks ({network_pass}P/{network_fail}F/{network_warn}W/{network_error}E)")

    print("\n" + "=" * 80)
    print("Sprint 1 Implementation Complete!")
    print("New checks: 17 (10 sudo + 7 IPv6/TCP Wrappers)")
    print("Total project checks: 270 (~67% of CIS Benchmark)")
    print("=" * 80)


if __name__ == '__main__':
    main()
