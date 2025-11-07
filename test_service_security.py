#!/usr/bin/env python3
"""
Test Script for Service Security Checks
Phase 6 Priority 5: Remaining Service & Network Checks

Total checks: 15
- 2.1.23: Postfix local-only configuration
- 2.1.24: Unnecessary packages check
- 3.5.1: Core dumps restricted
- 3.5.2: Packet redirect sending disabled
- 3.5.3: Suspicious packets logged
- 3.5.4: TCP SYN cookies enabled
- 3.5.5: IPv6 router advertisements disabled
- 3.5.6: Uncommon network protocols disabled
- 3.5.7: Wireless interfaces disabled
- 5.7.1: System accounts non-login
- 5.7.2: Default accounts locked
- 5.7.3: Inactive password lock
- 5.7.4: Shell timeout configured
- 7.2.11: Root PATH integrity
- 7.2.12: All users have home directories
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    AuditReporter,
    ServiceSecurityAuditor,
    Status
)


def test_service_security_checks():
    """Test Service Security implementation"""
    print("=" * 80)
    print("SERVICE SECURITY TEST: Service & Network Hardening (2.1.x/3.5.x/5.7.x/7.2.x)")
    print("=" * 80)
    print()
    print("Testing 15 service security and network hardening checks:")
    print("  • Service security (2): Postfix, unnecessary packages")
    print("  • Network hardening (7): Core dumps, packet redirects, suspicious packets,")
    print("    TCP SYN cookies, IPv6 RA, uncommon protocols, wireless interfaces")
    print("  • User security (4): System accounts, default accounts, inactive passwords,")
    print("    shell timeout")
    print("  • Path integrity (2): Root PATH, user home directories")
    print()

    reporter = AuditReporter()

    print("[*] Testing Service Security Checks...")
    service_auditor = ServiceSecurityAuditor(reporter)
    service_auditor.run_all_checks()
    print("    ✓ Service Security checks completed")
    print()

    # Summary
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    summary = reporter.get_summary()
    print(f"Total Checks:  {summary['total']}")
    print(f"✓ Passed:      {summary['pass']}")
    print(f"✗ Failed:      {summary['fail']}")
    print(f"⚠ Warnings:    {summary['warning']}")
    print(f"- Skipped:     {summary['skip']}")
    print(f"! Errors:      {summary['error']}")
    print()

    # Detailed results
    print("=" * 80)
    print("DETAILED RESULTS")
    print("=" * 80)
    print()

    for result in reporter.results:
        status_icon = {
            Status.PASS: "✓",
            Status.FAIL: "✗",
            Status.WARNING: "⚠",
            Status.SKIP: "-",
            Status.ERROR: "!"
        }.get(result.status, "?")

        print(f"{status_icon} [{result.check_id}] {result.title}")
        print(f"   Status: {result.status.value}")
        print(f"   Message: {result.message}")

        if result.details:
            print(f"   Details: {result.details}")

        if result.remediation:
            print(f"   Remediation: {result.remediation}")

        print()

    print("=" * 80)
    print("SERVICE SECURITY CHECK BREAKDOWN")
    print("=" * 80)
    print()
    print("Service Security (2 checks):")
    print("  - 2.1.23: Postfix configured for local-only")
    print("  - 2.1.24: Unnecessary packages check")
    print()
    print("Network Hardening (7 checks):")
    print("  - 3.5.1: Core dumps restricted")
    print("  - 3.5.2: Packet redirect sending disabled")
    print("  - 3.5.3: Suspicious packets logged")
    print("  - 3.5.4: TCP SYN cookies enabled")
    print("  - 3.5.5: IPv6 router advertisements disabled")
    print("  - 3.5.6: Uncommon network protocols disabled")
    print("  - 3.5.7: Wireless interfaces disabled")
    print()
    print("User Security (4 checks):")
    print("  - 5.7.1: System accounts non-login")
    print("  - 5.7.2: Default accounts locked")
    print("  - 5.7.3: Inactive password lock configured")
    print("  - 5.7.4: Shell timeout configured")
    print()
    print("Path Integrity (2 checks):")
    print("  - 7.2.11: Root PATH integrity")
    print("  - 7.2.12: All users have home directories")
    print()

    return summary['total']


if __name__ == '__main__':
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 18 + "SERVICE SECURITY IMPLEMENTATION TEST" + " " * 23 + "║")
    print("║" + " " * 17 + "Service & Network Hardening (Phase 6 P5)" + " " * 20 + "║")
    print("╚" + "═" * 78 + "╝")
    print()

    total_checks = test_service_security_checks()

    print("=" * 80)
    print("TEST COMPLETED")
    print("=" * 80)
    print(f"✓ Service Security Implementation: {total_checks} checks tested")
    print()
    print("Next Steps:")
    print("  1. Run full audit: sudo python3 debian_cis_audit.py")
    print("  2. Verify all 343 checks are working correctly")
    print()
