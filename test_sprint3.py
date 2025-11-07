#!/usr/bin/env python3
"""
Test Script for Sprint 3 Implementation
Tests: User Accounts (5.6.x) + Additional Services (2.2.x)

Sprint 3 adds:
- 5.6.9: root PATH Integrity
- 5.6.10: Interactive users home directories exist
- 2.2.1: Time synchronization is in use (Meta-Check)

Total new checks: 3
"""

import sys
import os

# Add parent directory to path to import the main module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    AuditReporter,
    UserAuditor,
    ServiceAuditor,
    Status
)


def test_sprint3_checks():
    """Test Sprint 3 implementation: User Accounts + Services"""
    print("=" * 80)
    print("SPRINT 3 TEST: User Accounts (5.6.x) + Additional Services (2.2.x)")
    print("=" * 80)
    print()

    reporter = AuditReporter()

    # Test User Accounts checks (5.6.x - 2 new checks)
    print("[*] Testing User Accounts Checks (5.6.x)...")
    user_auditor = UserAuditor(reporter)
    user_auditor.check_root_path_integrity()
    user_auditor.check_all_users_have_home_dirs()
    print("    ✓ User Accounts checks completed")
    print()

    # Test Additional Services check (2.2.1 - 1 new check)
    print("[*] Testing Additional Services Check (2.2.x)...")
    service_auditor = ServiceAuditor(reporter)
    service_auditor.check_time_synchronization()
    print("    ✓ Additional Services check completed")
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
        print(f"   Severity: {result.severity.value}")
        print(f"   Message: {result.message}")

        if result.details:
            print(f"   Details: {result.details}")

        if result.remediation:
            print(f"   Remediation: {result.remediation}")

        print()

    print("=" * 80)
    print("SPRINT 3 CHECK BREAKDOWN")
    print("=" * 80)
    print()
    print("User Accounts (5.6.x):")
    print("  - 5.6.9:  root PATH Integrity")
    print("  - 5.6.10: Interactive users home directories exist")
    print()
    print("Additional Services (2.2.x):")
    print("  - 2.2.1:  Time synchronization is in use (Meta-Check)")
    print()
    print("Total Sprint 3 Checks: 3")
    print()
    print("NOTE: Sprint 3 completes Phase 5 with minimal additions as most")
    print("      5.6.x and 2.2.x checks were already covered by 7.2.x and 2.1.x")
    print()

    return summary['total']


if __name__ == '__main__':
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "SPRINT 3 IMPLEMENTATION TEST" + " " * 30 + "║")
    print("║" + " " * 15 + "User Accounts + Additional Services" + " " * 27 + "║")
    print("╚" + "═" * 78 + "╝")
    print()

    total_checks = test_sprint3_checks()

    print("=" * 80)
    print("TEST COMPLETED")
    print("=" * 80)
    print(f"✓ Sprint 3 Implementation: {total_checks} checks tested")
    print()
    print("Next Steps:")
    print("  1. Run full audit: sudo python3 debian_cis_audit.py")
    print("  2. Verify all 282 checks are working correctly")
    print("  3. Update ROADMAP.md with Sprint 3 completion")
    print()
