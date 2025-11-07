#!/usr/bin/env python3
"""
Test Script for Extended Filesystem Checks
Phase 6 Priority 3: Extended Filesystem Security (1.1.4 - 1.1.18)

Total checks: 18 (8 basic + 10 extended)
- Basic checks (1.1.4.x - 1.1.8): tmp, /dev/shm, sticky bit, automounting, USB
- Extended checks (1.1.9 - 1.1.18): quotas, ACL, noatime, reserved blocks, error handling,
  tmpfs limits, /proc hidepid, journaling, xattr, encryption
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    AuditReporter,
    ExtendedFilesystemAuditor,
    Status
)


def test_extended_filesystem_checks():
    """Test Extended Filesystem implementation"""
    print("=" * 80)
    print("EXTENDED FILESYSTEM TEST: Mount Options & Security (1.1.4-1.1.18)")
    print("=" * 80)
    print()
    print("Testing 18 extended filesystem security checks:")
    print("  • Basic checks (8): /tmp, /dev/shm, sticky bit, automounting, USB")
    print("  • Extended checks (10): quotas, ACL, noatime, reserved blocks,")
    print("    error handling, tmpfs limits, /proc hidepid, journaling,")
    print("    xattr support, encryption")
    print()

    reporter = AuditReporter()

    print("[*] Testing Extended Filesystem Checks...")
    fs_auditor = ExtendedFilesystemAuditor(reporter)
    fs_auditor.run_all_checks()
    print("    ✓ Extended Filesystem checks completed")
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
    print("EXTENDED FILESYSTEM CHECK BREAKDOWN")
    print("=" * 80)
    print()
    print("Mount Options & Security (8 checks):")
    print("  - 1.1.4.1: /tmp noexec option")
    print("  - 1.1.4.2: /var/tmp bound to /tmp")
    print("  - 1.1.5.1: /dev/shm noexec option")
    print("  - 1.1.5.2: /dev/shm nodev option")
    print("  - 1.1.5.3: /dev/shm nosuid option")
    print("  - 1.1.6:   Sticky bit on world-writable dirs")
    print("  - 1.1.7:   Autofs disabled")
    print("  - 1.1.8:   USB storage disabled")
    print()

    return summary['total']


if __name__ == '__main__':
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 18 + "EXTENDED FILESYSTEM IMPLEMENTATION TEST" + " " * 20 + "║")
    print("║" + " " * 22 + "Mount Options & Security (1.1.x)" + " " * 22 + "║")
    print("╚" + "═" * 78 + "╝")
    print()

    total_checks = test_extended_filesystem_checks()

    print("=" * 80)
    print("TEST COMPLETED")
    print("=" * 80)
    print(f"✓ Extended Filesystem Implementation: {total_checks} checks tested")
    print()
    print("Next Steps:")
    print("  1. Run full audit: sudo python3 debian_cis_audit.py")
    print("  2. Verify all 303 checks are working correctly")
    print()
