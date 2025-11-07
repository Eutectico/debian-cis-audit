#!/usr/bin/env python3
"""
Test Script for Phase 6 Priority 1 & 4
Tests: Process Hardening (1.6.1.x) + Mandatory Access Controls (1.6.2.x)

Phase 6 Implementation:
- Priority 1: Process Hardening & Kernel Security (10 checks)
- Priority 4: Mandatory Access Controls (3 checks)

Total checks: 13
"""

import sys
import os

# Add parent directory to path to import the main module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    AuditReporter,
    ProcessHardeningAuditor,
    MandatoryAccessControlAuditor,
    Status
)


def test_phase6_checks():
    """Test Phase 6 Priority 1 & 4 implementation"""
    print("=" * 80)
    print("PHASE 6 TEST: Process Hardening + MAC (1.6.x)")
    print("=" * 80)
    print()

    reporter = AuditReporter()

    # Test Process Hardening checks (1.6.1.x - 10 checks)
    print("[*] Testing Process Hardening Checks (1.6.1.x)...")
    hardening_auditor = ProcessHardeningAuditor(reporter)
    hardening_auditor.run_all_checks()
    print("    ✓ Process Hardening checks completed")
    print()

    # Test MAC checks (1.6.2.x - 3 checks)
    print("[*] Testing Mandatory Access Control Checks (1.6.2.x)...")
    mac_auditor = MandatoryAccessControlAuditor(reporter)
    mac_auditor.run_all_checks()
    print("    ✓ MAC checks completed")
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
    print("PHASE 6 CHECK BREAKDOWN")
    print("=" * 80)
    print()
    print("Priority 1 - Process Hardening (1.6.1.x - 10 checks):")
    print("  - ASLR, prelink, ptrace, dmesg, kptr")
    print("  - BPF, userns, perf_event, kexec, /dev/mem")
    print()
    print("Priority 4 - Mandatory Access Controls (1.6.2.x - 3 checks):")
    print("  - MAC installed (AppArmor/SELinux)")
    print("  - MAC enabled")
    print("  - MAC in enforcing mode")
    print()
    print("Total Phase 6 Checks: 13")
    print()

    return summary['total']


if __name__ == '__main__':
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 22 + "PHASE 6 IMPLEMENTATION TEST" + " " * 28 + "║")
    print("║" + " " * 15 + "Process Hardening + Mandatory Access Control" + " " * 18 + "║")
    print("╚" + "═" * 78 + "╝")
    print()

    total_checks = test_phase6_checks()

    print("=" * 80)
    print("TEST COMPLETED")
    print("=" * 80)
    print(f"✓ Phase 6 Implementation: {total_checks} checks tested")
    print()
    print("Next Steps:")
    print("  1. Run full audit: sudo python3 debian_cis_audit.py")
    print("  2. Verify all 295 checks are working correctly")
    print("  3. Continue with Extended Filesystem Checks (Priority 3)")
    print()
