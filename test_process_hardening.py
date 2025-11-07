#!/usr/bin/env python3
"""
Test Script for Process Hardening Checks (1.6.1.x)
Tests: Process Hardening & Kernel Security Parameters

Phase 6 - Priority 1: Process Hardening
Total checks: 10

CIS Checks:
- 1.6.1.1:  ASLR enabled
- 1.6.1.2:  Prelink not installed
- 1.6.1.3:  Yama ptrace_scope configured
- 1.6.1.4:  kernel.dmesg_restrict set
- 1.6.1.5:  kernel.kptr_restrict set
- 1.6.1.6:  kernel.unprivileged_bpf_disabled set
- 1.6.1.7:  kernel.unprivileged_userns_clone disabled
- 1.6.1.8:  kernel.perf_event_paranoid set
- 1.6.1.9:  kernel.kexec_load_disabled set
- 1.6.1.10: /dev/mem and /dev/kmem restricted
"""

import sys
import os

# Add parent directory to path to import the main module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    AuditReporter,
    ProcessHardeningAuditor,
    Status
)


def test_process_hardening_checks():
    """Test Process Hardening implementation"""
    print("=" * 80)
    print("PROCESS HARDENING TEST: Kernel Security Parameters (1.6.1.x)")
    print("=" * 80)
    print()

    reporter = AuditReporter()

    # Test Process Hardening checks (1.6.1.x - 10 checks)
    print("[*] Testing Process Hardening Checks (1.6.1.x)...")
    hardening_auditor = ProcessHardeningAuditor(reporter)
    hardening_auditor.run_all_checks()
    print("    ✓ Process Hardening checks completed")
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
    print("PROCESS HARDENING CHECK BREAKDOWN")
    print("=" * 80)
    print()
    print("Kernel Security Parameters (1.6.1.x):")
    print("  - 1.6.1.1:  ASLR enabled")
    print("  - 1.6.1.2:  Prelink not installed")
    print("  - 1.6.1.3:  Yama ptrace_scope configured")
    print("  - 1.6.1.4:  kernel.dmesg_restrict set")
    print("  - 1.6.1.5:  kernel.kptr_restrict set")
    print("  - 1.6.1.6:  kernel.unprivileged_bpf_disabled set")
    print("  - 1.6.1.7:  kernel.unprivileged_userns_clone disabled")
    print("  - 1.6.1.8:  kernel.perf_event_paranoid set")
    print("  - 1.6.1.9:  kernel.kexec_load_disabled set")
    print("  - 1.6.1.10: /dev/mem and /dev/kmem restricted")
    print()
    print("Total Process Hardening Checks: 10")
    print()
    print("NOTE: Phase 6 Priority 1 - These checks enforce critical kernel")
    print("      security features to prevent privilege escalation and")
    print("      information disclosure attacks.")
    print()

    return summary['total']


if __name__ == '__main__':
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 18 + "PROCESS HARDENING IMPLEMENTATION TEST" + " " * 22 + "║")
    print("║" + " " * 18 + "Kernel Security Parameters (1.6.1.x)" + " " * 24 + "║")
    print("╚" + "═" * 78 + "╝")
    print()

    total_checks = test_process_hardening_checks()

    print("=" * 80)
    print("TEST COMPLETED")
    print("=" * 80)
    print(f"✓ Process Hardening Implementation: {total_checks} checks tested")
    print()
    print("Next Steps:")
    print("  1. Run full audit: sudo python3 debian_cis_audit.py")
    print("  2. Verify all 292 checks are working correctly")
    print("  3. Continue Phase 6 with additional priorities")
    print()
