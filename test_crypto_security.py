#!/usr/bin/env python3
"""
Test script for Crypto and TLS Security Checks (9.x)

This script tests the CryptoSecurityAuditor class which implements
checks for cryptographic policies, TLS/SSL configuration, certificates,
and SSH cryptographic settings.

Tests:
- 9.1.x: System Crypto Policies (2 checks)
- 9.2.x: TLS/SSL Configuration (2 checks)
- 9.3.x: Certificate Management (3 checks)
- 9.4.x: SSH Crypto Configuration (3 checks)

Total: 10 checks
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    CryptoSecurityAuditor,
    AuditReporter,
    Status
)


def print_section(title):
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_result(result):
    status_icon = {
        Status.PASS: "✓",
        Status.FAIL: "✗",
        Status.WARNING: "⚠",
        Status.SKIP: "-",
        Status.ERROR: "!",
    }

    icon = status_icon.get(result.status, "?")
    print(f"\n{icon} [{result.check_id}] {result.title}")
    print(f"   Status: {result.status.value} | Severity: {result.severity.value}")
    print(f"   Message: {result.message}")

    if result.details:
        print(f"   Details: {result.details}")

    if result.remediation:
        print(f"   Remediation: {result.remediation}")


def main():
    print_section("Crypto & TLS Security Tests")
    print("Testing CryptoSecurityAuditor class (9.x checks)")
    print("\nThese checks validate:")
    print("  - System-wide crypto policies")
    print("  - TLS/SSL configuration")
    print("  - Certificate management")
    print("  - SSH cryptographic settings")

    reporter = AuditReporter()
    auditor = CryptoSecurityAuditor(reporter)

    print_section("Running Crypto & TLS Security Checks")
    auditor.run_all_checks()

    print_section("Test Results")
    for result in reporter.results:
        print_result(result)

    summary = reporter.get_summary()
    print_section("Summary")
    print(f"Total Checks: {summary['total']}")
    print(f"✓ Passed:     {summary['pass']}")
    print(f"✗ Failed:     {summary['fail']}")
    print(f"⚠ Warnings:   {summary['warning']}")
    print(f"- Skipped:    {summary['skip']}")
    print(f"! Errors:     {summary['error']}")

    print_section("Crypto & TLS Insights")
    crypto_checks = [r for r in reporter.results if r.check_id.startswith('9.1')]
    tls_checks = [r for r in reporter.results if r.check_id.startswith('9.2')]
    cert_checks = [r for r in reporter.results if r.check_id.startswith('9.3')]
    ssh_checks = [r for r in reporter.results if r.check_id.startswith('9.4')]

    print(f"\nCrypto Policy Checks (9.1.x): {len(crypto_checks)} checks")
    print(f"TLS/SSL Checks (9.2.x): {len(tls_checks)} checks")
    print(f"Certificate Checks (9.3.x): {len(cert_checks)} checks")
    print(f"SSH Crypto Checks (9.4.x): {len(ssh_checks)} checks")

    critical_issues = [r for r in reporter.results
                      if r.status in [Status.FAIL, Status.WARNING]
                      and r.severity.value in ['CRITICAL', 'HIGH']]

    if critical_issues:
        print_section("⚠ Critical Issues Found")
        for result in critical_issues:
            print(f"\n[{result.check_id}] {result.title}")
            print(f"  {result.message}")
            if result.remediation:
                print(f"  → {result.remediation}")
    else:
        print("\n✓ No critical crypto/TLS security issues found!")

    print("\n" + "=" * 80)
    print("Test completed successfully!")
    print("=" * 80)


if __name__ == '__main__':
    main()
