#!/usr/bin/env python3
"""
Test script for Container and Virtualization Security Checks (8.x)

This script tests the ContainerVirtualizationAuditor class which implements
checks for Docker, Podman, and libvirt/KVM security configurations.

Tests:
- 8.1.x: Docker Security (4 checks)
- 8.2.x: Podman & Container User Namespaces (2 checks)
- 8.3.x: libvirt/KVM Virtualization Security (5 checks)

Total: 12 checks (11 new checks + 1 overlap with existing checks)
"""

import sys
import os

# Add parent directory to path to import main module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    ContainerVirtualizationAuditor,
    AuditReporter,
    Status
)


def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_result(result):
    """Print a single audit result"""
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
    """Main test function"""
    print_section("Container & Virtualization Security Tests")
    print("Testing ContainerVirtualizationAuditor class (8.x checks)")
    print("\nThese checks validate security configurations for:")
    print("  - Docker container runtime")
    print("  - Podman rootless containers")
    print("  - libvirt/KVM virtualization")

    # Create reporter and auditor
    reporter = AuditReporter()
    auditor = ContainerVirtualizationAuditor(reporter)

    # Run all checks
    print_section("Running Container & Virtualization Security Checks")
    auditor.run_all_checks()

    # Display results
    print_section("Test Results")

    for result in reporter.results:
        print_result(result)

    # Summary
    summary = reporter.get_summary()
    print_section("Summary")
    print(f"Total Checks: {summary['total']}")
    print(f"✓ Passed:     {summary['pass']}")
    print(f"✗ Failed:     {summary['fail']}")
    print(f"⚠ Warnings:   {summary['warning']}")
    print(f"- Skipped:    {summary['skip']}")
    print(f"! Errors:     {summary['error']}")

    # Container & Virtualization-specific insights
    print_section("Container & Virtualization Insights")

    docker_checks = [r for r in reporter.results if r.check_id.startswith('8.1')]
    podman_checks = [r for r in reporter.results if r.check_id.startswith('8.2')]
    virt_checks = [r for r in reporter.results if r.check_id.startswith('8.3')]

    print(f"\nDocker Security Checks (8.1.x): {len(docker_checks)} checks")
    print(f"Podman & Container Checks (8.2.x): {len(podman_checks)} checks")
    print(f"Virtualization Checks (8.3.x): {len(virt_checks)} checks")

    # Check for critical issues
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
        print("\n✓ No critical container/virtualization security issues found!")

    # Recommendations
    print_section("Recommendations")

    docker_installed = any(r.check_id == '8.1.1' and 'installed' in r.message and r.status != Status.SKIP for r in reporter.results)
    podman_installed = any(r.check_id == '8.2.1' and 'installed' in r.message and r.status != Status.SKIP for r in reporter.results)
    libvirt_installed = any(r.check_id == '8.3.1' and 'installed' in r.message and r.status != Status.SKIP for r in reporter.results)

    if docker_installed:
        print("\n✓ Docker is installed:")
        print("  - Ensure daemon.json is configured with secure settings")
        print("  - Enable Docker Content Trust (DOCKER_CONTENT_TRUST=1)")
        print("  - Check socket permissions (should be 660)")
    else:
        print("\n- Docker is not installed (container checks skipped)")

    if podman_installed:
        print("\n✓ Podman is installed (rootless containers):")
        print("  - Ensure user namespaces are enabled")
        print("  - Consider using Podman for better security isolation")
    else:
        print("\n- Podman is not installed")

    if libvirt_installed:
        print("\n✓ libvirt/KVM is installed:")
        print("  - Configure QEMU to run as non-root (libvirt-qemu)")
        print("  - Enable SASL authentication for remote connections")
        print("  - Use TLS encryption for network connections")
    else:
        print("\n- libvirt/KVM is not installed (virtualization checks skipped)")

    print("\n" + "=" * 80)
    print("Test completed successfully!")
    print("=" * 80)


if __name__ == '__main__':
    main()
