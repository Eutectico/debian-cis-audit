#!/usr/bin/env python3
"""
Test script for Phase 5 CIS checks
Tests: Warning Banners (1.8.x), Software Updates (1.2.x),
       Network Devices (3.1.x), Network Protocols (3.2.x),
       Filesystem Configuration (1.1.3.x)
"""

import sys
import os

# Import from the main audit script
from debian_cis_audit import (
    AuditReporter,
    WarningBannerAuditor,
    SoftwareUpdatesAuditor,
    NetworkAuditor,
    FilesystemPartitionAuditor
)


def print_section(title):
    """Print a section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def main():
    """Test Phase 5 checks"""
    print("=" * 80)
    print("Phase 5 CIS Checks - Test Script")
    print("=" * 80)
    print("\nThis script tests the newly implemented Phase 5 checks:")
    print("  - Warning Banners (1.8.x) - 6 checks")
    print("  - Software Updates (1.2.x) - 2 checks")
    print("  - Network Devices (3.1.x) - 3 checks")
    print("  - Network Protocols (3.2.x) - 5 checks")
    print("  - Filesystem Configuration (1.1.3.x) - 3 checks")
    print("\n  Total: 19 new checks")

    if os.geteuid() != 0:
        print("\n⚠ WARNING: Not running as root. Some checks may fail or be incomplete.")
        print("           For complete testing, run with sudo.")

    # Create reporter
    reporter = AuditReporter()

    # Test Warning Banner Checks (1.8.x)
    print_section("Testing Warning Banner Checks (1.8.x)")
    print("Testing /etc/motd, /etc/issue, /etc/issue.net configuration...")
    banner_auditor = WarningBannerAuditor(reporter)
    banner_auditor.run_all_checks()
    print("✓ Warning Banner checks completed (6 checks)")

    # Test Software Updates Checks (1.2.x)
    print_section("Testing Software Updates Checks (1.2.x)")
    print("Testing APT repositories and GPG keys configuration...")
    software_auditor = SoftwareUpdatesAuditor(reporter)
    software_auditor.run_all_checks()
    print("✓ Software Updates checks completed (2 checks)")

    # Test Network Checks (3.1.x + 3.2.x)
    print_section("Testing Network Checks (3.1.x + 3.2.x)")
    print("Testing wireless, bluetooth, network protocols...")
    network_auditor = NetworkAuditor(reporter)
    # Run only the new checks
    print("  - Checking wireless interfaces...")
    network_auditor.check_wireless_interfaces_disabled()
    print("  - Checking bluetooth...")
    network_auditor.check_bluetooth_disabled()
    print("  - Checking packet redirect sending...")
    network_auditor.check_packet_redirect_sending_disabled()
    print("  - Checking DCCP protocol...")
    network_auditor.check_dccp_disabled()
    print("  - Checking SCTP protocol...")
    network_auditor.check_sctp_disabled()
    print("  - Checking RDS protocol...")
    network_auditor.check_rds_disabled()
    print("  - Checking TIPC protocol...")
    network_auditor.check_tipc_disabled()
    print("  - Checking IPv6 status...")
    network_auditor.check_ipv6_disabled()
    print("✓ Network checks completed (8 checks)")

    # Test Filesystem Configuration Checks (1.1.3.x)
    print_section("Testing Filesystem Configuration Checks (1.1.3.x)")
    print("Testing /var partition mount options...")
    partition_auditor = FilesystemPartitionAuditor(reporter)
    # Run only the new 1.1.3.x checks
    print("  - Checking /var nodev option...")
    partition_auditor.check_var_nodev_1_1_3_1()
    print("  - Checking /var nosuid option...")
    partition_auditor.check_var_nosuid_1_1_3_2()
    print("  - Checking /var noexec option...")
    partition_auditor.check_var_noexec()
    print("✓ Filesystem Configuration checks completed (3 checks)")

    # Print summary
    print_section("Test Summary")
    summary = reporter.get_summary()
    print(f"Total Checks Run: {summary['total']}")
    print(f"  ✓ Passed:       {summary['pass']}")
    print(f"  ✗ Failed:       {summary['fail']}")
    print(f"  ⚠ Warnings:     {summary['warning']}")
    print(f"  - Skipped:      {summary['skip']}")
    print(f"  ! Errors:       {summary['error']}")

    # Show failures
    if summary['fail'] > 0:
        print("\n" + "-" * 80)
        print("Failed Checks:")
        print("-" * 80)
        for result in reporter.results:
            if result.status.value == 'FAIL':
                print(f"\n✗ [{result.check_id}] {result.title}")
                print(f"  {result.message}")
                if result.remediation:
                    print(f"  Remediation: {result.remediation}")

    # Show warnings
    if summary['warning'] > 0:
        print("\n" + "-" * 80)
        print("Warnings:")
        print("-" * 80)
        for result in reporter.results:
            if result.status.value == 'WARNING':
                print(f"\n⚠ [{result.check_id}] {result.title}")
                print(f"  {result.message}")

    print("\n" + "=" * 80)
    print("Phase 5 Testing Complete!")
    print("=" * 80)

    # Return exit code based on results
    if summary['error'] > 0:
        return 2
    elif summary['fail'] > 0:
        return 1
    else:
        return 0


if __name__ == '__main__':
    sys.exit(main())
