#!/usr/bin/env python3
"""
Test script for Phase 4 Advanced Features Checks

This script demonstrates and tests the Time Synchronization (2.3.x),
Job Schedulers (2.4.x), and GNOME Display Manager (1.7.x) checks
from the CIS Debian 12 Benchmark.

Usage:
    python3 test_phase4_advanced.py

    # With sudo for complete checks:
    sudo python3 test_phase4_advanced.py
"""

import sys
import os

# Add parent directory to path to import from debian_cis_audit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import (
    TimeSyncAuditor, JobSchedulerAuditor, GDMAuditor,
    AuditReporter, Status, Severity
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
    print_separator("Phase 4 Advanced Features Test")

    # Check if running as root
    if os.geteuid() != 0:
        print("\n⚠ WARNING: Not running as root!")
        print("Some checks may fail or return incomplete results.")
        print("Run with 'sudo' for complete testing.\n")

    # Create reporter
    reporter = AuditReporter()

    # Test Time Synchronization Checks
    print_separator("Time Synchronization Checks (2.3.x)")
    print("\nTesting 7 time synchronization checks...\n")

    timesync_auditor = TimeSyncAuditor(reporter)

    print("→ Running 2.3.1.1 - Ensure systemd-timesyncd is installed")
    timesync_auditor.check_systemd_timesyncd_installed()

    print("→ Running 2.3.1.2 - Ensure systemd-timesyncd is enabled and running")
    timesync_auditor.check_systemd_timesyncd_enabled()

    print("→ Running 2.3.1.3 - Ensure systemd-timesyncd is configured")
    timesync_auditor.check_systemd_timesyncd_configured()

    print("→ Running 2.3.2.1 - Ensure chrony is installed")
    timesync_auditor.check_chrony_installed()

    print("→ Running 2.3.2.2 - Ensure chrony is enabled and running")
    timesync_auditor.check_chrony_enabled()

    print("→ Running 2.3.2.3 - Ensure chrony is configured")
    timesync_auditor.check_chrony_configured()

    print("→ Running 2.3.3 - Ensure only one time synchronization daemon is in use")
    timesync_auditor.check_single_time_sync_daemon()

    # Test Job Scheduler Checks
    print_separator("Job Scheduler Checks (2.4.x)")
    print("\nTesting 9 job scheduler checks...\n")

    jobscheduler_auditor = JobSchedulerAuditor(reporter)

    print("→ Running 2.4.1.1 - Ensure cron daemon is installed")
    jobscheduler_auditor.check_cron_installed()

    print("→ Running 2.4.1.2 - Ensure cron daemon is enabled and running")
    jobscheduler_auditor.check_cron_enabled()

    print("→ Running 2.4.1.3-2.4.1.8 - Check cron directory/file permissions")
    jobscheduler_auditor.check_crontab_permissions()
    jobscheduler_auditor.check_cron_hourly_permissions()
    jobscheduler_auditor.check_cron_daily_permissions()
    jobscheduler_auditor.check_cron_weekly_permissions()
    jobscheduler_auditor.check_cron_monthly_permissions()
    jobscheduler_auditor.check_cron_d_permissions()

    print("→ Running 2.4.2.1 - Ensure at is restricted to authorized users")
    jobscheduler_auditor.check_at_restricted()

    # Test GNOME Display Manager Checks
    print_separator("GNOME Display Manager Checks (1.7.x)")
    print("\nTesting 10 GDM configuration checks...\n")

    gdm_auditor = GDMAuditor(reporter)

    print("→ Running 1.7.1 - Ensure GDM is removed or login is configured")
    gdm_auditor.check_gdm_removed_or_configured()

    print("→ Running 1.7.2 - Ensure GDM login banner is configured")
    gdm_auditor.check_gdm_banner()

    print("→ Running 1.7.3 - Ensure GDM disable-user-list option is enabled")
    gdm_auditor.check_gdm_disable_user_list()

    print("→ Running 1.7.4 - Ensure GDM screen locks when the user is idle")
    gdm_auditor.check_gdm_screen_lock_idle()

    print("→ Running 1.7.5 - Ensure GDM screen locks cannot be overridden")
    gdm_auditor.check_gdm_screen_lock_override()

    print("→ Running 1.7.6 - Ensure GDM automatic mounting of removable media is disabled")
    gdm_auditor.check_gdm_automount_disabled()

    print("→ Running 1.7.7 - Ensure GDM disabling automatic mounting is not overridden")
    gdm_auditor.check_gdm_automount_override()

    print("→ Running 1.7.8 - Ensure GDM autorun-never is enabled")
    gdm_auditor.check_gdm_autorun_never()

    print("→ Running 1.7.9 - Ensure GDM autorun-never is not overridden")
    gdm_auditor.check_gdm_autorun_override()

    print("→ Running 1.7.10 - Ensure XDMCP is not enabled")
    gdm_auditor.check_xdmcp_disabled()

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
