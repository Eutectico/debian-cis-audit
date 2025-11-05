#!/usr/bin/env python3
"""
Test script for Integrity Checking (6.3.x)
Tests the new AIDE-related checks
"""

import sys
import os

# Add current directory to path to import debian_cis_audit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import IntegrityAuditor, AuditReporter

def main():
    print("="*80)
    print("Testing Integrity Checking (6.3.x)")
    print("="*80)
    print()

    reporter = AuditReporter()
    auditor = IntegrityAuditor(reporter)

    # Test each check individually
    print("Running 6.3.1 - AIDE installation check...")
    auditor.check_aide_installed()

    print("Running 6.3.2 - Filesystem integrity check schedule...")
    auditor.check_filesystem_integrity_checked()

    print("Running 6.3.3 - Audit tools integrity protection...")
    auditor.check_audit_tools_integrity()

    print()
    print("="*80)
    print("Test Results")
    print("="*80)

    # Display results
    print(reporter.generate_console_report())

    # Summary
    summary = reporter.get_summary()
    print("\n" + "="*80)
    print(f"Summary: {summary['pass']} passed, {summary['fail']} failed, "
          f"{summary['warning']} warnings, {summary['error']} errors")
    print("="*80)

if __name__ == '__main__':
    main()
