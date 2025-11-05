#!/usr/bin/env python3
"""
Test script for Audit Data Retention checks (6.2.2.x)
Tests the new checks against the local auditd.conf file
"""

import sys
import os

# Add current directory to path to import debian_cis_audit
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from debian_cis_audit import AuditdAuditor, AuditReporter, BaseAuditor

# Create a custom BaseAuditor that uses local file
class TestAuditor(AuditdAuditor):
    """Test auditor that reads local auditd.conf file"""

    def file_exists(self, path):
        if path == '/etc/audit/auditd.conf':
            return os.path.exists('./auditd.conf')
        return os.path.exists(path)

    def read_file(self, path):
        if path == '/etc/audit/auditd.conf':
            path = './auditd.conf'
        try:
            with open(path, 'r') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading {path}: {e}")
            return None

def main():
    print("="*80)
    print("Testing Audit Data Retention Checks (6.2.2.x)")
    print("="*80)
    print()

    reporter = AuditReporter()
    auditor = TestAuditor(reporter)

    # Test each check individually
    print("Running 6.2.2.1 - Audit log file size check...")
    auditor.check_audit_log_file_size()

    print("Running 6.2.2.2 - Max log file action check...")
    auditor.check_audit_max_log_file_action()

    print("Running 6.2.2.3 - Space left action check...")
    auditor.check_audit_space_left_action()

    print("Running 6.2.2.4 - Admin space left action check...")
    auditor.check_audit_admin_space_left_action()

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
