#!/usr/bin/env python3
"""
Test script for PAM and Password Policy Checks (5.3.x and 5.4.x)

This script demonstrates the PAM and password policy auditing functionality
without requiring root privileges for most checks.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the parent directory to the path so we can import the main module
sys.path.insert(0, str(Path(__file__).parent))

from debian_cis_audit import (
    PAMAuditor, AuditReporter, Status, Severity
)


def create_test_files():
    """Create test configuration files"""
    test_dir = tempfile.mkdtemp(prefix='pam_test_')
    print(f"Creating test files in: {test_dir}")

    # Test pwquality.conf - FAIL case
    pwquality_fail = os.path.join(test_dir, 'pwquality_fail.conf')
    with open(pwquality_fail, 'w') as f:
        f.write("""# Password quality configuration - INSECURE
minlen = 8
minclass = 2
dcredit = 0
ucredit = 0
lcredit = 0
ocredit = 0
""")

    # Test pwquality.conf - PASS case
    pwquality_pass = os.path.join(test_dir, 'pwquality_pass.conf')
    with open(pwquality_pass, 'w') as f:
        f.write("""# Password quality configuration - SECURE
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
""")

    # Test common-password - FAIL case (no pwhistory)
    common_password_fail = os.path.join(test_dir, 'common_password_fail')
    with open(common_password_fail, 'w') as f:
        f.write("""# PAM configuration for password changes - INSECURE
password [success=1 default=ignore] pam_unix.so obscure
password requisite pam_deny.so
password required pam_permit.so
""")

    # Test common-password - PASS case (with pwhistory and sha512)
    common_password_pass = os.path.join(test_dir, 'common_password_pass')
    with open(common_password_pass, 'w') as f:
        f.write("""# PAM configuration for password changes - SECURE
password requisite pam_pwquality.so retry=3
password required pam_pwhistory.so remember=5 use_authtok
password [success=1 default=ignore] pam_unix.so obscure sha512
password requisite pam_deny.so
password required pam_permit.so
""")

    # Test login.defs - FAIL case
    login_defs_fail = os.path.join(test_dir, 'login_defs_fail')
    with open(login_defs_fail, 'w') as f:
        f.write("""# Login configuration - INSECURE
PASS_MAX_DAYS 99999
PASS_MIN_DAYS 0
PASS_WARN_AGE 3
""")

    # Test login.defs - PASS case
    login_defs_pass = os.path.join(test_dir, 'login_defs_pass')
    with open(login_defs_pass, 'w') as f:
        f.write("""# Login configuration - SECURE
PASS_MAX_DAYS 90
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
""")

    # Test bash.bashrc - FAIL case (weak umask)
    bash_bashrc_fail = os.path.join(test_dir, 'bash_bashrc_fail')
    with open(bash_bashrc_fail, 'w') as f:
        f.write("""# Bash configuration - INSECURE
umask 022
""")

    # Test bash.bashrc - PASS case (strong umask)
    bash_bashrc_pass = os.path.join(test_dir, 'bash_bashrc_pass')
    with open(bash_bashrc_pass, 'w') as f:
        f.write("""# Bash configuration - SECURE
umask 027
""")

    # Test profile - FAIL case (no TMOUT)
    profile_fail = os.path.join(test_dir, 'profile_fail')
    with open(profile_fail, 'w') as f:
        f.write("""# Profile configuration - INSECURE
export PATH=/usr/local/bin:/usr/bin:/bin
""")

    # Test profile - PASS case (with TMOUT)
    profile_pass = os.path.join(test_dir, 'profile_pass')
    with open(profile_pass, 'w') as f:
        f.write("""# Profile configuration - SECURE
export PATH=/usr/local/bin:/usr/bin:/bin
TMOUT=900
readonly TMOUT
export TMOUT
""")

    return test_dir, {
        'pwquality_fail': pwquality_fail,
        'pwquality_pass': pwquality_pass,
        'common_password_fail': common_password_fail,
        'common_password_pass': common_password_pass,
        'login_defs_fail': login_defs_fail,
        'login_defs_pass': login_defs_pass,
        'bash_bashrc_fail': bash_bashrc_fail,
        'bash_bashrc_pass': bash_bashrc_pass,
        'profile_fail': profile_fail,
        'profile_pass': profile_pass,
    }


def test_pwquality_config(auditor, test_files):
    """Test password quality configuration check"""
    print("\n" + "=" * 80)
    print("TEST: Password Quality Configuration (5.3.1.2)")
    print("=" * 80)

    # Monkey-patch the file_exists and read_file methods for testing
    original_file_exists = auditor.file_exists
    original_read_file = auditor.read_file

    # Test FAIL case
    print("\n[TEST 1] Testing with INSECURE configuration...")
    auditor.file_exists = lambda path: path == '/etc/security/pwquality.conf'
    auditor.read_file = lambda path: open(test_files['pwquality_fail']).read()

    auditor.check_pwquality_config()

    # Test PASS case
    print("\n[TEST 2] Testing with SECURE configuration...")
    auditor.read_file = lambda path: open(test_files['pwquality_pass']).read()

    auditor.check_pwquality_config()

    # Restore original methods
    auditor.file_exists = original_file_exists
    auditor.read_file = original_read_file


def test_pam_pwhistory(auditor, test_files):
    """Test password history check"""
    print("\n" + "=" * 80)
    print("TEST: Password Reuse Limitation (5.3.3.1)")
    print("=" * 80)

    original_file_exists = auditor.file_exists
    original_read_file = auditor.read_file

    # Test FAIL case - no pwhistory
    print("\n[TEST 1] Testing without password history...")
    auditor.file_exists = lambda path: path == '/etc/pam.d/common-password'
    auditor.read_file = lambda path: open(test_files['common_password_fail']).read()

    auditor.check_pam_pwhistory()

    # Test PASS case - with pwhistory
    print("\n[TEST 2] Testing with password history (remember=5)...")
    auditor.read_file = lambda path: open(test_files['common_password_pass']).read()

    auditor.check_pam_pwhistory()

    auditor.file_exists = original_file_exists
    auditor.read_file = original_read_file


def test_pam_unix_sha512(auditor, test_files):
    """Test SHA-512 hashing check"""
    print("\n" + "=" * 80)
    print("TEST: Password Hashing Algorithm (5.3.3.2)")
    print("=" * 80)

    original_file_exists = auditor.file_exists
    original_read_file = auditor.read_file

    # Test FAIL case
    print("\n[TEST 1] Testing without SHA-512...")
    auditor.file_exists = lambda path: path == '/etc/pam.d/common-password'
    auditor.read_file = lambda path: open(test_files['common_password_fail']).read()

    auditor.check_pam_unix_sha512()

    # Test PASS case
    print("\n[TEST 2] Testing with SHA-512...")
    auditor.read_file = lambda path: open(test_files['common_password_pass']).read()

    auditor.check_pam_unix_sha512()

    auditor.file_exists = original_file_exists
    auditor.read_file = original_read_file


def test_password_policies(auditor, test_files):
    """Test password aging policies"""
    print("\n" + "=" * 80)
    print("TEST: Password Aging Policies (5.4.1.x)")
    print("=" * 80)

    original_file_exists = auditor.file_exists
    original_read_file = auditor.read_file

    # Test FAIL case
    print("\n[TEST 1] Testing with INSECURE password policies...")
    auditor.file_exists = lambda path: path == '/etc/login.defs'
    auditor.read_file = lambda path: open(test_files['login_defs_fail']).read()

    auditor.check_password_max_days()
    auditor.check_password_min_days()
    auditor.check_password_warn_age()

    # Test PASS case
    print("\n[TEST 2] Testing with SECURE password policies...")
    auditor.read_file = lambda path: open(test_files['login_defs_pass']).read()

    auditor.check_password_max_days()
    auditor.check_password_min_days()
    auditor.check_password_warn_age()

    auditor.file_exists = original_file_exists
    auditor.read_file = original_read_file


def test_umask(auditor, test_files):
    """Test umask configuration"""
    print("\n" + "=" * 80)
    print("TEST: Default User umask (5.4.4)")
    print("=" * 80)

    original_file_exists = auditor.file_exists
    original_read_file = auditor.read_file

    # Test FAIL case
    print("\n[TEST 1] Testing with weak umask (022)...")
    def file_exists_weak(path):
        return path in ['/etc/bash.bashrc', '/etc/profile']

    def read_file_weak(path):
        if path == '/etc/bash.bashrc':
            return open(test_files['bash_bashrc_fail']).read()
        return ""

    auditor.file_exists = file_exists_weak
    auditor.read_file = read_file_weak

    auditor.check_default_umask()

    # Test PASS case
    print("\n[TEST 2] Testing with strong umask (027)...")
    def read_file_strong(path):
        if path == '/etc/bash.bashrc':
            return open(test_files['bash_bashrc_pass']).read()
        return ""

    auditor.read_file = read_file_strong

    auditor.check_default_umask()

    auditor.file_exists = original_file_exists
    auditor.read_file = original_read_file


def test_shell_timeout(auditor, test_files):
    """Test shell timeout configuration"""
    print("\n" + "=" * 80)
    print("TEST: Shell Timeout (5.4.5)")
    print("=" * 80)

    original_file_exists = auditor.file_exists
    original_read_file = auditor.read_file
    original_run_command = auditor.run_command

    # Test FAIL case - no TMOUT
    print("\n[TEST 1] Testing without TMOUT...")
    def file_exists_no_tmout(path):
        return path in ['/etc/bash.bashrc', '/etc/profile', '/etc/profile.d']

    def read_file_no_tmout(path):
        if path == '/etc/profile':
            return open(test_files['profile_fail']).read()
        return ""

    auditor.file_exists = file_exists_no_tmout
    auditor.read_file = read_file_no_tmout
    auditor.run_command = lambda cmd: (1, "", "")  # No profile.d files

    auditor.check_root_timeout()

    # Test PASS case - with TMOUT
    print("\n[TEST 2] Testing with TMOUT=900...")
    def read_file_with_tmout(path):
        if path == '/etc/profile':
            return open(test_files['profile_pass']).read()
        return ""

    auditor.read_file = read_file_with_tmout

    auditor.check_root_timeout()

    auditor.file_exists = original_file_exists
    auditor.read_file = original_read_file
    auditor.run_command = original_run_command


def print_summary(reporter):
    """Print test summary"""
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    summary = reporter.get_summary()
    print(f"\nTotal Checks: {summary['total']}")
    print(f"  ✓ PASS:    {summary['pass']}")
    print(f"  ✗ FAIL:    {summary['fail']}")
    print(f"  ⚠ WARNING: {summary['warning']}")
    print(f"  - SKIP:    {summary['skip']}")
    print(f"  ! ERROR:   {summary['error']}")

    print("\n" + "=" * 80)
    print("DETAILED RESULTS")
    print("=" * 80)

    for result in reporter.results:
        status_symbol = {
            Status.PASS: "✓",
            Status.FAIL: "✗",
            Status.WARNING: "⚠",
            Status.SKIP: "-",
            Status.ERROR: "!"
        }[result.status]

        print(f"\n{status_symbol} [{result.check_id}] {result.title}")
        print(f"   Status: {result.status.value} | Severity: {result.severity.value}")
        print(f"   Message: {result.message}")
        if result.details:
            print(f"   Details: {result.details}")
        if result.remediation:
            print(f"   Remediation: {result.remediation}")


def main():
    """Main test function"""
    print("=" * 80)
    print("PAM AND PASSWORD POLICY CHECKS TEST SUITE")
    print("Testing CIS Checks 5.3.x and 5.4.x")
    print("=" * 80)

    # Create test files
    test_dir, test_files = create_test_files()

    try:
        # Create reporter and auditor
        reporter = AuditReporter()
        auditor = PAMAuditor(reporter)

        # Run tests
        print("\n[INFO] Running password quality tests...")
        test_pwquality_config(auditor, test_files)

        print("\n[INFO] Running password history tests...")
        test_pam_pwhistory(auditor, test_files)

        print("\n[INFO] Running password hashing tests...")
        test_pam_unix_sha512(auditor, test_files)

        print("\n[INFO] Running password aging policy tests...")
        test_password_policies(auditor, test_files)

        print("\n[INFO] Running umask tests...")
        test_umask(auditor, test_files)

        print("\n[INFO] Running shell timeout tests...")
        test_shell_timeout(auditor, test_files)

        # Print summary
        print_summary(reporter)

        print("\n" + "=" * 80)
        print("✓ All tests completed successfully!")
        print("=" * 80)

    finally:
        # Cleanup
        import shutil
        shutil.rmtree(test_dir)
        print(f"\n[INFO] Cleaned up test directory: {test_dir}")


if __name__ == '__main__':
    main()
