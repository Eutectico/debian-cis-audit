# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Send details to the project maintainers via private channels
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will:
- Acknowledge receipt within 48 hours
- Provide a detailed response within 7 days
- Work on a fix and coordinate disclosure timing with you

## Security Best Practices

When using this audit tool:

1. **Run with Root Privileges Carefully**
   - Only run as root when necessary for system checks
   - Review the code before running with elevated privileges
   - Never run untrusted versions with root access

2. **Protect Audit Reports**
   - Audit reports may contain sensitive system information
   - Store reports securely with appropriate permissions
   - Never commit reports with sensitive data to version control
   - Use `--output` flag to save reports to secure locations

3. **Configuration Files**
   - Do not commit configuration files with sensitive data
   - Remove sensitive information before sharing examples
   - Use `.gitignore` to prevent accidental commits

4. **CIS Benchmark PDFs**
   - Do not include CIS Benchmark PDFs in the repository
   - These are copyrighted materials
   - Users should obtain them directly from CIS

## Known Security Considerations

### Command Execution
This tool executes system commands (systemctl, dpkg, find, etc.) to audit the system. All commands are:
- Hardcoded in the source code
- Do not accept user input directly
- Use safe subprocess execution methods
- Have appropriate error handling

### File System Access
The tool reads system configuration files to perform audits:
- Files are read with minimal permissions needed
- No files are modified during audit
- File paths are validated before access

### Privilege Escalation
Some checks require root privileges to access protected files. The tool:
- Does not attempt privilege escalation on its own
- Warns users when not running as root
- Gracefully handles permission errors
- Only reads files, never modifies them

## Dependencies

This tool uses only Python standard library modules to minimize security risks:
- No external dependencies
- No network access (except for monitoring integrations)
- No dynamic code execution
- No user input parsing vulnerabilities

## Security Updates

Security updates will be released as soon as possible after vulnerabilities are confirmed. Users should:
- Watch the repository for security advisories
- Update to the latest version regularly
- Review the CHANGELOG for security-related updates

## Code Review

Security-focused code reviews are welcome! Please:
- Review the source code for potential vulnerabilities
- Report findings through the vulnerability reporting process
- Suggest improvements via pull requests (for non-critical issues)

## Security Tools

This project uses:
- GitHub Security Advisories
- Dependabot (if dependencies are added)
- Bandit (Python security linter) in CI/CD

## Disclaimer

This tool is provided "as is" without warranty. Users are responsible for:
- Reviewing the code before use
- Understanding the implications of audit checks
- Securing audit reports appropriately
- Complying with their organization's security policies

---

Thank you for helping keep this project secure!
