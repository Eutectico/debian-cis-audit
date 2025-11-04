# Contributing to Debian CIS Audit

First off, thank you for considering contributing to Debian CIS Audit! It's people like you that make this tool better for everyone.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (command line used, configuration files, etc.)
- **Describe the behavior you observed** and what behavior you expected
- **Include logs and error messages**
- **Specify your environment**:
  - OS version (e.g., Debian 12.1)
  - Python version
  - How you're running the script (sudo, user, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the suggested enhancement
- **Explain why this enhancement would be useful**
- **List any alternative solutions** you've considered

### Adding New CIS Checks

We welcome contributions that add more CIS Benchmark checks! Here's how:

1. **Identify the check** from the CIS Benchmark document
2. **Create a new method** in the appropriate Auditor class (or create a new Auditor)
3. **Follow the existing pattern**:
   ```python
   def check_something(self):
       """Check description from CIS Benchmark"""
       # Your check logic here

       if condition_failed:
           self.reporter.add_result(AuditResult(
               check_id="X.Y.Z",  # CIS Benchmark section number
               title="CIS Benchmark title",
               status=Status.FAIL,
               severity=Severity.HIGH,
               message="Clear message about what failed",
               details="Additional details if needed",
               remediation="How to fix this issue"
           ))
       else:
           self.reporter.add_result(AuditResult(
               check_id="X.Y.Z",
               title="CIS Benchmark title",
               status=Status.PASS,
               severity=Severity.HIGH,
               message="Check passed"
           ))
   ```
4. **Add the check** to the `run_all_checks()` method
5. **Test your check** thoroughly
6. **Document the check** in the README

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Test your changes** thoroughly
4. **Update documentation** if needed
5. **Write a clear commit message** explaining your changes
6. **Submit a pull request**

## Development Setup

### Prerequisites

- Python 3.6 or higher
- Debian-based Linux system (for testing)
- Root access (for testing system-level checks)

### Setting Up Your Development Environment

```bash
# Clone your fork (replace YOUR-USERNAME with your GitHub username)
git clone https://github.com/YOUR-USERNAME/debian-cis-audit.git
cd debian-cis-audit

# Create a virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install development dependencies (if any)
pip install -r requirements-dev.txt  # If we add any

# Make the script executable
chmod +x debian_cis_audit.py
```

### Running Tests

```bash
# Test the auditd configuration check
python3 test_auditd_check.py

# Run the full audit (requires root)
sudo python3 debian_cis_audit.py

# Test JSON output
sudo python3 debian_cis_audit.py --format json --output test_report.json
```

## Coding Standards

### Python Style Guide

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters (flexible for readability)
- Use meaningful variable and function names
- Add docstrings to all classes and methods

### Code Organization

- Keep related checks in the same Auditor class
- Each check should be a separate method
- Use the `BaseAuditor` helper methods (`run_command`, `read_file`, etc.)
- Keep methods focused and single-purpose

### Documentation

- Add docstrings to new classes and methods
- Update README.md with new features
- Include CIS Benchmark check IDs in comments
- Explain complex logic with inline comments

### Error Handling

- Use try-except blocks for operations that might fail
- Return appropriate status codes (PASS, FAIL, WARNING, ERROR, SKIP)
- Provide clear error messages
- Never crash the entire audit due to one failed check

## Commit Message Guidelines

Write clear, concise commit messages:

```
Add check for SSH protocol version (CIS 5.2.4)

- Implement check_ssh_protocol() method
- Add to SSHAuditor class
- Include remediation instructions
- Update README with new check
```

### Commit Message Format

- **First line**: Brief summary (50 characters or less)
- **Body**: Detailed explanation (if needed)
- **Footer**: Issue references (e.g., "Fixes #123")

## Testing Checklist

Before submitting a pull request, ensure:

- [ ] Code runs without errors
- [ ] All existing checks still work
- [ ] New checks follow the existing pattern
- [ ] CIS check IDs are correct
- [ ] Severity levels are appropriate
- [ ] Remediation instructions are clear
- [ ] Code is documented
- [ ] README is updated (if needed)
- [ ] No sensitive information in code or commits

## CIS Benchmark Usage

### Important Notes

- **DO NOT** include CIS Benchmark PDFs in the repository
- **DO NOT** copy large sections of CIS text
- **DO** reference CIS check numbers (e.g., "CIS 6.2.1.1")
- **DO** use your own words for descriptions
- **DO** provide clear remediation steps

### Getting the CIS Benchmark

Users should obtain the official CIS Benchmark from:
https://www.cisecurity.org/cis-benchmarks/

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Debian CIS Audit! 🎉
