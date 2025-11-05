# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Debian CIS Benchmark Audit Script** - A Python security auditing tool that checks Debian 12 systems against CIS Benchmark v1.1.0 requirements, with special focus on detecting misconfigurations that cause availability issues.

**Key Differentiator:** Unlike typical CIS audit tools that only check security, this tool actively detects dangerous configurations (e.g., auditd settings that fill partitions and crash systems).

## Architecture

The codebase follows a modular, class-based architecture:

```
BaseAuditor (base class with helper methods)
    ├── AuditdAuditor - Auditd configuration checks (6.2.x)
    ├── FileSystemAuditor - File permissions and security (7.1.x)
    ├── ServiceAuditor - System service checks (2.2.x)
    ├── NetworkAuditor - Network configuration (3.x)
    ├── SSHAuditor - SSH server configuration (5.1.x - 22 checks)
    └── UserAuditor - User/group checks (7.2.x)

AuditReporter - Handles result collection and report generation
    ├── Console format (color-coded, human-readable)
    └── JSON format (machine-parseable)

DebianCISAudit - Main orchestrator that runs all auditors
```

### Core Classes

- **AuditResult**: Dataclass representing a single check result with check_id, status, severity, message, details, and remediation
- **Status**: Enum (PASS, FAIL, WARNING, SKIP, ERROR)
- **Severity**: Enum (CRITICAL, HIGH, MEDIUM, LOW, INFO)

### Helper Methods (BaseAuditor)

- `run_command(cmd)`: Execute shell commands with timeout
- `file_exists(path)`: Check file existence
- `read_file(path)`: Read file contents safely
- `get_file_stat(path)`: Get file statistics

## Development Commands

### Running the Audit

```bash
# Full audit (requires root)
sudo python3 debian_cis_audit.py

# JSON output
sudo python3 debian_cis_audit.py --format json --output report.json

# Console output to file
sudo python3 debian_cis_audit.py --output report.txt
```

### Testing

```bash
# Test auditd configuration check on local file
python3 test_auditd_check.py

# Run with pip install (creates console commands)
pip install -e .
debian-cis-audit  # Main audit script
debian-cis-monitor  # Monitoring integration examples
```

### Development Tools

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Code quality
black debian_cis_audit.py
flake8 debian_cis_audit.py
pylint debian_cis_audit.py
mypy debian_cis_audit.py

# Testing
pytest
pytest --cov
```

## Adding New CIS Checks

Follow this pattern when implementing new checks:

1. **Identify the appropriate Auditor class** (or create a new one if needed)
2. **Add a check method** following this template:

```python
def check_something(self):
    """Check description from CIS Benchmark"""
    # Perform check logic

    if condition_failed:
        self.reporter.add_result(AuditResult(
            check_id="X.Y.Z",  # CIS section number
            title="Descriptive title from CIS",
            status=Status.FAIL,
            severity=Severity.HIGH,
            message="Clear failure message",
            details="Additional context (optional)",
            remediation="Specific commands to fix"
        ))
    else:
        self.reporter.add_result(AuditResult(
            check_id="X.Y.Z",
            title="Descriptive title from CIS",
            status=Status.PASS,
            severity=Severity.HIGH,
            message="Check passed"
        ))
```

3. **Add the method to `run_all_checks()`** in the Auditor class
4. **Register the auditor** in `DebianCISAudit.run_audit()` if it's a new class
5. **Test thoroughly** with both passing and failing scenarios

## Critical Implementation Details

### Auditd Configuration Checks

The auditd checks in `AuditdAuditor.check_auditd_config()` are particularly important as they detect availability-threatening misconfigurations:

- `max_log_file_action = keep_logs` → Fills partition, crashes system
- `disk_full_action = halt` → Stops system when disk full
- `admin_space_left_action = halt` → Premature system shutdown

These checks parse `/etc/audit/auditd.conf` line-by-line and validate critical parameters.

### File Permission Checks

File permission checks use octal mode comparisons. Key pattern:

```python
mode = stat.S_IMODE(stat_info.st_mode)
if mode & 0o077:  # Check if group/other have permissions
    # Fail - too permissive
```

### Service Checks

Service checks use systemctl to verify services are disabled:

```python
returncode, stdout, _ = self.run_command(['systemctl', 'is-enabled', service_name])
if stdout.strip() in ['disabled', 'masked'] or returncode != 0:
    # Pass - service not enabled
```

## Status Tracking

**Current Implementation:** 36 checks (~9% of CIS Benchmark)
- Phase 1 (Foundation): 14 checks ✅
- Phase 2 (SSH Configuration): 22 checks ✅
**Next Priority:** Filesystem partition checks (1.1.2.x - 35 checks)

See ROADMAP.md for the full implementation plan covering 400+ checks.

## Important Constraints

1. **No external dependencies**: Uses only Python standard library
2. **Python 3.6+ compatible**: Maintain backward compatibility
3. **Sudo required**: Most checks need root access for system files
4. **CIS Copyright**: Never include CIS PDFs or large text excerpts
5. **Error isolation**: Individual check failures must not crash entire audit
6. **Documentation language**: README and user-facing messages are in German; code comments and internal documentation use English

## File Structure

All code is contained in a single-directory flat structure:

- `debian_cis_audit.py`: Main audit script (~1726 lines) - contains all auditor classes and main entry point
- `test_auditd_check.py`: Standalone demonstration tool for testing auditd.conf files locally
- `monitoring_integration_example.py`: Example integrations for Prometheus, Nagios, and Zabbix monitoring
- `setup.py`: Package configuration for pip installation with console script entry points
- `auditd.conf`: Intentionally misconfigured example file demonstrating dangerous settings
- `auditd.conf.recommended`: Corrected configuration showing safe settings
- `ROADMAP.md`: Detailed implementation plan for 400+ CIS checks (currently at ~3%)

## Testing Approach

The project uses example-based testing rather than traditional unit tests:

1. `test_auditd_check.py` is a standalone demonstration tool that checks local auditd.conf files with detailed output
2. The main script is designed to be run against live Debian systems for real-world validation
3. CI/CD (via GitHub Actions) validates code quality (linting, type checking) but not functional correctness
4. When implementing new checks, test manually on real systems or VMs with both passing and failing configurations

## Code Style Preferences

- PEP 8 compliant
- Max line length: 100 characters (flexible for readability)
- Docstrings on all classes and public methods
- Type hints for function parameters (dataclasses use them)
- Error handling: catch exceptions, return ERROR status, never crash
- Clear variable names (no single letters except loop counters)

## Git Workflow

Repository is at: https://github.com/Eutectico/debian-cis-audit

Main branch: `main`

When committing:
- Use clear, descriptive messages
- Reference CIS check IDs in commits for new checks
- Update README when adding significant features
- Never commit CIS Benchmark PDFs
