#!/usr/bin/env python3
"""
Example: Integration of CIS Audit Script into Monitoring Systems

This script demonstrates how to integrate the CIS audit into monitoring
systems like Prometheus, Nagios, Zabbix, etc.
"""

import sys
import json
from debian_cis_audit import DebianCISAudit, Status, Severity


def generate_prometheus_metrics():
    """Generate Prometheus-compatible metrics"""
    audit = DebianCISAudit()
    audit.run_audit()

    summary = audit.reporter.get_summary()

    # Generate Prometheus metrics
    metrics = []
    metrics.append("# HELP cis_audit_checks_total Total number of CIS audit checks")
    metrics.append("# TYPE cis_audit_checks_total gauge")
    metrics.append(f"cis_audit_checks_total {summary['total']}")

    metrics.append("# HELP cis_audit_checks_passed Number of passed checks")
    metrics.append("# TYPE cis_audit_checks_passed gauge")
    metrics.append(f"cis_audit_checks_passed {summary['pass']}")

    metrics.append("# HELP cis_audit_checks_failed Number of failed checks")
    metrics.append("# TYPE cis_audit_checks_failed gauge")
    metrics.append(f"cis_audit_checks_failed {summary['fail']}")

    metrics.append("# HELP cis_audit_checks_warning Number of warnings")
    metrics.append("# TYPE cis_audit_checks_warning gauge")
    metrics.append(f"cis_audit_checks_warning {summary['warning']}")

    # Count by severity
    severity_counts = {sev: 0 for sev in Severity}
    for result in audit.reporter.results:
        if result.status == Status.FAIL:
            severity_counts[result.severity] += 1

    metrics.append("# HELP cis_audit_critical_failures Critical severity failures")
    metrics.append("# TYPE cis_audit_critical_failures gauge")
    metrics.append(f"cis_audit_critical_failures {severity_counts[Severity.CRITICAL]}")

    metrics.append("# HELP cis_audit_high_failures High severity failures")
    metrics.append("# TYPE cis_audit_high_failures gauge")
    metrics.append(f"cis_audit_high_failures {severity_counts[Severity.HIGH]}")

    return "\n".join(metrics)


def generate_nagios_status():
    """Generate Nagios/Icinga compatible exit status and message"""
    audit = DebianCISAudit()
    audit.run_audit()

    summary = audit.reporter.get_summary()

    # Count critical and high severity failures
    critical_count = 0
    high_count = 0

    for result in audit.reporter.results:
        if result.status == Status.FAIL:
            if result.severity == Severity.CRITICAL:
                critical_count += 1
            elif result.severity == Severity.HIGH:
                high_count += 1

    # Nagios exit codes: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN
    if critical_count > 0:
        exit_code = 2  # CRITICAL
        status = "CRITICAL"
        message = f"CIS Audit: {critical_count} CRITICAL failures, {high_count} HIGH failures"
    elif high_count > 0:
        exit_code = 1  # WARNING
        status = "WARNING"
        message = f"CIS Audit: {high_count} HIGH failures, {summary['fail']} total failures"
    elif summary['fail'] > 0:
        exit_code = 1  # WARNING
        status = "WARNING"
        message = f"CIS Audit: {summary['fail']} failures"
    else:
        exit_code = 0  # OK
        status = "OK"
        message = f"CIS Audit: All {summary['total']} checks passed"

    # Add performance data
    perfdata = (
        f"total={summary['total']} "
        f"passed={summary['pass']} "
        f"failed={summary['fail']} "
        f"critical={critical_count} "
        f"high={high_count}"
    )

    print(f"{status}: {message} | {perfdata}")
    return exit_code


def generate_zabbix_json():
    """Generate Zabbix Low-Level Discovery JSON"""
    audit = DebianCISAudit()
    audit.run_audit()

    # Zabbix discovery format
    discovery = {"data": []}

    for result in audit.reporter.results:
        discovery["data"].append({
            "{#CHECK_ID}": result.check_id,
            "{#CHECK_TITLE}": result.title,
            "{#SEVERITY}": result.severity.value
        })

    # Item values
    items = {}
    for result in audit.reporter.results:
        items[f"cis.check.status[{result.check_id}]"] = result.status.value
        items[f"cis.check.severity[{result.check_id}]"] = result.severity.value
        items[f"cis.check.message[{result.check_id}]"] = result.message

    return {
        "discovery": discovery,
        "items": items
    }


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='CIS Audit Monitoring Integration')
    parser.add_argument(
        '--format',
        choices=['prometheus', 'nagios', 'zabbix'],
        required=True,
        help='Output format'
    )

    args = parser.parse_args()

    if args.format == 'prometheus':
        print(generate_prometheus_metrics())
        return 0

    elif args.format == 'nagios':
        return generate_nagios_status()

    elif args.format == 'zabbix':
        result = generate_zabbix_json()
        print(json.dumps(result, indent=2))
        return 0


if __name__ == '__main__':
    sys.exit(main())
