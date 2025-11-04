---
name: New CIS Check
about: Propose adding a new CIS Benchmark check
title: '[CIS CHECK] Add check X.Y.Z - '
labels: enhancement, cis-check
assignees: ''
---

## CIS Benchmark Information

- **Check ID**: [e.g., 5.3.1]
- **Check Title**: [Full title from CIS Benchmark]
- **Benchmark Version**: [e.g., CIS Debian Linux 12 v1.1.0]
- **Profile Level**: [e.g., Level 1 Server, Level 2 Workstation]
- **Automated/Manual**: [e.g., Automated]

## Check Description

Describe what this check verifies (in your own words, not copied from CIS).

## Why This Check Is Important

Explain the security or operational importance of this check.

## Implementation Approach

How should this check be implemented?

### Audit Command(s)

What commands or file checks are needed?

```bash
# Example audit commands
cat /etc/some/config
systemctl status service-name
```

### Expected Result

What indicates PASS vs FAIL?

### Remediation

How to fix if the check fails?

```bash
# Example remediation commands
```

## Complexity

- [ ] Simple (file permission check)
- [ ] Medium (configuration parsing)
- [ ] Complex (multiple checks, complex logic)

## Testing

How can this check be tested?

## Additional Notes

Any other relevant information.

## Would you like to implement this?

- [ ] Yes, I can submit a pull request
- [ ] No, but I can help with testing
- [ ] No, just suggesting
