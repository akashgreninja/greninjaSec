# Vulnerable App Example

This directory contains intentionally vulnerable dependencies for testing CVE scanning.

## Known Vulnerabilities

### Go Dependencies (go.mod)
- `gin-gonic/gin v1.7.0` - Multiple CVEs including HTTP response splitting
- `golang.org/x/crypto` (old version) - Multiple SSH and crypto vulnerabilities
- `jwt-go v3.2.0` - JWT validation bypass vulnerability

### Node Dependencies (package.json)
- `lodash 4.17.15` - Prototype pollution vulnerabilities
- `axios 0.21.0` - SSRF vulnerability
- `express 4.17.1` - Various security issues

### Container Image (Dockerfile)
- `node:14.15.0-alpine` - 50+ CVEs in base image
- Missing security controls (running as root)

## Testing

```bash
# Scan for vulnerabilities
greninjasec --vulnerabilities --path examples/vulnerable-app

# Scan everything
greninjasec --all --path examples/vulnerable-app
```

## Remediation

See the scan output for specific CVE IDs, CVSS scores, and fixed versions.
