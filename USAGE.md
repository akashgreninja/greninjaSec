# InfraGuardian CLI Quick Reference

## Installation

```bash
# Build the binary
go build -o infraguardian

# Make it executable (optional)
chmod +x infraguardian

# Move to PATH (optional)
sudo mv infraguardian /usr/local/bin/
```

## Usage Examples

### Show Help
```bash
infraguardian --help
```

### Scan Everything (Default)
```bash
# Scans both manifests and secrets
infraguardian --all --path /path/to/repo

# Short form
infraguardian -a -p /path/to/repo

# Current directory (default)
infraguardian --all
```

### Scan Only Kubernetes Manifests
```bash
infraguardian --manifest --path ./k8s
infraguardian -m -p ./k8s
```

### Scan Only for Secrets
```bash
infraguardian --secrets --path .
infraguardian -s -p .
```

### Output as JSON (for CI/CD)
```bash
infraguardian --all --format json
infraguardian -a -f json

# Pipe to jq for filtering
infraguardian --all -f json | jq '.[] | select(.severity == "CRITICAL")'
```

## Available Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--all` | `-a` | - | Run all scanners (manifests + secrets) |
| `--manifest` | `-m` | - | Scan Kubernetes manifests only |
| `--secrets` | `-s` | - | Scan for hardcoded secrets only |
| `--path` | `-p` | `.` | Path to scan |
| `--format` | `-f` | `pretty` | Output format: `pretty` or `json` |
| `--help` | `-h` | - | Show help |

## What Gets Scanned

### Manifest Analysis (`--manifest`)
- ✅ Kubernetes YAML files
- ✅ Missing `runAsNonRoot` settings
- ✅ 15+ Kubesec security checks:
  - Missing resource limits
  - Missing security contexts
  - Service account misconfigurations
  - Privilege escalation risks
  - And more...

### Secret Detection (`--secrets`)
- ✅ AWS Access Keys & Secret Keys
- ✅ GitHub Personal Access Tokens
- ✅ Google API Keys
- ✅ Slack Tokens & Webhooks
- ✅ Private SSH/RSA Keys
- ✅ Generic passwords and API keys
- ✅ High-entropy strings (possible secrets)
- ✅ Docker authentication tokens
- ✅ JWT tokens

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    ./infraguardian --all --format json > scan-results.json
    # Fail if critical issues found
    if jq -e '.[] | select(.severity == "CRITICAL")' scan-results.json; then
      exit 1
    fi
```

### GitLab CI
```yaml
security-scan:
  script:
    - ./infraguardian --all --format json | tee scan-results.json
    - '[ $(jq ".[] | select(.severity == \"CRITICAL\") | length" scan-results.json) -eq 0 ]'
```

## Severity Levels

- 🔴 **CRITICAL** - Immediate action required (exposed credentials, critical misconfigs)
- 🟠 **HIGH** - Important security issues (missing security controls)
- 🟡 **MEDIUM** - Recommended improvements (best practices)
- 🟢 **LOW** - Minor suggestions

## Exit Codes

- `0` - Success (scan completed)
- `1` - Error (invalid flags, scan failed)

Note: The tool currently does NOT exit with non-zero on findings. You can parse JSON output to implement custom exit logic.

## Examples

### Scan entire project
```bash
infraguardian --all
```

### Scan only K8s manifests in specific directory
```bash
infraguardian --manifest --path ./k8s-configs
```

### Find only critical secrets
```bash
infraguardian --secrets -f json | jq '.[] | select(.severity == "CRITICAL")'
```

### Count findings by severity
```bash
infraguardian --all -f json | jq 'group_by(.severity) | map({severity: .[0].severity, count: length})'
```

### Export results
```bash
infraguardian --all -f json > security-report.json
```

## Tips

1. **Default behavior**: If you don't specify `--manifest`, `--secrets`, or `--all`, it will scan everything
2. **Performance**: Secret scanning is fast, but Kubesec adds overhead for each YAML file
3. **False positives**: High-entropy detection may flag legitimate long strings
4. **Skip patterns**: The scanner automatically skips `vendor/`, `node_modules/`, `.git/`, and binary files

## Coming Soon

- 🔄 Terraform configuration scanning
- 🔄 Dockerfile security checks
- 🔄 Dynamic rule loading from YAML
- 🔄 Attack chain analysis
- 🔄 AI-enhanced false positive reduction
- 🔄 HTML report generation
