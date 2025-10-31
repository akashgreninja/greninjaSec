# GreninjaSec CLI Quick Reference

## Installation

```bash
# One-line installer (Linux/macOS)
curl -sSL https://raw.githubusercontent.com/akashgreninja/greninjaSec/main/install.sh | bash

# Manual installation
# Download pre-built binary from GitHub releases or build from source
go build -o greninjasec

# Make it executable (optional)
chmod +x greninjasec

# Move to PATH (optional)
sudo mv greninjasec /usr/local/bin/
```

## Usage Examples

### Show Help
```bash
greninjasec --help
```

### Scan Everything (Default)
```bash
# Scans manifests, secrets, dockerfiles, terraform, and CVEs
greninjasec --all --path /path/to/repo

# Short form
greninjasec -a -p /path/to/repo

# Current directory (default)
greninjasec --all
```

### Scan Only Kubernetes Manifests
```bash
greninjasec --manifest --path ./k8s
greninjasec -m -p ./k8s
```

### Scan Only for Secrets
```bash
greninjasec --secrets --path .
greninjasec -s -p .
```

### 🆕 Deep Git History Secret Scanning
```bash
# Scans ALL commits for leaked secrets
greninjasec --deep-scan --path .

# Combined with regular secret scanning
greninjasec --secrets --deep-scan --path .
```

### 🆕 Memory/Resource Leak Detection (Go Projects)
```bash
# Detect unclosed files, HTTP responses, timers, contexts, etc.
greninjasec --leaks --path .

# Test on sample file
greninjasec --leaks --path examples/sample_leaks.go
```

### 🆕 AI-Powered Smart Remediation
```bash
# Generate AI fix suggestions for CRITICAL/HIGH findings
greninjasec --all --ai-remediation --path .

# Requires .env file with:
# AI_ENABLED=true
# OPENWEBUI_URL=https://your-openwebui-instance.com/api
# OPENWEBUI_TOKEN=your-api-token
# AI_MODEL=gpt-4
```

### Attack Chain Analysis
```bash
# Correlate findings into exploit paths
greninjasec --all --attack-chains --path .

# Verbose output with all details
greninjasec --all --attack-chains --verbose --path .
```

### Output as JSON (for CI/CD)
```bash
greninjasec --all --format json
greninjasec -a -f json

# Pipe to jq for filtering
greninjasec --all -f json | jq '.[] | select(.severity == "CRITICAL")'
```

### Generate HTML Report
```bash
# Create interactive HTML report with charts
greninjasec --all --attack-chains --html security-report.html --path .

# With AI remediation included
greninjasec --all --ai-remediation --html report.html --path .
```

## Available Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--all` | `-a` | - | Run all scanners (manifests + secrets + dockerfile + terraform + CVEs) |
| `--manifest` | `-m` | - | Scan Kubernetes manifests only |
| `--secrets` | `-s` | - | Scan for hardcoded secrets only |
| `--dockerfile` | - | - | Scan Dockerfiles with Hadolint |
| `--terraform` | - | - | Scan Terraform files with Tfsec |
| `--vulnerabilities` | - | - | Scan for CVEs with Trivy |
| `--deep-scan` | - | - | 🆕 Scan entire Git history for leaked secrets |
| `--leaks` | - | - | 🆕 Detect memory/resource leaks (Go projects) |
| `--ai-remediation` | - | - | 🆕 Generate AI-powered fix suggestions |
| `--attack-chains` | - | - | Analyze attack chain possibilities |
| `--path` | `-p` | `.` | Path to scan |
| `--format` | `-f` | `pretty` | Output format: `pretty` or `json` |
| `--html` | - | - | Generate HTML report (e.g., `--html report.html`) |
| `--verbose` | - | - | Show all findings (not just top 3 per severity) |
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

### 🆕 Deep Git History Scanning (`--deep-scan`)
- ✅ Scans ALL commits (not just current files)
- ✅ Tracks commit hash, author, and timestamp
- ✅ Calculates days exposed
- ✅ Detects if secret still exists in current repo
- ✅ Generates Git cleanup commands (git-filter-branch + BFG)
- ✅ Masks secrets in output (shows first/last 4 chars)

### 🆕 Memory/Resource Leak Detection (`--leaks`)
**AST-based analysis for Go projects:**
- ✅ Unclosed files (`os.Open` without `defer file.Close()`)
- ✅ Unclosed HTTP responses (`http.Get` without `defer resp.Body.Close()`)
- ✅ Unclosed database connections
- ✅ File watchers never closed (`fsnotify.NewWatcher`)
- ✅ Timers never stopped (`time.NewTicker/NewTimer`)
- ✅ Contexts never cancelled (`context.WithTimeout`)
- ✅ Event listeners never removed
- ✅ Message queue subscriptions never unsubscribed
- ✅ Goroutines without cancellation mechanism
- ✅ Unbounded slice growth in loops
- ✅ CPU issues (infinite loops, regex compiled in loops)
- ✅ Custom fix suggestions per resource type

### 🆕 AI-Powered Remediation (`--ai-remediation`)
**Smart fix suggestions via OpenWebUI/GPT-4:**
- ✅ Detailed explanations of vulnerabilities
- ✅ Risk analysis and impact assessment
- ✅ Code patches with line-by-line changes
- ✅ Shell commands for quick fixes
- ✅ Manual remediation steps
- ✅ Testing and verification steps
- ✅ Confidence scoring (0-100%)
- ✅ Alternative fix suggestions
- ✅ Reference links to documentation
- ✅ Response caching (avoids redundant API calls)

### Dockerfile Scanning (`--dockerfile`)
- ✅ 50+ Hadolint checks
- ✅ Best practices violations
- ✅ Security misconfigurations

### Terraform Scanning (`--terraform`)
- ✅ 100+ Tfsec checks
- ✅ Cloud misconfigurations
- ✅ Security risks

### CVE/Vulnerability Scanning (`--vulnerabilities`)
- ✅ Trivy integration
- ✅ CVSS scoring
- ✅ Dependency vulnerabilities
- ✅ Container image vulnerabilities

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    ./greninjasec --all --format json > scan-results.json
    # Fail if critical issues found
    if jq -e '.[] | select(.severity == "CRITICAL")' scan-results.json; then
      exit 1
    fi

# With AI remediation
- name: Security Scan with AI
  env:
    OPENWEBUI_URL: ${{ secrets.OPENWEBUI_URL }}
    OPENWEBUI_TOKEN: ${{ secrets.OPENWEBUI_TOKEN }}
    AI_MODEL: gpt-4
    AI_ENABLED: true
  run: |
    ./greninjasec --all --ai-remediation --html report.html --path .
    # Upload report as artifact
```

### GitLab CI
```yaml
security-scan:
  script:
    - ./greninjasec --all --format json | tee scan-results.json
    - '[ $(jq ".[] | select(.severity == \"CRITICAL\") | length" scan-results.json) -eq 0 ]'

# With leak detection
leak-scan:
  script:
    - ./greninjasec --leaks --format json | tee leak-results.json
```

### Pre-commit Hooks
```bash
# Install the hook (blocks CRITICAL findings)
greninjasec install-hooks

# Install with warnings only (don't block)
greninjasec install-hooks --allow-critical

# Uninstall the hook
greninjasec uninstall-hooks
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

### Scan entire project with all features
```bash
greninjasec --all --attack-chains --ai-remediation --html report.html
```

### Scan only K8s manifests in specific directory
```bash
greninjasec --manifest --path ./k8s-configs
```

### Find only critical secrets
```bash
greninjasec --secrets -f json | jq '.[] | select(.severity == "CRITICAL")'
```

### Deep scan Git history for leaked credentials
```bash
greninjasec --deep-scan --path . --verbose
```

### Detect memory leaks in Go codebase
```bash
greninjasec --leaks --path ./internal
```

### Count findings by severity
```bash
greninjasec --all -f json | jq 'group_by(.severity) | map({severity: .[0].severity, count: length})'
```

### Export results
```bash
greninjasec --all -f json > security-report.json
```

### Combined security audit
```bash
# Run all scanners + AI + attack chains + leak detection
greninjasec --all --deep-scan --leaks --ai-remediation --attack-chains --html full-audit.html --path .
```

## Tips

1. **Default behavior**: If you don't specify any scanner flags, use `--all` to run everything
2. **Performance**: 
   - Secret scanning is very fast
   - Deep Git history scanning can be slow on large repos (scans ALL commits)
   - Leak detection uses AST parsing (accurate but slower than regex)
   - AI remediation adds latency (30s default timeout per request)
3. **False positives**: 
   - High-entropy detection may flag legitimate long strings
   - Use `--verbose` to see all findings and assess false positives
4. **Skip patterns**: The scanner automatically skips `vendor/`, `node_modules/`, `.git/`, and binary files
5. **AI Configuration**: Create `.env` file in project root:
   ```
   AI_ENABLED=true
   OPENWEBUI_URL=https://your-instance.com/api
   OPENWEBUI_TOKEN=your-token
   AI_MODEL=gpt-4
   AI_CACHE_ENABLED=true
   ```
6. **Git History Cleanup**: Use generated commands from `--deep-scan` output:
   ```bash
   # BFG Repo-Cleaner (recommended - faster)
   java -jar bfg.jar --delete-files secret.key .git
   
   # Or git filter-branch (slower)
   git filter-branch --force --index-filter \
     'git rm --cached --ignore-unmatch path/to/secret' \
     --prune-empty --tag-name-filter cat -- --all
   ```

## Coming Soon

- 🔄 **Secret Validation** — Check if leaked AWS keys/GitHub tokens are still active
- 🔄 **TUI Dashboard** — Interactive terminal UI with Bubble Tea
- 🔄 **Dynamic Rule Loading** — Load custom rules from YAML
- 🔄 **Helm Chart Support** — Security scanning for Helm charts
- 🔄 **GitHub Action** — Automated PR scanning with inline comments
- 🔄 **Security Score Tracking** — Trend analysis across commits
- 🔄 **SBOM Generation** — Software Bill of Materials (CycloneDX/SPDX)
- 🔄 **Policy Enforcement** — Custom security policies with pass/fail gates
