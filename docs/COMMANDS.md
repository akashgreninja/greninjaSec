# 🥷 GreninjaSec Command Reference

Complete guide to all GreninjaSec commands, flags, and features including AI-powered remediation.

## 📚 Table of Contents

1. [Installation](#installation)
2. [Basic Commands](#basic-commands)
3. [Scanner Types](#scanner-types)
4. [AI Features](#ai-features)
5. [Output Formats](#output-formats)
6. [Attack Chain Analysis](#attack-chain-analysis)
7. [Git Hooks](#git-hooks)
8. [CI/CD Integration](#cicd-integration)
9. [Examples](#examples)

---

## 🚀 Installation

### Quick Install (Recommended)
```bash
curl -sSL https://raw.githubusercontent.com/akashgreninja/greninjaSec/main/install.sh | bash
```

### Manual Download
```bash
# Linux (x64)
curl -L https://github.com/akashgreninja/greninjaSec/releases/latest/download/greninjasec-linux-amd64 -o greninjasec

# macOS (M1/M2)
curl -L https://github.com/akashgreninja/greninjaSec/releases/latest/download/greninjasec-darwin-arm64 -o greninjasec

# macOS (Intel)
curl -L https://github.com/akashgreninja/greninjaSec/releases/latest/download/greninjasec-darwin-amd64 -o greninjasec

chmod +x greninjasec && sudo mv greninjasec /usr/local/bin/
```

---

## 🔧 Basic Commands

### Help & Version
```bash
# Show help
greninjasec --help
greninjasec -h

# Show version
greninjasec version

# Help for specific command
greninjasec install-hooks --help
```

### Quick Scans
```bash
# Scan everything (recommended)
greninjasec --all

# Scan current directory with attack chains
greninjasec --all --attack-chains

# Scan specific path
greninjasec --all --path /path/to/project

# Verbose output (show all findings)
greninjasec --all --verbose
```

---

## 🔍 Scanner Types

### Individual Scanners

#### Kubernetes Manifests
```bash
# Scan YAML manifests only
greninjasec --manifest
greninjasec -m

# With specific path
greninjasec --manifest --path ./k8s-configs
```
**Detects:** 15+ security misconfigurations via Kubesec

#### Secrets Detection
```bash
# Scan for hardcoded secrets
greninjasec --secrets
greninjasec -s

# Secrets in specific files
greninjasec --secrets --path config.txt
```
**Detects:** AWS keys, GitHub tokens, API keys, private keys, high-entropy strings

#### Dockerfile Security
```bash
# Scan Dockerfiles
greninjasec --dockerfile
greninjasec -d

# Scan specific Dockerfile
greninjasec --dockerfile --path ./Dockerfile
```
**Detects:** 50+ security issues via Hadolint

#### Terraform Security
```bash
# Scan Terraform files
greninjasec --terraform
greninjasec -t

# Scan Terraform directory
greninjasec --terraform --path ./infrastructure
```
**Detects:** 100+ security issues via Tfsec

#### CVE Vulnerabilities
```bash
# Scan for CVE vulnerabilities
greninjasec --vulnerabilities

# Include CVSS scores
greninjasec --vulnerabilities --path .
```
**Detects:** CVE vulnerabilities with CVSS scores via Trivy

### Combined Scanners
```bash
# All scanners (recommended)
greninjasec --all
greninjasec -a

# Custom combination
greninjasec --manifest --secrets --dockerfile --path ./app

# Everything with attack chains
greninjasec --all --attack-chains --path .
```

---

## 🤖 AI Features

> **Prerequisites:** Create `.env` file with F5 AI credentials:
> ```bash
> OPENWEBUI_URL=https://your-openwebui-instance.com/api
> OPENWEBUI_TOKEN=your-token-here
> ```

### AI-Enhanced Analysis
```bash
# AI-enhanced attack chain discovery
greninjasec --all --attack-chains --ai-enhance

# Basic scan + AI enhancement
greninjasec --secrets --ai-enhance
```
**Features:** AI discovers additional attack chains beyond predefined templates

### AI-Powered Remediation ⭐ **NEW**
```bash
# Get AI remediation suggestions
greninjasec --all --ai-remediation

# AI remediation for specific scan
greninjasec --secrets --ai-remediation

# AI remediation with HTML report
greninjasec --all --ai-remediation --html ai-report.html

# Comprehensive AI analysis
greninjasec --all --attack-chains --ai-remediation --verbose
```

**AI Remediation Provides:**
- 🎯 **Confidence Scores** (50-100%)
- 🔧 **Code Patches** (diff format)
- 💻 **CLI Commands** (step-by-step)
- ✋ **Manual Steps** (human instructions)
- 🔄 **Alternative Solutions**
- 🧪 **Testing Procedures**
- 📚 **Reference Links**

---

## 📊 Output Formats

### Pretty Output (Default)
```bash
# Human-readable format
greninjasec --all

# Verbose mode (all findings)
greninjasec --all --verbose
greninjasec --all -v
```

### JSON Output
```bash
# Machine-readable JSON
greninjasec --all --format json
greninjasec --all -f json

# Pipe to jq for filtering
greninjasec --all -f json | jq '.findings[] | select(.severity == "CRITICAL")'
```

### HTML Reports ⭐ **NEW**
```bash
# Generate HTML report
greninjasec --all --html report.html

# HTML with attack chains
greninjasec --all --attack-chains --html security-report.html

# AI-powered HTML report
greninjasec --all --ai-remediation --html ai-report.html

# Comprehensive HTML report
greninjasec --all --attack-chains --ai-remediation --html comprehensive-report.html
```

**HTML Features:**
- 📊 Interactive tabs and charts
- 🎯 Attack chain visualization  
- 🤖 AI remediation sections
- 📱 Responsive design
- 🎨 Beautiful UI with confidence scores

---

## ⚡ Attack Chain Analysis

### Basic Attack Chains
```bash
# Analyze attack chains
greninjasec --all --attack-chains
greninjasec --all -c

# Attack chains with specific scanners
greninjasec --secrets --terraform --attack-chains
```

### AI-Enhanced Attack Chains
```bash
# AI discovers additional chains
greninjasec --all --attack-chains --ai-enhance

# Full AI analysis with remediation
greninjasec --all --attack-chains --ai-enhance --ai-remediation
```

**Attack Chain Templates:**
1. 💀 AWS Credential Exposure → S3 Data Exfiltration
2. 💀 Container Escape → Kubernetes Cluster Takeover  
3. 💀 Hardcoded Secrets → Multi-Service Compromise
4. 💀 Public Database Exposure → Direct Data Breach
5. 💀 IAM Over-Privileges → AWS Account Takeover
6. And more with AI enhancement...

---

## 🔗 Git Hooks

### Install Pre-commit Hook
```bash
# Install hook (blocks CRITICAL findings)
greninjasec install-hooks

# Install with warnings only
greninjasec install-hooks --allow-critical

# Custom path
greninjasec install-hooks --path /path/to/repo
```

### Manage Hooks
```bash
# Remove hook
greninjasec uninstall-hooks

# Bypass hook for single commit
git commit --no-verify -m "bypass security scan"
```

**Hook Behavior:**
- 🔴 **CRITICAL**: Blocks commit (unless `--allow-critical`)
- 🟠 **HIGH**: Warning only
- 🟡 **MEDIUM/LOW**: Info only

---

## 🚀 CI/CD Integration

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install GreninjaSec
        run: curl -sSL https://raw.githubusercontent.com/akashgreninja/greninjaSec/main/install.sh | bash
      - name: Security Scan
        run: |
          greninjasec --all --format json > scan-results.json
          # Fail on critical issues
          if jq -e '.findings[] | select(.severity == "CRITICAL")' scan-results.json; then
            exit 1
          fi
      - name: Generate HTML Report
        run: greninjasec --all --attack-chains --html security-report.html
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.html
```

### GitLab CI
```yaml
security-scan:
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq
    - curl -sSL https://raw.githubusercontent.com/akashgreninja/greninjaSec/main/install.sh | sh
  script:
    - greninjasec --all --format json | tee scan-results.json
    - '[ $(jq "[.findings[] | select(.severity == \"CRITICAL\")] | length" scan-results.json) -eq 0 ]'
  artifacts:
    reports:
      junit: scan-results.json
    paths:
      - scan-results.json
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'curl -sSL https://raw.githubusercontent.com/akashgreninja/greninjaSec/main/install.sh | bash'
                sh 'greninjasec --all --format json > scan-results.json'
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security-report.html',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}
```

---

## 💡 Examples

### Basic Scans
```bash
# Quick security check
greninjasec --all

# Scan specific directory
greninjasec --all --path ./my-project

# Only check for secrets
greninjasec --secrets --path config/
```

### Advanced Scans
```bash
# Full security analysis with AI
greninjasec --all --attack-chains --ai-remediation --verbose

# Generate comprehensive HTML report
greninjasec --all --attack-chains --ai-remediation --html security-report.html

# CI/CD friendly JSON output
greninjasec --all --format json | jq '.findings[] | {severity, title, file}'
```

### Filtering Results
```bash
# Only critical findings
greninjasec --all -f json | jq '.findings[] | select(.severity == "CRITICAL")'

# Count by severity
greninjasec --all -f json | jq '[.findings[] | .severity] | group_by(.) | map({severity: .[0], count: length})'

# Files with most issues
greninjasec --all -f json | jq '[.findings[] | .file] | group_by(.) | map({file: .[0], count: length}) | sort_by(.count) | reverse'
```

### Monitoring & Automation
```bash
# Daily security scan
#!/bin/bash
DATE=$(date +%Y-%m-%d)
greninjasec --all --attack-chains --html "security-report-$DATE.html"
echo "Security scan completed: security-report-$DATE.html"

# Send to Slack (requires webhook)
CRITICAL_COUNT=$(greninjasec --all -f json | jq '[.findings[] | select(.severity == "CRITICAL")] | length')
if [ $CRITICAL_COUNT -gt 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"🚨 $CRITICAL_COUNT critical security issues found!\"}" \
    $SLACK_WEBHOOK_URL
fi
```

---

## 🏷️ Severity Levels

| Level | Icon | Description | Action Required |
|-------|------|-------------|-----------------|
| **CRITICAL** | 🔴 | Exposed credentials, critical misconfigs | **Immediate** |
| **HIGH** | 🟠 | Important security issues | **This Sprint** |
| **MEDIUM** | 🟡 | Recommended improvements | **Next Sprint** |
| **LOW** | 🟢 | Minor suggestions | **Backlog** |

---

## ⚙️ Configuration

### Environment Variables
```bash
# AI Integration (optional)
OPENWEBUI_URL=https://your-openwebui-instance.com/api
OPENWEBUI_TOKEN=your-token-here

# Custom tool paths (optional)
HADOLINT_PATH=/custom/path/to/hadolint
TRIVY_PATH=/custom/path/to/trivy
```

### Tool Auto-Download
GreninjaSec automatically downloads required tools to `~/.greninjasec/bin/`:
- **Hadolint** (Dockerfile scanning)
- **Kubesec** (Kubernetes scanning)  
- **Tfsec** (Terraform scanning)
- **Trivy** (Vulnerability scanning)

---

## 🎯 Quick Reference Card

```bash
# Most Common Commands
greninjasec --all                                    # Basic scan
greninjasec --all --attack-chains                   # With attack analysis  
greninjasec --all --ai-remediation                  # With AI fixes
greninjasec --all --ai-remediation --html report.html # Full AI HTML report
greninjasec --secrets --path config/                # Secrets only
greninjasec --all -f json                          # JSON output
greninjasec install-hooks                          # Pre-commit hook
```

---

## 📞 Support

- **GitHub**: [akashgreninja/greninjaSec](https://github.com/akashgreninja/greninjaSec)
- **Issues**: [Report a bug](https://github.com/akashgreninja/greninjaSec/issues)
- **Docs**: [Live Demo Reports](https://akashgreninja.github.io/greninjaSec/)

---

**🥷 Happy Securing!**