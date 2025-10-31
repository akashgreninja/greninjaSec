# � GreninjaSec — Kubernetes Security Scanner

> **Current Status:** MVP with core scanning engine and Kubesec integration ✅

A lightweight, offensive security scanner for Kubernetes infrastructure. Detects misconfigurations, security vulnerabilities, and compliance issues in YAML manifests.

---

## 🚀 **Quick Start**

### Installation (Recommended)

**One-line installer (Linux/macOS):**
```bash
curl -sSL https://raw.githubusercontent.com/akashgreninja/greninjaSec/main/install.sh | bash
```

**Manual installation:**
```bash
# Linux (x64)
curl -L https://github.com/akashgreninja/greninjaSec/releases/latest/download/greninjasec-linux-amd64 -o greninjasec
chmod +x greninjasec
sudo mv greninjasec /usr/local/bin/

# macOS (M1/M2)
curl -L https://github.com/akashgreninja/greninjaSec/releases/latest/download/greninjasec-darwin-arm64 -o greninjasec
chmod +x greninjasec
sudo mv greninjasec /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/akashgreninja/greninjaSec/releases/latest/download/greninjasec-darwin-amd64 -o greninjasec
chmod +x greninjasec
sudo mv greninjasec /usr/local/bin/
```

**From source:**
```bash
git clone https://github.com/akashgreninja/greninjaSec.git
cd greninjaSec
go build -o greninjasec
```

### Usage

```bash
# Scan a directory with all scanners + attack chain analysis
greninjasec --all --attack-chains --path /path/to/your/code

# Scan specific types
greninjasec --manifest --secrets --path examples/

# Scan for CVE vulnerabilities and CVSS scores
greninjasec --vulnerabilities --path .

# 🆕 AI-powered remediation suggestions (requires OpenWebUI/GPT-4)
greninjasec --all --ai-remediation --path .

# 🆕 Deep Git history secret scanning (scans ALL commits)
greninjasec --deep-scan --path .

# 🆕 Memory/resource leak detection (Go codebases)
greninjasec --leaks --path .

# Output as JSON (for CI/CD)
greninjasec --all --format json --path .

# Verbose output (show all findings)
greninjasec --all --attack-chains --verbose --path examples/

# Generate HTML report with visualizations
greninjasec --all --attack-chains --html security-report.html --path .
```

### Pre-commit Hooks

Install a Git pre-commit hook that automatically scans your code before commits and blocks commits with CRITICAL findings:

```bash
# Install the hook (blocks CRITICAL findings)
greninjasec install-hooks

# Install with warnings only (don't block)
greninjasec install-hooks --allow-critical

# Uninstall the hook
greninjasec uninstall-hooks

# Bypass the hook for a single commit
git commit --no-verify -m "commit message"
```

**Security Policy:**
- 🔴 CRITICAL: Blocked (unless `--allow-critical`)
- 🟠 HIGH: Warning only
- 🟡 MEDIUM/LOW: Info only

---

## ✅ **Currently Implemented**

### 🧱 Core Security Engine

#### ✅ Full Repo Scanner
- ✅ Single Go binary — scans repos recursively
- ✅ **Supports:** Kubernetes YAML, Dockerfiles, Terraform files
- ✅ Multi-document YAML support (handles `---` separated docs)
- ✅ No dependencies required — runs locally
- ✅ Smart directory skipping (`.git`, `vendor`, `node_modules`)
- ✅ **Pre-built binaries** for Linux, macOS, Windows (no compilation needed!)

#### ✅ Security Detection
**Multi-scanner support:**
- ✅ **Kubernetes manifests** via Kubesec (15+ checks)
- ✅ **Hardcoded secrets detection** (12+ patterns: AWS keys, GitHub tokens, Google API keys, private keys, high entropy strings)
- ✅ **Dockerfile security scanning** via Hadolint (50+ checks)
- ✅ **Terraform security scanning** via Tfsec (100+ checks)
- ✅ **CVE/Vulnerability scanning** via Trivy with CVSS scores (scans dependencies + container images)
- ✅ **🆕 Deep Git History Scanning** — Finds secrets leaked in ALL commits with exposure timeline
- ✅ **🆕 Memory/Resource Leak Detection** — AST-based detection for Go codebases (15+ resource types)
- ✅ **Auto-download tool management** (no manual installation required)

**Advanced Features:**
- ✅ **Attack Chain Analyzer** — Correlates findings into exploit paths (8 pre-defined templates)
- ✅ **🆕 AI-Powered Remediation** — OpenWebUI/GPT-4 integration for smart fix suggestions with confidence scores
- ✅ **Smart Output Formatting** — Concise mode (top 3 per severity) or verbose mode (all details)
- ✅ **Priority Recommendations** — Actionable summary with top risks
- ✅ **🆕 Interactive HTML Reports** — Expandable AI fix sections with code patches, commands, and testing steps

✅ **Severity levels:** CRITICAL / HIGH / MEDIUM / LOW

#### ✅ Custom Rule Engine
- ✅ YAML-based rule definitions in `internal/rules/default_rules.yaml`
- ✅ Rule structure: ID, name, severity, description, fix guidance
- ✅ Currently: 1 custom rule (R001) + 15+ Kubesec rules

#### ✅ Multi-format Reporting
- ✅ **Pretty CLI output** (human-readable, formatted)
- ✅ **JSON output** (`--format json`) for CI/CD pipelines
- ✅ Each finding includes:
  - Rule ID
  - Title/description
  - Severity
  - File path
  - Code snippet

---

## 📊 **Sample Output**

```bash
Scanned path: examples/
Findings: 6

[1] R001 - Container missing runAsNonRoot (file: examples/bad_deployment.yaml)
     Severity: HIGH
     Snippet: apiVersion: apps/v1...

[2] KUBESEC_ApparmorAny - Well defined AppArmor policies may provide greater protection
     Severity: MEDIUM
     Snippet: Recommendation: .metadata .annotations ."container.apparmor.security..."

[3] KUBESEC_ServiceAccountName - Service accounts restrict Kubernetes API access
     Severity: MEDIUM
     Snippet: Recommendation: .spec .serviceAccountName
```

---

## 🏗️ **Architecture**

```
greninjasec/
├── cmd/
│   └── root.go          # CLI entry point (Cobra)
├── internal/
│   ├── scanner/
│   │   ├── scanner.go          # Core scanning logic + Kubesec integration
│   │   ├── secrets.go          # Secrets detection engine
│   │   ├── dockerfile.go       # Dockerfile scanner (Hadolint)
│   │   ├── git_history.go      # 🆕 Deep Git history secret scanner
│   │   ├── leaks.go            # 🆕 Memory/resource leak detector (AST-based)
│   │   ├── ai_enrichment.go    # 🆕 AI remediation integration
│   │   └── tools.go            # Auto-download manager
│   ├── ai/
│   │   ├── client.go           # 🆕 OpenWebUI API client
│   │   ├── config.go           # 🆕 AI configuration
│   │   └── types.go            # 🆕 AI request/response types
│   └── rules/
│       ├── default_rules.yaml  # Custom rule definitions
│       └── rules.go            # Rule loading
├── examples/
│   ├── bad_deployment.yaml     # Test YAML with vulnerabilities
│   ├── bad_dockerfile          # Test Dockerfile
│   ├── sample_leaks.go         # 🆕 Example leaks for testing
│   └── config.txt              # Test secrets file
└── main.go
```

---

## 🔄 **In Progress / Roadmap**

### 🔨 Core Engine Enhancements
- 🔄 Dynamic rule loading from `default_rules.yaml`
- 🔄 Support for Helm charts
- 🔄 Regex/JSONPath pattern matching for custom rules
- 🔄 RBAC/IAM over-privileged role detection

### 🆕 **Recently Completed**
- ✅ **AI-Powered Smart Remediation** — GPT-4 integration via OpenWebUI with:
  - Detailed fix explanations and risk analysis
  - Code patches with line-by-line changes
  - Shell commands for quick fixes
  - Testing steps and verification methods
  - Confidence scoring (0-100%)
  - Response caching to avoid redundant API calls
- ✅ **Deep Git History Secret Scanning** — Detects secrets in ALL commits with:
  - Commit hash, author, and timestamp tracking
  - Days exposed calculation
  - Detection if secret still exists in current repo
  - Git cleanup command generation (git-filter-branch + BFG)
- ✅ **Memory/Resource Leak Detection** (Go codebases) — AST-based analysis for:
  - Unclosed files, HTTP responses, DB connections
  - File watchers (fsnotify) never closed
  - Timers (time.NewTicker) never stopped
  - Contexts never cancelled
  - Event listeners never removed
  - Message queue subscriptions never unsubscribed
  - Goroutines without cancellation
  - Unbounded slice growth
  - CPU issues (infinite loops, regex in loops)
  - Custom fix suggestions per resource type

### 🧨 Red-Team Simulation
- ✅ Attack Chain Analyzer (8 pre-defined templates)
- 📅 Exploit Path Simulation (non-destructive)
- 📅 Exploit Surface Score calculation
- 📅 Step-by-step attack narrative generation

### 🔗 DevSecOps Integration
- ✅ Pre-commit hook to block critical findings
- ✅ HTML report with visual attack graphs
- 📅 GitHub Action for PR scanning + inline comments
- 📅 Slack/email notifications

### 💾 Storage & Caching
- 📅 BoltDB/SQLite for result caching
- 📅 Trend tracking and versioned logs
- 📅 False-positive management

### 🤖 AI Integration Enhancements
- ✅ AI-generated fix suggestions
- ✅ Risk prioritization and triage
- 📅 Exploit chain narration (convert findings → human-readable stories)
- 📅 False positive classification
- 📅 Auto-generate PR comments
- 📅 Rule authoring assistant

### 🔐 Security Validation
- 📅 **Secret Validation** — Check if leaked credentials are still active:
  - AWS keys → Test against AWS STS API
  - GitHub tokens → Test against GitHub API
  - Google API keys → Test against Google APIs
  - Mark as CRITICAL if active, LOW if revoked

### 📋 Compliance Mapping
- 📅 Tag findings to compliance frameworks:
  - CIS Benchmarks
  - FedRAMP
  - FIPS
  - PCI-DSS
  - NIST

---

## 🛠️ **Dependencies**

### Zero Manual Setup Required! 🎉
GreninjaSec automatically downloads required tools on first use:
- **Hadolint** (Dockerfile linting) → Auto-downloaded to `~/.greninjasec/bin/`
- **Kubesec** (K8s security scanning) → Auto-downloaded to `~/.greninjasec/bin/`

The tool checks for binaries in this order:
1. System PATH (`/usr/local/bin/`, etc.)
2. User's home directory (`~/.greninjasec/bin/`)
3. Auto-download if not found

**No sudo required** — everything installs to your home directory.

### Build Requirements
- Go 1.21+

### Go Modules
```
github.com/spf13/cobra  # CLI framework
gopkg.in/yaml.v3        # YAML parsing
```

---

## 📝 **Configuration**

### Command-line Flags
```bash
--path, -p    Path to scan (default: current directory)
--format, -f  Output format: pretty | json (default: pretty)
```

### Rule Configuration
Edit `internal/rules/default_rules.yaml` to add custom rules:
```yaml
- id: R002
  name: "Missing pod security policy"
  severity: "MEDIUM"
  description: "Pods should reference a PodSecurityPolicy"
  fix: "Add securityContext with appropriate PSP"
```

---

## 🧪 **Testing**

```bash
# Run on example files
./greninjasec --path examples/

# Test JSON output
./greninjasec --path examples/ --format json | jq

# Test specific scanners
./greninjasec --secrets --path examples/
./greninjasec --dockerfile --path examples/
./greninjasec --manifest --path examples/
./greninjasec --vulnerabilities --path .

# 🆕 Test AI remediation (requires .env with OpenWebUI credentials)
./greninjasec --all --ai-remediation --path examples/

# 🆕 Test deep Git history scanning
./greninjasec --deep-scan --path .

# 🆕 Test leak detection on sample file
./greninjasec --leaks --path examples/sample_leaks.go
```

---

## 📈 **Project Progress**

**MVP Completion: ~65%**

| Feature Category | Status | Completion |
|-----------------|--------|-----------|
| Core Scanner | ✅ Working | 90% |
| Kubesec Integration | ✅ Working | 100% |
| CVE/Vulnerability Scanning | ✅ Working | 100% |
| Deep Git History Scanning | ✅ Working | 100% |
| Memory/Resource Leak Detection | ✅ Working | 100% |
| AI-Powered Remediation | ✅ Working | 100% |
| Custom Rules | 🔄 In Progress | 30% |
| Multi-format Output | ✅ Working | 80% |
| HTML Reports | ✅ Working | 90% |
| Pre-commit Hooks | ✅ Working | 100% |
| Attack Chain Analysis | ✅ Working | 70% |
| CI/CD Integration | 📅 Planned | 0% |
| Secret Validation (Live Check) | 📅 Planned | 0% |
| Compliance Mapping | 📅 Planned | 0% |

---

## 🎯 **Next Steps**

1. **Secret Validation** — Check if leaked AWS keys/GitHub tokens are still active
2. **TUI Dashboard** — Interactive terminal UI with Bubble Tea
3. **GitHub Action** — Enable automated PR scanning
4. **Security Score Tracking** — Trend analysis across commits

---

## 📄 **License**

MIT License — See [LICENSE](LICENSE) file

---

## 🤝 **Contributing**

This is an early-stage MVP. Contributions welcome!

**Priority areas:**
- Additional rule definitions
- Support for more file types (Terraform, Helm, etc.)
- Attack chain correlation logic
- CI/CD integrations

---

**Built with ❤️ for DevSecOps teams**
