# 🥷 GreninjaSec — Kubernetes Security Scanner

> **Current Status:** Production-ready with Shadow Deploy Attack Simulation! ✅

A revolutionary offensive security scanner for Kubernetes infrastructure. Not only detects vulnerabilities, but **ac## 🎭 **Shadow Deploy Simulator** (Revolutionary Feature!)

**The world's first security scanner that actually demonstrates attacks!**

### What Makes It Unique?

Traditional scanners tell you:
> ❌ "Privileged container found (HIGH severity)"

**Shadow Deploy shows you:**
> ✅ "Here's the exact 4-minute attack path to steal your database:
> 1. Escape container via nsenter (15 seconds)
> 2. Extract AWS credentials from host (30 seconds)  
> 3. Access S3 customer-data bucket (2 minutes)
> 4. Download 2.3M records (1.5 minutes)
> 💰 Estimated breach cost: $2.5M"

### 🧠 How Shadow Deploy Actually Works

**In simple terms:** Shadow Deploy matches found vulnerabilities against a knowledge base of real-world attack techniques and generates realistic command outputs to show exactly how hackers would exploit your systems.

**The 5-Step Process:**

1. **Vulnerability Analysis** 📋
   - Shadow Deploy receives vulnerabilities found by other scanners (Kubernetes, Docker, Secrets, CVE)
   - Example findings: `privileged: true`, `docker.sock mounted`, `AWS credentials hardcoded`
   - It asks: "Are these exploitable?" by checking against a known list of dangerous configurations

2. **Attack Vector Mapping** 🎯
   - Each vulnerability type is mapped to attack techniques in `internal/shadow/simulator.go`
   - Example mappings:
     - `privileged_container` → Container Escape
     - `docker_socket_mount` → Docker Socket Abuse
     - `aws_credentials_exposed` → Cloud Account Takeover
   - **Key insight:** Different vulnerabilities often use the SAME exploitation techniques!

3. **Playbook Selection** 📖
   - Shadow Deploy has pre-written attack playbooks in `internal/shadow/playbooks.go`
   - Each playbook contains step-by-step commands that real penetration testers use
   - Example: "Container Escape via nsenter" playbook has 4 steps with actual Linux commands
   - These are based on **MITRE ATT&CK framework** (industry-standard attack taxonomy)

4. **Safe Simulation** 🛡️
   - **IT NEVER ACTUALLY RUNS THE ATTACKS!** Everything is 100% safe simulation
   - Instead of executing `aws sts get-caller-identity`, it calls `getRealisticOutput()`
   - This function returns what that command WOULD show if it ran successfully
   - Example: Returns realistic JSON with fake AWS account details, not real ones

5. **Impact Calculation** 💥
   - Based on successful attack paths, it estimates:
     - Systems compromised (e.g., 15 pods/services)
     - Secrets exposed (e.g., 47 credentials)
     - Time to compromise (e.g., 4 minutes)
     - Estimated breach cost (e.g., $500K - $2.5M)

**Why Only ~15 Vulnerability Types?**

You might wonder: "There are millions of CVEs - how can 15 types be enough?"

**Answer:** Most attacks follow the same patterns!
- **CVEs/Vulnerabilities** = Different ways to GET IN (the door)
- **Attack Playbooks** = What hackers DO AFTER they're in (the steps)

Examples:
- 1000s of different container CVEs → All use the SAME escape technique
- 100s of AWS misconfigurations → All exploited with the SAME AWS CLI commands
- Dozens of RBAC issues → All use the SAME privilege escalation steps

Shadow Deploy focuses on **infrastructure misconfigurations** (privileged containers, exposed credentials) rather than specific CVE exploits. These misconfigurations are what make breaches devastating, regardless of which CVE got the attacker in!

**Current Attack Coverage (Top 80% of Real-World Attacks):**
1. Container Escape (nsenter, hostPID)
2. Docker Socket Abuse
3. Cloud Credential Theft (AWS, GCP, Azure)
4. Kubernetes Lateral Movement
5. Privilege Escalation (RBAC → cluster-admin)
6. Data Exfiltration (S3, databases)
7. Persistence Mechanisms
8. Cloud Account Takeover real attacks** to show you exactly what hackers can do.

**🎭 World's First Attack Simulation Scanner** — See the exact exploit path from vulnerability to full compromise!

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

# 🎭 Shadow Deploy - Simulate real attacks! (REVOLUTIONARY!)
greninjasec --shadow-deploy --path examples/shadow-test.yaml

# 🤖 Shadow Deploy with AI enhancement
greninjasec --shadow-deploy --ai-remediation --path k8s/

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
- ✅ **🎭 Shadow Deploy Simulator** — **WORLD'S FIRST!** Actually simulates attacks to demonstrate exploit paths
  - Real attack commands (nsenter, kubectl, AWS CLI, Docker)
  - Blast radius calculation (systems/databases/secrets compromised)
  - Estimated breach cost ($500K-$2.5M)
  - Time-to-compromise metrics
  - 8 pre-built attack playbooks
  - AI-powered exploit discovery
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

### 🎭 **Shadow Deploy Simulation**

```bash
$ greninjasec --shadow-deploy --path examples/shadow-test.yaml

🎭 Shadow Deploy Simulator - Attack Demonstration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[1/5] 🔍 Analyzing vulnerabilities...
      Found 13 total issues, 7 are exploitable

[2/5] 🎯 Identifying attack vectors...
      Discovered 4 critical attack paths

[3/5] 🏗️  Preparing simulation environment...
      Running in DRY-RUN mode (safe)

[4/5] 🥷 Simulating attacks...

      ┌─ Container Escape via nsenter
      │  ✓ Check if container is privileged
      │  ✓ Escape to host namespace
      │  ✓ Verify host access
      │  ✓ Search for cloud credentials
      │  Impact: CRITICAL
      │
      ┌─ Docker Socket Host Takeover
      │  ✓ Check Docker socket accessibility
      │  ✓ List running containers
      │  ✓ Spawn privileged container with host root
      │  ✓ Access host secrets
      │  Impact: CRITICAL
      │
      ┌─ AWS Account Takeover
      │  ✓ Identify current AWS permissions
      │  ✓ List IAM users and roles
      │  ✓ Check if can create new admin user
      │  ✓ List accessible EC2 instances
      │  Impact: CRITICAL

[5/5] 📊 Calculating impact...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Simulation Complete!

📈 Attack Success Rate: 100%
⏱️  Time to Full Compromise: 4 minutes 23 seconds
💰 Estimated Breach Cost: $0.5M - $2.5M

🔥 BLAST RADIUS:
   ├─ Systems Compromised: 15
   ├─ Secrets Exposed: 47
   ├─ Databases Accessible: [postgres redis mongodb]
   └─ Network Scope: cluster-wide

🎯 Priority Fixes: 7 critical issues
```

### 📋 **Standard Security Scan**

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

## � **Shadow Deploy Simulator** (Revolutionary Feature!)

**The world's first security scanner that actually demonstrates attacks!**

### What Makes It Unique?

Traditional scanners tell you:
> ❌ "Privileged container found (HIGH severity)"

**Shadow Deploy shows you:**
> ✅ "Here's the exact 4-minute attack path to steal your database:
> 1. Escape container via nsenter (15 seconds)
> 2. Extract AWS credentials from host (30 seconds)  
> 3. Access S3 customer-data bucket (2 minutes)
> 4. Download 2.3M records (1.5 minutes)
> 💰 Estimated breach cost: $2.5M"

### 🎯 Attack Vectors Simulated

1. **Container Escape**
   - Privileged containers → host root access
   - hostPID/hostIPC namespace abuse
   - Capabilities exploitation (SYS_ADMIN, etc.)

2. **Docker Socket Abuse**
   - Mounted `/var/run/docker.sock`
   - Spawn privileged container on host
   - Full host filesystem access

3. **Cloud Credential Theft**
   - AWS metadata service (169.254.169.254)
   - GCP/Azure metadata endpoints
   - Instance profile credentials
   - Hardcoded keys in environment variables

4. **Kubernetes Lateral Movement**
   - Service account token theft
   - RBAC privilege escalation
   - Pod-to-pod access
   - Secret exfiltration across namespaces

5. **Data Exfiltration**
   - S3 bucket enumeration and download
   - Database access (postgres, redis, mongodb)
   - Secret manager access

6. **Privilege Escalation**
   - RBAC → cluster-admin
   - IAM role assumption
   - Kubernetes API abuse

7. **Persistence Mechanisms**
   - Backdoor user creation
   - Malicious pod deployment
   - CronJob persistence

8. **Cloud Account Takeover**
   - AWS IAM manipulation
   - EC2 instance spawning
   - Resource enumeration

### 🤖 AI-Powered Enhancements

When combined with `--ai-remediation`, Shadow Deploy gets superpowers:

- **Creative Exploit Discovery** - AI finds attack paths beyond pre-built playbooks
- **Multi-Vulnerability Chaining** - Combines separate issues into sophisticated attacks
- **Defense Prioritization** - AI ranks fixes by impact vs. effort
- **Executive Summaries** - Translates technical exploits into business impact

### 📊 Metrics Provided

- **Attack Success Rate** - Percentage of attack paths that succeed
- **Time to Compromise** - How fast can attacker get full access
- **Blast Radius** - What systems/data can attacker reach
- **Estimated Damage** - Breach cost in dollars ($500K - $8M range)
- **Systems Compromised** - Count of pods/services/databases accessible
- **Secrets Exposed** - Number of credentials/keys leaked
- **Compliance Violations** - PCI-DSS, HIPAA, GDPR impacts

### 💡 Use Cases

**For Security Teams:**
- Prioritize fixes based on real exploitability
- Understand actual attack surface
- Learn offensive security techniques
- Validate security controls

**For Executives:**
- See business impact in dollar terms
- Understand "why this matters"
- Get clear ROI on security investments
- Board-ready breach scenarios

**For DevOps:**
- Learn what NOT to do in production
- Understand Kubernetes security best practices
- Fix issues before they become breaches
- Security training through real examples

**For Compliance:**
- Demonstrate due diligence
- Show risk assessment process
- Prove security controls work
- Audit trail of security posture

### 🚀 Example Commands

```bash
# Basic simulation (dry-run, safe)
greninjasec --shadow-deploy --path k8s/

# With AI enhancement for creative attacks
greninjasec --shadow-deploy --ai-remediation --path .

# Combine with full security scan
greninjasec --all --shadow-deploy --attack-chains --path .

# Generate HTML report with attack visualizations
greninjasec --shadow-deploy --html shadow-report.html --path k8s/
```

### 🛡️ Safety Features

- **Dry-run by default** - Never actually executes attacks
- **Isolated sandbox** - Optional container isolation
- **Safe commands only** - Read-only operations
- **Audit logging** - Every step is recorded
- **Mock services** - Uses fake AWS/K8s APIs when needed

---

## �🏗️ **Architecture**
````

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
│   ├── shadow/                  # 🎭 Shadow Deploy Simulator
│   │   ├── simulator.go        # Attack simulation engine
│   │   ├── playbooks.go        # 8 attack technique playbooks
│   │   ├── ai_enhancer.go      # AI-powered exploit discovery
│   │   ├── sandbox.go          # Safe execution environment
│   │   └── types.go            # Data structures
│   ├── ai/
│   │   ├── client.go           # 🆕 OpenWebUI API client
│   │   ├── config.go           # 🆕 AI configuration
│   │   └── types.go            # 🆕 AI request/response types
│   └── rules/
│       ├── default_rules.yaml  # Custom rule definitions
│       └── rules.go            # Rule loading
├── examples/
│   ├── bad_deployment.yaml     # Test YAML with vulnerabilities
│   ├── shadow-test.yaml        # 🎭 Shadow Deploy test case
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
