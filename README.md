# � GreninjaSec — Kubernetes Security Scanner

> **Current Status:** MVP with core scanning engine and Kubesec integration ✅

A lightweight, offensive security scanner for Kubernetes infrastructure. Detects misconfigurations, security vulnerabilities, and compliance issues in YAML manifests.

---

## 🚀 **Quick Start**

```bash
# Build the binary
go build -o greninjasec

# Scan a directory
./greninjasec --path examples/

# Output as JSON (for CI/CD)
./greninjasec --path . --format json
```

---

## ✅ **Currently Implemented (MVP)**

### 🧱 Core Security Engine

#### ✅ Full Repo Scanner
- ✅ Single Go binary — scans repos recursively
- ✅ **Supports:** Kubernetes YAML files (`.yaml`, `.yml`)
- ✅ Multi-document YAML support (handles `---` separated docs)
- ✅ No dependencies required — runs locally
- ✅ Smart directory skipping (`.git`, `vendor`, `node_modules`)

#### ✅ Security Detection
**Built-in checks:**
- ✅ Containers running as root (missing `runAsNonRoot: true`)
- ✅ **Kubesec integration** for 15+ Kubernetes security best practices
- ✅ **Hardcoded secrets detection** (AWS keys, GitHub tokens, Google API keys, private keys, etc.)
- ✅ **Dockerfile security scanning** via Hadolint (50+ checks)
- ✅ **Auto-download tool management** (no manual installation required)

**Kubernetes checks (via Kubesec):**
- Missing resource limits (CPU/Memory)
- Missing seccomp/AppArmor profiles
- Service account token automounting
- Missing security contexts (runAsUser, runAsGroup)
- Privileged containers
- Read-only root filesystem recommendations
- Capability drops
- And 8+ more...

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
│   │   ├── scanner.go   # Core scanning logic + Kubesec integration
│   │   ├── secrets.go   # Secrets detection engine
│   │   ├── dockerfile.go # Dockerfile scanner (Hadolint)
│   │   └── tools.go     # Auto-download manager
│   └── rules/
│       ├── default_rules.yaml  # Custom rule definitions
│       └── rules.go     # Rule loading (in progress)
├── examples/
│   ├── bad_deployment.yaml  # Test YAML with vulnerabilities
│   ├── bad_dockerfile       # Test Dockerfile
│   └── config.txt           # Test secrets file
└── main.go
```

---

## 🔄 **In Progress / Roadmap**

### 🔨 Core Engine Enhancements
- 🔄 Dynamic rule loading from `default_rules.yaml`
- 🔄 Support for Helm charts, Terraform, Dockerfiles
- 🔄 Regex/JSONPath pattern matching for custom rules
- 🔄 Colorized CLI output
- 🔄 Hardcoded credential detection
- 🔄 RBAC/IAM over-privileged role detection

### 🧨 Red-Team Simulation
- 📅 Attack Chain Analyzer
  - Correlate findings to map exploit paths
  - Example: leaked CI key → public ECR → privileged SA → cluster compromise
- 📅 Exploit Path Simulation (non-destructive)
  - Simulate what an attacker could do
  - Returns: LIKELY / POSSIBLE / UNLIKELY exploitability
- 📅 Exploit Surface Score calculation
- 📅 Step-by-step attack narrative generation

### 🔗 DevSecOps Integration
- 📅 Pre-commit hook to block critical findings
- 📅 GitHub Action for PR scanning + inline comments
- 📅 Slack/email notifications
- 📅 HTML report with visual attack graphs (D3.js)

### 💾 Storage & Caching
- 📅 BoltDB/SQLite for result caching
- 📅 Trend tracking and versioned logs
- 📅 False-positive management

### 🤖 AI Integration (via OpenWebUI)
- 📅 AI-generated fix suggestions
- 📅 Exploit chain narration (convert findings → human-readable stories)
- 📅 Risk prioritization and triage
- 📅 False positive classification
- 📅 Auto-generate PR comments
- 📅 Rule authoring assistant

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
```

---

## 📈 **Project Progress**

**MVP Completion: ~30%**

| Feature Category | Status | Completion |
|-----------------|--------|-----------|
| Core Scanner | ✅ Working | 80% |
| Kubesec Integration | ✅ Working | 100% |
| Custom Rules | 🔄 In Progress | 30% |
| Multi-format Output | ✅ Working | 60% |
| Red-Team Simulation | 📅 Planned | 0% |
| Attack Chain Analysis | 📅 Planned | 0% |
| CI/CD Integration | 📅 Planned | 0% |
| AI Integration | 📅 Planned | 0% |
| Compliance Mapping | 📅 Planned | 0% |

---

## 🎯 **Next Steps**

1. **Dynamic rule loading** — Load and execute rules from YAML
2. **Terraform/Dockerfile support** — Expand scanner to more IaC types
3. **Attack chain correlation** — Link findings to create exploit paths
4. **GitHub Action** — Enable automated PR scanning

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
