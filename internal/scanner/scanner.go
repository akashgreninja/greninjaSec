package scanner

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Finding represents a single security issue discovered
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	File     string `json:"file"`
	Snippet  string `json:"snippet"`
	
	// AI remediation (populated if --ai-remediation flag is used)
	AIRemediation *AIRemediationData `json:"ai_remediation,omitempty"`
}

// AIRemediationData holds AI-generated fix suggestions
type AIRemediationData struct {
	Summary         string   `json:"summary"`
	Explanation     string   `json:"explanation"`
	RiskAnalysis    string   `json:"risk_analysis"`
	CodePatch       string   `json:"code_patch,omitempty"`
	Commands        []string `json:"commands,omitempty"`
	ManualSteps     []string `json:"manual_steps,omitempty"`
	AlternateFix    string   `json:"alternate_fix,omitempty"`
	ConfidenceScore float64  `json:"confidence_score"`
	TestingSteps    []string `json:"testing_steps,omitempty"`
	References      []string `json:"references,omitempty"`
}

// ScanOptions defines what types of scans to perform
type ScanOptions struct {
	ScanManifests       bool // Scan Kubernetes YAML manifests
	ScanSecrets         bool // Scan for hardcoded secrets
	ScanDockerfile      bool // Scan Dockerfiles
	ScanTerraform       bool // Scan Terraform files
	ScanVulnerabilities bool // Scan for CVEs with Trivy
	AnalyzeChains       bool // Analyze attack chains
	AIEnhance           bool // Use AI for enhanced attack chain analysis
	AIRemediation       bool // Get AI-powered fix suggestions
}

// ScanResult contains findings and optional attack chain analysis
type ScanResult struct {
	Findings     []Finding     `json:"findings"`
	AttackChains []AttackChain `json:"attack_chains,omitempty"`
}

// Scanner is a minimal repo scanner.
type Scanner struct {
	toolManager *ToolManager
}

func NewScanner() *Scanner {
	return &Scanner{
		toolManager: NewToolManager(),
	}
}

// Scan walks the path and scans for all security issues (backward compatibility)
func (s *Scanner) Scan(path string) ([]Finding, error) {
	opts := ScanOptions{
		ScanManifests:  true,
		ScanSecrets:    true,
		ScanDockerfile: true,
		ScanTerraform:  true,
	}
	return s.ScanWithOptions(path, opts)
}

// ScanWithOptions walks the path and scans based on provided options
func (s *Scanner) ScanWithOptions(path string, opts ScanOptions) ([]Finding, error) {
	var findings []Finding

	// --- Scan for vulnerabilities with Trivy (if enabled) ---
	// This runs once for the entire directory before the file walk
	if opts.ScanVulnerabilities {
		vulnFindings, err := s.scanVulnerabilities(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Vulnerability scanning failed: %v\n", err)
		} else {
			findings = append(findings, vulnFindings...)
		}
	}

	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// ignore permission errors gracefully
			return nil
		}
		if d.IsDir() {
			// skip vendor/.git etc quickly
			base := filepath.Base(p)
			if base == ".git" || base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		// --- Scan ALL files for hardcoded secrets (if enabled) ---
		if opts.ScanSecrets {
			secretFindings := scanFileForSecrets(p)
			findings = append(findings, secretFindings...)
		}

		// --- Scan Dockerfiles (if enabled) ---
		if opts.ScanDockerfile {
			dockerFindings := scanDockerfile(p)
			findings = append(findings, dockerFindings...)
		}

		// --- Scan Terraform files (if enabled) ---
		if opts.ScanTerraform {
			terraformFindings := scanTerraform(p)
			findings = append(findings, terraformFindings...)
		}

		// --- Kubernetes YAML specific scanning (if enabled) ---
		if !opts.ScanManifests || !isYAML(p) {
			return nil
		}

		// read file
		b, err := os.ReadFile(p)
		if err != nil {
			return nil // ignore read error
		}

		// Split multi-doc YAMLs
		docs := splitYAMLDocs(string(b))
		for _, doc := range docs {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(doc), &node); err != nil {
				continue
			}

			// --- Custom rule: missing runAsNonRoot ---
			if matchesMissingRunAsNonRoot(doc) {
				f := Finding{
					ID:   "R001",
					Title:    "Container missing runAsNonRoot",
					Severity: "HIGH",
					File:     p,
					Snippet:  snippetForDoc(doc),
				}
				findings = append(findings, f)
			}
		}

		// --- Run Kubesec on the entire YAML file (once per file, not per doc) ---
		kubeFindings := runKubesecIntegration(p)
		findings = append(findings, kubeFindings...)

		return nil
	})

	return findings, err
}

// ScanWithAttackChains performs a full scan and optionally analyzes attack chains
func (s *Scanner) ScanWithAttackChains(path string, opts ScanOptions) (ScanResult, error) {
	// First, run normal scan
	findings, err := s.ScanWithOptions(path, opts)
	if err != nil {
		return ScanResult{Findings: findings}, err
	}

	result := ScanResult{
		Findings: findings,
	}

	// If attack chain analysis is enabled
	if opts.AnalyzeChains {
		// Run rule-based attack chain analysis
		chains := AnalyzeAttackChains(findings)

		// If AI enhancement is enabled, use it
		if opts.AIEnhance {
			aiChains, err := AIEnhancedChainAnalysis(findings, chains)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  AI enhancement failed: %v\n", err)
				result.AttackChains = chains // Fall back to rule-based only
			} else {
				result.AttackChains = aiChains
			}
		} else {
			result.AttackChains = chains
		}
	}

	return result, nil
}

// ----------------------------------------
// Kubesec Integration
// ----------------------------------------

func runKubesecIntegration(filePath string) []Finding {
	// Ensure kubesec is available
	tm := NewToolManager()
	kubesecPath, err := tm.EnsureKubesec()
	if err != nil {
		// Warn but don't fail - just skip kubesec scanning
		fmt.Fprintf(os.Stderr, "⚠️  Skipping Kubesec scan: %v\n", err)
		return nil
	}

	cmd := exec.Command(kubesecPath, "scan", "--format", "json", filePath)
	output, _ := cmd.CombinedOutput()
	// Note: kubesec returns exit code 2 even on success, so we ignore the error
	// We only care if we got valid JSON output

	if len(output) == 0 {
		// No output means kubesec isn't installed or completely failed
		return nil
	}

	type KubesecAdvice struct {
		ID       string `json:"id"`
		Selector string `json:"selector"`
		Reason   string `json:"reason"`
		Points   int    `json:"points"`
	}

	type KubesecResult struct {
		Object   string `json:"object"`
		Score    int    `json:"score"`
		FileName string `json:"fileName"`
		Scoring  struct {
			Critical []KubesecAdvice `json:"critical"`
			Advise   []KubesecAdvice `json:"advise"`
		} `json:"scoring"`
	}

	var results []KubesecResult
	if err := json.Unmarshal(output, &results); err != nil {
		// JSON parse failed, skip
		return nil
	}

	if len(results) == 0 {
		return nil
	}

	res := results[0]
	var findings []Finding

	// Convert Kubesec critical findings
	for _, c := range res.Scoring.Critical {
		f := Finding{
			ID:   "KUBESEC_CRITICAL_" + c.ID,
			Title:    c.Reason,
			Severity: "CRITICAL",
			File:     filePath,
			Snippet:  fmt.Sprintf("Missing: %s", c.Selector),
		}
		findings = append(findings, f)
	}

	// Convert Kubesec advice findings (only show top 5 to avoid noise)
	for i, a := range res.Scoring.Advise {
		if i >= 5 {
			break
		}
		f := Finding{
			ID:   "KUBESEC_" + a.ID,
			Title:    a.Reason,
			Severity: "MEDIUM",
			File:     filePath,
			Snippet:  fmt.Sprintf("Recommendation: %s", a.Selector),
		}
		findings = append(findings, f)
	}

	return findings
}

// ----------------------------------------
// Utility Helpers
// ----------------------------------------

func isYAML(path string) bool {
	l := strings.ToLower(path)
	return strings.HasSuffix(l, ".yaml") || strings.HasSuffix(l, ".yml")
}

func splitYAMLDocs(content string) []string {
	parts := strings.Split(content, "\n---")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func matchesMissingRunAsNonRoot(doc string) bool {
	lower := strings.ToLower(doc)
	if strings.Contains(lower, "containers:") && !strings.Contains(lower, "runasnonroot: true") {
		return true
	}
	return false
}

func snippetForDoc(doc string) string {
	if len(doc) > 200 {
		return doc[:200] + "..."
	}
	return doc
}

// PrintJSON prints findings as JSON to stdout
func PrintJSON(findings []Finding) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}
