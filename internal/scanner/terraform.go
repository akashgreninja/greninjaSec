package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TfsecResult represents a single tfsec finding
type TfsecResult struct {
	RuleID          string   `json:"rule_id"`
	LongID          string   `json:"long_id"`
	RuleDescription string   `json:"rule_description"`
	RuleProvider    string   `json:"rule_provider"`
	Links           []string `json:"links"`
	Location        struct {
		Filename  string `json:"filename"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	} `json:"location"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// TfsecOutput represents tfsec JSON output
type TfsecOutput struct {
	Results []TfsecResult `json:"results"`
}

// scanTerraform scans Terraform files using tfsec
func scanTerraform(filePath string) []Finding {
	// Check if file is a Terraform file
	if !isTerraformFile(filePath) {
		return nil
	}

	// Ensure tfsec is available
	tm := NewToolManager()
	tfsecPath, err := tm.EnsureTfsec()
	if err != nil {
		// Warn but don't fail - just skip Terraform scanning
		fmt.Fprintf(os.Stderr, "⚠️  Skipping Terraform scan: %v\n", err)
		return nil
	}

	// tfsec scans directories, not individual files
	// So we'll scan the parent directory
	dir := filePath
	fileInfo, err := os.Stat(filePath)
	if err == nil && !fileInfo.IsDir() {
		dir = filepath.Dir(filePath)
	}

	// Run tfsec on the directory
	cmd := exec.Command(tfsecPath, "--format", "json", "--no-color", dir)
	output, _ := cmd.CombinedOutput()
	// Note: tfsec returns non-zero exit code when it finds issues, so we ignore err

	if len(output) == 0 {
		// No output
		return nil
	}

	var tfsecOutput TfsecOutput
	if err := json.Unmarshal(output, &tfsecOutput); err != nil {
		// JSON parse failed, skip
		return nil
	}

	var findings []Finding
	for _, result := range tfsecOutput.Results {
		// Map tfsec severity to our severity levels
		severity := mapTfsecSeverity(result.Severity)

		snippet := fmt.Sprintf("[Line %d-%d] %s",
			result.Location.StartLine,
			result.Location.EndLine,
			result.RuleID)

		f := Finding{
			RuleID:   "TFSEC_" + result.RuleID,
			Title:    result.RuleDescription,
			Severity: severity,
			File:     result.Location.Filename,
			Snippet:  snippet,
		}
		findings = append(findings, f)
	}

	return findings
}

// isTerraformFile checks if a file is a Terraform file
func isTerraformFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".tf") || strings.HasSuffix(lower, ".tfvars")
}

// mapTfsecSeverity maps tfsec severity to our severity levels
func mapTfsecSeverity(tfsecSev string) string {
	switch strings.ToUpper(tfsecSev) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "MEDIUM"
	}
}
