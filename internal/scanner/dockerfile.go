package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// HadolintResult represents a single hadolint finding
type HadolintResult struct {
	Code    string `json:"code"`
	Column  int    `json:"column"`
	File    string `json:"file"`
	Level   string `json:"level"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// scanDockerfile scans a Dockerfile using hadolint
func scanDockerfile(filePath string) []Finding {
	// Check if file looks like a Dockerfile
	if !isDockerfile(filePath) {
		return nil
	}

	// Ensure hadolint is available
	tm := NewToolManager()
	hadolintPath, err := tm.EnsureHadolint()
	if err != nil {
		// Warn but don't fail - just skip Dockerfile scanning
		fmt.Fprintf(os.Stderr, "⚠️  Skipping Dockerfile scan: %v\n", err)
		return nil
	}

	// Run hadolint
	cmd := exec.Command(hadolintPath, "--format", "json", filePath)
	output, _ := cmd.CombinedOutput()
	// Note: hadolint returns non-zero exit code when it finds issues, so we ignore err

	if len(output) == 0 {
		// No output
		return nil
	}

	var results []HadolintResult
	if err := json.Unmarshal(output, &results); err != nil {
		// JSON parse failed, skip
		return nil
	}

	var findings []Finding
	for _, r := range results {
		f := Finding{
			ID:   "HADOLINT_" + r.Code,
			Title:    r.Message,
			Severity: mapHadolintSeverity(r.Level),
			File:     filePath,
			Snippet:  fmt.Sprintf("[Line %d, Col %d] %s", r.Line, r.Column, r.Code),
		}
		findings = append(findings, f)
	}

	return findings
}

// isDockerfile checks if a file is likely a Dockerfile
func isDockerfile(path string) bool {
	lower := strings.ToLower(path)
	
	// Check for common Dockerfile naming patterns
	patterns := []string{
		"dockerfile",
		".dockerfile",
		"dockerfile.",
		"containerfile",
	}
	
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	
	return false
}

// mapHadolintSeverity maps hadolint severity levels to our severity levels
func mapHadolintSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "HIGH"
	case "warning":
		return "MEDIUM"
	case "info":
		return "LOW"
	case "style":
		return "LOW"
	default:
		return "MEDIUM"
	}
}
