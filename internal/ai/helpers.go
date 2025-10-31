package ai

import (
	"fmt"
	"path/filepath"
	"strings"
)

// BuildRemediationRequest creates an AI remediation request from a finding
// This extracts only the essential context to minimize token usage
func BuildRemediationRequest(finding interface{}) *RemediationRequest {
	req := &RemediationRequest{}

	// Try to extract fields from the finding based on its type
	// We'll handle different finding types (CVE, K8s, Secrets, etc.)
	
	switch f := finding.(type) {
	case map[string]interface{}:
		req.FindingID = getString(f, "id")
		req.Severity = getString(f, "severity")
		req.Title = getString(f, "title")
		req.Description = getString(f, "description")
		req.FilePath = getString(f, "file")
		req.CodeSnippet = getString(f, "snippet")
		
		// CVE-specific fields
		if cveID := getString(f, "cve_id"); cveID != "" {
			req.CVEID = cveID
			req.CVSSScore = getString(f, "cvss_score")
			req.PackageName = getString(f, "package_name")
			req.InstalledVersion = getString(f, "installed_version")
			req.FixedVersion = getString(f, "fixed_version")
		}
		
		// Determine file type
		req.FileType = detectFileType(req.FilePath)
		
		// Add line number if available
		if lineNum, ok := f["line_number"].(int); ok {
			req.LineNumber = lineNum
		}
		
	default:
		// Fallback for unknown types
		req.FindingID = "unknown"
		req.Severity = "UNKNOWN"
		req.Title = "Unknown finding"
	}

	return req
}

// ShouldGetRemediation determines if a finding should get AI remediation
// Only process CRITICAL and HIGH severity findings to save API calls
func ShouldGetRemediation(severity string, findingType string) bool {
	// Prioritize based on severity
	severity = strings.ToUpper(severity)
	if severity != "CRITICAL" && severity != "HIGH" {
		return false
	}

	// Skip low-value findings
	lowValueTypes := []string{
		"HADOLINT_DL3009", // Delete apt-get lists
		"HADOLINT_DL3015", // --no-install-recommends
	}

	for _, skip := range lowValueTypes {
		if strings.HasPrefix(findingType, skip) {
			return false
		}
	}

	return true
}

// detectFileType determines the type of file from its path
func detectFileType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	base := strings.ToLower(filepath.Base(filePath))

	switch {
	case ext == ".yaml" || ext == ".yml":
		if strings.Contains(base, "deployment") {
			return "kubernetes-deployment"
		}
		if strings.Contains(base, "service") {
			return "kubernetes-service"
		}
		return "yaml"
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile."):
		return "dockerfile"
	case ext == ".tf":
		return "terraform"
	case base == "go.mod":
		return "go-module"
	case base == "package.json":
		return "npm-package"
	case base == "requirements.txt":
		return "python-requirements"
	case base == "pom.xml":
		return "maven-pom"
	case base == "build.gradle":
		return "gradle-build"
	default:
		return "unknown"
	}
}

// getString safely extracts a string value from a map
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// TruncateSnippet ensures code snippets don't exceed token limits
// Keeps approximately 50 lines of context
func TruncateSnippet(snippet string, maxLines int) string {
	if maxLines <= 0 {
		maxLines = 50
	}

	lines := strings.Split(snippet, "\n")
	if len(lines) <= maxLines {
		return snippet
	}

	// Keep first half and last half
	half := maxLines / 2
	kept := append(lines[:half], "... (truncated) ...")
	kept = append(kept, lines[len(lines)-half:]...)

	return strings.Join(kept, "\n")
}

// FormatAttackChainContext creates a concise attack chain description
func FormatAttackChainContext(chainTitle string, step int, totalSteps int) string {
	return fmt.Sprintf("Part of attack chain: %s (step %d/%d)", chainTitle, step, totalSteps)
}
