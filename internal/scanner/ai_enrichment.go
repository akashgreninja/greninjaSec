package scanner

import (
	"fmt"
	"greninjaSec/internal/ai"
	"os"
	"strings"
)

// EnrichFindingsWithAI adds AI-powered remediation to findings
func (s *Scanner) EnrichFindingsWithAI(findings []Finding) ([]Finding, error) {
	// Load AI config
	config, err := ai.LoadConfig()
	if err != nil {
		return findings, fmt.Errorf("failed to load AI config: %w", err)
	}

	if !config.Enabled {
		return findings, fmt.Errorf("AI is not enabled in .env (set AI_ENABLED=true)")
	}

	// Create AI client
	client := ai.NewClient(config)

	fmt.Fprintf(os.Stderr, "🤖 Analyzing findings with AI (%s)...\n", config.Model)

	enrichedCount := 0
	totalToProcess := 0

	// Count findings that need remediation
	for _, finding := range findings {
		if shouldGetAIRemediation(finding) {
			totalToProcess++
		}
	}

	if totalToProcess == 0 {
		fmt.Fprintf(os.Stderr, "ℹ️  No CRITICAL/HIGH findings to analyze\n")
		return findings, nil
	}

	fmt.Fprintf(os.Stderr, "📊 Processing %d CRITICAL/HIGH findings...\n", totalToProcess)

	// Process findings
	for i := range findings {
		if !shouldGetAIRemediation(findings[i]) {
			continue
		}

		// Build remediation request
		req := buildRemediationRequest(&findings[i])

		// Get AI remediation
		fmt.Fprintf(os.Stderr, "   ⏳ Analyzing: %s...\n", truncateString(findings[i].Title, 60))
		
		resp, err := client.GetRemediation(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "   ⚠️  AI error: %v\n", err)
			continue
		}

		// Attach remediation to finding
		findings[i].AIRemediation = &AIRemediationData{
			Summary:         resp.Summary,
			Explanation:     resp.Explanation,
			RiskAnalysis:    resp.RiskAnalysis,
			CodePatch:       resp.CodePatch,
			Commands:        resp.Commands,
			ManualSteps:     resp.ManualSteps,
			AlternateFix:    resp.AlternateFix,
			ConfidenceScore: resp.ConfidenceScore,
			TestingSteps:    resp.TestingSteps,
			References:      resp.References,
		}

		enrichedCount++
		fmt.Fprintf(os.Stderr, "   ✅ Got fix (confidence: %.0f%%)\n", resp.ConfidenceScore)
	}

	fmt.Fprintf(os.Stderr, "✨ AI analysis complete: %d/%d findings enriched\n\n", enrichedCount, totalToProcess)

	return findings, nil
}

// shouldGetAIRemediation determines if a finding should get AI remediation
func shouldGetAIRemediation(finding Finding) bool {
	severity := strings.ToUpper(finding.Severity)
	
	// Only process CRITICAL and HIGH
	if severity != "CRITICAL" && severity != "HIGH" {
		return false
	}

	// Skip low-value linting issues
	lowValuePrefixes := []string{
		"HADOLINT_DL3009", // Delete apt-get lists
		"HADOLINT_DL3015", // --no-install-recommends
	}

	for _, prefix := range lowValuePrefixes {
		if strings.HasPrefix(finding.ID, prefix) {
			return false
		}
	}

	return true
}

// buildRemediationRequest creates an AI request from a finding
func buildRemediationRequest(finding *Finding) *ai.RemediationRequest {
	req := &ai.RemediationRequest{
		FindingID:   finding.ID,
		Severity:    finding.Severity,
		Title:       finding.Title,
		Description: finding.Message,
		FilePath:    finding.File,
		CodeSnippet: truncateString(finding.Snippet, 500), // Limit snippet size
	}

	// Extract CVE information if present
	if strings.Contains(finding.ID, "CVE") {
		req.CVEID = extractCVEID(finding.ID)
		// Try to extract package info from title or message
		req.PackageName = extractPackageName(finding.Title, finding.Message)
		req.CVSSScore = extractCVSS(finding.Message)
		req.FixedVersion = extractFixedVersion(finding.Message)
		req.InstalledVersion = extractInstalledVersion(finding.Message)
	}

	// Detect file type
	req.FileType = detectFileType(finding.File)

	return req
}

// Helper functions for extraction
func extractCVEID(id string) string {
	// Extract CVE-YYYY-NNNNN from ID like "CVE_CVE-2024-12345"
	parts := strings.Split(id, "_")
	for _, part := range parts {
		if strings.HasPrefix(part, "CVE-") {
			return part
		}
	}
	return ""
}

func extractPackageName(title, message string) string {
	// Try to find package name in message like "Package: golang.org/x/crypto"
	if idx := strings.Index(message, "Package: "); idx != -1 {
		rest := message[idx+9:]
		if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
			return rest[:spaceIdx]
		}
		if pipeIdx := strings.Index(rest, "|"); pipeIdx != -1 {
			return strings.TrimSpace(rest[:pipeIdx])
		}
	}
	return ""
}

func extractCVSS(message string) string {
	// Extract CVSS score like "CVSS: 9.8"
	if idx := strings.Index(message, "CVSS: "); idx != -1 {
		rest := message[idx+6:]
		if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
			return rest[:spaceIdx]
		}
		if pipeIdx := strings.Index(rest, "|"); pipeIdx != -1 {
			return strings.TrimSpace(rest[:pipeIdx])
		}
	}
	return ""
}

func extractFixedVersion(message string) string {
	// Extract fixed version like "Fixed: 1.2.3"
	if idx := strings.Index(message, "Fixed: "); idx != -1 {
		rest := message[idx+7:]
		if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
			return rest[:spaceIdx]
		}
		if pipeIdx := strings.Index(rest, "|"); pipeIdx != -1 {
			return strings.TrimSpace(rest[:pipeIdx])
		}
		return strings.TrimSpace(rest)
	}
	return ""
}

func extractInstalledVersion(message string) string {
	// Extract installed version like "Installed: 1.0.0"
	if idx := strings.Index(message, "Installed: "); idx != -1 {
		rest := message[idx+11:]
		if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
			return rest[:spaceIdx]
		}
		if pipeIdx := strings.Index(rest, "|"); pipeIdx != -1 {
			return strings.TrimSpace(rest[:pipeIdx])
		}
	}
	return ""
}

func detectFileType(filePath string) string {
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		if strings.Contains(filePath, "deployment") {
			return "kubernetes-deployment"
		}
		return "yaml"
	}
	if strings.Contains(filePath, "Dockerfile") || strings.Contains(filePath, "dockerfile") {
		return "dockerfile"
	}
	if strings.HasSuffix(filePath, ".tf") {
		return "terraform"
	}
	if strings.Contains(filePath, "go.mod") {
		return "go-module"
	}
	return "unknown"
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
