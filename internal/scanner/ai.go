package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
)

// AIConfig holds OpenWebUI configuration
type AIConfig struct {
	URL     string
	Token   string
	Model   string
	Enabled bool
}

// LoadAIConfig loads configuration from environment variables
func LoadAIConfig() AIConfig {
	return AIConfig{
		URL:     getEnv("OPENWEBUI_URL", ""),
		Token:   getEnv("OPENWEBUI_TOKEN", ""),
		Model:   getEnv("AI_MODEL", "gpt-3.5-turbo"),
		Enabled: getEnv("AI_ENABLED", "false") == "true",
	}
}

// getEnv gets environment variable with default fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// AIEnhancedChainAnalysis uses AI to discover additional attack chains
func AIEnhancedChainAnalysis(findings []Finding, ruleBasedChains []AttackChain) ([]AttackChain, error) {
	config := LoadAIConfig()

	if !config.Enabled || config.URL == "" || config.Token == "" {
		return ruleBasedChains, nil // Return rule-based chains only
	}

	// Filter and prioritize findings for AI analysis
	prioritizedFindings := filterAndPrioritizeFindings(findings)

	// Skip AI analysis if no high-priority findings
	if len(prioritizedFindings) == 0 {
		fmt.Fprintf(os.Stderr, "ℹ️  No high-priority findings for AI analysis\n")
		return ruleBasedChains, nil
	}

	// Prepare optimized findings summary for AI
	findingsSummary := prepareOptimizedFindingsSummary(prioritizedFindings)

	// Check if prompt would exceed reasonable size
	estimatedTokens := estimateTokenCount(findingsSummary)
	maxTokens := 800000 // Conservative limit to stay under context window

	if estimatedTokens > maxTokens {
		// Further reduce findings if still too large
		prioritizedFindings = reduceFindingsForContext(prioritizedFindings, maxTokens)
		findingsSummary = prepareOptimizedFindingsSummary(prioritizedFindings)
		fmt.Fprintf(os.Stderr, "ℹ️  Reduced findings to %d for AI analysis due to size constraints\n", len(prioritizedFindings))
	}

	// Create AI prompt
	prompt := fmt.Sprintf(`You are an expert red team security analyst. Analyze these security findings and identify realistic attack chains.

FINDINGS SUMMARY:
%s

EXISTING DETECTED CHAINS:
%s

TASK:
1. Identify any ADDITIONAL attack chains not already detected
2. Look for non-obvious correlations between findings
3. Consider real-world attack patterns
4. Focus on HIGH and CRITICAL severity chains only

Return ONLY a JSON array of attack chains in this format:
[
  {
    "name": "Attack Chain Name",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "likelihood": "HIGH|MEDIUM|LOW", 
    "impact": "Description of worst-case impact",
    "steps": [
      {
        "step": 1,
        "finding_id": "FINDING_ID",
        "description": "What attacker does in this step"
      }
    ],
    "remediation": "Specific steps to fix"
  }
]

Return EMPTY array [] if no additional chains found. Do not include chains already detected.`,
		findingsSummary,
		summarizeExistingChains(ruleBasedChains))

	// Call OpenWebUI API
	aiChains, err := callOpenWebUI(config, prompt)
	if err != nil {
		// AI failed, but don't break the scan - return rule-based chains
		fmt.Fprintf(os.Stderr, "⚠️  AI analysis failed: %v (continuing with rule-based chains)\n", err)
		return ruleBasedChains, nil
	}

	// Merge rule-based and AI-discovered chains
	allChains := append(ruleBasedChains, aiChains...)
	return allChains, nil
}

// prepareFindingsSummary creates a concise summary of findings for AI
func prepareFindingsSummary(findings []Finding) string {
	var summary strings.Builder

	// Group by severity
	bySeverity := make(map[string][]Finding)
	for _, f := range findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if findings, ok := bySeverity[severity]; ok && len(findings) > 0 {
			summary.WriteString(fmt.Sprintf("\n%s (%d findings):\n", severity, len(findings)))
			for _, f := range findings {
				summary.WriteString(fmt.Sprintf("  - %s: %s (File: %s)\n", f.ID, f.Title, f.File))
			}
		}
	}

	return summary.String()
}

// summarizeExistingChains creates summary of already-detected chains
func summarizeExistingChains(chains []AttackChain) string {
	if len(chains) == 0 {
		return "None detected by rule-based analysis"
	}

	var summary strings.Builder
	for _, chain := range chains {
		summary.WriteString(fmt.Sprintf("- %s (Severity: %s)\n", chain.Name, chain.Severity))
	}
	return summary.String()
}

// OpenWebUIRequest represents the API request format
type OpenWebUIRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenWebUIResponse represents the API response
type OpenWebUIResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}

// callOpenWebUI sends request to OpenWebUI API
func callOpenWebUI(config AIConfig, prompt string) ([]AttackChain, error) {
	// Prepare request
	reqBody := OpenWebUIRequest{
		Model: config.Model,
		Messages: []Message{
			{
				Role:    "system",
				Content: "You are an expert red team security analyst specializing in infrastructure security and attack chain analysis. Provide concise, actionable security analysis.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create HTTP request
	url := strings.TrimSuffix(config.URL, "/") + "/chat/completions"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.Token)

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp OpenWebUIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	if len(apiResp.Choices) == 0 {
		return []AttackChain{}, nil
	}

	// Extract JSON from AI response
	content := apiResp.Choices[0].Message.Content

	// Try to extract JSON array from response (AI might wrap it in markdown)
	content = extractJSONArray(content)

	// Parse attack chains
	var aiChains []AttackChain
	if err := json.Unmarshal([]byte(content), &aiChains); err != nil {
		return nil, fmt.Errorf("failed to parse AI chains: %v (response: %s)", err, content)
	}

	// Assign IDs to AI-discovered chains
	for i := range aiChains {
		aiChains[i].ID = fmt.Sprintf("AI-CHAIN-%03d", i+1)
	}

	return aiChains, nil
}

// extractJSONArray extracts JSON array from markdown-wrapped response
func extractJSONArray(content string) string {
	// Remove markdown code blocks if present
	content = strings.ReplaceAll(content, "```json", "")
	content = strings.ReplaceAll(content, "```", "")
	content = strings.TrimSpace(content)

	// Find array boundaries
	start := strings.Index(content, "[")
	end := strings.LastIndex(content, "]")

	if start != -1 && end != -1 && end > start {
		return content[start : end+1]
	}

	return content
}

// filterAndPrioritizeFindings filters out false positives and prioritizes findings for AI analysis
func filterAndPrioritizeFindings(findings []Finding) []Finding {
	var prioritized []Finding

	// Priority scoring: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1
	severityPriority := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}

	// Filter out likely false positives
	for _, f := range findings {
		if isLikelyFalsePositive(f) {
			continue
		}
		// Include CRITICAL, HIGH, and some MEDIUM findings for AI analysis
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" ||
			(f.Severity == "MEDIUM" && !strings.Contains(strings.ToLower(f.File), "_test.go")) {
			prioritized = append(prioritized, f)
		}
	}

	// Sort by severity (highest first) and deduplicate similar findings
	sort.Slice(prioritized, func(i, j int) bool {
		return severityPriority[prioritized[i].Severity] > severityPriority[prioritized[j].Severity]
	})

	// Deduplicate and limit findings
	deduped := deduplicateFindings(prioritized)

	// Limit to most important findings to stay within context
	if len(deduped) > 100 {
		return deduped[:100]
	}

	return deduped
}

// isLikelyFalsePositive determines if a finding is likely a false positive
func isLikelyFalsePositive(f Finding) bool {
	file := strings.ToLower(f.File)
	snippet := strings.ToLower(f.Snippet)

	// Skip test files with obvious test data
	if strings.Contains(file, "_test.go") || strings.Contains(file, "/test/") {
		// Allow only truly dangerous secrets in test files
		if f.ID == "SECRET_HIGH_ENTROPY" {
			return true
		}
		// Check for test patterns in snippets
		testPatterns := []string{"test", "example", "mock", "dummy", "fake", "sample"}
		for _, pattern := range testPatterns {
			if strings.Contains(snippet, pattern) || strings.Contains(file, pattern) {
				return true
			}
		}
	}

	// Filter out common false positive patterns for high entropy strings
	if f.ID == "SECRET_HIGH_ENTROPY" {
		falsePositivePatterns := []string{
			"expected", "want", "got", "assert", "test", "example",
			"lorem", "ipsum", "placeholder", "template", "schema",
			"protobuf", "proto", "generated", "uuid", "guid",
			"hex", "hash", "checksum", "digest", "base64",
		}

		for _, pattern := range falsePositivePatterns {
			if strings.Contains(snippet, pattern) || strings.Contains(file, pattern) {
				return true
			}
		}

		// Skip very common variable names that trigger entropy
		commonVarPatterns := []string{
			"expe", "want", "got", "name", "type", "spec", "conf",
			"opts", "args", "params", "meta", "data", "info",
		}

		for _, pattern := range commonVarPatterns {
			if strings.Contains(snippet, pattern) {
				return true
			}
		}
	}

	// Skip documentation and config template files
	if strings.Contains(file, ".md") || strings.Contains(file, "readme") ||
		strings.Contains(file, ".example") || strings.Contains(file, "template") {
		return true
	}

	return false
}

// deduplicateFindings removes duplicate or very similar findings
func deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding

	for _, f := range findings {
		// Create a key based on rule + file + general location
		key := fmt.Sprintf("%s:%s", f.ID, f.File)

		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	return unique
}

// prepareOptimizedFindingsSummary creates a concise, optimized summary for AI
func prepareOptimizedFindingsSummary(findings []Finding) string {
	var summary strings.Builder

	// Group by severity and type
	bySeverity := make(map[string]map[string][]Finding)
	for _, f := range findings {
		if bySeverity[f.Severity] == nil {
			bySeverity[f.Severity] = make(map[string][]Finding)
		}
		bySeverity[f.Severity][f.ID] = append(bySeverity[f.Severity][f.ID], f)
	}

	// Output in priority order with compact format
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if ruleFindings, ok := bySeverity[severity]; ok && len(ruleFindings) > 0 {
			summary.WriteString(fmt.Sprintf("\n%s SEVERITY:\n", severity))

			for ruleID, ruleFindings := range ruleFindings {
				fileList := make(map[string]int)
				for _, f := range ruleFindings {
					fileList[f.File]++
				}

				// Compact representation
				var files []string
				for file, count := range fileList {
					if count > 1 {
						files = append(files, fmt.Sprintf("%s(x%d)", shortenPath(file), count))
					} else {
						files = append(files, shortenPath(file))
					}
				}

				summary.WriteString(fmt.Sprintf("  %s [%s]: %s\n",
					ruleID, ruleFindings[0].Title, strings.Join(files, ", ")))
			}
		}
	}

	return summary.String()
}

// shortenPath shortens file paths for compact display
func shortenPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 3 {
		return ".../" + strings.Join(parts[len(parts)-2:], "/")
	}
	return path
}

// estimateTokenCount estimates the number of tokens in text (rough approximation)
func estimateTokenCount(text string) int {
	// Rough estimate: 1 token ≈ 4 characters
	return len(text) / 4
}

// reduceFindingsForContext reduces findings to fit within context constraints
func reduceFindingsForContext(findings []Finding, maxTokens int) []Finding {
	if len(findings) == 0 {
		return findings
	}

	// Start with highest priority findings and add until we approach limit
	var reduced []Finding
	currentSize := 0

	// Reserve tokens for prompt structure
	reservedTokens := 1000
	availableTokens := maxTokens - reservedTokens

	for _, f := range findings {
		// Estimate tokens for this finding
		findingText := fmt.Sprintf("%s %s %s", f.ID, f.Title, f.File)
		findingTokens := estimateTokenCount(findingText)

		if currentSize+findingTokens > availableTokens {
			break
		}

		reduced = append(reduced, f)
		currentSize += findingTokens
	}

	return reduced
}
