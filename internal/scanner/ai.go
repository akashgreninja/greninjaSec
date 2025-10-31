package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

	// Prepare findings summary for AI
	findingsSummary := prepareFindingsSummary(findings)

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
4. Focus on HIGH and CRITICAL severity chains

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
				summary.WriteString(fmt.Sprintf("  - %s: %s (File: %s)\n", f.RuleID, f.Title, f.File))
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
