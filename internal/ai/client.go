package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client handles communication with OpenWebUI API
type Client struct {
	config *Config
	cache  *RemediationCache
	client *http.Client
}

// NewClient creates a new AI client
func NewClient(config *Config) *Client {
	return &Client{
		config: config,
		cache:  NewRemediationCache(),
		client: &http.Client{
			Timeout: time.Duration(config.TimeoutSec) * time.Second,
		},
	}
}

// GetRemediation gets AI-powered remediation for a finding
func (c *Client) GetRemediation(req *RemediationRequest) (*RemediationResponse, error) {
	// Check cache first if enabled
	if c.config.CacheEnabled {
		cacheKey := c.getCacheKey(req)
		if cached, found := c.cache.Get(cacheKey); found {
			return cached, nil
		}
	}

	// Build the prompt for the AI
	prompt := c.buildPrompt(req)

	// Call OpenWebUI API
	response, err := c.callAPI(prompt)
	if err != nil {
		return &RemediationResponse{
			Error: fmt.Sprintf("AI API error: %v", err),
		}, err
	}

	// Parse AI response into structured format
	remediation := c.parseResponse(response, req)

	// Cache the result
	if c.config.CacheEnabled && remediation.Error == "" {
		cacheKey := c.getCacheKey(req)
		c.cache.Set(cacheKey, remediation)
	}

	return remediation, nil
}

// buildPrompt creates a detailed prompt for the AI
func (c *Client) buildPrompt(req *RemediationRequest) string {
	var prompt strings.Builder

	prompt.WriteString("You are a security expert helping fix vulnerabilities. ")
	prompt.WriteString("Provide a structured remediation plan in JSON format.\n\n")

	prompt.WriteString(fmt.Sprintf("**Finding:** %s\n", req.Title))
	prompt.WriteString(fmt.Sprintf("**Severity:** %s\n", req.Severity))
	prompt.WriteString(fmt.Sprintf("**File:** %s\n", req.FilePath))

	if req.CVEID != "" {
		prompt.WriteString(fmt.Sprintf("\n**CVE:** %s (CVSS: %s)\n", req.CVEID, req.CVSSScore))
		prompt.WriteString(fmt.Sprintf("**Package:** %s\n", req.PackageName))
		prompt.WriteString(fmt.Sprintf("**Current Version:** %s\n", req.InstalledVersion))
		if req.FixedVersion != "" {
			prompt.WriteString(fmt.Sprintf("**Fixed Version:** %s\n", req.FixedVersion))
		}
	}

	prompt.WriteString(fmt.Sprintf("\n**Code Context:**\n```\n%s\n```\n", req.CodeSnippet))

	if req.AttackChainContext != "" {
		prompt.WriteString(fmt.Sprintf("\n**Attack Chain Context:** %s\n", req.AttackChainContext))
	}

	prompt.WriteString("\n**Required Output Format (JSON):**\n")
	prompt.WriteString("{\n")
	prompt.WriteString(`  "summary": "One-line fix summary",` + "\n")
	prompt.WriteString(`  "explanation": "Detailed explanation of the vulnerability and fix",` + "\n")
	prompt.WriteString(`  "risk_analysis": "Why this is critical and impact if not fixed",` + "\n")
	prompt.WriteString(`  "code_patch": "Exact code changes needed (diff format if possible)",` + "\n")
	prompt.WriteString(`  "commands": ["Shell commands to fix (e.g., go get -u package@version)"],` + "\n")
	prompt.WriteString(`  "manual_steps": ["Step-by-step manual fix instructions"],` + "\n")
	prompt.WriteString(`  "alternate_fix": "Alternative fix approach if needed",` + "\n")
	prompt.WriteString(`  "confidence_score": 85.5,` + "\n")
	prompt.WriteString(`  "testing_steps": ["How to verify the fix works"],` + "\n")
	prompt.WriteString(`  "references": ["https://cve.org/...", "https://docs..."]` + "\n")
	prompt.WriteString("}\n\n")
	prompt.WriteString("**Important:**\n")
	prompt.WriteString("- Provide ONLY valid JSON in your response\n")
	prompt.WriteString("- Be specific with version numbers and commands\n")
	prompt.WriteString("- For CVEs, prioritize updating to the fixed version\n")
	prompt.WriteString("- For config issues, provide exact YAML/JSON/code patches\n")
	prompt.WriteString("- Include testing steps to verify the fix\n")

	return prompt.String()
}

// callAPI makes the HTTP request to OpenWebUI
func (c *Client) callAPI(prompt string) (string, error) {
	// Prepare request
	reqBody := OpenWebUIRequest{
		Model: c.config.Model,
		Messages: []Message{
			{
				Role:    "system",
				Content: "You are a cybersecurity expert specializing in vulnerability remediation. Always respond with valid JSON following the exact schema provided.",
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
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build endpoint URL
	endpoint := strings.TrimSuffix(c.config.APIEndpoint, "/") + "/chat/completions"

	// Create HTTP request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIToken)

	// Execute request with retries
	var resp *http.Response
	var lastErr error

	for i := 0; i < c.config.MaxRetries; i++ {
		resp, lastErr = c.client.Do(req)
		if lastErr == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second * time.Duration(i+1)) // Exponential backoff
	}

	if lastErr != nil {
		return "", fmt.Errorf("API request failed after %d retries: %w", c.config.MaxRetries, lastErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse OpenWebUI response
	var apiResp OpenWebUIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("failed to parse API response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return "", fmt.Errorf("API returned no choices")
	}

	return apiResp.Choices[0].Message.Content, nil
}

// parseResponse parses the AI response into RemediationResponse
func (c *Client) parseResponse(aiResponse string, req *RemediationRequest) *RemediationResponse {
	// Try to extract JSON from the response (AI might wrap it in markdown)
	jsonContent := c.extractJSON(aiResponse)

	var remediation RemediationResponse
	if err := json.Unmarshal([]byte(jsonContent), &remediation); err != nil {
		// If parsing fails, create a basic response with the raw content
		return &RemediationResponse{
			Summary:         "AI-generated fix (parsing failed)",
			Explanation:     aiResponse,
			ConfidenceScore: 50.0,
			Error:           fmt.Sprintf("Failed to parse JSON: %v", err),
		}
	}

	return &remediation
}

// extractJSON extracts JSON content from markdown code blocks or plain text
func (c *Client) extractJSON(content string) string {
	// Try to find JSON in markdown code blocks
	if strings.Contains(content, "```json") {
		start := strings.Index(content, "```json") + 7
		end := strings.Index(content[start:], "```")
		if end > 0 {
			return strings.TrimSpace(content[start : start+end])
		}
	}

	// Try to find JSON in generic code blocks
	if strings.Contains(content, "```") {
		start := strings.Index(content, "```") + 3
		end := strings.Index(content[start:], "```")
		if end > 0 {
			return strings.TrimSpace(content[start : start+end])
		}
	}

	// If no code blocks, try to find JSON object
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start >= 0 && end > start {
		return strings.TrimSpace(content[start : end+1])
	}

	return content
}

// getCacheKey generates a cache key for a remediation request
func (c *Client) getCacheKey(req *RemediationRequest) string {
	// Use CVE ID if available, otherwise use finding ID
	if req.CVEID != "" {
		return fmt.Sprintf("cve:%s:%s", req.CVEID, req.PackageName)
	}
	return fmt.Sprintf("finding:%s", req.FindingID)
}

// IsEnabled checks if AI remediation is enabled
func (c *Client) IsEnabled() bool {
	return c.config.Enabled
}
