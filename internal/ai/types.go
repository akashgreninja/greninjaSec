package ai

// RemediationRequest contains the context needed for AI to suggest a fix
type RemediationRequest struct {
	// Finding details
	FindingID   string `json:"finding_id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`

	// CVE-specific (if applicable)
	CVEID            string `json:"cve_id,omitempty"`
	CVSSScore        string `json:"cvss_score,omitempty"`
	PackageName      string `json:"package_name,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`

	// File context
	FilePath    string `json:"file_path"`
	FileType    string `json:"file_type"` // go.mod, Dockerfile, deployment.yaml, etc.
	CodeSnippet string `json:"code_snippet"`
	LineNumber  int    `json:"line_number,omitempty"`

	// Additional context
	AttackChainContext string `json:"attack_chain_context,omitempty"` // If part of an attack chain
}

// RemediationResponse contains the AI-generated fix suggestion
type RemediationResponse struct {
	// Fix description
	Summary      string `json:"summary"`       // One-line fix summary
	Explanation  string `json:"explanation"`   // Detailed explanation of the fix
	RiskAnalysis string `json:"risk_analysis"` // Why this is critical

	// Actionable fixes
	CodePatch    string   `json:"code_patch,omitempty"`     // Actual code changes (diff format)
	Commands     []string `json:"commands,omitempty"`       // Shell commands to run (e.g., go get -u package@version)
	ManualSteps  []string `json:"manual_steps,omitempty"`   // Manual steps if auto-fix isn't possible
	AlternateFix string   `json:"alternate_fix,omitempty"`  // Alternative approach

	// Metadata
	ConfidenceScore float64 `json:"confidence_score"` // 0-100, how confident AI is in this fix
	TestingSteps    []string `json:"testing_steps,omitempty"`
	References      []string `json:"references,omitempty"` // Links to documentation, CVE details, etc.
	
	// Processing info
	Error string `json:"error,omitempty"` // Error message if remediation failed
}

// OpenWebUIRequest is the request format for OpenWebUI API
type OpenWebUIRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

// OpenWebUIResponse is the response format from OpenWebUI API
type OpenWebUIResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`    // "system", "user", or "assistant"
	Content string `json:"content"` // Message content
}

// RemediationCache stores AI responses to avoid redundant API calls
type RemediationCache struct {
	Responses map[string]*RemediationResponse // Key: finding ID or CVE ID
}

// NewRemediationCache creates a new cache
func NewRemediationCache() *RemediationCache {
	return &RemediationCache{
		Responses: make(map[string]*RemediationResponse),
	}
}

// Get retrieves a cached response
func (c *RemediationCache) Get(key string) (*RemediationResponse, bool) {
	resp, exists := c.Responses[key]
	return resp, exists
}

// Set stores a response in cache
func (c *RemediationCache) Set(key string, response *RemediationResponse) {
	c.Responses[key] = response
}
