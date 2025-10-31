package shadow

import (
	"encoding/json"
	"fmt"
	"strings"
	"regexp"
	
	"greninjaSec/internal/ai"
)

// AIExploitTechnique represents an AI-discovered exploit technique
type AIExploitTechnique struct {
	Name             string            `json:"name"`
	Vector           string            `json:"vector"`
	Description      string            `json:"description"`
	Steps            []AIExploitStep   `json:"steps"`
	Impact           string            `json:"impact"`
	MitreAttack      string            `json:"mitre_attack"`
	WhyDangerous     string            `json:"why_dangerous"`
	RealWorldExample string            `json:"real_world_example"`
}

// AIExploitStep represents a step in an AI-discovered attack
type AIExploitStep struct {
	Description string `json:"description"`
	Command     string `json:"command"`
	Impact      string `json:"impact"`
}

// AIDefenseRecommendation represents an AI-generated defense
type AIDefenseRecommendation struct {
	Priority      int    `json:"priority"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Fix           string `json:"fix"`
	Impact        string `json:"impact"`
	Effort        string `json:"effort"`
	Effectiveness int    `json:"effectiveness"`
}

// AIExploitEnhancer uses AI to discover additional exploit techniques
type AIExploitEnhancer struct {
	client *ai.Client
	enabled bool
}

// NewAIExploitEnhancer creates a new AI-powered exploit enhancer
func NewAIExploitEnhancer(aiClient *ai.Client) *AIExploitEnhancer {
	return &AIExploitEnhancer{
		client: aiClient,
		enabled: aiClient != nil,
	}
}

// EnhanceAttackPaths uses AI to find additional exploit techniques
func (e *AIExploitEnhancer) EnhanceAttackPaths(vulns []Vulnerability, existingPaths []AttackPath) ([]AttackPath, error) {
	if !e.enabled {
		return existingPaths, nil
	}

	fmt.Println("\n🤖 AI Enhancement: Analyzing for advanced exploit techniques...")

	// Build context for AI
	context := e.buildVulnerabilityContext(vulns, existingPaths)
	
	// Ask AI for additional attack paths
	prompt := e.buildExploitPrompt(context)
	
	// Call AI API
	response, err := e.callAI(prompt)
	if err != nil {
		return existingPaths, fmt.Errorf("AI enhancement failed: %w", err)
	}

	// Parse AI response into attack paths
	aiPaths := e.parseAIResponse(response)
	
	fmt.Printf("      ✓ AI discovered %d additional attack techniques\n", len(aiPaths))

	// Combine with existing paths
	allPaths := append(existingPaths, aiPaths...)
	return allPaths, nil
}

// buildVulnerabilityContext creates context for AI
func (e *AIExploitEnhancer) buildVulnerabilityContext(vulns []Vulnerability, paths []AttackPath) string {
	var ctx strings.Builder
	
	ctx.WriteString("Current Vulnerabilities:\n")
	for i, v := range vulns {
		ctx.WriteString(fmt.Sprintf("%d. %s (%s) - %s\n", i+1, v.Type, v.Severity, v.Description))
	}
	
	ctx.WriteString("\nExisting Attack Paths Discovered:\n")
	for i, p := range paths {
		ctx.WriteString(fmt.Sprintf("%d. %s (Vector: %s, Impact: %s)\n", i+1, p.Name, p.Vector, p.Impact))
	}
	
	return ctx.String()
}

// buildExploitPrompt creates the AI prompt for exploit discovery
func (e *AIExploitEnhancer) buildExploitPrompt(context string) string {
	var prompt strings.Builder
	
	prompt.WriteString("You are an expert penetration tester and red team operator. ")
	prompt.WriteString("Analyze the following vulnerabilities and suggest ADDITIONAL creative exploit techniques ")
	prompt.WriteString("that go beyond standard playbooks.\n\n")
	
	prompt.WriteString(context)
	
	prompt.WriteString("\n\n**Your Task:**\n")
	prompt.WriteString("1. Identify exploit chains that combine multiple vulnerabilities\n")
	prompt.WriteString("2. Suggest creative lateral movement techniques\n")
	prompt.WriteString("3. Recommend privilege escalation paths\n")
	prompt.WriteString("4. Identify data exfiltration methods\n")
	prompt.WriteString("5. Suggest persistence mechanisms an attacker would use\n\n")
	
	prompt.WriteString("**Output Format (JSON Array):**\n")
	prompt.WriteString("[\n")
	prompt.WriteString("  {\n")
	prompt.WriteString(`    "name": "Exploit technique name",` + "\n")
	prompt.WriteString(`    "vector": "container_escape|lateral_movement|privilege_escalation|credential_theft|data_exfiltration|cloud_takeover",` + "\n")
	prompt.WriteString(`    "description": "Detailed description of the attack",` + "\n")
	prompt.WriteString(`    "steps": [` + "\n")
	prompt.WriteString(`      {` + "\n")
	prompt.WriteString(`        "description": "Step description",` + "\n")
	prompt.WriteString(`        "command": "Actual shell command to execute",` + "\n")
	prompt.WriteString(`        "impact": "CRITICAL|HIGH|MEDIUM|LOW"` + "\n")
	prompt.WriteString(`      }` + "\n")
	prompt.WriteString(`    ],` + "\n")
	prompt.WriteString(`    "impact": "CRITICAL|HIGH|MEDIUM",` + "\n")
	prompt.WriteString(`    "mitre_attack": "T1234 - Technique name",` + "\n")
	prompt.WriteString(`    "why_dangerous": "Explanation of why this is critical",` + "\n")
	prompt.WriteString(`    "real_world_example": "Reference to actual breaches using this technique"` + "\n")
	prompt.WriteString("  }\n")
	prompt.WriteString("]\n\n")
	
	prompt.WriteString("Focus on realistic, practical attacks. Be creative but stay technical.")
	
	return prompt.String()
}

// callAI makes the API call to AI service
func (e *AIExploitEnhancer) callAI(prompt string) (string, error) {
	// Use the existing AI client
	// Create a temporary request structure
	req := &ai.RemediationRequest{
		Title:       "Shadow Deploy Exploit Analysis",
		Severity:    "CRITICAL",
		FilePath:    "shadow-simulation",
		CodeSnippet: prompt,
	}
	
	response, err := e.client.GetRemediation(req)
	if err != nil {
		return "", err
	}
	
	// For now, return the explanation as raw response
	// TODO: Properly structure this
	return response.Explanation, nil
}

// parseAIResponse converts AI text response into AttackPath structures
func (e *AIExploitEnhancer) parseAIResponse(response string) []AttackPath {
	var paths []AttackPath
	
	// Extract JSON from response (AI might include explanatory text before/after JSON)
	jsonStr := e.extractJSON(response)
	if jsonStr == "" {
		// Fallback: create a generic path with the AI response as description
		return e.createFallbackPath(response)
	}
	
	// Parse AI techniques from JSON
	var aiTechniques []AIExploitTechnique
	if err := json.Unmarshal([]byte(jsonStr), &aiTechniques); err != nil {
		// If JSON parsing fails, create fallback with raw response
		return e.createFallbackPath(response)
	}
	
	// Convert AI techniques to AttackPath structures
	for i, technique := range aiTechniques {
		if len(technique.Steps) == 0 {
			continue // Skip techniques without steps
		}
		
		// Convert AI vector to our vector type (remove unused variable)
		
		// Convert AI steps to our steps
		var steps []AttackStep
		for j, aiStep := range technique.Steps {
			step := AttackStep{
				Number:      j + 1,
				Description: aiStep.Description,
				Command:     aiStep.Command,
				Success:     true, // Assume success for simulation
			}
			steps = append(steps, step)
		}
		
		// Create attack path from AI technique
		path := AttackPath{
			ID:          fmt.Sprintf("AI-%d", i+1),
			Name:        fmt.Sprintf("🤖 AI-Discovered: %s", technique.Name),
			Vector:      e.mapAIVectorToVector(technique.Vector),
			Description: fmt.Sprintf("%s\n\n🎯 MITRE ATT&CK: %s\n⚠️  Why Dangerous: %s\n📖 Real-world Example: %s", 
				technique.Description, technique.MitreAttack, technique.WhyDangerous, technique.RealWorldExample),
			Impact:      e.mapAIImpactToImpact(technique.Impact),
			Steps:       steps,
			Success:     true,
		}
		
		paths = append(paths, path)
	}
	
	return paths
}

// extractJSON finds and extracts JSON array from AI response
func (e *AIExploitEnhancer) extractJSON(response string) string {
	// Look for JSON array patterns
	jsonRegex := regexp.MustCompile(`\[\s*\{[\s\S]*?\}\s*\]`)
	matches := jsonRegex.FindStringSubmatch(response)
	
	if len(matches) > 0 {
		return matches[0]
	}
	
	// Try to find individual JSON objects and wrap in array
	objRegex := regexp.MustCompile(`\{[\s\S]*?"name"[\s\S]*?\}`)
	objMatches := objRegex.FindAllString(response, -1)
	
	if len(objMatches) > 0 {
		// Wrap individual objects in array
		return "[" + strings.Join(objMatches, ",") + "]"
	}
	
	return ""
}

// createFallbackPath creates a generic path when JSON parsing fails
func (e *AIExploitEnhancer) createFallbackPath(response string) []AttackPath {
	// Only create fallback if response seems to contain exploit information
	if !strings.Contains(strings.ToLower(response), "exploit") && 
	   !strings.Contains(strings.ToLower(response), "attack") &&
	   !strings.Contains(strings.ToLower(response), "technique") {
		return []AttackPath{}
	}
	
	// Create a generic AI-discovered path
	aiPath := AttackPath{
		ID:          "AI-GENERIC-1",
		Name:        "🤖 AI-Discovered: Advanced Technique",
		Vector:      VectorPrivilegeEscalation,
		Description: fmt.Sprintf("AI analysis revealed additional attack surface:\n\n%s", truncateString(response, 500)),
		Impact:      ImpactHigh,
		Steps: []AttackStep{
			{
				Number:      1,
				Description: "AI-suggested technique: " + truncateString(response, 200),
				Command:     "# See full AI analysis in description",
				Success:     true,
			},
		},
	}
	
	return []AttackPath{aiPath}
}

// mapAIVectorToVector converts AI vector strings to our AttackVector type
func (e *AIExploitEnhancer) mapAIVectorToVector(aiVector string) AttackVector {
	switch strings.ToLower(aiVector) {
	case "container_escape":
		return VectorContainerEscape
	case "lateral_movement":
		return VectorLateralMovement
	case "privilege_escalation":
		return VectorPrivilegeEscalation
	case "credential_theft":
		return VectorCredentialTheft
	case "data_exfiltration":
		return VectorDataExfiltration
	case "cloud_takeover":
		return VectorCloudTakeover
	default:
		return VectorPrivilegeEscalation // Default fallback
	}
}

// mapAIImpactToImpact converts AI impact strings to our ImpactLevel type
func (e *AIExploitEnhancer) mapAIImpactToImpact(aiImpact string) ImpactLevel {
	switch strings.ToUpper(aiImpact) {
	case "CRITICAL":
		return ImpactCritical
	case "HIGH":
		return ImpactHigh
	case "MEDIUM":
		return ImpactMedium
	case "LOW":
		return ImpactLow
	default:
		return ImpactHigh // Default fallback
	}
}

// SuggestDefenses uses AI to recommend defenses against attack paths
func (e *AIExploitEnhancer) SuggestDefenses(simulation ShadowSimulation) ([]Recommendation, error) {
	if !e.enabled {
		return []Recommendation{}, nil
	}

	fmt.Println("\n🛡️  AI Enhancement: Generating defense recommendations...")

	// Build attack summary for AI
	attackSummary := e.summarizeAttacks(simulation)
	
	prompt := e.buildDefensePrompt(attackSummary)
	
	response, err := e.callAI(prompt)
	if err != nil {
		return []Recommendation{}, err
	}

	recommendations := e.parseDefenseResponse(response)
	
	fmt.Printf("      ✓ AI generated %d prioritized recommendations\n", len(recommendations))
	
	return recommendations, nil
}

// summarizeAttacks creates a summary of successful attack paths
func (e *AIExploitEnhancer) summarizeAttacks(sim ShadowSimulation) string {
	var summary strings.Builder
	
	summary.WriteString(fmt.Sprintf("Target: %s\n", sim.TargetType))
	summary.WriteString(fmt.Sprintf("Attack Success Rate: %.0f%%\n", sim.SuccessRate))
	summary.WriteString(fmt.Sprintf("Time to Compromise: %s\n", sim.TimeToCompromise))
	summary.WriteString(fmt.Sprintf("Systems Compromised: %d\n\n", sim.BlastRadius.SystemsCompromised))
	
	summary.WriteString("Successful Attack Paths:\n")
	for i, path := range sim.AttackPaths {
		if path.Success {
			summary.WriteString(fmt.Sprintf("%d. %s (Vector: %s, Impact: %s)\n", 
				i+1, path.Name, path.Vector, path.Impact))
		}
	}
	
	return summary.String()
}

// buildDefensePrompt creates prompt for defense recommendations
func (e *AIExploitEnhancer) buildDefensePrompt(attackSummary string) string {
	var prompt strings.Builder
	
	prompt.WriteString("You are a security architect tasked with defending against the following successful attacks:\n\n")
	prompt.WriteString(attackSummary)
	prompt.WriteString("\n\n**Your Task:**\n")
	prompt.WriteString("Provide prioritized, actionable defense recommendations in JSON format:\n\n")
	prompt.WriteString("[\n")
	prompt.WriteString("  {\n")
	prompt.WriteString(`    "priority": 1,` + "\n")
	prompt.WriteString(`    "title": "Short recommendation title",` + "\n")
	prompt.WriteString(`    "description": "Detailed explanation",` + "\n")
	prompt.WriteString(`    "fix": "Exact configuration/code changes needed",` + "\n")
	prompt.WriteString(`    "impact": "What this prevents",` + "\n")
	prompt.WriteString(`    "effort": "low|medium|high",` + "\n")
	prompt.WriteString(`    "effectiveness": "Percentage of attacks this blocks (0-100)"` + "\n")
	prompt.WriteString("  }\n")
	prompt.WriteString("]\n\n")
	prompt.WriteString("Focus on defense-in-depth. Prioritize by impact vs. effort.")
	
	return prompt.String()
}

// parseDefenseResponse converts AI defense suggestions to recommendations
func (e *AIExploitEnhancer) parseDefenseResponse(response string) []Recommendation {
	var recommendations []Recommendation
	
	// Extract JSON from response
	jsonStr := e.extractJSON(response)
	if jsonStr == "" {
		// Fallback: create a generic recommendation
		return e.createFallbackRecommendations(response)
	}
	
	// Parse AI recommendations from JSON
	var aiRecommendations []AIDefenseRecommendation
	if err := json.Unmarshal([]byte(jsonStr), &aiRecommendations); err != nil {
		return e.createFallbackRecommendations(response)
	}
	
	// Convert AI recommendations to our format
	for _, aiRec := range aiRecommendations {
		rec := Recommendation{
			Priority:    aiRec.Priority,
			Title:       aiRec.Title,
			Description: fmt.Sprintf("%s\n\n💡 Fix: %s\n📈 Effort: %s\n🎯 Effectiveness: %d%%", 
				aiRec.Description, aiRec.Fix, aiRec.Effort, aiRec.Effectiveness),
			Fix:         aiRec.Fix,
			Impact:      aiRec.Impact,
		}
		recommendations = append(recommendations, rec)
	}
	
	return recommendations
}

// createFallbackRecommendations creates generic recommendations when JSON parsing fails
func (e *AIExploitEnhancer) createFallbackRecommendations(response string) []Recommendation {
	return []Recommendation{
		{
			Priority:    1,
			Title:       "🤖 AI-Generated Security Recommendation",
			Description: fmt.Sprintf("AI Analysis Result:\n\n%s", truncateString(response, 500)),
			Fix:         "Review the AI analysis above for detailed remediation steps",
			Impact:      "Reduces attack surface based on AI analysis",
		},
	}
}

// ExplainAttackChain uses AI to generate a human-readable attack narrative
func (e *AIExploitEnhancer) ExplainAttackChain(path AttackPath) (string, error) {
	if !e.enabled {
		return "", nil
	}

	// Build context
	var context strings.Builder
	context.WriteString(fmt.Sprintf("Attack: %s\n", path.Name))
	context.WriteString(fmt.Sprintf("Vector: %s\n", path.Vector))
	context.WriteString(fmt.Sprintf("Impact: %s\n\n", path.Impact))
	context.WriteString("Steps:\n")
	
	for _, step := range path.Steps {
		context.WriteString(fmt.Sprintf("%d. %s\n", step.Number, step.Description))
		context.WriteString(fmt.Sprintf("   Command: %s\n", step.Command))
	}

	prompt := fmt.Sprintf(`Explain the following attack chain in a way that executives and non-technical stakeholders can understand:

%s

Provide:
1. A brief summary (2-3 sentences)
2. Business impact in dollar terms
3. Real-world example of similar attacks
4. Why immediate action is needed

Use clear, non-technical language.`, context.String())

	response, err := e.callAI(prompt)
	if err != nil {
		return "", err
	}

	return response, nil
}

// Helper function
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
