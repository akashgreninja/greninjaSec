package scanner

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
)

// SecretPattern defines a secret detection pattern
type SecretPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Description string
	Severity    string
}

// Common secret patterns
var secretPatterns = []SecretPattern{
	{
		ID:          "SECRET_AWS_ACCESS_KEY",
		Name:        "AWS Access Key ID",
		Pattern:     regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
		Description: "AWS Access Key ID exposed",
		Severity:    "CRITICAL",
	},
	{
		ID:          "SECRET_AWS_SECRET_KEY",
		Name:        "AWS Secret Access Key",
		Pattern:     regexp.MustCompile(`(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]`),
		Description: "AWS Secret Access Key exposed",
		Severity:    "CRITICAL",
	},
	{
		ID:          "SECRET_GITHUB_TOKEN",
		Name:        "GitHub Token",
		Pattern:     regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),
		Description: "GitHub Personal Access Token exposed",
		Severity:    "CRITICAL",
	},
	{
		ID:          "SECRET_GITHUB_OAUTH",
		Name:        "GitHub OAuth Token",
		Pattern:     regexp.MustCompile(`(?i)gho_[a-zA-Z0-9]{36}`),
		Description: "GitHub OAuth Access Token exposed",
		Severity:    "CRITICAL",
	},
	{
		ID:          "SECRET_GOOGLE_API_KEY",
		Name:        "Google API Key",
		Pattern:     regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
		Description: "Google API Key exposed",
		Severity:    "CRITICAL",
	},
	{
		ID:          "SECRET_SLACK_TOKEN",
		Name:        "Slack Token",
		Pattern:     regexp.MustCompile(`(?i)xox[baprs]-[0-9a-zA-Z\-]{10,48}`),
		Description: "Slack API Token exposed",
		Severity:    "CRITICAL",
	},
	{
		ID:          "SECRET_SLACK_WEBHOOK",
		Name:        "Slack Webhook",
		Pattern:     regexp.MustCompile(`(?i)https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
		Description: "Slack Webhook URL exposed",
		Severity:    "HIGH",
	},
	{
		ID:          "SECRET_PRIVATE_KEY",
		Name:        "Private Key",
		Pattern:     regexp.MustCompile(`(?i)-----BEGIN[ A-Z]*PRIVATE KEY-----`),
		Description: "Private cryptographic key exposed",
		Severity:    "CRITICAL",
	},
	{
		ID:          "SECRET_GENERIC_API_KEY",
		Name:        "Generic API Key",
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?token)[\s]*[=:]["']?([a-zA-Z0-9_\-]{20,})`),
		Description: "Possible API key in configuration",
		Severity:    "HIGH",
	},
	{
		ID:          "SECRET_PASSWORD",
		Name:        "Password in Code",
		Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd)[\s]*[=:]["']([^"'\s]{6,})`),
		Description: "Hardcoded password detected",
		Severity:    "HIGH",
	},
	{
		ID:          "SECRET_DOCKER_AUTH",
		Name:        "Docker Auth Token",
		Pattern:     regexp.MustCompile(`(?i)(?:dockerhub|docker).*(?:password|token|auth)[\s]*[=:]["']?([a-zA-Z0-9_\-]{20,})`),
		Description: "Docker authentication token exposed",
		Severity:    "HIGH",
	},
	{
		ID:          "SECRET_JWT",
		Name:        "JWT Token",
		Pattern:     regexp.MustCompile(`(?i)ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		Description: "JSON Web Token (JWT) exposed",
		Severity:    "MEDIUM",
	},
}

// scanFileForSecrets scans a single file for hardcoded secrets
func scanFileForSecrets(filePath string) []Finding {
	var findings []Finding

	// Skip binary files and common non-secret files
	if shouldSkipForSecrets(filePath) {
		return findings
	}

	file, err := os.Open(filePath)
	if err != nil {
		return findings
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comments (basic check)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check against all secret patterns
		for _, pattern := range secretPatterns {
			matches := pattern.Pattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				// Extract the actual secret value
				secretValue := ""
				if len(match) > 1 {
					secretValue = match[1]
				} else {
					secretValue = match[0]
				}

				// Redact the secret for display (show first/last 4 chars)
				redacted := redactSecret(secretValue)

				f := Finding{
					RuleID:   pattern.ID,
					Title:    pattern.Name,
					Severity: pattern.Severity,
					File:     filePath,
					Snippet:  formatSecretSnippet(lineNum, line, redacted),
				}
				findings = append(findings, f)
			}
		}

		// High entropy detection (potential secrets)
		if shouldCheckEntropy(line) {
			words := strings.Fields(line)
			for _, word := range words {
				// Clean the word
				cleaned := cleanWord(word)
				if len(cleaned) >= 20 && len(cleaned) <= 100 && !isLikelyFalsePositiveString(cleaned, line) {
					entropy := calculateEntropy(cleaned)
					if entropy > 4.8 { // Increased threshold to reduce false positives
						f := Finding{
							RuleID:   "SECRET_HIGH_ENTROPY",
							Title:    "High Entropy String (Possible Secret)",
							Severity: "MEDIUM",
							File:     filePath,
							Snippet:  formatSecretSnippet(lineNum, line, redactSecret(cleaned)),
						}
						findings = append(findings, f)
						break // Only report once per line
					}
				}
			}
		}
	}

	return findings
}

// shouldSkipForSecrets determines if a file should be skipped for secret scanning
func shouldSkipForSecrets(filePath string) bool {
	lower := strings.ToLower(filePath)

	// Skip binary and media files
	skipPatterns := []string{
		".lock", ".sum", ".svg", ".png", ".jpg",
		".gif", ".ico", ".woff", ".ttf", ".pdf",
		".bin", ".exe", ".so", ".dylib",
		"vendor/", "node_modules/",
	}

	for _, pattern := range skipPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// shouldCheckEntropy determines if a line should be checked for high entropy
func shouldCheckEntropy(line string) bool {
	lower := strings.ToLower(line)

	// Skip test files and documentation
	if strings.Contains(lower, "test") || strings.Contains(lower, "example") ||
		strings.Contains(lower, "mock") || strings.Contains(lower, "dummy") {
		return false
	}

	// Look for assignment patterns and secret-like contexts
	return (strings.Contains(lower, "=") ||
		strings.Contains(lower, ":") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "key") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "auth")) &&
		!strings.Contains(lower, "//") && // Skip comments
		!strings.Contains(lower, "#") // Skip comments
}

// cleanWord removes common delimiters and quotes from a word
func cleanWord(word string) string {
	cleaned := strings.Trim(word, `"':;,()[]{}`)
	return cleaned
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// redactSecret redacts a secret showing only first and last 4 characters
func redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "***REDACTED***"
	}
	return secret[:4] + "***REDACTED***" + secret[len(secret)-4:]
}

// formatSecretSnippet formats a snippet showing the line number and redacted secret
func formatSecretSnippet(lineNum int, line string, redacted string) string {
	// Limit line length
	if len(line) > 100 {
		line = line[:100] + "..."
	}
	return fmt.Sprintf("[Line %d] %s", lineNum, redacted)
}

// isLikelyFalsePositiveString checks if a high-entropy string is likely a false positive
func isLikelyFalsePositiveString(s, line string) bool {
	lower := strings.ToLower(s)
	lowerLine := strings.ToLower(line)

	// Common false positive patterns
	falsePositivePatterns := []string{
		"expected", "want", "got", "assert", "test", "example", "mock",
		"dummy", "fake", "sample", "lorem", "ipsum", "placeholder",
		"template", "schema", "protobuf", "proto", "generated",
		"spec", "config", "option", "param", "argument",
	}

	for _, pattern := range falsePositivePatterns {
		if strings.Contains(lower, pattern) || strings.Contains(lowerLine, pattern) {
			return true
		}
	}

	// Check for common programming patterns that generate high entropy
	if strings.Contains(lowerLine, "uuid") || strings.Contains(lowerLine, "guid") ||
		strings.Contains(lowerLine, "hash") || strings.Contains(lowerLine, "checksum") ||
		strings.Contains(lowerLine, "digest") || strings.Contains(lowerLine, "base64") {
		return true
	}

	// Check for repeated characters (often templates or placeholders)
	if hasRepeatedPatterns(s) {
		return true
	}

	return false
}

// hasRepeatedPatterns checks for repeated character patterns that suggest placeholders
func hasRepeatedPatterns(s string) bool {
	if len(s) < 8 {
		return false
	}

	// Check for patterns like "XXXXXXXX" or "abcdefgh" repeated
	for i := 2; i <= 8; i++ {
		if len(s)%i == 0 {
			pattern := s[:i]
			repeated := strings.Repeat(pattern, len(s)/i)
			if repeated == s {
				return true
			}
		}
	}

	// Check for sequential characters (abcd, 1234, etc.)
	sequential := 0
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1]+1 {
			sequential++
		}
	}

	// If more than 60% of characters are sequential, likely a placeholder
	return float64(sequential)/float64(len(s)) > 0.6
}
