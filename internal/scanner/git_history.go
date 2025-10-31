package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// GitSecretFinding represents a secret found in Git history
type GitSecretFinding struct {
	SecretType    string    `json:"secret_type"`
	Pattern       string    `json:"pattern"`
	FilePath      string    `json:"file_path"`
	CommitHash    string    `json:"commit_hash"`
	Author        string    `json:"author"`
	Date          time.Time `json:"date"`
	DaysExposed   int       `json:"days_exposed"`
	StillInRepo   bool      `json:"still_in_repo"`
	SecretValue   string    `json:"secret_value,omitempty"` // Masked version
	IsStillActive bool      `json:"is_still_active"`        // If we validated it
	DeletedIn     string    `json:"deleted_in,omitempty"`   // Commit where it was removed
}

// ScanGitHistory scans entire Git history for secrets
func ScanGitHistory(repoPath string) ([]GitSecretFinding, error) {
	// Check if this is a Git repository
	gitDir := filepath.Join(repoPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("not a git repository: %s", repoPath)
	}

	var findings []GitSecretFinding

	// Get all commits with their patches
	cmd := exec.Command("git", "log", "-p", "--all", "--reverse")
	cmd.Dir = repoPath

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run git log: %w", err)
	}

	// Parse the git log output
	commits := parseGitLog(string(output))

	fmt.Fprintf(os.Stderr, "🔍 Scanning %d commits in Git history...\n", len(commits))

	// Scan each commit for secrets
	for i, commit := range commits {
		if i%100 == 0 && i > 0 {
			fmt.Fprintf(os.Stderr, "   Progress: %d/%d commits scanned\n", i, len(commits))
		}

		secretsInCommit := scanCommitForSecrets(commit)
		findings = append(findings, secretsInCommit...)
	}

	// Calculate exposure timeline and check if still in repo
	findings = enrichGitFindings(findings, repoPath)

	fmt.Fprintf(os.Stderr, "✅ Found %d secrets in Git history\n", len(findings))

	return findings, nil
}

// GitCommit represents a parsed Git commit
type GitCommit struct {
	Hash      string
	Author    string
	Date      time.Time
	Message   string
	Diff      string
	FilePaths []string
}

// parseGitLog parses git log -p output into structured commits
func parseGitLog(logOutput string) []GitCommit {
	var commits []GitCommit
	var current *GitCommit

	lines := strings.Split(logOutput, "\n")
	var diffLines []string

	for _, line := range lines {
		if strings.HasPrefix(line, "commit ") {
			// Save previous commit
			if current != nil {
				current.Diff = strings.Join(diffLines, "\n")
				commits = append(commits, *current)
			}

			// Start new commit
			current = &GitCommit{
				Hash: strings.TrimPrefix(line, "commit "),
			}
			diffLines = []string{}

		} else if current != nil {
			if strings.HasPrefix(line, "Author: ") {
				current.Author = strings.TrimPrefix(line, "Author: ")
			} else if strings.HasPrefix(line, "Date: ") {
				dateStr := strings.TrimPrefix(line, "Date: ")
				dateStr = strings.TrimSpace(dateStr)
				// Parse git date format
				if t, err := time.Parse("Mon Jan 2 15:04:05 2006 -0700", dateStr); err == nil {
					current.Date = t
				}
			} else if strings.HasPrefix(line, "diff --git") {
				// Extract file path
				parts := strings.Fields(line)
				if len(parts) >= 4 {
					filePath := strings.TrimPrefix(parts[2], "a/")
					current.FilePaths = append(current.FilePaths, filePath)
				}
			} else if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				// This is an added line (potential secret)
				diffLines = append(diffLines, line)
			}
		}
	}

	// Save last commit
	if current != nil {
		current.Diff = strings.Join(diffLines, "\n")
		commits = append(commits, *current)
	}

	return commits
}

// scanCommitForSecrets scans a single commit's diff for secrets
func scanCommitForSecrets(commit GitCommit) []GitSecretFinding {
	var findings []GitSecretFinding

	// Use the same secret patterns from secrets.go
	patterns := getSecretPatterns()

	scanner := bufio.NewScanner(strings.NewReader(commit.Diff))
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// Skip if not an added line
		if !strings.HasPrefix(line, "+") {
			continue
		}

		// Remove the + prefix
		content := strings.TrimPrefix(line, "+")

		// Check against all patterns
		for _, pattern := range patterns {
			if pattern.Pattern.MatchString(content) {
				matches := pattern.Pattern.FindStringSubmatch(content)
				secretValue := ""
				if len(matches) > 1 {
					secretValue = matches[1]
				}

				// Determine which file this is from
				filePath := "unknown"
				if len(commit.FilePaths) > 0 {
					filePath = commit.FilePaths[0] // Simplified - could be improved
				}

				finding := GitSecretFinding{
					SecretType:  pattern.Name,
					Pattern:     pattern.Description,
					FilePath:    filePath,
					CommitHash:  commit.Hash,
					Author:      commit.Author,
					Date:        commit.Date,
					SecretValue: maskSecret(secretValue),
					StillInRepo: true, // Will be updated later
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// enrichGitFindings adds timeline info and checks if secrets still exist
func enrichGitFindings(findings []GitSecretFinding, repoPath string) []GitSecretFinding {
	// Group findings by file path and secret value (to track duplicates)
	secretTracker := make(map[string]*GitSecretFinding)

	for i := range findings {
		key := findings[i].FilePath + ":" + findings[i].SecretValue

		// Calculate days exposed (from commit date to now)
		findings[i].DaysExposed = int(time.Since(findings[i].Date).Hours() / 24)

		// Check if this secret still exists in current files
		findings[i].StillInRepo = checkIfSecretInCurrentRepo(repoPath, findings[i].FilePath, findings[i].SecretValue)

		// Track first occurrence
		if existing, exists := secretTracker[key]; exists {
			// This is a duplicate - update the original with deletion info if this one was deleted
			if !findings[i].StillInRepo && existing.StillInRepo {
				existing.DeletedIn = findings[i].CommitHash
			}
		} else {
			secretTracker[key] = &findings[i]
		}
	}

	return findings
}

// checkIfSecretInCurrentRepo checks if a secret still exists in the current working tree
func checkIfSecretInCurrentRepo(repoPath, filePath, secretValue string) bool {
	fullPath := filepath.Join(repoPath, filePath)

	content, err := os.ReadFile(fullPath)
	if err != nil {
		return false // File doesn't exist = not in repo
	}

	// Check if the secret value (unmasked part) is in the file
	unmaskedPart := strings.TrimRight(secretValue, "*")
	return strings.Contains(string(content), unmaskedPart)
}

// maskSecret masks most of the secret value for display
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}

	// Show first 4 and last 4 chars
	visible := 4
	return secret[:visible] + strings.Repeat("*", len(secret)-visible*2) + secret[len(secret)-visible:]
}

// getSecretPatterns returns the same patterns used in secrets.go
func getSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{
			ID:          "SECRET_AWS_ACCESS_KEY",
			Name:        "AWS Access Key ID",
			Pattern:     regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
			Description: "AWS Access Key ID",
			Severity:    "CRITICAL",
		},
		{
			ID:          "SECRET_AWS_SECRET_KEY",
			Name:        "AWS Secret Access Key",
			Pattern:     regexp.MustCompile(`(?i)aws_secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})`),
			Description: "AWS Secret Access Key",
			Severity:    "CRITICAL",
		},
		{
			ID:          "SECRET_GITHUB_TOKEN",
			Name:        "GitHub Token",
			Pattern:     regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
			Description: "GitHub Personal Access Token",
			Severity:    "CRITICAL",
		},
		{
			ID:          "SECRET_GOOGLE_API",
			Name:        "Google API Key",
			Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			Description: "Google API Key",
			Severity:    "HIGH",
		},
		{
			ID:          "SECRET_SLACK_TOKEN",
			Name:        "Slack Token",
			Pattern:     regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
			Description: "Slack Token",
			Severity:    "HIGH",
		},
		{
			ID:          "SECRET_PRIVATE_KEY",
			Name:        "Private Key",
			Pattern:     regexp.MustCompile(`-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----`),
			Description: "Private SSH/RSA Key",
			Severity:    "CRITICAL",
		},
		{
			ID:          "SECRET_GENERIC_API_KEY",
			Name:        "Generic API Key",
			Pattern:     regexp.MustCompile(`(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{32,})`),
			Description: "Generic API Key",
			Severity:    "HIGH",
		},
		{
			ID:          "SECRET_GENERIC_SECRET",
			Name:        "Generic Secret",
			Pattern:     regexp.MustCompile(`(?i)(password|secret|token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9!@#$%^&*]{8,})`),
			Description: "Generic Secret/Password",
			Severity:    "MEDIUM",
		},
	}
}

// GenerateGitCleanupCommands generates commands to remove secrets from Git history
func GenerateGitCleanupCommands(findings []GitSecretFinding) []string {
	var commands []string

	// Get unique file paths
	fileSet := make(map[string]bool)
	for _, f := range findings {
		fileSet[f.FilePath] = true
	}

	files := make([]string, 0, len(fileSet))
	for file := range fileSet {
		files = append(files, file)
	}

	if len(files) == 0 {
		return commands
	}

	commands = append(commands, "# WARNING: These commands will rewrite Git history!")
	commands = append(commands, "# Make sure to backup your repository first")
	commands = append(commands, "")
	commands = append(commands, "# Option 1: Using git filter-branch (built-in)")
	for _, file := range files {
		commands = append(commands, fmt.Sprintf("git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch %s' --prune-empty --tag-name-filter cat -- --all", file))
	}

	commands = append(commands, "")
	commands = append(commands, "# Option 2: Using BFG Repo-Cleaner (faster, recommended)")
	commands = append(commands, "# Download: https://rtyley.github.io/bfg-repo-cleaner/")
	for _, file := range files {
		commands = append(commands, fmt.Sprintf("bfg --delete-files %s", filepath.Base(file)))
	}

	commands = append(commands, "")
	commands = append(commands, "# After cleaning history, force push:")
	commands = append(commands, "git push origin --force --all")
	commands = append(commands, "git push origin --force --tags")

	commands = append(commands, "")
	commands = append(commands, "# IMPORTANT: All team members must re-clone the repository!")
	commands = append(commands, "# Old clones will still contain the secrets in their history")

	return commands
}
