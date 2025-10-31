package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
)

// AttackChain represents a correlated sequence of findings that form an attack path
type AttackChain struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Severity    string      `json:"severity"`
	Likelihood  string      `json:"likelihood"`
	Impact      string      `json:"impact"`
	Steps       []ChainStep `json:"steps"`
	Remediation string      `json:"remediation"`
	Findings    []Finding   `json:"findings"` // Original findings in this chain
}

// ChainStep represents one step in an attack chain
type ChainStep struct {
	Step        int    `json:"step"`
	FindingID   string `json:"finding_id"`
	Description string `json:"description"`
}

// AttackChainTemplate defines a pattern for detecting attack chains
type AttackChainTemplate struct {
	Name        string
	Patterns    []string // Regex patterns to match finding IDs
	Severity    string
	Likelihood  string
	Impact      string
	Description string
	Remediation string
}

// AnalyzeAttackChains correlates findings to identify attack paths
func AnalyzeAttackChains(findings []Finding) []AttackChain {
	chains := []AttackChain{}

	// Define attack chain templates
	templates := getAttackChainTemplates()

	// Check each template against findings
	for i, template := range templates {
		matched := matchTemplate(template, findings)
		if len(matched) > 0 {
			chain := AttackChain{
				ID:          fmt.Sprintf("CHAIN-%03d", i+1),
				Name:        template.Name,
				Severity:    template.Severity,
				Likelihood:  template.Likelihood,
				Impact:      template.Impact,
				Remediation: template.Remediation,
				Findings:    matched,
				Steps:       generateSteps(template, matched),
			}
			chains = append(chains, chain)
		}
	}

	return chains
}

// getAttackChainTemplates returns pre-defined attack chain patterns
func getAttackChainTemplates() []AttackChainTemplate {
	return []AttackChainTemplate{
		// Chain 1: AWS Credential Leak → S3 Data Exfiltration
		{
			Name:        "AWS Credential Exposure → S3 Data Exfiltration",
			Patterns:    []string{"SECRET_AWS_ACCESS_KEY", "TFSEC_.*S3.*"},
			Severity:    "CRITICAL",
			Likelihood:  "HIGH",
			Impact:      "Complete AWS account compromise, data breach, financial loss, compliance violations (GDPR, SOC2)",
			Description: "Attacker discovers hardcoded AWS credentials and uses them to access S3 buckets",
			Remediation: "1. Immediately rotate all AWS credentials\n2. Enable S3 bucket encryption and block public access\n3. Implement AWS Secrets Manager for credential management\n4. Enable CloudTrail logging and set up alerts for unusual S3 access\n5. Apply least-privilege IAM policies",
		},

		// Chain 2: Container Escape → Kubernetes Cluster Takeover
		{
			Name:        "Container Escape → Kubernetes Cluster Takeover",
			Patterns:    []string{"R001", "KUBESEC_.*[Ss]ervice.*[Aa]ccount.*", "KUBESEC_.*[Pp]rivileged.*"},
			Severity:    "CRITICAL",
			Likelihood:  "MEDIUM",
			Impact:      "Full Kubernetes cluster compromise, lateral movement to all nodes, data exfiltration from all workloads",
			Description: "Attacker exploits containers running as root with mounted service accounts to escalate privileges",
			Remediation: "1. Set runAsNonRoot: true in all pod security contexts\n2. Disable service account token auto-mounting unless required\n3. Drop all Linux capabilities and add only necessary ones\n4. Implement Pod Security Standards (restricted profile)\n5. Enable RBAC with least-privilege roles\n6. Use network policies to segment workloads",
		},

		// Chain 3: Hardcoded Secrets → Multi-Service Compromise
		{
			Name:        "Hardcoded Secrets → Multi-Service Compromise",
			Patterns:    []string{"SECRET_.*", "SECRET_.*"},
			Severity:    "CRITICAL",
			Likelihood:  "HIGH",
			Impact:      "Compromise of multiple services (GitHub, AWS, Google Cloud), source code theft, infrastructure takeover",
			Description: "Multiple hardcoded credentials found - attacker can access various cloud services and APIs",
			Remediation: "1. Remove ALL hardcoded secrets from code and config files\n2. Rotate all exposed credentials immediately\n3. Use secret management solutions (Vault, AWS Secrets Manager, K8s Secrets)\n4. Implement pre-commit hooks to prevent secret commits\n5. Scan git history and purge secrets using tools like git-filter-repo\n6. Enable MFA on all service accounts",
		},

		// Chain 4: Public Database + Open Security Group → Data Breach
		{
			Name:        "Public Database Exposure → Direct Data Breach",
			Patterns:    []string{"TFSEC_.*RDS.*[Pp]ublic.*", "TFSEC_.*[Ss]ecurity.*[Gg]roup.*0\\.0\\.0\\.0.*"},
			Severity:    "CRITICAL",
			Likelihood:  "HIGH",
			Impact:      "Direct database access from internet, complete data exfiltration, ransomware potential",
			Description: "Database is publicly accessible with overly permissive security groups allowing internet access",
			Remediation: "1. Move RDS instances to private subnets immediately\n2. Restrict security groups to specific IP ranges or VPN only\n3. Enable encryption at rest and in transit\n4. Enable RDS audit logging\n5. Implement database activity monitoring\n6. Use AWS PrivateLink for secure access",
		},

		// Chain 5: IAM Wildcard Permissions → Privilege Escalation
		{
			Name:        "IAM Over-Privileges → AWS Account Takeover",
			Patterns:    []string{"TFSEC_.*IAM.*[Ww]ildcard.*", "SECRET_AWS.*"},
			Severity:    "CRITICAL",
			Likelihood:  "MEDIUM",
			Impact:      "Complete AWS account takeover, ability to create backdoors, infrastructure destruction",
			Description: "Combination of leaked credentials with wildcard IAM permissions grants full AWS access",
			Remediation: "1. Rotate compromised AWS credentials\n2. Replace wildcard IAM policies with least-privilege policies\n3. Implement IAM permission boundaries\n4. Enable AWS CloudTrail and GuardDuty\n5. Use AWS Organizations SCPs to limit maximum permissions\n6. Regularly audit IAM policies with Access Analyzer",
		},

		// Chain 6: Dockerfile Vulnerabilities → Container Compromise
		{
			Name:        "Insecure Dockerfile → Container Compromise",
			Patterns:    []string{"HADOLINT_DL3007", "HADOLINT_DL3008", "R001"},
			Severity:    "HIGH",
			Likelihood:  "MEDIUM",
			Impact:      "Container compromise via outdated packages, potential for supply chain attacks",
			Description: "Using latest tag and unpinned packages makes containers vulnerable to supply chain attacks",
			Remediation: "1. Pin specific image versions (no 'latest' tag)\n2. Pin package versions in apt-get/apk install\n3. Use multi-stage builds with minimal base images\n4. Run containers as non-root user\n5. Implement container image scanning in CI/CD\n6. Use distroless or minimal base images",
		},

		// Chain 7: Unencrypted Resources → Compliance Violation
		{
			Name:        "Unencrypted Infrastructure → Compliance Violations",
			Patterns:    []string{"TFSEC_.*[Ee]ncrypt.*", "TFSEC_.*[Ee]ncrypt.*"},
			Severity:    "HIGH",
			Likelihood:  "MEDIUM",
			Impact:      "Data exposure, compliance violations (PCI-DSS, HIPAA, SOC2), potential fines",
			Description: "Multiple resources lack encryption at rest, violating compliance requirements",
			Remediation: "1. Enable encryption for all S3 buckets using KMS\n2. Enable RDS encryption at rest\n3. Encrypt EBS volumes\n4. Use AWS KMS with customer-managed keys\n5. Enable CloudTrail log encryption\n6. Document encryption standards in security policies",
		},

		// Chain 8: Network Exposure → Attack Surface Expansion
		{
			Name:        "Network Over-Exposure → Attack Surface Expansion",
			Patterns:    []string{"TFSEC_.*0\\.0\\.0\\.0.*", "KUBESEC_.*[Nn]etwork.*"},
			Severity:    "HIGH",
			Likelihood:  "HIGH",
			Impact:      "Increased attack surface, easier reconnaissance, direct access to services from internet",
			Description: "Resources exposed to internet (0.0.0.0/0) without proper network segmentation",
			Remediation: "1. Restrict security groups to specific IP ranges\n2. Implement Kubernetes network policies\n3. Use VPN or AWS PrivateLink for internal access\n4. Enable VPC Flow Logs for network monitoring\n5. Implement Web Application Firewall (WAF) for public endpoints\n6. Use bastion hosts for administrative access",
		},
	}
}

// matchTemplate checks if findings match a template pattern
func matchTemplate(template AttackChainTemplate, findings []Finding) []Finding {
	matched := []Finding{}

	// Need at least 2 patterns to match (to form a chain)
	if len(template.Patterns) < 2 {
		// Single pattern - just check if exists
		for _, pattern := range template.Patterns {
			for _, finding := range findings {
				if matchPattern(pattern, finding.ID) {
					matched = append(matched, finding)
				}
			}
		}
		return matched
	}

	// For chains, we need findings matching different patterns
	patternMatches := make(map[int][]Finding)

	for i, pattern := range template.Patterns {
		for _, finding := range findings {
			if matchPattern(pattern, finding.ID) {
				patternMatches[i] = append(patternMatches[i], finding)
			}
		}
	}

	// Check if we have matches for at least 2 different patterns
	matchedPatterns := 0
	for _, matches := range patternMatches {
		if len(matches) > 0 {
			matchedPatterns++
			matched = append(matched, matches...)
		}
	}

	// Only return if we matched at least 2 different pattern types
	if matchedPatterns >= 2 {
		return matched
	}

	return []Finding{}
}

// matchPattern checks if a finding ID matches a pattern (supports wildcards)
func matchPattern(pattern, findingID string) bool {
	// Simple regex-like matching with * wildcard
	if strings.Contains(pattern, ".*") {
		// Convert simple regex to Go matching
		prefix := strings.Split(pattern, ".*")[0]
		return strings.HasPrefix(findingID, prefix)
	}
	return pattern == findingID
}

// generateSteps creates step-by-step attack narrative from matched findings
func generateSteps(template AttackChainTemplate, findings []Finding) []ChainStep {
	steps := []ChainStep{}

	for i, finding := range findings {
		step := ChainStep{
			Step:        i + 1,
			FindingID:   finding.ID,
			Description: generateStepDescription(i+1, finding, template.Name),
		}
		steps = append(steps, step)
	}

	return steps
}

// generateStepDescription creates a narrative for each step with specific details
func generateStepDescription(stepNum int, finding Finding, chainName string) string {
	// Extract file and line info from snippet if available
	fileInfo := filepath.Base(finding.File)
	
	// For specific finding types, provide detailed descriptions
	switch {
	case strings.HasPrefix(finding.ID, "SECRET_AWS"):
		return fmt.Sprintf("Hardcoded AWS credentials found in %s - %s", fileInfo, finding.Title)
	
	case strings.HasPrefix(finding.ID, "SECRET_GITHUB"):
		return fmt.Sprintf("GitHub token exposed in %s - %s", fileInfo, finding.Title)
	
	case strings.HasPrefix(finding.ID, "SECRET_GOOGLE"):
		return fmt.Sprintf("Google API key found in %s - %s", fileInfo, finding.Title)
	
	case strings.HasPrefix(finding.ID, "SECRET_"):
		return fmt.Sprintf("Secret credentials in %s - %s", fileInfo, finding.Title)
	
	case strings.HasPrefix(finding.ID, "CVE_"):
		// Extract CVE ID and package name from snippet
		snippet := finding.Snippet
		if strings.Contains(snippet, "CVE:") {
			return fmt.Sprintf("Vulnerable dependency in %s - %s", fileInfo, finding.Title)
		}
		return fmt.Sprintf("CVE vulnerability in %s - %s", fileInfo, finding.Title)
	
	case strings.HasPrefix(finding.ID, "TFSEC_"):
		// Show the actual terraform issue, not generic text
		return fmt.Sprintf("Terraform: %s (in %s)", finding.Title, fileInfo)
	
	case finding.ID == "R001":
		return fmt.Sprintf("Container running as root in %s - %s", fileInfo, finding.Title)
	
	case strings.HasPrefix(finding.ID, "KUBESEC_"):
		return fmt.Sprintf("K8s misconfiguration in %s - %s", fileInfo, finding.Title)
	
	case strings.HasPrefix(finding.ID, "HADOLINT_"):
		return fmt.Sprintf("Dockerfile issue in %s - %s", fileInfo, finding.Title)
	
	default:
		return fmt.Sprintf("%s in %s", finding.Title, fileInfo)
	}
}
