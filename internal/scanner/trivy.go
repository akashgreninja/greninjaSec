package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TrivyResult represents the JSON output from Trivy
type TrivyResult struct {
	Results []TrivyTargetResult `json:"Results"`
}

type TrivyTargetResult struct {
	Target          string                `json:"Target"`
	Class           string                `json:"Class"`
	Type            string                `json:"Type"`
	Vulnerabilities []TrivyVulnerability  `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string  `json:"VulnerabilityID"`
	PkgName          string  `json:"PkgName"`
	InstalledVersion string  `json:"InstalledVersion"`
	FixedVersion     string  `json:"FixedVersion"`
	Severity         string  `json:"Severity"`
	Title            string  `json:"Title"`
	Description      string  `json:"Description"`
	PrimaryURL       string  `json:"PrimaryURL"`
	CVSS             CVSSInfo `json:"CVSS"`
}

type CVSSInfo struct {
	NVD    CVSSScore `json:"nvd"`
	RedHat CVSSScore `json:"redhat"`
}

type CVSSScore struct {
	V2Score  float64 `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
}

// scanVulnerabilities scans for CVEs and vulnerabilities using Trivy
func (s *Scanner) scanVulnerabilities(path string) ([]Finding, error) {
	// Ensure Trivy is installed
	trivyPath, err := s.toolManager.EnsureTrivy()
	if err != nil {
		return nil, fmt.Errorf("trivy not available: %w", err)
	}

	fmt.Fprintf(os.Stderr, "🔍 Running Trivy vulnerability scan...\n")

	var findings []Finding

	// Scan filesystem for dependency vulnerabilities
	fsFindings, err := s.scanFilesystemVulnerabilities(trivyPath, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Trivy filesystem scan failed: %v\n", err)
	} else {
		findings = append(findings, fsFindings...)
		fmt.Fprintf(os.Stderr, "✅ Found %d filesystem vulnerabilities\n", len(fsFindings))
	}

	// Scan for container images if we find Dockerfiles
	imageFindings, err := s.scanDockerImagesForVulnerabilities(trivyPath, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Trivy image scan failed: %v\n", err)
	} else {
		findings = append(findings, imageFindings...)
		fmt.Fprintf(os.Stderr, "✅ Found %d image vulnerabilities\n", len(imageFindings))
	}

	return findings, nil
}

func (s *Scanner) scanFilesystemVulnerabilities(trivyPath, path string) ([]Finding, error) {
	// Run trivy filesystem scan - quiet mode to suppress INFO logs
	cmd := exec.Command(trivyPath, "fs", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM", "--quiet", path)
	output, err := cmd.Output()
	if err != nil {
		// Trivy returns non-zero if vulnerabilities found, check if output is valid JSON
		if len(output) == 0 {
			return nil, fmt.Errorf("trivy failed: %w", err)
		}
	}

	// Parse Trivy output
	var result TrivyResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	var findings []Finding
	for _, target := range result.Results {
		if target.Vulnerabilities == nil {
			continue
		}

		for _, vuln := range target.Vulnerabilities {
			// Get CVSS score (prefer v3 over v2)
			cvssScore := vuln.CVSS.NVD.V3Score
			if cvssScore == 0 {
				cvssScore = vuln.CVSS.NVD.V2Score
			}
			if cvssScore == 0 {
				cvssScore = vuln.CVSS.RedHat.V3Score
			}
			if cvssScore == 0 {
				cvssScore = vuln.CVSS.RedHat.V2Score
			}

			// Build snippet with vulnerability details
			snippet := fmt.Sprintf("CVE: %s | Package: %s | Installed: %s | Fixed: %s | CVSS: %.1f",
				vuln.VulnerabilityID,
				vuln.PkgName,
				vuln.InstalledVersion,
				valueOrNA(vuln.FixedVersion),
				cvssScore,
			)

			// Map Trivy severity to our severity
			severity := mapTrivySeverity(vuln.Severity)

			findings = append(findings, Finding{
				ID:       fmt.Sprintf("CVE_%s", vuln.VulnerabilityID),
				RuleID:   vuln.VulnerabilityID,
				Title:    fmt.Sprintf("%s - %s", vuln.VulnerabilityID, truncate(vuln.Title, 80)),
				Severity: severity,
				File:     target.Target,
				Snippet:  snippet,
			})
		}
	}

	return findings, nil
}

func (s *Scanner) scanDockerImagesForVulnerabilities(trivyPath, path string) ([]Finding, error) {
	// Find Dockerfiles
	var dockerfiles []string
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if shouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		
		// Check if it's a Dockerfile
		basename := filepath.Base(filePath)
		if strings.HasPrefix(strings.ToLower(basename), "dockerfile") {
			dockerfiles = append(dockerfiles, filePath)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var findings []Finding
	
	// For each Dockerfile, extract the FROM image and scan it
	for _, dockerfile := range dockerfiles {
		images := extractDockerImages(dockerfile)
		for _, image := range images {
			// Scan the image - quiet mode to suppress INFO logs
			cmd := exec.Command(trivyPath, "image", "--format", "json", "--severity", "CRITICAL,HIGH", "--quiet", image)
			output, err := cmd.Output()
			if err != nil && len(output) == 0 {
				continue // Skip if image not available locally
			}

			var result TrivyResult
			if err := json.Unmarshal(output, &result); err != nil {
				continue
			}

			for _, target := range result.Results {
				if target.Vulnerabilities == nil {
					continue
				}

				for _, vuln := range target.Vulnerabilities {
					cvssScore := vuln.CVSS.NVD.V3Score
					if cvssScore == 0 {
						cvssScore = vuln.CVSS.NVD.V2Score
					}

					snippet := fmt.Sprintf("Image: %s | CVE: %s | Package: %s | CVSS: %.1f | Fixed: %s",
						image,
						vuln.VulnerabilityID,
						vuln.PkgName,
						cvssScore,
						valueOrNA(vuln.FixedVersion),
					)

					findings = append(findings, Finding{
						ID:       fmt.Sprintf("CVE_IMAGE_%s", vuln.VulnerabilityID),
						RuleID:   vuln.VulnerabilityID,
						Title:    fmt.Sprintf("Container Image: %s - %s", vuln.VulnerabilityID, truncate(vuln.Title, 60)),
						Severity: mapTrivySeverity(vuln.Severity),
						File:     dockerfile,
						Snippet:  snippet,
					})
				}
			}
		}
	}

	return findings, nil
}

func extractDockerImages(dockerfilePath string) []string {
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return nil
	}

	var images []string
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			// Extract image name
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				image := parts[1]
				// Skip scratch and multi-stage build aliases
				if image != "scratch" && !strings.Contains(strings.ToLower(line), "as ") {
					images = append(images, image)
				} else if strings.Contains(strings.ToLower(line), "as ") && len(parts) >= 4 {
					// Get the actual image before "as"
					image = parts[1]
					if image != "scratch" {
						images = append(images, image)
					}
				}
			}
		}
	}

	return images
}

func mapTrivySeverity(trivySev string) string {
	switch strings.ToUpper(trivySev) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

func valueOrNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func shouldSkipDir(name string) bool {
	return name == ".git" || name == "vendor" || name == "node_modules" || name == ".terraform"
}
