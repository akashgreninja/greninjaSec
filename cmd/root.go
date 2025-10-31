package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"greninjaSec/internal/scanner"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var (
	targetPath     string
	format         string
	scanManifests  bool
	scanSecrets    bool
	scanDockerfile bool
	scanTerraform  bool
	scanAll        bool
	analyzeChains  bool
	aiEnhance      bool
	rootCmd        = &cobra.Command{
		Use:   "greninjasec",
		Short: "GreninjaSec - Kubernetes & Infrastructure Security Scanner",
		Long: `GreninjaSec - A comprehensive security scanner for infrastructure-as-code

Detects security misconfigurations in:
  • Kubernetes manifests (YAML)
  • Hardcoded secrets (credentials, API keys, tokens)
  • Dockerfiles (50+ hadolint security checks)
  • Terraform files (100+ tfsec security checks)

Examples:
  # Scan everything (manifests + secrets + dockerfiles + terraform)
  greninjasec --all --path /path/to/repo

  # Scan only Kubernetes manifests
  greninjasec --manifest --path ./k8s

  # Scan only Dockerfiles
  greninjasec --dockerfile --path .

  # Scan only Terraform files
  greninjasec --terraform --path ./infra

  # Scan only for secrets
  greninjasec --secrets --path .

  # Combine scanners
  greninjasec --manifest --dockerfile --terraform --path ./infra

  # Output as JSON for CI/CD
  greninjasec --all --format json

  # Scan current directory (default)
  greninjasec --all`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetPath == "" {
				targetPath = "."
			}

			// Determine what to scan
			opts := scanner.ScanOptions{
				ScanManifests:  scanManifests,
				ScanSecrets:    scanSecrets,
				ScanDockerfile: scanDockerfile,
				ScanTerraform:  scanTerraform,
				AnalyzeChains:  analyzeChains,
				AIEnhance:      aiEnhance,
			}

			// If --all is specified, enable everything
			if scanAll {
				opts.ScanManifests = true
				opts.ScanSecrets = true
				opts.ScanDockerfile = true
				opts.ScanTerraform = true
			}

			// If nothing specified, default to --all
			if !scanManifests && !scanSecrets && !scanDockerfile && !scanTerraform && !scanAll {
				opts.ScanManifests = true
				opts.ScanSecrets = true
				opts.ScanDockerfile = true
				opts.ScanTerraform = true
			}

			s := scanner.NewScanner()

			// If attack chain analysis is requested, use the enhanced method
			if opts.AnalyzeChains {
				result, err := s.ScanWithAttackChains(targetPath, opts)
				if err != nil {
					return err
				}

				if format == "json" {
					return printResultJSON(result)
				}

				return printResultPretty(result, opts)
			}

			// Otherwise use simple finding-based scan
			findings, err := s.ScanWithOptions(targetPath, opts)
			if err != nil {
				return err
			}

			if format == "json" {
				return scanner.PrintJSON(findings)
			}

			// pretty print
			fmt.Printf("GreninjaSec Security Scan\n")
			fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			fmt.Printf("Scanned path: %s\n", targetPath)
			fmt.Printf("Scan options: ")
			if opts.ScanManifests {
				fmt.Printf("[Manifests] ")
			}
			if opts.ScanSecrets {
				fmt.Printf("[Secrets] ")
			}
			if opts.ScanDockerfile {
				fmt.Printf("[Dockerfiles] ")
			}
			if opts.ScanTerraform {
				fmt.Printf("[Terraform] ")
			}
			fmt.Printf("\n")
			fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

			if len(findings) == 0 {
				fmt.Printf("✅ No security issues found!\n")
				return nil
			}

			fmt.Printf("Total Findings: %d\n\n", len(findings))

			// Group by severity
			critical := []scanner.Finding{}
			high := []scanner.Finding{}
			medium := []scanner.Finding{}
			low := []scanner.Finding{}

			for _, f := range findings {
				switch f.Severity {
				case "CRITICAL":
					critical = append(critical, f)
				case "HIGH":
					high = append(high, f)
				case "MEDIUM":
					medium = append(medium, f)
				default:
					low = append(low, f)
				}
			}

			// Print by severity
			printFindings("🔴 CRITICAL", critical)
			printFindings("🟠 HIGH", high)
			printFindings("🟡 MEDIUM", medium)
			printFindings("🟢 LOW", low)

			return nil
		},
	}
)

func printFindings(header string, findings []scanner.Finding) {
	if len(findings) == 0 {
		return
	}

	fmt.Printf("%s (%d)\n", header, len(findings))
	fmt.Printf("─────────────────────────────────────────────────────────\n")
	for i, f := range findings {
		fmt.Printf("[%d] %s - %s\n", i+1, f.RuleID, f.Title)
		fmt.Printf("    File: %s\n", f.File)
		fmt.Printf("    Snippet: %s\n\n", f.Snippet)
	}
}

func init() {
	// Load .env file if it exists
	godotenv.Load()

	rootCmd.Flags().StringVarP(&targetPath, "path", "p", ".", "Path to scan (defaults to current directory)")
	rootCmd.Flags().StringVarP(&format, "format", "f", "pretty", "Output format: pretty|json")
	rootCmd.Flags().BoolVarP(&scanManifests, "manifest", "m", false, "Scan Kubernetes manifests for misconfigurations")
	rootCmd.Flags().BoolVarP(&scanSecrets, "secrets", "s", false, "Scan for hardcoded secrets and credentials")
	rootCmd.Flags().BoolVarP(&scanDockerfile, "dockerfile", "d", false, "Scan Dockerfiles with hadolint (50+ checks)")
	rootCmd.Flags().BoolVarP(&scanTerraform, "terraform", "t", false, "Scan Terraform files with tfsec (100+ checks)")
	rootCmd.Flags().BoolVarP(&scanAll, "all", "a", false, "Run all scanners (manifests + secrets + dockerfiles + terraform)")
	rootCmd.Flags().BoolVarP(&analyzeChains, "attack-chains", "c", false, "Analyze attack chains (correlate findings into exploit paths)")
	rootCmd.Flags().BoolVarP(&aiEnhance, "ai-enhance", "", false, "Use AI to discover additional attack chains (requires .env with OPENWEBUI_URL and OPENWEBUI_TOKEN)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// printResultJSON prints scan result with attack chains as JSON
func printResultJSON(result scanner.ScanResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// printResultPretty prints scan result with attack chains in pretty format
func printResultPretty(result scanner.ScanResult, opts scanner.ScanOptions) error {
	// Print header
	fmt.Printf("GreninjaSec Security Scan 🥷\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Scanned path: %s\n", ".")
	fmt.Printf("Scan options: ")
	if opts.ScanManifests {
		fmt.Printf("[Manifests] ")
	}
	if opts.ScanSecrets {
		fmt.Printf("[Secrets] ")
	}
	if opts.ScanDockerfile {
		fmt.Printf("[Dockerfiles] ")
	}
	if opts.ScanTerraform {
		fmt.Printf("[Terraform] ")
	}
	if opts.AnalyzeChains {
		fmt.Printf("[Attack Chains")
		if opts.AIEnhance {
			fmt.Printf(" + AI")
		}
		fmt.Printf("] ")
	}
	fmt.Printf("\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Print findings summary
	fmt.Printf("Total Findings: %d\n", len(result.Findings))

	if len(result.AttackChains) > 0 {
		fmt.Printf("Attack Chains Detected: %d\n", len(result.AttackChains))
	}
	fmt.Printf("\n")

	// Print attack chains first (more important)
	if len(result.AttackChains) > 0 {
		printAttackChains(result.AttackChains)
		fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	}

	// Print findings grouped by severity
	critical := []scanner.Finding{}
	high := []scanner.Finding{}
	medium := []scanner.Finding{}
	low := []scanner.Finding{}

	for _, f := range result.Findings {
		switch f.Severity {
		case "CRITICAL":
			critical = append(critical, f)
		case "HIGH":
			high = append(high, f)
		case "MEDIUM":
			medium = append(medium, f)
		default:
			low = append(low, f)
		}
	}

	if len(result.AttackChains) == 0 {
		fmt.Printf("Individual Findings:\n\n")
	}

	printFindings("🔴 CRITICAL", critical)
	printFindings("🟠 HIGH", high)
	printFindings("🟡 MEDIUM", medium)
	printFindings("🟢 LOW", low)

	return nil
}

// printAttackChains prints attack chains in pretty format
func printAttackChains(chains []scanner.AttackChain) {
	fmt.Printf("🥷 ATTACK CHAINS - Correlated Exploit Paths\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n\n")

	for i, chain := range chains {
		// Print chain header
		severityIcon := getSeverityIcon(chain.Severity)
		fmt.Printf("[%d] %s %s\n", i+1, severityIcon, chain.Name)
		fmt.Printf("    ID: %s\n", chain.ID)
		fmt.Printf("    Severity: %s | Likelihood: %s\n", chain.Severity, chain.Likelihood)
		fmt.Printf("    Impact: %s\n", chain.Impact)
		fmt.Printf("\n")

		// Print attack steps
		fmt.Printf("    Attack Steps:\n")
		for _, step := range chain.Steps {
			fmt.Printf("      %d. %s\n", step.Step, step.Description)
			fmt.Printf("         └─ Finding: %s\n", step.FindingID)
		}
		fmt.Printf("\n")

		// Print remediation
		fmt.Printf("    🔧 Remediation:\n")
		remLines := strings.Split(chain.Remediation, "\n")
		for _, line := range remLines {
			if line != "" {
				fmt.Printf("       %s\n", line)
			}
		}
		fmt.Printf("\n")

		if i < len(chains)-1 {
			fmt.Printf("    ───────────────────────────────────────────────────\n\n")
		}
	}
}

// getSeverityIcon returns emoji for severity
func getSeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return "💀"
	case "HIGH":
		return "🔥"
	case "MEDIUM":
		return "⚠️"
	case "LOW":
		return "ℹ️"
	default:
		return "•"
	}
}
