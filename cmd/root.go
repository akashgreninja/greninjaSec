package cmd

import (
	"fmt"
	"os"

	"greninjaSec/internal/scanner"

	"github.com/spf13/cobra"
)

var (
	targetPath    string
	format        string
	scanManifests bool
	scanSecrets   bool
	scanAll       bool
	rootCmd       = &cobra.Command{
		Use:   "infraguardian",
		Short: "InfraGuardian - Kubernetes & Infrastructure Security Scanner",
		Long: `InfraGuardian - A comprehensive security scanner for infrastructure-as-code

Detects security misconfigurations in:
  • Kubernetes manifests (YAML)
  • Hardcoded secrets (credentials, API keys, tokens)
  • Terraform configurations (coming soon)
  • Dockerfiles (coming soon)

Examples:
  # Scan everything (manifests + secrets)
  infraguardian --all --path /path/to/repo

  # Scan only Kubernetes manifests
  infraguardian --manifest --path ./k8s

  # Scan only for secrets
  infraguardian --secrets --path .

  # Output as JSON for CI/CD
  infraguardian --all --format json

  # Scan current directory (default)
  infraguardian --all`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetPath == "" {
				targetPath = "."
			}

			// Determine what to scan
			opts := scanner.ScanOptions{
				ScanManifests: scanManifests,
				ScanSecrets:   scanSecrets,
			}

			// If --all is specified, enable everything
			if scanAll {
				opts.ScanManifests = true
				opts.ScanSecrets = true
			}

			// If nothing specified, default to --all
			if !scanManifests && !scanSecrets && !scanAll {
				opts.ScanManifests = true
				opts.ScanSecrets = true
			}

			s := scanner.NewScanner()
			findings, err := s.ScanWithOptions(targetPath, opts)
			if err != nil {
				return err
			}

			if format == "json" {
				return scanner.PrintJSON(findings)
			}

			// pretty print
			fmt.Printf("InfraGuardian Security Scan\n")
			fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			fmt.Printf("Scanned path: %s\n", targetPath)
			fmt.Printf("Scan options: ")
			if opts.ScanManifests {
				fmt.Printf("[Manifests] ")
			}
			if opts.ScanSecrets {
				fmt.Printf("[Secrets] ")
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
	rootCmd.Flags().StringVarP(&targetPath, "path", "p", ".", "Path to scan (defaults to current directory)")
	rootCmd.Flags().StringVarP(&format, "format", "f", "pretty", "Output format: pretty|json")
	rootCmd.Flags().BoolVarP(&scanManifests, "manifest", "m", false, "Scan Kubernetes manifests for misconfigurations")
	rootCmd.Flags().BoolVarP(&scanSecrets, "secrets", "s", false, "Scan for hardcoded secrets and credentials")
	rootCmd.Flags().BoolVarP(&scanAll, "all", "a", false, "Run all scanners (manifests + secrets)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
