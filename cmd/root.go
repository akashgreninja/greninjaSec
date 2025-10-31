package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"greninjaSec/internal/scanner"
	"greninjaSec/internal/shadow"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var (
	targetPath          string
	format              string
	htmlOutput          string
	scanManifests       bool
	scanSecrets         bool
	scanDockerfile      bool
	scanTerraform       bool
	scanVulnerabilities bool
	scanAll             bool
	analyzeChains       bool
	aiEnhance           bool
	aiRemediation       bool
	deepScan            bool
	scanLeaks           bool
	shadowDeploy        bool
	verbose             bool
	Version             = "dev" // Set via ldflags during build
	rootCmd        = &cobra.Command{
		Use:   "greninjasec",
		Short: "GreninjaSec - Kubernetes & Infrastructure Security Scanner",
		Long: `GreninjaSec - A comprehensive security scanner for infrastructure-as-code

Detects security misconfigurations in:
  • Kubernetes manifests (YAML)
  • Hardcoded secrets (credentials, API keys, tokens)
  • Dockerfiles (50+ hadolint security checks)
  • Terraform files (100+ tfsec security checks)
  • CVE vulnerabilities with CVSS scores (Trivy integration)

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

  # Scan for CVE vulnerabilities with CVSS scores
  greninjasec --vulnerabilities --path .

  # Combine scanners
  greninjasec --manifest --dockerfile --terraform --vulnerabilities --path ./infra

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
				ScanManifests:       scanManifests,
				ScanSecrets:         scanSecrets,
				ScanDockerfile:      scanDockerfile,
				ScanTerraform:       scanTerraform,
				ScanVulnerabilities: scanVulnerabilities,
				AnalyzeChains:       analyzeChains,
				AIEnhance:           aiEnhance,
				AIRemediation:       aiRemediation,
			}

			// If --all is specified, enable everything
			if scanAll {
				opts.ScanManifests = true
				opts.ScanSecrets = true
				opts.ScanDockerfile = true
				opts.ScanTerraform = true
				opts.ScanVulnerabilities = true
			}

			// If nothing specified, default to --all
			if !scanManifests && !scanSecrets && !scanDockerfile && !scanTerraform && !scanVulnerabilities && !scanAll {
				opts.ScanManifests = true
				opts.ScanSecrets = true
				opts.ScanDockerfile = true
				opts.ScanTerraform = true
				opts.ScanVulnerabilities = true
			}

			s := scanner.NewScanner()

			// If attack chain analysis is requested, use the enhanced method
			if opts.AnalyzeChains {
				result, err := s.ScanWithAttackChains(targetPath, opts)
				if err != nil {
					return err
				}

				// Enrich findings with AI remediation if requested
				if opts.AIRemediation {
					result.Findings, err = s.EnrichFindingsWithAI(result.Findings)
					if err != nil {
						fmt.Fprintf(os.Stderr, "⚠️  AI remediation failed: %v\n", err)
					}
				}

				if format == "json" {
					return printResultJSON(result)
				}

				// Generate HTML report if requested
				if htmlOutput != "" {
					if err := scanner.GenerateHTMLReportV2(result, htmlOutput); err != nil {
						return fmt.Errorf("failed to generate HTML report: %w", err)
					}
					fmt.Printf("✅ HTML report generated: %s\n", htmlOutput)
					if format != "pretty" {
						return nil // Don't print to console if HTML only
					}
				}

				return printResultPretty(result, opts)
			}

			// Otherwise use simple finding-based scan
			findings, err := s.ScanWithOptions(targetPath, opts)
			if err != nil {
				return err
			}

			// Deep scan Git history if requested
			var gitSecrets []scanner.GitSecretFinding
			if deepScan {
				gitSecrets, err = scanner.ScanGitHistory(targetPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "⚠️  Deep scan failed: %v\n", err)
				} else if len(gitSecrets) > 0 {
					// Convert GitSecretFindings to regular Findings
					for _, gs := range gitSecrets {
						severity := "HIGH"
						if gs.StillInRepo {
							severity = "CRITICAL" // Still exposed = critical
						}
						if gs.IsStillActive {
							severity = "CRITICAL" // Active secret = critical
						}

						message := fmt.Sprintf("Found in Git history | Commit: %s | Author: %s | Days exposed: %d | Still in repo: %v",
							gs.CommitHash[:8], gs.Author, gs.DaysExposed, gs.StillInRepo)

						finding := scanner.Finding{
							ID:       "GIT_HISTORY_" + gs.SecretType,
							Title:    fmt.Sprintf("%s exposed in Git history", gs.SecretType),
							Severity: severity,
							Message:  message,
							File:     gs.FilePath,
							Snippet:  fmt.Sprintf("Secret: %s | Commit: %s (%s)", gs.SecretValue, gs.CommitHash[:8], gs.Date.Format("2006-01-02")),
						}
						findings = append(findings, finding)
					}

					// Print cleanup commands
					fmt.Fprintf(os.Stderr, "\n🧹 Git History Cleanup Commands:\n")
					fmt.Fprintf(os.Stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
					cleanupCmds := scanner.GenerateGitCleanupCommands(gitSecrets)
					for _, cmd := range cleanupCmds {
						fmt.Fprintf(os.Stderr, "%s\n", cmd)
					}
					fmt.Fprintf(os.Stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
				}
			}

			// Scan for memory/resource leaks if requested
			if scanLeaks {
				fmt.Fprintf(os.Stderr, "🔍 Scanning for memory/resource leaks...\n")
				leaks, err := scanner.ScanForLeaks(targetPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "⚠️  Leak scan failed: %v\n", err)
				} else if len(leaks) > 0 {
					fmt.Fprintf(os.Stderr, "✅ Found %d potential leaks\n\n", len(leaks))

					// Convert LeakFindings to regular Findings
					for _, leak := range leaks {
						message := fmt.Sprintf("%s | Fix: %s", leak.Description, leak.Fix)

						finding := scanner.Finding{
							ID:       "LEAK_" + strings.ToUpper(leak.Category),
							Title:    fmt.Sprintf("[%s] %s", strings.ToUpper(leak.Type), leak.Category),
							Severity: leak.Severity,
							Message:  message,
							File:     leak.File,
							Snippet:  fmt.Sprintf("[Line %d] %s", leak.Line, leak.CodeSnippet),
						}
						findings = append(findings, finding)
					}
				}
			}

			// Run Shadow Deploy simulation if requested
			if shadowDeploy {
				if err := runShadowDeploy(targetPath, findings); err != nil {
					fmt.Fprintf(os.Stderr, "⚠️  Shadow Deploy simulation failed: %v\n", err)
				}
			}

			// Enrich findings with AI remediation if requested
			if opts.AIRemediation {
				findings, err = s.EnrichFindingsWithAI(findings)
				if err != nil {
					fmt.Fprintf(os.Stderr, "⚠️  AI remediation failed: %v\n", err)
				}
			}

			// Generate HTML report if requested (for simple scans)
			if htmlOutput != "" {
				// Convert findings to ScanResult for HTML generation
				result := scanner.ScanResult{
					Findings:     findings,
					AttackChains: []scanner.AttackChain{}, // No attack chains for simple scans
				}
				if err := scanner.GenerateHTMLReportV2(result, htmlOutput); err != nil {
					return fmt.Errorf("failed to generate HTML report: %w", err)
				}
				fmt.Printf("✅ HTML report generated: %s\n", htmlOutput)
				if format != "pretty" {
					return nil // Don't print to console if HTML only
				}
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
			if opts.ScanVulnerabilities {
				fmt.Printf("[CVE/Vulnerabilities] ")
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

	// In non-verbose mode, show only top 3 findings per severity
	limit := len(findings)
	if !verbose && limit > 3 {
		limit = 3
	}

	for i := 0; i < limit; i++ {
		f := findings[i]
		fmt.Printf("[%d] %s - %s\n", i+1, f.ID, f.Title)
		fmt.Printf("    File: %s\n", f.File)

		// Truncate long snippets
		snippet := f.Snippet
		if len(snippet) > 100 && !verbose {
			snippet = snippet[:100] + "..."
		}
		fmt.Printf("    Snippet: %s\n\n", snippet)
	}

	// Show count of hidden findings
	if !verbose && len(findings) > 3 {
		fmt.Printf("    ... and %d more %s findings (use --verbose to see all)\n\n", len(findings)-3, strings.ToLower(header))
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of GreninjaSec",
	Long:  `All software has versions. This is GreninjaSec's.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("GreninjaSec %s\n", Version)
	},
}

func init() {
	// Load .env file if it exists
	godotenv.Load()

	// Add version command
	rootCmd.AddCommand(versionCmd)

	rootCmd.Flags().StringVarP(&targetPath, "path", "p", ".", "Path to scan (defaults to current directory)")
	rootCmd.Flags().StringVarP(&format, "format", "f", "pretty", "Output format: pretty|json")
	rootCmd.Flags().StringVar(&htmlOutput, "html", "", "Generate HTML report (e.g., --html report.html)")
	rootCmd.Flags().BoolVarP(&scanManifests, "manifest", "m", false, "Scan Kubernetes manifests for misconfigurations")
	rootCmd.Flags().BoolVarP(&scanSecrets, "secrets", "s", false, "Scan for hardcoded secrets and credentials")
	rootCmd.Flags().BoolVarP(&scanDockerfile, "dockerfile", "d", false, "Scan Dockerfiles with hadolint (50+ checks)")
	rootCmd.Flags().BoolVarP(&scanTerraform, "terraform", "t", false, "Scan Terraform files with tfsec (100+ checks)")
	rootCmd.Flags().BoolVar(&scanVulnerabilities, "vulnerabilities", false, "Scan for CVE vulnerabilities with CVSS scores using Trivy")
	rootCmd.Flags().BoolVarP(&scanAll, "all", "a", false, "Run all scanners (manifests + secrets + dockerfiles + terraform + vulnerabilities)")
	rootCmd.Flags().BoolVarP(&analyzeChains, "attack-chains", "c", false, "Analyze attack chains (correlate findings into exploit paths)")
	rootCmd.Flags().BoolVarP(&aiEnhance, "ai-enhance", "", false, "Use AI to discover additional attack chains (requires .env with OPENWEBUI_URL and OPENWEBUI_TOKEN)")
	rootCmd.Flags().BoolVarP(&aiRemediation, "ai-remediation", "", false, "Get AI-powered fix suggestions for CRITICAL/HIGH findings (requires .env)")
	rootCmd.Flags().BoolVarP(&deepScan, "deep-scan", "", false, "Scan entire Git history for exposed secrets (not just current files)")
	rootCmd.Flags().BoolVarP(&scanLeaks, "leaks", "", false, "Scan for memory/resource leaks and CPU issues (Go files only)")
	rootCmd.Flags().BoolVarP(&shadowDeploy, "shadow-deploy", "", false, "🎭 Simulate real attacks to demonstrate exploit paths (safe dry-run)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed output for all findings (default: summary only)")
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
	if opts.ScanVulnerabilities {
		fmt.Printf("[CVE/Vulnerabilities] ")
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

	// Print summary with actionable recommendations
	if !verbose {
		fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("📊 SUMMARY\n")
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

		totalIssues := len(critical) + len(high) + len(medium) + len(low)
		fmt.Printf("Total Issues: %d\n", totalIssues)
		fmt.Printf("  🔴 Critical: %d\n", len(critical))
		fmt.Printf("  🟠 High: %d\n", len(high))
		fmt.Printf("  🟡 Medium: %d\n", len(medium))
		fmt.Printf("  🟢 Low: %d\n\n", len(low))

		if len(result.AttackChains) > 0 {
			fmt.Printf("Attack Chains: %d\n", len(result.AttackChains))
			criticalChains := 0
			for _, c := range result.AttackChains {
				if c.Severity == "CRITICAL" {
					criticalChains++
				}
			}
			if criticalChains > 0 {
				fmt.Printf("  💀 Critical Attack Paths: %d\n", criticalChains)
			}
			fmt.Printf("\n")
		}

		// Priority recommendations
		if len(critical) > 0 || len(high) > 0 {
			fmt.Printf("🎯 PRIORITY ACTIONS:\n")
			if len(critical) > 0 {
				fmt.Printf("  1. Fix %d CRITICAL issues immediately\n", len(critical))
			}
			if len(high) > 0 {
				fmt.Printf("  2. Address %d HIGH severity issues\n", len(high))
			}
			if len(result.AttackChains) > 0 {
				fmt.Printf("  3. Review attack chains to understand exploit paths\n")
			}
			fmt.Printf("\n💡 Use --verbose flag to see all details\n")
			fmt.Printf("💡 Use --format json for machine-readable output\n")
		}
	}

	return nil
}

// printAttackChains prints attack chains in pretty format
func printAttackChains(chains []scanner.AttackChain) {
	fmt.Printf("🥷 ATTACK CHAINS - Correlated Exploit Paths\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n\n")

	// In non-verbose mode, show only top 3 chains
	limit := len(chains)
	if !verbose && limit > 3 {
		limit = 3
	}

	for i := 0; i < limit; i++ {
		chain := chains[i]
		// Print chain header
		severityIcon := getSeverityIcon(chain.Severity)
		fmt.Printf("[%d] %s %s\n", i+1, severityIcon, chain.Name)
		fmt.Printf("    ID: %s | Severity: %s | Likelihood: %s\n", chain.ID, chain.Severity, chain.Likelihood)
		fmt.Printf("    Impact: %s\n", chain.Impact)
		fmt.Printf("    Affected Findings: %d\n", len(chain.Findings))
		fmt.Printf("\n")

		// Print attack steps (limit to 5 in non-verbose mode)
		stepLimit := len(chain.Steps)
		if !verbose && stepLimit > 5 {
			stepLimit = 5
		}

		fmt.Printf("    Attack Steps:\n")
		for j := 0; j < stepLimit; j++ {
			step := chain.Steps[j]
			fmt.Printf("      %d. %s\n", step.Step, step.Description)
			if verbose {
				fmt.Printf("         └─ Finding: %s\n", step.FindingID)
			}
		}

		if !verbose && len(chain.Steps) > 5 {
			fmt.Printf("      ... %d more steps (use --verbose to see all)\n", len(chain.Steps)-5)
		}
		fmt.Printf("\n")

		// Print remediation (first 3 lines only in non-verbose mode)
		fmt.Printf("    🔧 Key Remediation:\n")
		remLines := strings.Split(chain.Remediation, "\n")
		remLimit := len(remLines)
		if !verbose && remLimit > 3 {
			remLimit = 3
		}

		for j := 0; j < remLimit; j++ {
			if remLines[j] != "" {
				fmt.Printf("       %s\n", remLines[j])
			}
		}

		if !verbose && len(remLines) > 3 {
			fmt.Printf("       ... (use --verbose for complete remediation steps)\n")
		}
		fmt.Printf("\n")

		if i < limit-1 {
			fmt.Printf("    ───────────────────────────────────────────────────\n\n")
		}
	}

	if !verbose && len(chains) > 3 {
		fmt.Printf("\n    💡 Showing top 3 attack chains (total: %d). Use --verbose to see all.\n", len(chains))
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

// runShadowDeploy executes the Shadow Deploy simulation
func runShadowDeploy(targetPath string, findings []scanner.Finding) error {
	// Convert findings to vulnerabilities for shadow simulator
	vulns := findingsToVulnerabilities(findings)
	
	if len(vulns) == 0 {
		fmt.Println("\n✅ No exploitable vulnerabilities found for simulation")
		return nil
	}
	
	// Determine target type based on path/findings
	targetType := determineTargetType(targetPath, findings)
	
	// Create simulator with config
	config := shadow.SimulationConfig{
		DryRun:         true, // Always dry-run for safety
		Verbose:        verbose,
		Isolated:       false,
		StopOnFailure:  false,
		GenerateReport: true,
		ReportFormat:   "html",
	}
	
	sim := shadow.NewSimulator(config)
	
	// Enable AI enhancement if AI remediation is enabled
	if aiRemediation || aiEnhance {
		// Load .env for AI credentials
		_ = godotenv.Load()
		
		aiConfig, err := scanner.LoadAIConfigForShadow()
		if err == nil && aiConfig.Enabled {
			aiClient := scanner.CreateAIClient(aiConfig)
			if aiClient != nil {
				enhancer := shadow.NewAIExploitEnhancer(aiClient)
				sim.SetAIEnhancer(enhancer)
				fmt.Println("🤖 AI-powered exploit enhancement enabled")
			}
		} else {
			fmt.Println("⚠️  AI enhancement requested but not configured (check .env)")
		}
	}
	
	// Run the simulation
	result, err := sim.Run(targetPath, targetType, vulns)
	if err != nil {
		return fmt.Errorf("simulation failed: %w", err)
	}
	
	// Result is already printed by simulator
	_ = result
	
	return nil
}

// findingsToVulnerabilities converts scanner findings to shadow vulnerabilities
func findingsToVulnerabilities(findings []scanner.Finding) []shadow.Vulnerability {
	vulns := []shadow.Vulnerability{}
	
	for _, f := range findings {
		vuln := shadow.Vulnerability{
			ID:          f.ID,
			Type:        mapFindingToVulnType(f),
			Severity:    f.Severity,
			CVSSScore:   0, // TODO: Parse from finding if available
			Description: f.Title,
			File:        f.File,
			Exploitable: false, // Will be determined by simulator
		}
		vulns = append(vulns, vuln)
	}
	
	return vulns
}

// mapFindingToVulnType maps finding IDs to vulnerability types
func mapFindingToVulnType(finding scanner.Finding) string {
	// Map Kubesec/scanner findings to exploit types
	idLower := strings.ToLower(finding.ID)
	titleLower := strings.ToLower(finding.Title)
	
	if strings.Contains(idLower, "privileged") || strings.Contains(titleLower, "privileged") {
		return "privileged_container"
	}
	if strings.Contains(idLower, "hostpath") || strings.Contains(titleLower, "hostpath") {
		return "hostpath_mount"
	}
	if strings.Contains(idLower, "hostnetwork") || strings.Contains(titleLower, "host network") {
		return "host_network"
	}
	if strings.Contains(idLower, "hostpid") || strings.Contains(titleLower, "host pid") {
		return "host_pid"
	}
	if strings.Contains(idLower, "hostipc") || strings.Contains(titleLower, "host ipc") {
		return "host_ipc"
	}
	if strings.Contains(idLower, "docker") && strings.Contains(idLower, "sock") {
		return "docker_socket_mount"
	}
	if strings.Contains(idLower, "aws") || strings.Contains(titleLower, "aws") {
		return "aws_credentials_exposed"
	}
	if strings.Contains(idLower, "secret") || strings.Contains(titleLower, "secret") {
		return "exposed_secrets"
	}
	if strings.Contains(idLower, "rbac") {
		return "weak_rbac"
	}
	if strings.Contains(idLower, "s3") && strings.Contains(titleLower, "public") {
		return "public_s3_bucket"
	}
	
	return "other"
}

// determineTargetType figures out what we're scanning
func determineTargetType(path string, findings []scanner.Finding) string {
	// Check findings for clues
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.File), ".yaml") || strings.Contains(strings.ToLower(f.File), ".yml") {
			return "kubernetes"
		}
		if strings.Contains(strings.ToLower(f.File), "dockerfile") {
			return "docker"
		}
		if strings.Contains(strings.ToLower(f.File), ".tf") {
			return "terraform"
		}
	}
	
	return "general"
}
