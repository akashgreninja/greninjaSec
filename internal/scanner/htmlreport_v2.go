package scanner

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed templates/report.html
var reportTemplate string

//go:embed templates/styles.css
var stylesCSS string

//go:embed templates/script.js
var scriptJS string

// GenerateHTMLReportV2 creates an interactive HTML report with tabs
func GenerateHTMLReportV2(result ScanResult, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Open output file
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer f.Close()

	// Prepare data for template
	data := prepareReportDataV2(result)

	// Inline CSS and JS into HTML template
	finalTemplate := strings.ReplaceAll(reportTemplate, `<link rel="stylesheet" href="./styles.css">`, `<style>`+stylesCSS+`</style>`)
	finalTemplate = strings.ReplaceAll(finalTemplate, `<script src="./script.js"></script>`, `<script>`+scriptJS+`</script>`)

	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"colorForSeverity": colorForSeverity,
		"lower":            func(s string) string { return strings.ToLower(s) },
		"add":              func(a, b int) int { return a + b },
		"sub":              func(a, b int) int { return a - b },
		"lt":               func(a, b int) bool { return a < b },
		"gt":               func(a, b int) bool { return a > b },
		"list":             func(items ...string) []string { return items },
		"hasPrefix":        func(s, prefix string) bool { return strings.HasPrefix(s, prefix) },
		"len":              func(v interface{}) int {
			switch v := v.(type) {
			case []Finding:
				return len(v)
			case []AttackChain:
				return len(v)
			default:
				return 0
			}
		},
	}).Parse(finalTemplate))

	return tmpl.Execute(f, data)
}

type reportDataV2 struct {
	Timestamp       string
	TotalFindings   int
	CriticalCount   int
	HighCount       int
	MediumCount     int
	LowCount        int
	CVECount        int
	CVEFindings     []Finding
	AttackChains    []AttackChain
	FindingsBySev   map[string][]Finding
	ScanSummary     string
}

func prepareReportDataV2(result ScanResult) reportDataV2 {
	// Group findings by severity
	findingsBySev := make(map[string][]Finding)
	for _, finding := range result.Findings {
		findingsBySev[finding.Severity] = append(findingsBySev[finding.Severity], finding)
	}

	// Extract CVE findings
	var cveFindings []Finding
	for _, finding := range result.Findings {
		if strings.HasPrefix(finding.ID, "CVE-") {
			cveFindings = append(cveFindings, finding)
		}
	}

	// Count by severity
	criticalCount := len(findingsBySev["CRITICAL"])
	highCount := len(findingsBySev["HIGH"])
	mediumCount := len(findingsBySev["MEDIUM"])
	lowCount := len(findingsBySev["LOW"])

	totalFindings := len(result.Findings)

	// Count unique files
	uniqueFiles := make(map[string]bool)
	for _, finding := range result.Findings {
		uniqueFiles[finding.File] = true
	}

	// Generate summary
	summary := fmt.Sprintf(
		"Scan completed on %s. Found %d total security issues across %d files. "+
			"%d critical, %d high, %d medium, and %d low severity findings detected.",
		time.Now().Format("January 2, 2006 at 3:04 PM"),
		totalFindings,
		len(uniqueFiles),
		criticalCount,
		highCount,
		mediumCount,
		lowCount,
	)

	if len(cveFindings) > 0 {
		summary += fmt.Sprintf(" Detected %d CVE vulnerabilities.", len(cveFindings))
	}

	if len(result.AttackChains) > 0 {
		summary += fmt.Sprintf(" Identified %d potential attack chains.", len(result.AttackChains))
	}

	return reportDataV2{
		Timestamp:     time.Now().Format("Monday, January 2, 2006 at 3:04 PM"),
		TotalFindings: totalFindings,
		CriticalCount: criticalCount,
		HighCount:     highCount,
		MediumCount:   mediumCount,
		LowCount:      lowCount,
		CVECount:      len(cveFindings),
		CVEFindings:   cveFindings,
		AttackChains:  result.AttackChains,
		FindingsBySev: findingsBySev,
		ScanSummary:   summary,
	}
}
