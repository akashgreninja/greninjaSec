package scanner

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GenerateHTMLReport creates an interactive HTML report with visualizations
func GenerateHTMLReport(result ScanResult, outputPath string) error {
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
	data := prepareReportData(result)

	// Execute template
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
	}).Parse(htmlTemplate))

	return tmpl.Execute(f, data)
}

type reportData struct {
	GeneratedAt     string
	TotalFindings   int
	CriticalCount   int
	HighCount       int
	MediumCount     int
	LowCount        int
	AttackChains    []AttackChain
	FindingsBySev   map[string][]Finding
	SeverityChart   map[string]int
	FileStats       map[string]int
	TopRisks        []Finding
	ScanSummary     string
}

func prepareReportData(result ScanResult) reportData {
	data := reportData{
		GeneratedAt:   time.Now().Format("2006-01-02 15:04:05"),
		TotalFindings: len(result.Findings),
		AttackChains:  result.AttackChains,
		FindingsBySev: make(map[string][]Finding),
		SeverityChart: make(map[string]int),
		FileStats:     make(map[string]int),
	}

	// Group findings by severity
	for _, f := range result.Findings {
		data.FindingsBySev[f.Severity] = append(data.FindingsBySev[f.Severity], f)
		data.SeverityChart[f.Severity]++
		
		// Count by file
		data.FileStats[f.File]++

		// Count by severity
		switch f.Severity {
		case "CRITICAL":
			data.CriticalCount++
		case "HIGH":
			data.HighCount++
		case "MEDIUM":
			data.MediumCount++
		case "LOW":
			data.LowCount++
		}
	}

	// Get top 5 critical/high risks
	for _, sev := range []string{"CRITICAL", "HIGH"} {
		findings := data.FindingsBySev[sev]
		for i, f := range findings {
			if i >= 5 {
				break
			}
			data.TopRisks = append(data.TopRisks, f)
		}
	}

	// Generate summary
	data.ScanSummary = fmt.Sprintf("Scanned infrastructure and identified %d security issues across %d files. Found %d attack chains with exploitable paths.",
		data.TotalFindings, len(data.FileStats), len(data.AttackChains))

	return data
}

func colorForSeverity(severity string) string {
	switch severity {
	case "CRITICAL":
		return "#dc2626"
	case "HIGH":
		return "#ea580c"
	case "MEDIUM":
		return "#f59e0b"
	case "LOW":
		return "#84cc16"
	default:
		return "#6b7280"
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GreninjaSec Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #1f2937;
            line-height: 1.6;
            padding: 2rem;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: white;
            padding: 2rem 3rem;
            border-bottom: 4px solid #818cf8;
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .ninja-icon {
            font-size: 3rem;
        }
        
        .header .meta {
            color: #cbd5e1;
            font-size: 0.9rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            padding: 2rem 3rem;
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border-left: 4px solid;
        }
        
        .stat-card.critical { border-color: #dc2626; }
        .stat-card.high { border-color: #ea580c; }
        .stat-card.medium { border-color: #f59e0b; }
        .stat-card.low { border-color: #84cc16; }
        .stat-card.total { border-color: #6366f1; }
        .stat-card.chains { border-color: #8b5cf6; }
        
        .stat-card h3 {
            font-size: 0.875rem;
            text-transform: uppercase;
            color: #64748b;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .stat-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #1e293b;
        }
        
        .content {
            padding: 3rem;
        }
        
        .section {
            margin-bottom: 3rem;
        }
        
        .section-title {
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            color: #1e293b;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .section-title::before {
            content: '';
            width: 4px;
            height: 2rem;
            background: #818cf8;
            border-radius: 2px;
        }
        
        .chart-container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        @media (max-width: 768px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
        }
        
        .attack-chain {
            background: white;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            transition: all 0.3s ease;
        }
        
        .attack-chain:hover {
            border-color: #818cf8;
            box-shadow: 0 4px 12px rgba(129, 140, 248, 0.2);
        }
        
        .attack-chain.critical { border-left: 6px solid #dc2626; }
        .attack-chain.high { border-left: 6px solid #ea580c; }
        .attack-chain.medium { border-left: 6px solid #f59e0b; }
        
        .chain-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .chain-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: #1e293b;
        }
        
        .chain-badges {
            display: flex;
            gap: 0.5rem;
        }
        
        .badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge.critical { background: #fecaca; color: #991b1b; }
        .badge.high { background: #fed7aa; color: #9a3412; }
        .badge.medium { background: #fde68a; color: #92400e; }
        .badge.low { background: #d9f99d; color: #3f6212; }
        
        .chain-meta {
            display: flex;
            gap: 2rem;
            margin-bottom: 1rem;
            font-size: 0.875rem;
            color: #64748b;
        }
        
        .chain-steps {
            margin: 1rem 0;
            padding: 1rem;
            background: #f8fafc;
            border-radius: 6px;
        }
        
        .chain-step {
            display: flex;
            gap: 1rem;
            margin-bottom: 0.75rem;
            align-items: flex-start;
        }
        
        .step-number {
            background: #818cf8;
            color: white;
            width: 2rem;
            height: 2rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            flex-shrink: 0;
        }
        
        .step-text {
            flex: 1;
            padding-top: 0.25rem;
        }
        
        .remediation {
            background: #ecfdf5;
            border-left: 4px solid #10b981;
            padding: 1rem;
            margin-top: 1rem;
            border-radius: 4px;
        }
        
        .remediation h4 {
            color: #047857;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .finding {
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 0.75rem;
        }
        
        .finding-title {
            font-weight: 600;
            color: #1e293b;
            flex: 1;
        }
        
        .finding-file {
            font-size: 0.875rem;
            color: #64748b;
            font-family: 'Courier New', monospace;
            margin-top: 0.5rem;
        }
        
        .finding-description {
            color: #475569;
            margin-bottom: 0.75rem;
        }
        
        .code-snippet {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            margin-top: 0.75rem;
        }
        
        #attack-graph {
            width: 100%;
            min-height: 400px;
            background: white;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
            padding: 2rem;
        }
        
        .chain-flow {
            margin-bottom: 3rem;
            background: #fafafa;
            padding: 2rem;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
        }
        
        .chain-flow-title {
            font-weight: 600;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.1rem;
            color: #1e293b;
        }
        
        .flow-container {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            overflow-x: auto;
            padding: 1rem 0;
            background: white;
            border-radius: 6px;
            padding: 1.5rem;
        }
        
        .flow-node {
            min-width: 180px;
            max-width: 220px;
            padding: 1rem 1.25rem;
            border-radius: 6px;
            background: #fff;
            border: 2px solid #cbd5e1;
            text-align: center;
            font-size: 0.85rem;
            line-height: 1.4;
            transition: all 0.2s ease;
            position: relative;
            flex-shrink: 0;
        }
        
        .flow-node:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            border-color: #64748b;
        }
        
        .flow-node.start {
            background: #fef2f2;
            border: 2px solid #dc2626;
            color: #991b1b;
            font-weight: 600;
        }
        
        .flow-node.step {
            background: #f8fafc;
            border: 2px solid #94a3b8;
            color: #334155;
        }
        
        .flow-node.end {
            background: #fef3c7;
            border: 2px solid #f59e0b;
            color: #92400e;
            font-weight: 600;
        }
        
        .flow-arrow {
            color: #64748b;
            font-size: 1.5rem;
            flex-shrink: 0;
            font-weight: bold;
        }
        
        .step-number {
            display: inline-block;
            background: #64748b;
            color: white;
            width: 22px;
            height: 22px;
            border-radius: 50%;
            font-size: 0.75rem;
            line-height: 22px;
            text-align: center;
            margin-right: 0.5rem;
            font-weight: 600;
        }
        
        .summary-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 8px;
            margin-bottom: 2rem;
        }
        
        .summary-box h3 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
        }
        
        .summary-box p {
            font-size: 1.1rem;
            line-height: 1.8;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><span class="ninja-icon">🥷</span> GreninjaSec Security Report</h1>
            <div class="meta">Generated: {{.GeneratedAt}}</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card total">
                <h3>Total Findings</h3>
                <div class="value">{{.TotalFindings}}</div>
            </div>
            <div class="stat-card critical">
                <h3>Critical</h3>
                <div class="value">{{.CriticalCount}}</div>
            </div>
            <div class="stat-card high">
                <h3>High</h3>
                <div class="value">{{.HighCount}}</div>
            </div>
            <div class="stat-card medium">
                <h3>Medium</h3>
                <div class="value">{{.MediumCount}}</div>
            </div>
            <div class="stat-card low">
                <h3>Low</h3>
                <div class="value">{{.LowCount}}</div>
            </div>
            <div class="stat-card chains">
                <h3>Attack Chains</h3>
                <div class="value">{{len .AttackChains}}</div>
            </div>
        </div>
        
        <div class="content">
            <div class="summary-box">
                <h3>📊 Scan Summary</h3>
                <p>{{.ScanSummary}}</p>
            </div>
            
            <div class="section">
                <h2 class="section-title">📈 Security Metrics</h2>
                <div class="charts-grid">
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <canvas id="fileChart"></canvas>
                    </div>
                </div>
            </div>
            
            {{if .AttackChains}}
            <div class="section">
                <h2 class="section-title">⛓️ Attack Chain Visualization</h2>
                <div id="attack-graph">
                    {{range $chainIdx, $chain := .AttackChains}}
                    {{if lt $chainIdx 3}}
                    <div class="chain-flow">
                        <div class="chain-flow-title">
                            <span class="badge {{$chain.Severity | lower}}">{{$chain.Severity}}</span>
                            {{$chain.Name}}
                        </div>
                        <div class="flow-container">
                            <div class="flow-node start">
                                🎯 Entry Point<br/>
                                <small style="font-size: 0.75rem; margin-top: 0.25rem; display: block;">{{len $chain.Findings}} vulnerabilities found</small>
                            </div>
                            <div class="flow-arrow">→</div>
                            {{range $stepIdx, $step := $chain.Steps}}
                            <div class="flow-node step">
                                <span class="step-number">{{add $stepIdx 1}}</span>
                                {{$step}}
                            </div>
                            {{if lt $stepIdx (sub (len $chain.Steps) 1)}}
                            <div class="flow-arrow">→</div>
                            {{end}}
                            {{end}}
                            <div class="flow-arrow">→</div>
                            <div class="flow-node end">
                                💀 Final Impact<br/>
                                <small style="font-size: 0.75rem; margin-top: 0.25rem; display: block;">{{$chain.Impact}}</small>
                            </div>
                        </div>
                    </div>
                    {{end}}
                    {{end}}
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">🎯 Identified Attack Chains</h2>
                {{range .AttackChains}}
                <div class="attack-chain {{.Severity | lower}}">
                    <div class="chain-header">
                        <div class="chain-title">{{.Name}}</div>
                        <div class="chain-badges">
                            <span class="badge {{.Severity | lower}}">{{.Severity}}</span>
                        </div>
                    </div>
                    <div class="chain-meta">
                        <div><strong>Likelihood:</strong> {{.Likelihood}}</div>
                        <div><strong>Impact:</strong> {{.Impact}}</div>
                        <div><strong>Findings:</strong> {{len .Findings}}</div>
                    </div>
                    <div class="chain-steps">
                        {{range $i, $step := .Steps}}
                        <div class="chain-step">
                            <div class="step-number">{{add $i 1}}</div>
                            <div class="step-text">{{$step}}</div>
                        </div>
                        {{end}}
                    </div>
                    <div class="remediation">
                        <h4>🛡️ Remediation</h4>
                        <p>{{.Remediation}}</p>
                    </div>
                </div>
                {{end}}
            </div>
            {{end}}
            
            {{if .TopRisks}}
            <div class="section">
                <h2 class="section-title">🔥 Top Security Risks</h2>
                {{range .TopRisks}}
                <div class="finding">
                    <div class="finding-header">
                        <div>
                            <div class="finding-title">{{.Title}}</div>
                            <div class="finding-file">📄 {{.File}}</div>
                        </div>
                        <span class="badge {{.Severity | lower}}">{{.Severity}}</span>
                    </div>
                    {{if .Snippet}}
                    <div class="code-snippet">{{.Snippet}}</div>
                    {{end}}
                </div>
                {{end}}
            </div>
            {{end}}
            
            <div class="section">
                <h2 class="section-title">📋 All Findings by Severity</h2>
                {{range $severity := list "CRITICAL" "HIGH" "MEDIUM" "LOW"}}
                    {{if index $.FindingsBySev $severity}}
                    <h3 style="color: {{colorForSeverity $severity}}; margin: 2rem 0 1rem 0;">{{$severity}} ({{len (index $.FindingsBySev $severity)}})</h3>
                    {{range index $.FindingsBySev $severity}}
                    <div class="finding">
                        <div class="finding-header">
                            <div>
                                <div class="finding-title">{{.Title}}</div>
                                <div class="finding-file">📄 {{.File}}</div>
                            </div>
                            <span class="badge {{.Severity | lower}}">{{.Severity}}</span>
                        </div>
                        {{if .Snippet}}
                        <div class="code-snippet">{{.Snippet}}</div>
                        {{end}}
                    </div>
                    {{end}}
                    {{end}}
                {{end}}
            </div>
        </div>
    </div>
    
    <script>
        // Helper functions
        function add(a, b) { return a + b; }
        function lower(s) { return s.toLowerCase(); }
        function list(...args) { return args; }
        
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        {{.CriticalCount}},
                        {{.HighCount}},
                        {{.MediumCount}},
                        {{.LowCount}}
                    ],
                    backgroundColor: ['#dc2626', '#ea580c', '#f59e0b', '#84cc16'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Findings by Severity',
                        font: { size: 16, weight: 'bold' }
                    },
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Files Chart
        const fileData = {{json .FileStats}};
        const fileLabels = Object.keys(fileData).slice(0, 10); // Top 10 files
        const fileCounts = fileLabels.map(f => fileData[f]);
        
        const fileCtx = document.getElementById('fileChart');
        new Chart(fileCtx, {
            type: 'bar',
            data: {
                labels: fileLabels.map(f => f.split('/').pop()),
                datasets: [{
                    label: 'Findings per File',
                    data: fileCounts,
                    backgroundColor: '#818cf8',
                    borderColor: '#6366f1',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Top Files with Most Issues',
                        font: { size: 16, weight: 'bold' }
                    },
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
`
