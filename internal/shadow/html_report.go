package shadow

import (
	"fmt"
	"html/template"
	"os"
	"time"
)

// GenerateHTMLReport creates an interactive HTML report for shadow deploy simulation
func GenerateHTMLReport(result *SimulationResult, outputPath string) error {
	// Create template with custom functions
	funcMap := template.FuncMap{
		"divideFloat": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
	}
	
	tmpl := template.Must(template.New("shadow").Funcs(funcMap).Parse(htmlTemplate))
	
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer f.Close()

	// Prepare data for template
	data := struct {
		Simulation      ShadowSimulation
		Result          SimulationResult
		GeneratedAt     string
		SuccessRate     string
		Duration        string
		AttackPaths     []AttackPath
		Recommendations []Recommendation
		Timeline        []TimelineEvent
	}{
		Simulation:      result.Simulation,
		Result:          *result,
		GeneratedAt:     time.Now().Format("2006-01-02 15:04:05"),
		SuccessRate:     fmt.Sprintf("%.0f%%", result.Simulation.SuccessRate),
		Duration:        formatDuration(result.Simulation.TimeToCompromise),
		AttackPaths:     result.Simulation.AttackPaths,
		Recommendations: result.Recommendations,
		Timeline:        result.AttackTimeline,
	}

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎭 Shadow Deploy Simulation Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8fafc;
        }
        
        .metric-card {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-left: 5px solid #3b82f6;
            transition: transform 0.3s ease;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.15);
        }
        
        .metric-card.critical {
            border-left-color: #dc2626;
        }
        
        .metric-card.success {
            border-left-color: #16a34a;
        }
        
        .metric-card.warning {
            border-left-color: #ea580c;
        }
        
        .metric-label {
            font-size: 0.9em;
            color: #64748b;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #1e293b;
        }
        
        .metric-unit {
            font-size: 0.4em;
            color: #94a3b8;
            margin-left: 5px;
        }
        
        .section {
            padding: 40px;
        }
        
        .section-title {
            font-size: 2em;
            margin-bottom: 30px;
            color: #1e293b;
            border-bottom: 3px solid #3b82f6;
            padding-bottom: 10px;
        }
        
        .attack-path {
            background: #f1f5f9;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            border-left: 8px solid #ef4444;
        }
        
        .attack-path.success {
            border-left-color: #22c55e;
        }
        
        .attack-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .attack-name {
            font-size: 1.5em;
            font-weight: bold;
            color: #1e293b;
        }
        
        .impact-badge {
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            color: white;
        }
        
        .impact-CRITICAL { background: #dc2626; }
        .impact-HIGH { background: #ea580c; }
        .impact-MEDIUM { background: #f59e0b; }
        .impact-LOW { background: #84cc16; }
        
        .attack-steps {
            margin-top: 20px;
        }
        
        .step {
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 10px;
            border-left: 4px solid #3b82f6;
            transition: all 0.3s ease;
        }
        
        .step:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transform: translateX(5px);
        }
        
        .step-number {
            display: inline-block;
            background: #3b82f6;
            color: white;
            width: 30px;
            height: 30px;
            line-height: 30px;
            text-align: center;
            border-radius: 50%;
            margin-right: 15px;
            font-weight: bold;
        }
        
        .step-description {
            font-size: 1.1em;
            color: #1e293b;
            margin-bottom: 10px;
        }
        
        .step-command {
            background: #1e293b;
            color: #10b981;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-top: 10px;
        }
        
        .step-status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .step-status.success {
            background: #d1fae5;
            color: #065f46;
        }
        
        .step-status.failed {
            background: #fee2e2;
            color: #991b1b;
        }
        
        .blast-radius {
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            padding: 30px;
            border-radius: 15px;
            margin: 30px 0;
        }
        
        .blast-radius h3 {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #92400e;
        }
        
        .blast-items {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        .blast-item {
            background: white;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        
        .blast-item-value {
            font-size: 2em;
            font-weight: bold;
            color: #dc2626;
        }
        
        .blast-item-label {
            font-size: 0.9em;
            color: #64748b;
            margin-top: 5px;
        }
        
        .timeline {
            position: relative;
            padding-left: 40px;
        }
        
        .timeline::before {
            content: '';
            position: absolute;
            left: 15px;
            top: 0;
            bottom: 0;
            width: 4px;
            background: #3b82f6;
        }
        
        .timeline-event {
            position: relative;
            padding: 20px;
            background: #f8fafc;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .timeline-event::before {
            content: '';
            position: absolute;
            left: -32px;
            top: 25px;
            width: 16px;
            height: 16px;
            background: #3b82f6;
            border: 4px solid white;
            border-radius: 50%;
        }
        
        .timeline-time {
            font-size: 0.9em;
            color: #64748b;
            margin-bottom: 5px;
        }
        
        .timeline-action {
            font-size: 1.1em;
            color: #1e293b;
            font-weight: 500;
        }
        
        .recommendations {
            background: #f0fdf4;
            padding: 30px;
            border-radius: 15px;
        }
        
        .recommendation {
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 5px solid #16a34a;
        }
        
        .recommendation-priority {
            display: inline-block;
            background: #dc2626;
            color: white;
            padding: 5px 15px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .recommendation-title {
            font-size: 1.3em;
            font-weight: bold;
            color: #1e293b;
            margin-bottom: 10px;
        }
        
        .recommendation-desc {
            color: #64748b;
            line-height: 1.6;
            margin-bottom: 15px;
        }
        
        .recommendation-fix {
            background: #f8fafc;
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #3b82f6;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .footer {
            background: #1e293b;
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .footer a {
            color: #60a5fa;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎭 Shadow Deploy Simulation Report</h1>
            <p>Attack Demonstration & Security Analysis</p>
            <p style="font-size: 0.9em; opacity: 0.7;">Generated: {{.GeneratedAt}}</p>
        </div>
        
        <div class="metrics">
            <div class="metric-card critical">
                <div class="metric-label">Attack Success Rate</div>
                <div class="metric-value">{{.SuccessRate}}</div>
            </div>
            
            <div class="metric-card warning">
                <div class="metric-label">Time to Compromise</div>
                <div class="metric-value">{{.Duration}}</div>
            </div>
            
            <div class="metric-card critical">
                <div class="metric-label">Estimated Breach Cost</div>
                <div class="metric-value">
                    ${{printf "%.1f" (divideFloat .Simulation.EstimatedDamage.MinCost 1000000)}}M
                    <span class="metric-unit">- ${{printf "%.1f" (divideFloat .Simulation.EstimatedDamage.MaxCost 1000000)}}M</span>
                </div>
            </div>
            
            <div class="metric-card warning">
                <div class="metric-label">Systems Compromised</div>
                <div class="metric-value">{{.Simulation.BlastRadius.SystemsCompromised}}</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">🔥 Blast Radius</h2>
            <div class="blast-radius">
                <h3>💥 What an Attacker Can Access</h3>
                <div class="blast-items">
                    <div class="blast-item">
                        <div class="blast-item-value">{{.Simulation.BlastRadius.SystemsCompromised}}</div>
                        <div class="blast-item-label">Systems Compromised</div>
                    </div>
                    <div class="blast-item">
                        <div class="blast-item-value">{{.Simulation.BlastRadius.SecretsExposed}}</div>
                        <div class="blast-item-label">Secrets Exposed</div>
                    </div>
                    <div class="blast-item">
                        <div class="blast-item-value">{{len .Simulation.BlastRadius.DatabasesAccessible}}</div>
                        <div class="blast-item-label">Databases Accessible</div>
                    </div>
                    <div class="blast-item">
                        <div class="blast-item-value">{{.Simulation.BlastRadius.NetworkScope}}</div>
                        <div class="blast-item-label">Network Scope</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">🥷 Attack Paths Demonstrated</h2>
            {{range .AttackPaths}}
            <div class="attack-path {{if .Success}}success{{end}}">
                <div class="attack-header">
                    <div class="attack-name">{{.Name}}</div>
                    <span class="impact-badge impact-{{.Impact}}">{{.Impact}}</span>
                </div>
                <p style="color: #64748b; margin-bottom: 20px;">Attack Vector: <strong>{{.Vector}}</strong></p>
                
                <div class="attack-steps">
                    {{range .Steps}}
                    <div class="step">
                        <div class="step-description">
                            <span class="step-number">{{.Number}}</span>
                            {{.Description}}
                            <span class="step-status {{if .Success}}success{{else}}failed{{end}}">
                                {{if .Success}}✓ Success{{else}}✗ Failed{{end}}
                            </span>
                        </div>
                        {{if .Command}}
                        <div class="step-command">$ {{.Command}}</div>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>
        
        {{if .Timeline}}
        <div class="section">
            <h2 class="section-title">⏱️ Attack Timeline</h2>
            <div class="timeline">
                {{range .Timeline}}
                <div class="timeline-event">
                    <div class="timeline-time">{{.Timestamp.Format "15:04:05"}}</div>
                    <div class="timeline-action">Step {{.Step}}: {{.Action}}</div>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}
        
        {{if .Recommendations}}
        <div class="section">
            <h2 class="section-title">🛡️ Defense Recommendations</h2>
            <div class="recommendations">
                {{range .Recommendations}}
                <div class="recommendation">
                    <span class="recommendation-priority">Priority {{.Priority}}</span>
                    <div class="recommendation-title">{{.Title}}</div>
                    <div class="recommendation-desc">{{.Description}}</div>
                    <div class="recommendation-fix">Fix: {{.Fix}}</div>
                </div>
                {{end}}
            </div>
        </div>
        {{end}}
        
        <div class="footer">
            <p>🥷 Powered by <strong>GreninjaSec</strong> Shadow Deploy Simulator</p>
            <p style="margin-top: 10px;">
                <a href="https://github.com/akashgreninja/greninjaSec" target="_blank">GitHub Repository</a> |
                <a href="https://github.com/akashgreninja/greninjaSec/blob/main/WATCHER_DETECTION.md">Documentation</a>
            </p>
            <p style="font-size: 0.9em; margin-top: 20px; opacity: 0.7;">
                This is a simulated attack demonstration. No actual systems were compromised.
            </p>
        </div>
    </div>
</body>
</html>`
