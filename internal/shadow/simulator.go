package shadow

import (
	"fmt"
	"time"
)

// Simulator is the main Shadow Deploy engine
type Simulator struct {
	config      SimulationConfig
	playbooks   map[AttackVector][]Playbook
	sandbox     *Sandbox
	aiEnhancer  *AIExploitEnhancer
}

// NewSimulator creates a new shadow deploy simulator
func NewSimulator(config SimulationConfig) *Simulator {
	return &Simulator{
		config:     config,
		playbooks:  initializePlaybooks(),
		sandbox:    NewSandbox(config.Isolated),
		aiEnhancer: nil, // Set via SetAIEnhancer if available
	}
}

// SetAIEnhancer enables AI-powered exploit enhancement
func (s *Simulator) SetAIEnhancer(enhancer *AIExploitEnhancer) {
	s.aiEnhancer = enhancer
}

// Run executes the full shadow deploy simulation
func (s *Simulator) Run(targetPath string, targetType string, vulnerabilities []Vulnerability) (*SimulationResult, error) {
	simulation := ShadowSimulation{
		ID:              generateID(),
		StartTime:       time.Now(),
		TargetType:      targetType,
		TargetPath:      targetPath,
		Vulnerabilities: vulnerabilities,
		AttackPaths:     []AttackPath{},
	}

	fmt.Println("\n🎭 Shadow Deploy Simulator - Attack Demonstration")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	// Phase 1: Identify exploitable vulnerabilities
	exploitable := s.filterExploitable(vulnerabilities)
	fmt.Printf("\n[1/5] 🔍 Analyzing vulnerabilities...\n")
	fmt.Printf("      Found %d total issues, %d are exploitable\n", len(vulnerabilities), len(exploitable))
	
	if len(exploitable) == 0 {
		return &SimulationResult{
			Simulation: simulation,
			ExecutionLog: []string{"No exploitable vulnerabilities found"},
		}, nil
	}

	// Phase 2: Map vulnerabilities to attack vectors
	attackVectors := s.mapToAttackVectors(exploitable)
	fmt.Printf("\n[2/5] 🎯 Identifying attack vectors...\n")
	fmt.Printf("      Discovered %d critical attack paths\n", len(attackVectors))

	// Phase 3: Build sandbox environment (if not dry-run)
	fmt.Printf("\n[3/5] 🏗️  Preparing simulation environment...\n")
	if s.config.DryRun {
		fmt.Printf("      Running in DRY-RUN mode (safe)\n")
	} else {
		fmt.Printf("      Building isolated sandbox...\n")
		if err := s.sandbox.Setup(); err != nil {
			return nil, fmt.Errorf("failed to setup sandbox: %w", err)
		}
		defer s.sandbox.Cleanup()
	}

	// Phase 4: Execute attack playbooks
	fmt.Printf("\n[4/5] 🥷 Simulating attacks...\n\n")
	executionLog := []string{}
	timeline := []TimelineEvent{}
	
	for _, vector := range attackVectors {
		playbook := s.selectPlaybook(vector, exploitable)
		if playbook == nil {
			continue
		}

		attackPath, logs, events := s.executePlaybook(playbook, vector)
		simulation.AttackPaths = append(simulation.AttackPaths, *attackPath)
		executionLog = append(executionLog, logs...)
		timeline = append(timeline, events...)
	}

	// AI Enhancement: Discover additional exploit techniques
	if s.aiEnhancer != nil {
		enhancedPaths, err := s.aiEnhancer.EnhanceAttackPaths(exploitable, simulation.AttackPaths)
		if err != nil {
			fmt.Printf("      ⚠️  AI enhancement failed: %v\n", err)
		} else {
			simulation.AttackPaths = enhancedPaths
		}
	}

	// Phase 5: Calculate blast radius and impact
	fmt.Printf("\n[5/5] 📊 Calculating impact...\n\n")
	simulation.BlastRadius = s.calculateBlastRadius(simulation.AttackPaths)
	simulation.EstimatedDamage = s.estimateDamage(simulation.BlastRadius, exploitable)
	simulation.TimeToCompromise = s.calculateTimeToCompromise(simulation.AttackPaths)
	simulation.SuccessRate = s.calculateSuccessRate(simulation.AttackPaths)
	simulation.EndTime = time.Now()

	// Generate recommendations
	recommendations := s.generateRecommendations(simulation)

	// AI Enhancement: Get AI-powered defense recommendations
	if s.aiEnhancer != nil {
		aiRecs, err := s.aiEnhancer.SuggestDefenses(simulation)
		if err != nil {
			fmt.Printf("      ⚠️  AI defense suggestions failed: %v\n", err)
		} else {
			// Merge AI recommendations with standard ones
			recommendations = append(recommendations, aiRecs...)
		}
	}

	// Print summary
	s.printSummary(simulation)

	result := &SimulationResult{
		Simulation:      simulation,
		ExecutionLog:    executionLog,
		AttackTimeline:  timeline,
		Recommendations: recommendations,
	}

	// Generate report if configured
	if s.config.GenerateReport {
		reportPath := "greninjasec-shadow-report.html"
		if err := GenerateHTMLReport(result, reportPath); err != nil {
			fmt.Printf("⚠️  Failed to generate HTML report: %v\n", err)
		} else {
			result.ReportPath = reportPath
			fmt.Printf("\n📄 Full report: %s\n", reportPath)
		}
	}

	return result, nil
}

// filterExploitable identifies which vulnerabilities are actually exploitable
func (s *Simulator) filterExploitable(vulns []Vulnerability) []Vulnerability {
	exploitable := []Vulnerability{}
	for _, v := range vulns {
		// Check if we have a playbook that can exploit this
		if s.canExploit(v) {
			v.Exploitable = true
			exploitable = append(exploitable, v)
		}
	}
	return exploitable
}

// canExploit checks if we have attack techniques for this vulnerability
func (s *Simulator) canExploit(vuln Vulnerability) bool {
	// Map common vulnerability types to exploitability
	exploitableTypes := map[string]bool{
		"privileged_container":       true,
		"docker_socket_mount":        true,
		"hostpath_mount":             true,
		"host_network":               true,
		"host_pid":                   true,
		"host_ipc":                   true,
		"no_security_context":        true,
		"run_as_root":                true,
		"aws_credentials_exposed":    true,
		"cloud_metadata_accessible":  true,
		"weak_rbac":                  true,
		"public_s3_bucket":           true,
		"public_database":            true,
		"weak_network_policy":        true,
		"exposed_secrets":            true,
	}
	
	return exploitableTypes[vuln.Type]
}

// mapToAttackVectors maps vulnerabilities to attack vectors
func (s *Simulator) mapToAttackVectors(vulns []Vulnerability) []AttackVector {
	vectors := make(map[AttackVector]bool)
	
	for _, v := range vulns {
		switch v.Type {
		case "privileged_container", "host_pid", "host_ipc":
			vectors[VectorContainerEscape] = true
		case "docker_socket_mount":
			vectors[VectorDockerSocketAbuse] = true
		case "hostpath_mount":
			vectors[VectorHostPathEscape] = true
		case "weak_rbac", "no_security_context":
			vectors[VectorLateralMovement] = true
			vectors[VectorPrivilegeEscalation] = true
		case "aws_credentials_exposed", "cloud_metadata_accessible":
			vectors[VectorCredentialTheft] = true
			vectors[VectorCloudTakeover] = true
		case "public_s3_bucket", "public_database":
			vectors[VectorDataExfiltration] = true
		}
	}
	
	result := []AttackVector{}
	for v := range vectors {
		result = append(result, v)
	}
	return result
}

// selectPlaybook chooses the right attack playbook
func (s *Simulator) selectPlaybook(vector AttackVector, vulns []Vulnerability) *Playbook {
	playbooks, exists := s.playbooks[vector]
	if !exists || len(playbooks) == 0 {
		return nil
	}
	
	// For now, return first matching playbook
	// TODO: Rank by likelihood of success
	for _, pb := range playbooks {
		if s.playbookMatches(pb, vulns) {
			return &pb
		}
	}
	
	return nil
}

// playbookMatches checks if vulnerabilities satisfy playbook requirements
func (s *Simulator) playbookMatches(playbook Playbook, vulns []Vulnerability) bool {
	if len(playbook.RequiredVulns) == 0 {
		return true
	}
	
	vulnTypes := make(map[string]bool)
	for _, v := range vulns {
		vulnTypes[v.Type] = true
	}
	
	for _, required := range playbook.RequiredVulns {
		if !vulnTypes[required] {
			return false
		}
	}
	
	return true
}

// executePlaybook runs an attack playbook and returns results
func (s *Simulator) executePlaybook(playbook *Playbook, vector AttackVector) (*AttackPath, []string, []TimelineEvent) {
	attackPath := AttackPath{
		ID:       generateID(),
		Name:     playbook.Name,
		Vector:   vector,
		Steps:    []AttackStep{},
		Success:  false,
		Duration: 0,
	}
	
	logs := []string{}
	timeline := []TimelineEvent{}
	startTime := time.Now()
	
	fmt.Printf("      ┌─ %s\n", playbook.Name)
	
	for i, step := range playbook.Steps {
		stepStart := time.Now()
		
		attackStep := AttackStep{
			Number:      i + 1,
			Command:     step.Command,
			Description: step.Description,
			Expected:    "Success",
			Timestamp:   stepStart,
		}
		
		// Execute or simulate the step
		var output string
		var success bool
		
		if s.config.DryRun {
			// Dry run - simulate success based on playbook expectations
			output = fmt.Sprintf("[SIMULATED] %s would succeed", step.Description)
			success = true
		} else {
			// Actually execute in sandbox
			output, success = s.sandbox.Execute(step.Command)
		}
		
		attackStep.Actual = output
		attackStep.Success = success
		attackStep.Duration = time.Since(stepStart)
		
		attackPath.Steps = append(attackPath.Steps, attackStep)
		
		icon := "✓"
		if !success {
			icon = "✗"
		}
		
		fmt.Printf("      │  %s %s\n", icon, step.Description)
		if s.config.Verbose {
			fmt.Printf("      │    Command: %s\n", step.Command)
			fmt.Printf("      │    Result: %s\n", truncate(output, 60))
		}
		
		// Add to timeline
		timeline = append(timeline, TimelineEvent{
			Timestamp: stepStart,
			Step:      i + 1,
			Action:    step.Description,
			Result:    truncate(output, 100),
			Impact:    step.Impact,
		})
		
		logs = append(logs, fmt.Sprintf("[%s] Step %d: %s - %s", 
			stepStart.Format("15:04:05"), i+1, step.Description, output))
		
		// Stop if step failed and configured to stop
		if !success && s.config.StopOnFailure {
			break
		}
	}
	
	attackPath.Duration = time.Since(startTime)
	attackPath.Success = attackPath.Steps[len(attackPath.Steps)-1].Success
	attackPath.Impact = s.determineImpact(attackPath)
	
	fmt.Printf("      │  Impact: %s\n", attackPath.Impact)
	fmt.Printf("      │\n")
	
	return &attackPath, logs, timeline
}

// Helper functions
func (s *Simulator) calculateBlastRadius(paths []AttackPath) BlastRadius {
	// TODO: Implement real blast radius calculation
	return BlastRadius{
		SystemsCompromised:  estimateSystemsCompromised(paths),
		SecretsExposed:      estimateSecretsExposed(paths),
		DatabasesAccessible: []string{"postgres", "redis"},
		NetworkScope:        "cluster-wide",
	}
}

func (s *Simulator) estimateDamage(radius BlastRadius, vulns []Vulnerability) DamageEstimate {
	// TODO: Implement real damage estimation
	return DamageEstimate{
		MinCost:           500000,
		MaxCost:           2500000,
		GDPRFines:         500000,
		ReputationDamage:  "High",
		DataBreachRecords: 100000,
	}
}

func (s *Simulator) calculateTimeToCompromise(paths []AttackPath) time.Duration {
	if len(paths) == 0 {
		return 0
	}
	// Return fastest path
	fastest := paths[0].Duration
	for _, p := range paths {
		if p.Success && p.Duration < fastest {
			fastest = p.Duration
		}
	}
	return fastest
}

func (s *Simulator) calculateSuccessRate(paths []AttackPath) float64 {
	if len(paths) == 0 {
		return 0
	}
	successful := 0
	for _, p := range paths {
		if p.Success {
			successful++
		}
	}
	return float64(successful) / float64(len(paths)) * 100
}

func (s *Simulator) determineImpact(path AttackPath) ImpactLevel {
	// Determine based on what was compromised
	switch path.Vector {
	case VectorContainerEscape, VectorCloudTakeover:
		return ImpactCritical
	case VectorCredentialTheft, VectorDataExfiltration:
		return ImpactCritical
	case VectorLateralMovement, VectorPrivilegeEscalation:
		return ImpactHigh
	default:
		return ImpactMedium
	}
}

func (s *Simulator) generateRecommendations(sim ShadowSimulation) []Recommendation {
	// Generate smart recommendations based on attack paths
	recs := []Recommendation{}
	
	// Track what we've recommended to avoid duplicates
	recommended := make(map[string]bool)
	
	for _, path := range sim.AttackPaths {
		if !path.Success {
			continue
		}
		
		// Generate recommendations based on attack vector
		var rec Recommendation
		
		switch path.Vector {
		case VectorContainerEscape:
			if !recommended["privileged"] {
				rec = Recommendation{
					Priority:    1,
					Title:       "Remove privileged containers",
					Description: "Containers with privileged: true can escape to host using nsenter or similar techniques",
					Fix:         "Set securityContext.privileged: false and use specific capabilities instead",
					Impact:      "Prevents container escape attacks that could compromise the entire host",
				}
				recs = append(recs, rec)
				recommended["privileged"] = true
			}
			
		case VectorDockerSocketAbuse:
			if !recommended["docker-socket"] {
				rec = Recommendation{
					Priority:    1,
					Title:       "Remove Docker socket mounts",
					Description: "Mounted /var/run/docker.sock allows spawning privileged containers on host",
					Fix:         "Remove hostPath volume mount for /var/run/docker.sock",
					Impact:      "Blocks Docker socket abuse leading to full host compromise",
				}
				recs = append(recs, rec)
				recommended["docker-socket"] = true
			}
			
		case VectorHostPathEscape:
			if !recommended["hostpath"] {
				rec = Recommendation{
					Priority:    2,
					Title:       "Restrict hostPath mounts",
					Description: "HostPath volumes provide access to host filesystem",
					Fix:         "Use PersistentVolumes instead of hostPath, or restrict with readOnly: true",
					Impact:      "Limits filesystem access and prevents sensitive file exfiltration",
				}
				recs = append(recs, rec)
				recommended["hostpath"] = true
			}
			
		case VectorCredentialTheft, VectorCloudTakeover:
			if !recommended["credentials"] {
				rec = Recommendation{
					Priority:    1,
					Title:       "Rotate exposed credentials immediately",
					Description: "Hardcoded AWS/cloud credentials detected in configuration",
					Fix:         "Use Kubernetes secrets + IAM roles for service accounts (IRSA for AWS)",
					Impact:      "Prevents cloud account takeover and data exfiltration",
				}
				recs = append(recs, rec)
				recommended["credentials"] = true
			}
			
		case VectorLateralMovement, VectorPrivilegeEscalation:
			if !recommended["rbac"] {
				rec = Recommendation{
					Priority:    2,
					Title:       "Implement least-privilege RBAC",
					Description: "Overly permissive service accounts allow cluster-wide access",
					Fix:         "Create specific RoleBindings instead of ClusterRoleBindings, limit permissions",
					Impact:      "Restricts lateral movement and privilege escalation within cluster",
				}
				recs = append(recs, rec)
				recommended["rbac"] = true
			}
		}
	}
	
	// Add general security best practices if we have successful attacks
	if len(sim.AttackPaths) > 0 {
		recs = append(recs, Recommendation{
			Priority:    3,
			Title:       "Implement Pod Security Standards",
			Description: "Enable Pod Security Admission to enforce baseline security policies",
			Fix:         "Add pod-security.kubernetes.io/enforce: restricted label to namespaces",
			Impact:      "Provides defense-in-depth by blocking dangerous configurations",
		})
	}
	
	return recs
}

func (s *Simulator) printSummary(sim ShadowSimulation) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("\n✅ Simulation Complete!")
	fmt.Println()
	
	fmt.Printf("📈 Attack Success Rate: %.0f%%\n", sim.SuccessRate)
	fmt.Printf("⏱️  Time to Full Compromise: %s\n", formatDuration(sim.TimeToCompromise))
	fmt.Printf("💰 Estimated Breach Cost: $%.1fM - $%.1fM\n", 
		sim.EstimatedDamage.MinCost/1000000, 
		sim.EstimatedDamage.MaxCost/1000000)
	
	fmt.Printf("\n🔥 BLAST RADIUS:\n")
	fmt.Printf("   ├─ Systems Compromised: %d\n", sim.BlastRadius.SystemsCompromised)
	fmt.Printf("   ├─ Secrets Exposed: %d\n", sim.BlastRadius.SecretsExposed)
	fmt.Printf("   ├─ Databases Accessible: %v\n", sim.BlastRadius.DatabasesAccessible)
	fmt.Printf("   └─ Network Scope: %s\n", sim.BlastRadius.NetworkScope)
	
	fmt.Printf("\n🎯 Priority Fixes: %d critical issues\n", len(sim.Vulnerabilities))
}

// Utility functions
func generateID() string {
	return fmt.Sprintf("shadow-%d", time.Now().UnixNano())
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func formatDuration(d time.Duration) string {
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%d minutes %d seconds", minutes, seconds)
}

func estimateSystemsCompromised(paths []AttackPath) int {
	// Simple estimation based on successful attacks
	count := 0
	for _, p := range paths {
		if p.Success {
			count += 5 // Each successful path compromises ~5 systems
		}
	}
	return count
}

func estimateSecretsExposed(paths []AttackPath) int {
	// Estimate based on attack vectors
	count := 0
	for _, p := range paths {
		if p.Success && (p.Vector == VectorCredentialTheft || p.Vector == VectorLateralMovement) {
			count += 10
		}
	}
	return count
}
