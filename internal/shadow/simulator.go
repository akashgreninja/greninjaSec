package shadow

import (
	"fmt"
	"strings"
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
			// Dry run - generate realistic output based on command
			output = s.getRealisticOutput(step.Command, step.Description)
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
	
	// Show AI-discovered attack techniques separately
	s.printAIDiscoveries(sim.AttackPaths)
	
	fmt.Printf("\n🎯 Priority Fixes: %d critical issues\n", len(sim.Vulnerabilities))
}

// printAIDiscoveries shows detailed information about AI-discovered attack techniques
func (s *Simulator) printAIDiscoveries(paths []AttackPath) {
	aiPaths := []AttackPath{}
	for _, path := range paths {
		if strings.Contains(path.Name, "🤖 AI-Discovered") {
			aiPaths = append(aiPaths, path)
		}
	}
	
	if len(aiPaths) == 0 {
		return
	}
	
	fmt.Printf("\n🤖 AI-DISCOVERED ATTACK TECHNIQUES:\n")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	for i, path := range aiPaths {
		fmt.Printf("\n[%d] %s\n", i+1, strings.TrimPrefix(path.Name, "🤖 AI-Discovered: "))
		fmt.Printf("    Vector: %s | Impact: %s\n", path.Vector, path.Impact)
		
		if len(path.Description) > 0 {
			// Split description into sections
			desc := path.Description
			if strings.Contains(desc, "🎯 MITRE ATT&CK:") {
				parts := strings.Split(desc, "\n\n")
				for _, part := range parts {
					if strings.HasPrefix(part, "🎯 MITRE ATT&CK:") {
						fmt.Printf("    %s\n", part)
					} else if strings.HasPrefix(part, "⚠️  Why Dangerous:") {
						fmt.Printf("    %s\n", part)
					} else if strings.HasPrefix(part, "📖 Real-world Example:") {
						fmt.Printf("    %s\n", part)
					} else if len(strings.TrimSpace(part)) > 0 {
						fmt.Printf("    📝 %s\n", truncateString(part, 150))
					}
				}
			} else {
				fmt.Printf("    📝 %s\n", truncateString(desc, 200))
			}
		}
		
		// Show key attack steps
		if len(path.Steps) > 0 {
			fmt.Printf("    🔧 Attack Steps:\n")
			for j, step := range path.Steps {
				if j >= 3 { // Show only first 3 steps
					fmt.Printf("       ... and %d more steps\n", len(path.Steps)-3)
					break
				}
				fmt.Printf("       %d. %s\n", step.Number, truncateString(step.Description, 100))
				if step.Command != "" && !strings.Contains(step.Command, "# See") {
					fmt.Printf("          Command: %s\n", truncateString(step.Command, 80))
				}
			}
		}
	}
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

// getRealisticOutput generates realistic command output for dry-run simulations
func (s *Simulator) getRealisticOutput(command, description string) string {
	// AWS commands
	if strings.Contains(command, "aws sts get-caller-identity") {
		return `{
    "UserId": "AIDAI23EXAMPLE4EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/compromised-user"
}`
	}
	
	if strings.Contains(command, "aws iam list-users") {
		return `{
    "Users": [
        {"UserName": "admin", "UserId": "AIDAI1234EXAMPLE", "Arn": "arn:aws:iam::123456789012:user/admin"},
        {"UserName": "dev-user", "UserId": "AIDAI5678EXAMPLE", "Arn": "arn:aws:iam::123456789012:user/dev-user"},
        {"UserName": "prod-deploy", "UserId": "AIDAI9012EXAMPLE", "Arn": "arn:aws:iam::123456789012:user/prod-deploy"}
    ]
}`
	}
	
	if strings.Contains(command, "aws iam create-user") {
		return `Insufficient permissions
Error: AccessDenied - User is not authorized to perform: iam:CreateUser`
	}
	
	if strings.Contains(command, "aws ec2 describe-instances") {
		return `[
    ["i-0abc123def456", "running", "10.0.1.45"],
    ["i-0def456ghi789", "running", "10.0.1.67"],
    ["i-0ghi789jkl012", "stopped", "10.0.2.23"]
]`
	}
	
	if strings.Contains(command, "aws s3 ls") && !strings.Contains(command, "s3://") {
		return `2024-01-15 10:23:45 customer-data
2024-02-20 14:56:12 backups-prod
2024-03-10 08:15:33 user-uploads
2024-04-05 16:42:18 analytics-logs`
	}
	
	if strings.Contains(command, "aws s3 ls s3://customer-data") {
		return `2024-10-15 11:23:45    1234567 users.db
2024-10-20 09:15:32     987654 transactions.csv
2024-10-25 14:42:18    2345678 customer-profiles.json
2024-10-28 16:33:21     456789 payment-info.enc
...`
	}
	
	// Kubernetes commands
	if strings.Contains(command, "kubectl auth can-i --list") {
		return `Resources                                       Non-Resource URLs   Resource Names   Verbs
*.*                                             []                  []               [*]
                                                [*]                 []               [*]
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []               [create]`
	}
	
	if strings.Contains(command, "kubectl get secrets") {
		return `NAMESPACE     NAME                          TYPE                                  DATA   AGE
default       db-credentials                Opaque                                3      45d
default       api-keys                      Opaque                                2      30d
kube-system   aws-auth                      Opaque                                1      90d
production    postgres-password             Opaque                                1      60d`
	}
	
	if strings.Contains(command, "kubectl get pods") && strings.Contains(command, "--all-namespaces") {
		return `NAMESPACE     NAME                                READY   STATUS    RESTARTS   AGE     IP           NODE
default       nginx-7c6b8f4d9-xh2p4              1/1     Running   0          5d      10.244.1.5   node-1
default       postgres-6d8f5c9b-mn3k7            1/1     Running   0          12d     10.244.2.8   node-2
production    api-server-5f7d9c8a-qw9r2          2/2     Running   0          3d      10.244.1.9   node-1
production    redis-master-0                     1/1     Running   0          8d      10.244.3.4   node-3
kube-system   coredns-5d78c9869d-p4k2m          1/1     Running   0          30d     10.244.0.2   master`
	}
	
	if strings.Contains(command, "kubectl get pods") && strings.Contains(command, "grep") {
		return `production    postgres-6d8f5c9b-mn3k7            1/1     Running   0          12d     10.244.2.8   node-2
production    redis-master-0                     1/1     Running   0          8d      10.244.3.4   node-3
default       mysql-api-7c9f8d5b-kl4p2          1/1     Running   0          7d      10.244.1.12  node-1`
	}
	
	if strings.Contains(command, "kubectl port-forward") {
		return `Forwarding from 127.0.0.1:5432 -> 5432
Forwarding from [::1]:5432 -> 5432`
	}
	
	if strings.Contains(command, "kubectl get secret") && strings.Contains(command, "base64") {
		return `P@ssw0rd123!SecureDB`
	}
	
	if strings.Contains(command, "kubectl create clusterrolebinding") {
		return `clusterrolebinding.rbac.authorization.k8s.io/pwn created`
	}
	
	if strings.Contains(command, "kubectl auth can-i '*' '*'") {
		return `yes`
	}
	
	// Docker commands
	if strings.Contains(command, "docker ps") {
		return `CONTAINER ID   IMAGE              COMMAND                  CREATED        STATUS        PORTS                    NAMES
a1b2c3d4e5f6   nginx:latest       "/docker-entrypoint.…"   2 hours ago    Up 2 hours    0.0.0.0:80->80/tcp       web-server
b2c3d4e5f6g7   postgres:14        "docker-entrypoint.s…"   5 hours ago    Up 5 hours    0.0.0.0:5432->5432/tcp   database
c3d4e5f6g7h8   redis:alpine       "docker-entrypoint.s…"   1 day ago      Up 1 day      0.0.0.0:6379->6379/tcp   cache`
	}
	
	if strings.Contains(command, "docker run") && strings.Contains(command, "chroot") {
		return `# Successfully spawned privileged container
# Now inside host root filesystem
# Full access to /host/* (entire host filesystem)`
	}
	
	// Container/Host checks
	if strings.Contains(command, "cat /proc/self/status") && strings.Contains(command, "CapEff") {
		return `CapInh: 0000003fffffffff
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000`
	}
	
	if strings.Contains(command, "nsenter") {
		return `# Escaped to host namespace successfully
# Now running as root on host system`
	}
	
	if strings.Contains(command, "hostname && cat /etc/os-release") {
		return `production-k8s-node-01
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"`
	}
	
	if strings.Contains(command, "find") && strings.Contains(command, "credentials") {
		return `/root/.aws/credentials
/home/ubuntu/.aws/credentials
/root/.kube/config
/home/deploy/.ssh/id_rsa
/opt/app/config/prod-credentials.json`
	}
	
	if strings.Contains(command, "ps aux") && !strings.Contains(command, "grep") {
		return `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168304 11584 ?        Ss   Oct28   0:12 /sbin/init
root       234  0.0  0.2 289456 18432 ?        Ssl  Oct28   1:23 /usr/lib/systemd/systemd-journald
root       567  0.0  0.1  12345  8912 ?        Ss   Oct28   0:45 /usr/sbin/sshd -D
...`
	}
	
	if strings.Contains(command, "ps aux") && strings.Contains(command, "systemd") {
		return `root         1  0.0  0.1 168304 11584 ?        Ss   Oct28   0:12 /lib/systemd/systemd --system --deserialize 32
root       234  0.0  0.2 289456 18432 ?        Ssl  Oct28   1:23 /lib/systemd/systemd-journald`
	}
	
	if strings.Contains(command, "ls -la /proc/1/root/") {
		return `total 88
drwxr-xr-x  19 root root  4096 Oct 28 10:15 .
drwxr-xr-x  19 root root  4096 Oct 28 10:15 ..
drwxr-xr-x   2 root root  4096 Oct 29 14:23 bin
drwxr-xr-x   3 root root  4096 Oct 28 10:16 boot
drwxr-xr-x  16 root root  3140 Oct 31 08:45 dev
drwxr-xr-x 103 root root  4096 Oct 31 09:12 etc
drwxr-xr-x   3 root root  4096 Oct 15 11:34 home
drwxr-xr-x  20 root root  4096 Oct 28 10:17 lib
drwx------   2 root root 16384 Oct 28 10:10 lost+found
drwxr-xr-x   3 root root  4096 Oct 15 11:30 opt
dr-xr-xr-x 245 root root     0 Oct 31 08:45 proc
drwx------   5 root root  4096 Oct 30 16:42 root`
	}
	
	if strings.Contains(command, "test -S /var/run/docker.sock") {
		return `Socket accessible`
	}
	
	if strings.Contains(command, "cat /host/root/.ssh/id_rsa") {
		return `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2K8h9vxFx6t5JN9wK3V8F...
[REDACTED - SSH private key would be here]
...
-----END RSA PRIVATE KEY-----`
	}
	
	if strings.Contains(command, "mount") && strings.Contains(command, "grep") {
		return `/dev/sda1 on /host type ext4 (rw,relatime)
/dev/sda1 on /host/var type ext4 (rw,relatime)
/dev/sda1 on /host/etc type ext4 (rw,relatime)`
	}
	
	if strings.Contains(command, "cat /host/etc/shadow") {
		return `No /etc/shadow access`
	}
	
	if strings.Contains(command, "find /host") && strings.Contains(command, "id_rsa") {
		return `/host/root/.ssh/id_rsa
/host/home/ubuntu/.ssh/id_rsa
/host/home/deploy/.ssh/id_rsa`
	}
	
	if strings.Contains(command, "find /host") && strings.Contains(command, "kubeconfig") {
		return `/host/root/.kube/config
/host/home/ubuntu/.kube/config`
	}
	
	// Cloud metadata
	if strings.Contains(command, "curl") && strings.Contains(command, "169.254.169.254/latest/meta-data/") && !strings.Contains(command, "iam") {
		return `ami-id
ami-launch-index
ami-manifest-path
hostname
iam/
instance-id
instance-type
local-hostname
local-ipv4
mac
placement/
public-hostname
public-ipv4
security-groups`
	}
	
	if strings.Contains(command, "169.254.169.254") && strings.Contains(command, "iam/security-credentials/") && !strings.Contains(command, "$(curl") {
		return `ec2-instance-profile-role`
	}
	
	if strings.Contains(command, "169.254.169.254") && strings.Contains(command, "$(curl") {
		return `{
  "Code" : "Success",
  "LastUpdated" : "2024-10-31T08:45:23Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAXAMPLEXAMPLEXAMP",
  "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token" : "IQoJb3JpZ2luX2VjEFQaCXVzLWVhc3QtMSJIMEYCIQDExample...",
  "Expiration" : "2024-10-31T15:12:34Z"
}`
	}
	
	// Service account token
	if strings.Contains(command, "cat /var/run/secrets/kubernetes.io/serviceaccount/token") {
		return `eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tYWJjZGUiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTAxMiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.ExampleSignatureDataHere...`
	}
	
	// Default fallback for unknown commands
	return fmt.Sprintf("✓ %s completed successfully", description)
}
