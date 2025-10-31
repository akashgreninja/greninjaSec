package shadow

import "time"

// AttackVector represents a type of exploit path
type AttackVector string

const (
	VectorContainerEscape     AttackVector = "container_escape"
	VectorLateralMovement     AttackVector = "lateral_movement"
	VectorPrivilegeEscalation AttackVector = "privilege_escalation"
	VectorCredentialTheft     AttackVector = "credential_theft"
	VectorDataExfiltration    AttackVector = "data_exfiltration"
	VectorCloudTakeover       AttackVector = "cloud_takeover"
	VectorDockerSocketAbuse   AttackVector = "docker_socket_abuse"
	VectorHostPathEscape      AttackVector = "hostpath_escape"
)

// ShadowSimulation represents the overall attack simulation
type ShadowSimulation struct {
	ID                string
	StartTime         time.Time
	EndTime           time.Time
	TargetType        string // "kubernetes", "docker", "terraform", "dockerfile"
	TargetPath        string
	Vulnerabilities   []Vulnerability
	AttackPaths       []AttackPath
	BlastRadius       BlastRadius
	EstimatedDamage   DamageEstimate
	TimeToCompromise  time.Duration
	SuccessRate       float64
}

// Vulnerability represents a security issue found
type Vulnerability struct {
	ID          string
	Type        string
	Severity    string
	CVSSScore   float64
	Description string
	File        string
	Line        int
	Exploitable bool
	ExploitPath string
}

// AttackPath represents a chain of exploit steps
type AttackPath struct {
	ID          string
	Name        string
	Vector      AttackVector
	Steps       []AttackStep
	Success     bool
	Duration    time.Duration
	Impact      ImpactLevel
	Description string
}

// AttackStep represents a single action in the attack chain
type AttackStep struct {
	Number      int
	Command     string
	Description string
	Expected    string
	Actual      string
	Success     bool
	Duration    time.Duration
	Timestamp   time.Time
}

// BlastRadius represents what an attacker can access
type BlastRadius struct {
	SystemsCompromised     int
	DatabasesAccessible    []string
	SecretsExposed         int
	PodsCompromised        []string
	ServicesCompromised    []string
	CloudResourcesAccessed []string
	NetworkScope           string
	DataExposure           DataExposure
}

// DataExposure represents sensitive data that can be accessed
type DataExposure struct {
	CustomerRecords    int
	FinancialData      bool
	PersonalData       bool
	HealthData         bool
	IntellectualProp   bool
	CredentialCount    int
}

// DamageEstimate represents potential financial/business impact
type DamageEstimate struct {
	MinCost            float64
	MaxCost            float64
	GDPRFines          float64
	ReputationDamage   string
	DowntimeHours      int
	DataBreachRecords  int
	ComplianceViolations []string
}

// ImpactLevel represents severity of impact
type ImpactLevel string

const (
	ImpactCritical ImpactLevel = "CRITICAL"
	ImpactHigh     ImpactLevel = "HIGH"
	ImpactMedium   ImpactLevel = "MEDIUM"
	ImpactLow      ImpactLevel = "LOW"
	ImpactInfo     ImpactLevel = "INFO"
)

// Playbook represents an attack technique/procedure
type Playbook struct {
	Name            string
	Description     string
	Vector          AttackVector
	RequiredVulns   []string // Vulnerability types needed
	Steps           []PlaybookStep
	ExpectedOutcome string
	MITREATTACK     string // MITRE ATT&CK technique ID
}

// PlaybookStep represents a template step in a playbook
type PlaybookStep struct {
	Description string
	Command     string
	CheckSuccess func(output string) bool
	Impact      ImpactLevel
}

// SimulationConfig controls how the simulation runs
type SimulationConfig struct {
	DryRun           bool
	Verbose          bool
	Isolated         bool
	MaxDuration      time.Duration
	StopOnFailure    bool
	RecordVideo      bool
	GenerateReport   bool
	ReportFormat     string // "html", "json", "pdf"
}

// SimulationResult is the final output
type SimulationResult struct {
	Simulation      ShadowSimulation
	ExecutionLog    []string
	AttackTimeline  []TimelineEvent
	Recommendations []Recommendation
	ReportPath      string
	VideoPath       string
}

// TimelineEvent represents a moment in the attack
type TimelineEvent struct {
	Timestamp   time.Time
	Step        int
	Action      string
	Result      string
	Impact      ImpactLevel
	Severity    string
}

// Recommendation represents a fix suggestion
type Recommendation struct {
	Priority    int
	Title       string
	Description string
	Fix         string
	CodePatch   string
	Impact      string
}
