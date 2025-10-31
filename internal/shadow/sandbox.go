package shadow

import (
	"fmt"
	"os/exec"
	"strings"
)

// Sandbox provides isolated execution environment for attack simulation
type Sandbox struct {
	isolated bool
	inDocker bool
	namespace string
}

// NewSandbox creates a new sandbox environment
func NewSandbox(isolated bool) *Sandbox {
	return &Sandbox{
		isolated:  isolated,
		inDocker:  false,
		namespace: fmt.Sprintf("shadow-%d", generateRandomID()),
	}
}

// Setup prepares the sandbox environment
func (s *Sandbox) Setup() error {
	if !s.isolated {
		return nil
	}
	
	// TODO: Create isolated Docker container or K8s namespace
	// For now, just validate we can run commands
	_, err := exec.LookPath("sh")
	return err
}

// Execute runs a command in the sandbox
func (s *Sandbox) Execute(command string) (string, bool) {
	if s.isolated {
		// TODO: Execute in isolated container
		// For now, simulate success
		return fmt.Sprintf("[SANDBOX] Executed: %s", command), true
	}
	
	// Dry run mode - just simulate
	return fmt.Sprintf("[SIMULATED] %s", command), true
}

// Cleanup destroys the sandbox environment
func (s *Sandbox) Cleanup() error {
	if !s.isolated {
		return nil
	}
	
	// TODO: Destroy Docker container or K8s namespace
	return nil
}

// Helper to check if Docker is available
func (s *Sandbox) hasDocker() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// Helper to check if kubectl is available
func (s *Sandbox) hasKubectl() bool {
	_, err := exec.LookPath("kubectl")
	return err == nil
}

// ExecuteDockerCommand runs a command in a Docker container
func (s *Sandbox) ExecuteDockerCommand(image string, command string) (string, error) {
	cmd := exec.Command("docker", "run", "--rm", image, "sh", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// CheckDockerSocket checks if Docker socket is mounted
func (s *Sandbox) CheckDockerSocket() bool {
	cmd := exec.Command("sh", "-c", "test -S /var/run/docker.sock && echo 'exists'")
	output, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(string(output), "exists")
}

// CheckCloudMetadata checks if cloud metadata endpoint is accessible
func (s *Sandbox) CheckCloudMetadata() (string, bool) {
	// Try AWS metadata
	cmd := exec.Command("sh", "-c", "curl -s --connect-timeout 1 http://169.254.169.254/latest/meta-data/")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return "AWS", true
	}
	
	// Try GCP metadata
	cmd = exec.Command("sh", "-c", "curl -s --connect-timeout 1 http://metadata.google.internal/computeMetadata/v1/")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return "GCP", true
	}
	
	// Try Azure metadata
	cmd = exec.Command("sh", "-c", "curl -s --connect-timeout 1 http://169.254.169.254/metadata/instance?api-version=2021-02-01")
	output, err = cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		return "Azure", true
	}
	
	return "", false
}

func generateRandomID() int64 {
	return 12345 // TODO: Use crypto/rand
}
