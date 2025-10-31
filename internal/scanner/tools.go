package scanner

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ToolManager handles external tool dependencies
type ToolManager struct {
	binDir string
}

// NewToolManager creates a new tool manager
func NewToolManager() *ToolManager {
	homeDir, _ := os.UserHomeDir()
	binDir := filepath.Join(homeDir, ".greninjasec", "bin")
	os.MkdirAll(binDir, 0755)

	return &ToolManager{
		binDir: binDir,
	}
}

// EnsureHadolint ensures hadolint is available
func (tm *ToolManager) EnsureHadolint() (string, error) {
	// 1. Check if in PATH
	if path, err := exec.LookPath("hadolint"); err == nil {
		return path, nil
	}

	// 2. Check in our bin directory
	localPath := filepath.Join(tm.binDir, "hadolint")
	if _, err := os.Stat(localPath); err == nil {
		return localPath, nil
	}

	// 3. Auto-download
	fmt.Fprintf(os.Stderr, "⏳ Hadolint not found. Downloading...\n")

	url := tm.getHadolintURL()
	if url == "" {
		return "", fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	if err := tm.downloadBinary(url, localPath); err != nil {
		return "", fmt.Errorf("failed to download hadolint: %v", err)
	}

	fmt.Fprintf(os.Stderr, "✅ Hadolint installed to %s\n", localPath)
	return localPath, nil
}

// EnsureKubesec ensures kubesec is available
func (tm *ToolManager) EnsureKubesec() (string, error) {
	// 1. Check if in PATH
	if path, err := exec.LookPath("kubesec"); err == nil {
		return path, nil
	}

	// 2. Check in our bin directory
	localPath := filepath.Join(tm.binDir, "kubesec")
	if _, err := os.Stat(localPath); err == nil {
		return localPath, nil
	}

	// 3. Auto-download
	fmt.Fprintf(os.Stderr, "⏳ Kubesec not found. Downloading...\n")

	url := tm.getKubesecURL()
	if url == "" {
		return "", fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	if err := tm.downloadBinary(url, localPath); err != nil {
		return "", fmt.Errorf("failed to download kubesec: %v", err)
	}

	fmt.Fprintf(os.Stderr, "✅ Kubesec installed to %s\n", localPath)
	return localPath, nil
}

// EnsureTfsec ensures tfsec is available
func (tm *ToolManager) EnsureTfsec() (string, error) {
	// 1. Check if in PATH
	if path, err := exec.LookPath("tfsec"); err == nil {
		return path, nil
	}

	// 2. Check in our bin directory
	localPath := filepath.Join(tm.binDir, "tfsec")
	if _, err := os.Stat(localPath); err == nil {
		return localPath, nil
	}

	// 3. Auto-download
	fmt.Fprintf(os.Stderr, "⏳ Tfsec not found. Downloading...\n")

	url := tm.getTfsecURL()
	if url == "" {
		return "", fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	if err := tm.downloadBinary(url, localPath); err != nil {
		return "", fmt.Errorf("failed to download tfsec: %v", err)
	}

	fmt.Fprintf(os.Stderr, "✅ Tfsec installed to %s\n", localPath)
	return localPath, nil
}

// getHadolintURL returns the download URL for the current platform
func (tm *ToolManager) getHadolintURL() string {
	version := "v2.12.0"
	baseURL := fmt.Sprintf("https://github.com/hadolint/hadolint/releases/download/%s", version)

	switch runtime.GOOS {
	case "linux":
		return fmt.Sprintf("%s/hadolint-Linux-x86_64", baseURL)
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return fmt.Sprintf("%s/hadolint-Darwin-arm64", baseURL)
		}
		return fmt.Sprintf("%s/hadolint-Darwin-x86_64", baseURL)
	case "windows":
		return fmt.Sprintf("%s/hadolint-Windows-x86_64.exe", baseURL)
	default:
		return ""
	}
}

// getKubesecURL returns the download URL for kubesec
func (tm *ToolManager) getKubesecURL() string {
	version := "v2.14.0"
	baseURL := fmt.Sprintf("https://github.com/controlplaneio/kubesec/releases/download/%s", version)

	switch runtime.GOOS {
	case "linux":
		return fmt.Sprintf("%s/kubesec_linux_amd64.tar.gz", baseURL)
	case "darwin":
		return fmt.Sprintf("%s/kubesec_darwin_amd64.tar.gz", baseURL)
	case "windows":
		return fmt.Sprintf("%s/kubesec_windows_amd64.tar.gz", baseURL)
	default:
		return ""
	}
}

// getTfsecURL returns the download URL for tfsec
func (tm *ToolManager) getTfsecURL() string {
	version := "v1.28.1"
	baseURL := fmt.Sprintf("https://github.com/aquasecurity/tfsec/releases/download/%s", version)

	switch runtime.GOOS {
	case "linux":
		return fmt.Sprintf("%s/tfsec-linux-amd64", baseURL)
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return fmt.Sprintf("%s/tfsec-darwin-arm64", baseURL)
		}
		return fmt.Sprintf("%s/tfsec-darwin-amd64", baseURL)
	case "windows":
		return fmt.Sprintf("%s/tfsec-windows-amd64.exe", baseURL)
	default:
		return ""
	}
}

// downloadBinary downloads a binary from url and saves it to dest
func (tm *ToolManager) downloadBinary(url, dest string) error {
	// Create HTTP client that follows redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Download
	fmt.Fprintf(os.Stderr, "   Downloading from: %s\n", url)
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed: HTTP %d - %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	// Create file
	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	// Copy content with progress
	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save file: %v", err)
	}

	fmt.Fprintf(os.Stderr, "   Downloaded %d bytes\n", written)

	// Make executable
	if err := os.Chmod(dest, 0755); err != nil {
		return fmt.Errorf("failed to make executable: %v", err)
	}

	return nil
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// EnsureTrivy ensures Trivy is available
func (tm *ToolManager) EnsureTrivy() (string, error) {
	// 1. Check if in PATH
	if path, err := exec.LookPath("trivy"); err == nil {
		return path, nil
	}

	// 2. Check in our bin directory
	localPath := filepath.Join(tm.binDir, "trivy")
	if _, err := os.Stat(localPath); err == nil {
		return localPath, nil
	}

	// 3. Auto-download
	fmt.Fprintf(os.Stderr, "⏳ Trivy not found. Downloading...\n")

	url := tm.getTrivyURL()
	if url == "" {
		return "", fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	if err := tm.downloadAndExtractTrivy(url, localPath); err != nil {
		return "", fmt.Errorf("failed to download trivy: %v", err)
	}

	fmt.Fprintf(os.Stderr, "✅ Trivy installed to %s\n", localPath)
	return localPath, nil
}

func (tm *ToolManager) getTrivyURL() string {
	version := "0.48.0" // Latest stable version
	
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_Linux-64bit.tar.gz", version, version)
		case "arm64":
			return fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_Linux-ARM64.tar.gz", version, version)
		}
	case "darwin":
		switch runtime.GOARCH {
		case "amd64":
			return fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_macOS-64bit.tar.gz", version, version)
		case "arm64":
			return fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_macOS-ARM64.tar.gz", version, version)
		}
	}
	return ""
}

func (tm *ToolManager) downloadAndExtractTrivy(url, dest string) error {
	// Trivy comes as tar.gz, we need to download and extract
	tmpFile := dest + ".tar.gz"
	defer os.Remove(tmpFile)

	// Download tar.gz
	if err := tm.downloadBinary(url, tmpFile); err != nil {
		return err
	}

	// Extract trivy binary from tar.gz
	cmd := exec.Command("tar", "-xzf", tmpFile, "-C", filepath.Dir(dest), "trivy")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract trivy: %v", err)
	}

	// Make executable
	if err := os.Chmod(dest, 0755); err != nil {
		return fmt.Errorf("failed to make executable: %v", err)
	}

	return nil
}
