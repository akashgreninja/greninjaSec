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
	binDir := filepath.Join(homeDir, ".infraguardian", "bin")
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

// downloadBinary downloads a binary from url and saves it to dest
func (tm *ToolManager) downloadBinary(url, dest string) error {
	// Download
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	
	// Create file
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	
	// Copy content
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	
	// Make executable
	return os.Chmod(dest, 0755)
}
