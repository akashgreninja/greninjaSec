package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var installHooksCmd = &cobra.Command{
	Use:   "install-hooks",
	Short: "Install pre-commit hook to scan code before commits",
	Long: `Install a Git pre-commit hook that automatically scans your code for security issues.

The hook will:
  • Scan staged files before each commit
  • Block commits if CRITICAL severity issues are found
  • Allow commits with HIGH/MEDIUM/LOW issues (with warnings)
  • Run fast by only scanning changed files

Examples:
  greninjasec install-hooks
  greninjasec install-hooks --allow-critical  # Don't block on critical (warn only)`,
	RunE: installHooks,
}

var uninstallHooksCmd = &cobra.Command{
	Use:   "uninstall-hooks",
	Short: "Remove the pre-commit hook",
	Long:  `Remove the GreninjaSec pre-commit hook from the current repository.`,
	RunE:  uninstallHooks,
}

var allowCritical bool

func init() {
	rootCmd.AddCommand(installHooksCmd)
	rootCmd.AddCommand(uninstallHooksCmd)
	
	installHooksCmd.Flags().BoolVar(&allowCritical, "allow-critical", false, "Don't block commits on CRITICAL findings (warn only)")
}

func installHooks(cmd *cobra.Command, args []string) error {
	// Find .git directory
	gitDir, err := findGitDir()
	if err != nil {
		return fmt.Errorf("not a git repository (or any parent up to mount point)\nRun this command from inside a git repository")
	}

	// Create hooks directory if it doesn't exist
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	// Path to pre-commit hook
	hookPath := filepath.Join(hooksDir, "pre-commit")

	// Check if hook already exists
	if _, err := os.Stat(hookPath); err == nil {
		// Hook exists - check if it's ours
		content, _ := os.ReadFile(hookPath)
		if len(content) > 50 && !bytes.Contains(content[:100], []byte("GreninjaSec pre-commit hook")) {
			return fmt.Errorf("pre-commit hook already exists and is not managed by GreninjaSec\nPlease remove or rename: %s", hookPath)
		}
		fmt.Println("⚠️  GreninjaSec hook already installed, updating...")
	}

	// Get path to greninjasec binary
	greninjasecPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get greninjasec path: %w", err)
	}

	// Create the hook script
	hookContent := generateHookScript(greninjasecPath, allowCritical)

	// Write the hook
	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("failed to write hook file: %w", err)
	}

	fmt.Printf("✅ Pre-commit hook installed successfully!\n\n")
	fmt.Printf("📍 Hook location: %s\n\n", hookPath)
	fmt.Printf("🔒 Security policy:\n")
	if allowCritical {
		fmt.Printf("   • CRITICAL issues: ⚠️  WARN (allowed)\n")
	} else {
		fmt.Printf("   • CRITICAL issues: 🚫 BLOCKED\n")
	}
	fmt.Printf("   • HIGH issues: ⚠️  WARN (allowed)\n")
	fmt.Printf("   • MEDIUM/LOW issues: ℹ️  INFO (allowed)\n\n")
	fmt.Printf("💡 Tip: Use 'git commit --no-verify' to bypass the hook if needed\n")

	return nil
}

func uninstallHooks(cmd *cobra.Command, args []string) error {
	// Find .git directory
	gitDir, err := findGitDir()
	if err != nil {
		return fmt.Errorf("not a git repository (or any parent up to mount point)")
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")

	// Check if hook exists
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		return fmt.Errorf("no pre-commit hook found at: %s", hookPath)
	}

	// Check if it's our hook
	content, err := os.ReadFile(hookPath)
	if err != nil {
		return fmt.Errorf("failed to read hook file: %w", err)
	}

	if string(content[:50]) != "#!/bin/sh\n# GreninjaSec pre-commit hook" {
		return fmt.Errorf("hook exists but is not managed by GreninjaSec\nManual removal required: %s", hookPath)
	}

	// Remove the hook
	if err := os.Remove(hookPath); err != nil {
		return fmt.Errorf("failed to remove hook: %w", err)
	}

	fmt.Printf("✅ Pre-commit hook removed successfully!\n")
	fmt.Printf("📍 Removed: %s\n", hookPath)

	return nil
}

func findGitDir() (string, error) {
	// Start from current directory
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Walk up directory tree looking for .git
	for {
		gitDir := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
			return gitDir, nil
		}

		// Move to parent directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root
			break
		}
		dir = parent
	}

	return "", fmt.Errorf(".git directory not found")
}

func generateHookScript(greninjasecPath string, allowCritical bool) string {
	blockPolicy := "true"
	if allowCritical {
		blockPolicy = "false"
	}

	return fmt.Sprintf(`#!/bin/sh
# GreninjaSec pre-commit hook
# Automatically scans staged files for security issues before commit

echo "🥷 GreninjaSec: Scanning staged files for security issues..."

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "✅ No files to scan"
    exit 0
fi

# Create temp directory for staged files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Copy staged files to temp directory
echo "$STAGED_FILES" | while read FILE; do
    if [ -f "$FILE" ]; then
        mkdir -p "$TEMP_DIR/$(dirname "$FILE")"
        cp "$FILE" "$TEMP_DIR/$FILE"
    fi
done

# Run greninjasec scan on temp directory
%s --all --path "$TEMP_DIR" --format json > /tmp/greninjasec-scan.json 2>/dev/null

# Check results
if [ -f /tmp/greninjasec-scan.json ]; then
    # Count findings by searching for severity patterns
    CRITICAL_COUNT=$(grep -c "CRITICAL" /tmp/greninjasec-scan.json 2>/dev/null || true)
    HIGH_COUNT=$(grep -c "HIGH" /tmp/greninjasec-scan.json 2>/dev/null || true)
    # Total is sum of both
    TOTAL_COUNT=$((CRITICAL_COUNT + HIGH_COUNT))
    
    # Ensure numeric values
    CRITICAL_COUNT=${CRITICAL_COUNT:-0}
    HIGH_COUNT=${HIGH_COUNT:-0}
    TOTAL_COUNT=${TOTAL_COUNT:-0}
    
    if [ "$TOTAL_COUNT" -gt 0 ]; then
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "⚠️  Security Issues Found:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo "   🔴 CRITICAL: $CRITICAL_COUNT"
        fi
        if [ "$HIGH_COUNT" -gt 0 ]; then
            echo "   🟠 HIGH: $HIGH_COUNT"
        fi
        echo "   📊 Total: $TOTAL_COUNT issues"
        echo ""
        echo "💡 Run 'greninjasec --all --verbose --path .' to see details"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        # Block on critical if policy enabled
        BLOCK_CRITICAL=%s
        if [ "$CRITICAL_COUNT" -gt 0 ] && [ "$BLOCK_CRITICAL" = "true" ]; then
            echo "🚫 COMMIT BLOCKED: Critical security issues must be fixed first"
            echo ""
            echo "To bypass: git commit --no-verify"
            echo ""
            rm -f /tmp/greninjasec-scan.json
            exit 1
        fi
        
        if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo "⚠️  WARNING: Critical issues found but commit allowed (--allow-critical)"
            echo ""
        fi
    else
        echo "✅ No security issues found"
    fi
    
    rm -f /tmp/greninjasec-scan.json
fi

exit 0
`, greninjasecPath, blockPolicy)
}
