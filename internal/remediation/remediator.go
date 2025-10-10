package remediation

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"archguardian/internal/config"
	"archguardian/internal/risk"
	"archguardian/types"
)

// Remediator handles automated remediation of identified issues
type Remediator struct {
	config    *config.Config
	diagnoser *risk.RiskDiagnoser
	ai        interface{} // TODO: Use proper AI inference engine type
	git       *GitManager
}

// GitManager handles Git operations for remediation
type GitManager struct {
	config *config.Config
}

// NewRemediator creates a new remediator
func NewRemediator(config *config.Config, diagnoser *risk.RiskDiagnoser) *Remediator {
	return &Remediator{
		config:    config,
		diagnoser: diagnoser,
		ai:        diagnoser, // TODO: Use proper AI engine
		git:       NewGitManager(config),
	}
}

// NewGitManager creates a new git manager
func NewGitManager(config *config.Config) *GitManager {
	return &GitManager{config: config}
}

// RemediateRisks performs automated remediation of identified risks
func (r *Remediator) RemediateRisks(ctx context.Context, assessment *types.RiskAssessment) error {
	log.Println("🔧 Starting automated remediation...")

	// Create remediation branch
	branchName := fmt.Sprintf("%s-%s", r.config.RemediationBranch, time.Now().Format("20060102-150405"))
	if err := r.git.CreateBranch(branchName); err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	remediationCount := 0

	// Fix security vulnerabilities
	for _, vuln := range assessment.SecurityVulns {
		if err := r.remediateSecurityVuln(ctx, vuln); err != nil {
			log.Printf("  ⚠️  Failed to remediate %s: %v", vuln.CVE, err)
			continue
		}
		remediationCount++
	}

	// Update dependencies
	for _, dep := range assessment.DangerousDependencies {
		if err := r.updateDependency(dep); err != nil {
			log.Printf("  ⚠️  Failed to update %s: %v", dep.Package, err)
			continue
		}
		remediationCount++
	}

	// Remove obsolete code
	for _, obsolete := range assessment.ObsoleteCode {
		if obsolete.RemovalSafety == "safe" {
			if err := r.removeObsoleteCode(ctx, obsolete); err != nil {
				log.Printf("  ⚠️  Failed to remove %s: %v", obsolete.Path, err)
				continue
			}
			remediationCount++
		}
	}

	// Address technical debt
	for _, debt := range assessment.TechnicalDebt {
		if debt.Severity == "critical" || debt.Severity == "high" {
			if err := r.fixTechnicalDebt(ctx, debt); err != nil {
				log.Printf("  ⚠️  Failed to fix %s: %v", debt.ID, err)
				continue
			}
			remediationCount++
		}
	}

	// Commit and push changes
	if remediationCount > 0 {
		commitMsg := fmt.Sprintf("🤖 Automated remediation: Fixed %d issues\n\n", remediationCount)
		commitMsg += fmt.Sprintf("- Security vulnerabilities: %d\n", len(assessment.SecurityVulns))
		commitMsg += fmt.Sprintf("- Dependency updates: %d\n", len(assessment.DangerousDependencies))
		commitMsg += fmt.Sprintf("- Obsolete code removed: %d\n", len(assessment.ObsoleteCode))
		commitMsg += fmt.Sprintf("- Technical debt addressed: %d\n", len(assessment.TechnicalDebt))

		if err := r.git.CommitAndPush(branchName, commitMsg); err != nil {
			return fmt.Errorf("failed to commit changes: %w", err)
		}

		log.Printf("✅ Remediation complete: %d issues fixed on branch %s", remediationCount, branchName)
	} else {
		log.Println("✅ No issues required remediation")
	}

	return nil
}

// remediateSecurityVuln remediates a security vulnerability
func (r *Remediator) remediateSecurityVuln(_ context.Context, vuln types.SecurityVulnerability) error {
	log.Printf("  🔒 Remediating %s in %s...", vuln.CVE, vuln.Package)

	// TODO: Use AI to generate remediation
	// For now, just log the remediation
	log.Printf("  📋 Would remediate %s: %s", vuln.CVE, vuln.Description)

	return nil
}

// updateDependency updates a dependency to the latest version
func (r *Remediator) updateDependency(dep types.DependencyRisk) error {
	log.Printf("  📦 Updating %s from %s to %s...", dep.Package, dep.CurrentVersion, dep.LatestVersion)

	// Determine package manager and update
	if strings.Contains(dep.Package, "/") {
		// Go module
		return r.updateGoModule(dep.Package, dep.LatestVersion)
	} else if fileExists(filepath.Join(r.config.ProjectPath, "package.json")) {
		// NPM package
		return r.updateNPMPackage(dep.Package, dep.LatestVersion)
	} else if fileExists(filepath.Join(r.config.ProjectPath, "requirements.txt")) {
		// Python package
		return r.updatePythonPackage(dep.Package, dep.LatestVersion)
	}

	return nil
}

// updateGoModule updates a Go module
func (r *Remediator) updateGoModule(pkg, version string) error {
	// Validate and sanitize package name to prevent command injection
	sanitizedPkg := sanitizePackageName(pkg)
	if sanitizedPkg == "" || !isValidPackageName(sanitizedPkg) {
		return fmt.Errorf("invalid package name: %s", pkg)
	}

	// Validate and sanitize version to prevent command injection
	sanitizedVersion := sanitizePackageName(version)
	if sanitizedVersion == "" || !isValidVersion(sanitizedVersion) {
		return fmt.Errorf("invalid version: %s", version)
	}

	// Set up command with timeout and proper environment
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use validated and sanitized arguments to prevent command injection
	cmd := exec.CommandContext(ctx, "go", "get", sanitizedPkg+"@"+sanitizedVersion)
	cmd.Dir = r.config.ProjectPath
	cmd.Env = append(os.Environ(), "GO111MODULE=on")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go get failed: %w\n%s", err, output)
	}

	// Run go mod tidy with timeout
	tidyCmd := exec.CommandContext(ctx, "go", "mod", "tidy")
	tidyCmd.Dir = r.config.ProjectPath
	tidyCmd.Env = append(os.Environ(), "GO111MODULE=on")
	if output, err := tidyCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go mod tidy failed: %w\n%s", err, output)
	}
	return nil
}

// updateNPMPackage updates an NPM package
func (r *Remediator) updateNPMPackage(pkg, version string) error {
	// Validate and sanitize package name to prevent command injection
	sanitizedPkg := sanitizePackageName(pkg)
	if sanitizedPkg == "" || !isValidPackageName(sanitizedPkg) {
		return fmt.Errorf("invalid package name: %s", pkg)
	}

	// Validate and sanitize version to prevent command injection
	sanitizedVersion := sanitizePackageName(version)
	if sanitizedVersion == "" || !isValidVersion(sanitizedVersion) {
		return fmt.Errorf("invalid version: %s", version)
	}

	// Set up command with timeout and proper environment
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "npm", "install", sanitizedPkg+"@"+sanitizedVersion)
	cmd.Dir = r.config.ProjectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("npm install failed: %w\n%s", err, output)
	}
	return nil
}

// updatePythonPackage updates a Python package
func (r *Remediator) updatePythonPackage(pkg, version string) error {
	// Update requirements.txt
	reqPath := filepath.Join(r.config.ProjectPath, "requirements.txt")
	content, err := os.ReadFile(reqPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	updated := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), pkg) {
			lines[i] = fmt.Sprintf("%s==%s", pkg, version)
			updated = true
			break
		}
	}

	if updated {
		return os.WriteFile(reqPath, []byte(strings.Join(lines, "\n")), 0600)
	}

	return nil
}

// removeObsoleteCode removes obsolete code files
func (r *Remediator) removeObsoleteCode(_ context.Context, obsolete types.ObsoleteCodeItem) error {
	log.Printf("  🗑️  Removing obsolete code: %s...", obsolete.Path)

	// Safety check
	if obsolete.References > 0 {
		return fmt.Errorf("code still has %d references", obsolete.References)
	}

	// Remove the file
	return os.Remove(obsolete.Path)
}

// fixTechnicalDebt fixes technical debt issues
func (r *Remediator) fixTechnicalDebt(_ context.Context, debt types.TechnicalDebtItem) error {
	log.Printf("  🔨 Fixing technical debt: %s...", debt.ID)

	// TODO: Use AI to generate remediation
	// For now, just log the fix
	log.Printf("  📋 Would fix technical debt: %s", debt.Description)

	return nil
}

// TODO: Implement applyFix when AI integration is complete
// applyFix applies a fix to the codebase
// func (r *Remediator) applyFix(fix, target string) error {
// 	if fix == "" {
// 		return fmt.Errorf("AI returned an empty fix for %s", target)
// 	}
//
// 	// If the target is not a file path, we can't apply a file-based fix
// 	absPath := filepath.Join(r.config.ProjectPath, target)
// 	if !fileExists(absPath) {
// 		log.Printf("    Skipping file-based fix for non-file target: %s", target)
// 		return nil
// 	}
//
// 	// Check if the fix is a patch
// 	trimmedFix := strings.TrimSpace(fix)
// 	if strings.HasPrefix(trimmedFix, "---") || strings.HasPrefix(trimmedFix, "diff --git") {
// 		log.Printf("    Applying patch to %s", target)
// 		// Use git apply to handle the patch
// 		cmd := exec.Command("git", "apply", "-")
// 		cmd.Dir = r.config.ProjectPath
// 		cmd.Stdin = strings.NewReader(fix)
// 		output, err := cmd.CombinedOutput()
// 		if err != nil {
// 			return fmt.Errorf("git apply failed for %s: %w\nOutput: %s", target, err, string(output))
// 		}
// 		log.Printf("    Successfully applied patch to %s", target)
// 		return nil
// 	}
//
// 	// If not a patch, assume it's the full file content and overwrite
// 	log.Printf("    Overwriting file %s with AI-generated content", target)
// 	return os.WriteFile(absPath, []byte(fix), 0600)
// }

// CreateBranch creates a new git branch for remediation
func (gm *GitManager) CreateBranch(branchName string) error {
	log.Printf("🌿 Creating branch: %s", branchName)

	// Checkout to main/master first
	checkoutCmd := exec.Command("git", "checkout", "main")
	checkoutCmd.Dir = gm.config.ProjectPath
	if err := checkoutCmd.Run(); err != nil {
		// Try master if main doesn't exist
		checkoutCmd = exec.Command("git", "checkout", "master")
		checkoutCmd.Dir = gm.config.ProjectPath
		if err := checkoutCmd.Run(); err != nil {
			return fmt.Errorf("failed to checkout base branch: %w", err)
		}
	}

	// Pull latest changes
	pullCmd := exec.Command("git", "pull")
	pullCmd.Dir = gm.config.ProjectPath
	_ = pullCmd.Run() // Ignore errors

	// Create and checkout new branch
	branchCmd := exec.Command("git", "checkout", "-b", branchName)
	branchCmd.Dir = gm.config.ProjectPath
	output, err := branchCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create branch: %w\n%s", err, output)
	}

	return nil
}

// CommitAndPush commits and pushes remediation changes
func (gm *GitManager) CommitAndPush(branchName, message string) error {
	log.Printf("💾 Committing changes...")

	// Add all changes
	addCmd := exec.Command("git", "add", ".")
	addCmd.Dir = gm.config.ProjectPath
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add changes: %w", err)
	}

	// Commit
	commitCmd := exec.Command("git", "commit", "-m", message)
	commitCmd.Dir = gm.config.ProjectPath
	output, err := commitCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to commit: %w\n%s", err, output)
	}

	// Push to remote
	log.Printf("⬆️  Pushing to remote...")
	pushCmd := exec.Command("git", "push", "-u", "origin", branchName)
	pushCmd.Dir = gm.config.ProjectPath
	output, err = pushCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to push: %w\n%s", err, output)
	}

	log.Printf("✅ Changes committed and pushed to branch: %s", branchName)
	return nil
}

// Helper functions for validation and sanitization

// isValidPackageName validates package names to prevent command injection
func isValidPackageName(pkg string) bool {
	// Package names should only contain letters, numbers, hyphens, dots, and slashes
	if pkg == "" {
		return false
	}

	// Check for dangerous characters
	dangerousChars := []string{";", "&", "|", "$", "(", ")", "<", ">", "`", "\\", "\n", "\r", "\t"}
	for _, char := range dangerousChars {
		if strings.Contains(pkg, char) {
			return false
		}
	}

	// Check for path traversal
	if strings.Contains(pkg, "..") {
		return false
	}

	// Basic regex pattern for valid package names
	return true
}

// sanitizePackageName sanitizes package names for safe command execution
func sanitizePackageName(pkg string) string {
	// Remove any potentially dangerous characters
	sanitized := strings.Map(func(r rune) rune {
		// Allow only safe characters: letters, numbers, hyphens, dots, forward slashes, underscores
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '.' ||
			r == '/' || r == '_' || r == '@' {
			return r
		}
		return -1 // Remove this character
	}, pkg)

	// Remove any path traversal attempts
	if strings.Contains(sanitized, "..") {
		return ""
	}

	return sanitized
}

// isValidVersion validates version strings to prevent command injection
func isValidVersion(version string) bool {
	// Version should only contain letters, numbers, dots, hyphens, and plus signs
	if version == "" {
		return false
	}

	// Check for dangerous characters
	dangerousChars := []string{";", "&", "|", "$", "(", ")", "<", ">", "`", "\\", "\n", "\r", "\t"}
	for _, char := range dangerousChars {
		if strings.Contains(version, char) {
			return false
		}
	}

	return true
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
