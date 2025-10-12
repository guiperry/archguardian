package risk

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"archguardian/internal/scanner"
	"archguardian/types"
)

// RiskDiagnoser handles risk analysis and diagnosis
type RiskDiagnoser struct {
	scanner             *scanner.Scanner
	codacyClient        types.CodacyClientInterface // Codacy API client for external analysis
	compatibilityIssues []types.TechnicalDebtItem
	latestAssessment    *types.RiskAssessment
	mutex               sync.RWMutex
}

// NewRiskDiagnoser creates a new risk diagnoser
func NewRiskDiagnoser(scanner *scanner.Scanner, codacyClient types.CodacyClientInterface) *RiskDiagnoser {
	return &RiskDiagnoser{
		scanner:      scanner,
		codacyClient: codacyClient,
	}
}

// AddManualIssues allows adding issues from other sources
func (rd *RiskDiagnoser) AddManualIssues(issues []types.TechnicalDebtItem) {
	rd.mutex.Lock()
	defer rd.mutex.Unlock()

	rd.compatibilityIssues = append(rd.compatibilityIssues, issues...)
	log.Printf("  [Compatibility Issue] Stored %d compatibility issues for integration into risk assessment", len(issues))
}

// DiagnoseRisks performs comprehensive risk analysis
func (rd *RiskDiagnoser) DiagnoseRisks(ctx context.Context) (*types.RiskAssessment, error) {
	log.Println("🔬 Diagnosing system risks...")

	rd.mutex.Lock()
	defer rd.mutex.Unlock()

	assessment := &types.RiskAssessment{
		TechnicalDebt:         make([]types.TechnicalDebtItem, 0),
		SecurityVulns:         make([]types.SecurityVulnerability, 0),
		ObsoleteCode:          make([]types.ObsoleteCodeItem, 0),
		DangerousDependencies: make([]types.DependencyRisk, 0),
		CompatibilityIssues:   make([]types.TechnicalDebtItem, 0),
		Timestamp:             time.Now(),
	}

	// Include compatibility issues that were added manually
	if len(rd.compatibilityIssues) > 0 {
		assessment.CompatibilityIssues = append(assessment.CompatibilityIssues, rd.compatibilityIssues...)
		log.Printf("  📊 Included %d compatibility issues in assessment", len(rd.compatibilityIssues))
	}

	// Use deterministic risk analysis
	log.Println("  🔍 Starting deterministic risk analysis...")

	// Extract technical debt using deterministic rules
	if technicalDebt, err := rd.extractTechnicalDebt(); err == nil {
		assessment.TechnicalDebt = append(assessment.TechnicalDebt, technicalDebt...)
	} else {
		log.Printf("  ⚠️  Technical debt extraction failed: %v", err)
	}

	// Extract security vulnerabilities using pattern-based detection
	if securityVulns, err := rd.extractSecurityVulns(); err == nil {
		assessment.SecurityVulns = append(assessment.SecurityVulns, securityVulns...)
	} else {
		log.Printf("  ⚠️  Security vulnerability extraction failed: %v", err)
	}

	// Extract obsolete code using static analysis
	if obsoleteCode, err := rd.extractObsoleteCode(); err == nil {
		assessment.ObsoleteCode = append(assessment.ObsoleteCode, obsoleteCode...)
	} else {
		log.Printf("  ⚠️  Obsolete code extraction failed: %v", err)
	}

	// Extract dependency risks using deterministic checks
	if dependencyRisks, err := rd.extractDependencyRisks(); err == nil {
		assessment.DangerousDependencies = append(assessment.DangerousDependencies, dependencyRisks...)
	} else {
		log.Printf("  ⚠️  Dependency risk extraction failed: %v", err)
	}

	log.Printf("  ✅ Deterministic analysis complete. Found %d technical debt items, %d security vulnerabilities, %d obsolete code items, %d dependency risks",
		len(assessment.TechnicalDebt), len(assessment.SecurityVulns), len(assessment.ObsoleteCode), len(assessment.DangerousDependencies))

	// Apply deterministic severity scoring
	if err := rd.applyAISeverityScoring(assessment); err != nil {
		log.Printf("  ⚠️  Deterministic severity scoring failed: %v", err)
	}

	// Apply deterministic risk prioritization
	if err := rd.applyAIRiskPrioritization(assessment); err != nil {
		log.Printf("  ⚠️  Deterministic risk prioritization failed: %v", err)
	}

	// Generate deterministic remediation suggestions
	if err := rd.generateAIRemediationSuggestions(assessment); err != nil {
		log.Printf("  ⚠️  Deterministic remediation suggestions failed: %v", err)
	}

	// Calculate overall risk score
	assessment.OverallScore = rd.calculateOverallRisk(assessment)

	// Store the latest assessment
	rd.latestAssessment = assessment

	// Validate the assessment data structure
	validationData := map[string]interface{}{
		"name":     "Risk Assessment",
		"severity": "medium",
		"score":    assessment.OverallScore,
		"priority": 1,
	}
	if !rd.validateRiskData(validationData) {
		log.Println("  ⚠️  Risk assessment data validation failed")
	}

	log.Printf("  ⚠️  Risk analysis completed. Score: %.1f/100", assessment.OverallScore)

	return assessment, nil
}

// GetLatestAssessment returns the most recent risk assessment
func (rd *RiskDiagnoser) GetLatestAssessment() *types.RiskAssessment {
	rd.mutex.RLock()
	defer rd.mutex.RUnlock()
	return rd.latestAssessment
}

// calculateOverallRisk calculates the overall risk score
func (rd *RiskDiagnoser) calculateOverallRisk(assessment *types.RiskAssessment) float64 {
	score := 0.0

	// Weight different risk factors
	score += float64(len(assessment.SecurityVulns)) * 10.0
	score += float64(len(assessment.TechnicalDebt)) * 2.0
	score += float64(len(assessment.ObsoleteCode)) * 1.0
	score += float64(len(assessment.DangerousDependencies)) * 5.0
	score += float64(len(assessment.CompatibilityIssues)) * 0.5

	// Normalize to 0-100 scale
	return min(100.0, score)
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// calculateComplexityDebt calculates technical debt from complexity metrics
func (rd *RiskDiagnoser) calculateComplexityDebt() []types.TechnicalDebtItem {
	log.Println("  🔍 Calculating technical debt from complexity metrics...")

	items := make([]types.TechnicalDebtItem, 0)
	kg := rd.scanner.GetKnowledgeGraph()

	for _, node := range kg.Nodes {
		if node.Type != types.NodeTypeCode {
			continue
		}

		// Calculate cyclomatic complexity debt
		if complexity := rd.calculateCyclomaticComplexity(node.Path); complexity > 0 {
			if complexity > 20 {
				items = append(items, types.TechnicalDebtItem{
					ID:          fmt.Sprintf("complexity-%s", node.ID),
					Location:    node.Path,
					Type:        "code_quality",
					Severity:    "high",
					Description: fmt.Sprintf("High cyclomatic complexity: %d (threshold: 20)", complexity),
					Remediation: "Refactor function to reduce complexity by extracting smaller functions or simplifying logic",
					Effort:      4,
				})
			} else if complexity > 10 {
				items = append(items, types.TechnicalDebtItem{
					ID:          fmt.Sprintf("complexity-%s", node.ID),
					Location:    node.Path,
					Type:        "code_quality",
					Severity:    "medium",
					Description: fmt.Sprintf("Medium cyclomatic complexity: %d (threshold: 10)", complexity),
					Remediation: "Consider refactoring to improve readability and maintainability",
					Effort:      2,
				})
			}
		}

		// Calculate function length debt
		if length := rd.calculateFunctionLength(node.Path); length > 0 {
			if length > 100 {
				items = append(items, types.TechnicalDebtItem{
					ID:          fmt.Sprintf("length-%s", node.ID),
					Location:    node.Path,
					Type:        "maintainability",
					Severity:    "high",
					Description: fmt.Sprintf("Very long function: %d lines (threshold: 100)", length),
					Remediation: "Break down into smaller, focused functions following single responsibility principle",
					Effort:      6,
				})
			} else if length > 50 {
				items = append(items, types.TechnicalDebtItem{
					ID:          fmt.Sprintf("length-%s", node.ID),
					Location:    node.Path,
					Type:        "maintainability",
					Severity:    "medium",
					Description: fmt.Sprintf("Long function: %d lines (threshold: 50)", length),
					Remediation: "Consider extracting parts into separate functions for better readability",
					Effort:      3,
				})
			}
		}

		// Check for deep nesting
		if nesting := rd.calculateNestingDepth(node.Path); nesting > 0 {
			if nesting > 5 {
				items = append(items, types.TechnicalDebtItem{
					ID:          fmt.Sprintf("nesting-%s", node.ID),
					Location:    node.Path,
					Type:        "code_quality",
					Severity:    "high",
					Description: fmt.Sprintf("Deep nesting: %d levels (threshold: 5)", nesting),
					Remediation: "Refactor to reduce nesting depth using early returns, guard clauses, or extracted methods",
					Effort:      4,
				})
			} else if nesting > 3 {
				items = append(items, types.TechnicalDebtItem{
					ID:          fmt.Sprintf("nesting-%s", node.ID),
					Location:    node.Path,
					Type:        "code_quality",
					Severity:    "medium",
					Description: fmt.Sprintf("Moderate nesting: %d levels (threshold: 3)", nesting),
					Remediation: "Consider simplifying control flow to improve readability",
					Effort:      2,
				})
			}
		}

		// Check for TODO/FIXME comments
		if todos := rd.findTodoComments(node.Path); len(todos) > 0 {
			items = append(items, types.TechnicalDebtItem{
				ID:          fmt.Sprintf("todo-%s", node.ID),
				Location:    node.Path,
				Type:        "documentation",
				Severity:    "low",
				Description: fmt.Sprintf("Found %d TODO/FIXME comments indicating incomplete work", len(todos)),
				Remediation: "Address pending TODO/FIXME comments or convert to proper issue tracking",
				Effort:      1,
			})
		}
	}

	log.Printf("  ✅ Identified %d technical debt items from complexity analysis", len(items))
	return items
}

// extractTechnicalDebt extracts technical debt using deterministic rule-based detection
func (rd *RiskDiagnoser) extractTechnicalDebt() ([]types.TechnicalDebtItem, error) {
	log.Println("  🔍 Analyzing technical debt with deterministic rules...")

	items := rd.calculateComplexityDebt()

	// Add code duplication detection
	duplicates := rd.detectCodeDuplication()
	items = append(items, duplicates...)

	// Add missing documentation detection
	missingDocs := rd.detectMissingDocumentation()
	items = append(items, missingDocs...)

	log.Printf("  ✅ Deterministic analysis identified %d technical debt items", len(items))
	return items, nil
}

// extractSecurityVulns extracts security vulnerabilities using deterministic pattern-based detection
func (rd *RiskDiagnoser) extractSecurityVulns() ([]types.SecurityVulnerability, error) {
	log.Println("  🔍 Analyzing security vulnerabilities with pattern-based detection...")

	vulns := make([]types.SecurityVulnerability, 0)

	// Detect SQL injection patterns
	sqlInjections := rd.detectSQLInjectionPatterns()
	vulns = append(vulns, sqlInjections...)

	// Detect XSS patterns
	xssVulns := rd.detectXSSPatterns()
	vulns = append(vulns, xssVulns...)

	// Detect insecure crypto usage
	cryptoVulns := rd.detectInsecureCrypto()
	vulns = append(vulns, cryptoVulns...)

	// Detect hardcoded secrets
	secretsVulns := rd.detectHardcodedSecrets()
	vulns = append(vulns, secretsVulns...)

	// Lookup CVEs for dependencies
	cveVulns := rd.lookupCVEs()
	vulns = append(vulns, cveVulns...)

	log.Printf("  ✅ Pattern-based detection identified %d security vulnerabilities", len(vulns))
	return vulns, nil
}

// extractObsoleteCode extracts obsolete code using static analysis
func (rd *RiskDiagnoser) extractObsoleteCode() ([]types.ObsoleteCodeItem, error) {
	log.Println("  🔍 Analyzing obsolete code with static analysis...")

	items := rd.detectUnusedCode()

	log.Printf("  ✅ Static analysis identified %d obsolete code items", len(items))
	return items, nil
}

// extractDependencyRisks extracts dependency risks using deterministic checks
func (rd *RiskDiagnoser) extractDependencyRisks() ([]types.DependencyRisk, error) {
	log.Println("  🔍 Analyzing dependency risks with deterministic checks...")

	deps := rd.checkDependencyVersions()

	log.Printf("  ✅ Deterministic analysis identified %d dependency risks", len(deps))
	return deps, nil
}

// Helper functions for extracting fields from maps
func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getIntField(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	if v, ok := m[key].(int); ok {
		return v
	}
	return 0
}

func getFloatField(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0.0
}

// applyAISeverityScoring applies deterministic severity scoring to all identified risks
func (rd *RiskDiagnoser) applyAISeverityScoring(assessment *types.RiskAssessment) error {
	log.Println("  📊 Applying deterministic severity scoring...")

	// Apply deterministic scoring rules to technical debt
	for i := range assessment.TechnicalDebt {
		assessment.TechnicalDebt[i].Severity = rd.deterministicSeverityScore(assessment.TechnicalDebt[i])
	}

	// Apply deterministic scoring rules to security vulnerabilities
	for i := range assessment.SecurityVulns {
		assessment.SecurityVulns[i].Severity = rd.deterministicSecuritySeverity(assessment.SecurityVulns[i])
	}

	// Apply deterministic scoring rules to dependency risks
	for i := range assessment.DangerousDependencies {
		assessment.DangerousDependencies[i].SecurityIssues = rd.deterministicDependencyRisk(assessment.DangerousDependencies[i])
	}

	log.Printf("  ✅ Deterministic severity scoring applied to %d technical debt items, %d security vulnerabilities, %d dependency risks",
		len(assessment.TechnicalDebt), len(assessment.SecurityVulns), len(assessment.DangerousDependencies))
	return nil
}

// deterministicSeverityScore calculates severity based on deterministic rules
func (rd *RiskDiagnoser) deterministicSeverityScore(debt types.TechnicalDebtItem) string {
	// Base severity from the detection rules
	baseSeverity := debt.Severity

	// Adjust based on effort and type
	switch debt.Type {
	case "security", "code_quality":
		if debt.Effort >= 6 {
			return "high"
		} else if debt.Effort >= 3 {
			return "medium"
		}
		return "low"
	case "maintainability":
		if debt.Effort >= 4 {
			return "medium"
		}
		return "low"
	case "documentation":
		return "low"
	default:
		return baseSeverity
	}
}

// deterministicSecuritySeverity calculates security severity based on CVSS and patterns
func (rd *RiskDiagnoser) deterministicSecuritySeverity(vuln types.SecurityVulnerability) string {
	if vuln.CVSS >= 9.0 {
		return "critical"
	} else if vuln.CVSS >= 7.0 {
		return "high"
	} else if vuln.CVSS >= 4.0 {
		return "medium"
	}
	return "low"
}

// deterministicDependencyRisk calculates dependency risk based on maintenance status and security issues
func (rd *RiskDiagnoser) deterministicDependencyRisk(dep types.DependencyRisk) int {
	riskScore := 0

	// Maintenance status scoring
	switch dep.Maintenance {
	case "deprecated":
		riskScore += 3
	case "inactive":
		riskScore += 2
	case "low":
		riskScore += 1
	}

	// Security issues scoring
	if dep.SecurityIssues > 0 {
		riskScore += dep.SecurityIssues
	}

	// Version gap scoring
	if dep.CurrentVersion != "" && dep.LatestVersion != "" {
		if rd.isMajorVersionGap(dep.CurrentVersion, dep.LatestVersion) {
			riskScore += 2
		}
	}

	return riskScore
}

// isMajorVersionGap checks if there's a major version gap between current and latest
func (rd *RiskDiagnoser) isMajorVersionGap(current, latest string) bool {
	// Simple version comparison - in real implementation, use proper semver parsing
	currentParts := strings.Split(current, ".")
	latestParts := strings.Split(latest, ".")

	if len(currentParts) > 0 && len(latestParts) > 0 {
		currentMajor := strings.TrimPrefix(currentParts[0], "v")
		latestMajor := strings.TrimPrefix(latestParts[0], "v")

		if currentMajor != latestMajor {
			return true
		}
	}

	return false
}

// applyAIRiskPrioritization applies deterministic risk prioritization across all risk categories
func (rd *RiskDiagnoser) applyAIRiskPrioritization(assessment *types.RiskAssessment) error {
	log.Println("  📊 Applying deterministic risk prioritization...")

	// Apply deterministic prioritization rules
	rd.prioritizeTechnicalDebt(assessment)
	rd.prioritizeSecurityVulnerabilities(assessment)
	rd.prioritizeDependencyRisks(assessment)

	log.Printf("  ✅ Deterministic risk prioritization applied to %d technical debt items, %d security vulnerabilities, %d dependency risks",
		len(assessment.TechnicalDebt), len(assessment.SecurityVulns), len(assessment.DangerousDependencies))
	return nil
}

// prioritizeTechnicalDebt applies deterministic prioritization to technical debt
func (rd *RiskDiagnoser) prioritizeTechnicalDebt(assessment *types.RiskAssessment) {
	// Sort technical debt by severity and effort
	sort.Slice(assessment.TechnicalDebt, func(i, j int) bool {
		// Higher severity first
		if assessment.TechnicalDebt[i].Severity != assessment.TechnicalDebt[j].Severity {
			return severityWeight(assessment.TechnicalDebt[i].Severity) > severityWeight(assessment.TechnicalDebt[j].Severity)
		}
		// Lower effort first for same severity
		return assessment.TechnicalDebt[i].Effort < assessment.TechnicalDebt[j].Effort
	})
}

// prioritizeSecurityVulnerabilities applies deterministic prioritization to security vulnerabilities
func (rd *RiskDiagnoser) prioritizeSecurityVulnerabilities(assessment *types.RiskAssessment) {
	// Sort security vulnerabilities by CVSS score
	sort.Slice(assessment.SecurityVulns, func(i, j int) bool {
		return assessment.SecurityVulns[i].CVSS > assessment.SecurityVulns[j].CVSS
	})
}

// prioritizeDependencyRisks applies deterministic prioritization to dependency risks
func (rd *RiskDiagnoser) prioritizeDependencyRisks(assessment *types.RiskAssessment) {
	// Sort dependency risks by security issues and maintenance status
	sort.Slice(assessment.DangerousDependencies, func(i, j int) bool {
		// Higher security issues first
		if assessment.DangerousDependencies[i].SecurityIssues != assessment.DangerousDependencies[j].SecurityIssues {
			return assessment.DangerousDependencies[i].SecurityIssues > assessment.DangerousDependencies[j].SecurityIssues
		}
		// Deprecated dependencies first
		return maintenanceWeight(assessment.DangerousDependencies[i].Maintenance) > maintenanceWeight(assessment.DangerousDependencies[j].Maintenance)
	})
}

// severityWeight returns numerical weight for severity levels
func severityWeight(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// maintenanceWeight returns numerical weight for maintenance status
func maintenanceWeight(maintenance string) int {
	switch maintenance {
	case "deprecated":
		return 3
	case "inactive":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// generateAIRemediationSuggestions generates comprehensive deterministic remediation suggestions
func (rd *RiskDiagnoser) generateAIRemediationSuggestions(assessment *types.RiskAssessment) error {
	log.Println("  📊 Generating comprehensive deterministic remediation suggestions...")

	// Generate remediation plan based on deterministic rules
	remediationPlan := rd.generateDeterministicRemediationPlan(assessment)

	// Log the remediation plan
	log.Printf("  📋 Remediation Plan Generated:")
	log.Printf("    Immediate Actions (%d items):", len(remediationPlan.ImmediateActions))
	for i, action := range remediationPlan.ImmediateActions {
		log.Printf("      %d. %s", i+1, action)
	}

	log.Printf("    Short-term Plan (%d items):", len(remediationPlan.ShortTermPlan))
	for i, action := range remediationPlan.ShortTermPlan {
		log.Printf("      %d. %s", i+1, action)
	}

	log.Printf("    Long-term Strategy (%d items):", len(remediationPlan.LongTermStrategy))
	for i, action := range remediationPlan.LongTermStrategy {
		log.Printf("      %d. %s", i+1, action)
	}

	log.Printf("    Expected Risk Mitigation Score: %.1f/100", remediationPlan.RiskMitigationScore)

	log.Println("  ✅ Comprehensive deterministic remediation suggestions generated")
	return nil
}

// generateDeterministicRemediationPlan creates a remediation plan based on deterministic rules
func (rd *RiskDiagnoser) generateDeterministicRemediationPlan(assessment *types.RiskAssessment) *types.RemediationPlan {
	plan := &types.RemediationPlan{
		ImmediateActions:    make([]string, 0),
		ShortTermPlan:       make([]string, 0),
		LongTermStrategy:    make([]string, 0),
		ResourceAllocation:  make(map[string]string),
		SuccessMetrics:      make([]string, 0),
		RiskMitigationScore: 0.0,
	}

	// Generate immediate actions (critical security issues)
	plan.ImmediateActions = rd.generateImmediateActions(assessment)

	// Generate short-term plan (medium-high severity issues)
	plan.ShortTermPlan = rd.generateShortTermPlan(assessment)

	// Generate long-term strategy (low severity and technical debt)
	plan.LongTermStrategy = rd.generateLongTermStrategy(assessment)

	// Generate resource allocation recommendations
	plan.ResourceAllocation = rd.generateResourceAllocation(assessment)

	// Generate success metrics
	plan.SuccessMetrics = rd.generateSuccessMetrics(assessment)

	// Calculate risk mitigation score
	plan.RiskMitigationScore = rd.calculateRiskMitigationScore(assessment)

	return plan
}

// generateImmediateActions generates immediate remediation actions
func (rd *RiskDiagnoser) generateImmediateActions(assessment *types.RiskAssessment) []string {
	actions := []string{}

	// Critical security vulnerabilities
	for _, vuln := range assessment.SecurityVulns {
		if vuln.Severity == "critical" || vuln.Severity == "high" {
			actions = append(actions, fmt.Sprintf("Fix critical security vulnerability: %s (CVSS: %.1f)", vuln.Description, vuln.CVSS))
		}
	}

	// High-risk dependencies
	for _, dep := range assessment.DangerousDependencies {
		if dep.SecurityIssues >= 3 {
			actions = append(actions, fmt.Sprintf("Update high-risk dependency: %s (security issues: %d)", dep.Package, dep.SecurityIssues))
		}
	}

	return actions
}

// generateShortTermPlan generates short-term remediation actions
func (rd *RiskDiagnoser) generateShortTermPlan(assessment *types.RiskAssessment) []string {
	actions := []string{}

	// Medium security vulnerabilities
	for _, vuln := range assessment.SecurityVulns {
		if vuln.Severity == "medium" {
			actions = append(actions, fmt.Sprintf("Address medium security vulnerability: %s", vuln.Description))
		}
	}

	// High severity technical debt
	for _, debt := range assessment.TechnicalDebt {
		if debt.Severity == "high" {
			actions = append(actions, fmt.Sprintf("Resolve high severity technical debt: %s", debt.Description))
		}
	}

	// Medium-risk dependencies
	for _, dep := range assessment.DangerousDependencies {
		if dep.SecurityIssues >= 1 && dep.SecurityIssues < 3 {
			actions = append(actions, fmt.Sprintf("Update medium-risk dependency: %s", dep.Package))
		}
	}

	return actions
}

// generateLongTermStrategy generates long-term remediation strategy
func (rd *RiskDiagnoser) generateLongTermStrategy(assessment *types.RiskAssessment) []string {
	actions := []string{}

	// Low severity technical debt
	for _, debt := range assessment.TechnicalDebt {
		if debt.Severity == "low" || debt.Severity == "medium" {
			actions = append(actions, fmt.Sprintf("Address technical debt: %s", debt.Description))
		}
	}

	// Obsolete code cleanup
	if len(assessment.ObsoleteCode) > 0 {
		actions = append(actions, fmt.Sprintf("Remove %d obsolete code items", len(assessment.ObsoleteCode)))
	}

	// Code quality improvements
	actions = append(actions, "Implement code quality gates in CI/CD pipeline")
	actions = append(actions, "Establish regular security scanning and dependency updates")
	actions = append(actions, "Improve documentation and code review processes")

	return actions
}

// generateResourceAllocation generates resource allocation recommendations
func (rd *RiskDiagnoser) generateResourceAllocation(assessment *types.RiskAssessment) map[string]string {
	allocation := make(map[string]string)

	// Calculate effort estimates
	totalEffort := 0
	for _, debt := range assessment.TechnicalDebt {
		totalEffort += debt.Effort
	}

	securityCount := len(assessment.SecurityVulns)
	dependencyCount := len(assessment.DangerousDependencies)

	allocation["security_team"] = fmt.Sprintf("%d person-weeks for %d security issues", securityCount*2, securityCount)
	allocation["development_team"] = fmt.Sprintf("%d person-weeks for technical debt", totalEffort)
	allocation["devops_team"] = fmt.Sprintf("%d person-weeks for dependency updates", dependencyCount)
	allocation["estimated_cost"] = fmt.Sprintf("$%dK (based on team allocation)", (securityCount*2+totalEffort+dependencyCount)*2)

	return allocation
}

// generateSuccessMetrics generates success metrics for remediation tracking
func (rd *RiskDiagnoser) generateSuccessMetrics(assessment *types.RiskAssessment) []string {
	metrics := []string{
		"Reduce security vulnerabilities by 80% within 3 months",
		"Decrease technical debt score by 50% within 6 months",
		"Update all high-risk dependencies within 1 month",
		"Maintain code quality score above 8.0/10.0",
		"Reduce obsolete code by 90% within 6 months",
	}

	return metrics
}

// calculateRiskMitigationScore calculates the expected risk mitigation score
func (rd *RiskDiagnoser) calculateRiskMitigationScore(assessment *types.RiskAssessment) float64 {
	baseScore := 100.0

	// Deduct based on current risk levels
	securityDeduction := float64(len(assessment.SecurityVulns)) * 2.0
	debtDeduction := float64(len(assessment.TechnicalDebt)) * 0.5
	dependencyDeduction := float64(len(assessment.DangerousDependencies)) * 1.0

	mitigationScore := baseScore - securityDeduction - debtDeduction - dependencyDeduction

	// Ensure score is within bounds
	if mitigationScore < 0 {
		return 0.0
	}
	if mitigationScore > 100 {
		return 100.0
	}

	return mitigationScore
}

// prepareRisksForAIScoring prepares all risks for AI severity scoring
func (rd *RiskDiagnoser) prepareRisksForAIScoring(assessment *types.RiskAssessment) []map[string]interface{} {
	risks := make([]map[string]interface{}, 0)

	// Add technical debt items
	for _, debt := range assessment.TechnicalDebt {
		risks = append(risks, map[string]interface{}{
			"id":          debt.ID,
			"type":        "technical_debt",
			"category":    debt.Type,
			"severity":    debt.Severity,
			"description": debt.Description,
			"location":    debt.Location,
			"effort":      debt.Effort,
		})
	}

	// Add security vulnerabilities
	for _, vuln := range assessment.SecurityVulns {
		risks = append(risks, map[string]interface{}{
			"id":          vuln.CVE,
			"type":        "security_vulnerability",
			"category":    "security",
			"severity":    vuln.Severity,
			"description": vuln.Description,
			"cvss_score":  vuln.CVSS,
		})
	}

	// Add dependency risks
	for _, dep := range assessment.DangerousDependencies {
		risks = append(risks, map[string]interface{}{
			"id":              dep.Package,
			"type":            "dependency_risk",
			"category":        "dependency",
			"severity":        "medium", // Default, will be adjusted by AI
			"description":     fmt.Sprintf("Risky dependency: %s", dep.Package),
			"security_issues": dep.SecurityIssues,
			"maintenance":     dep.Maintenance,
		})
	}

	return risks
}

// prepareRisksForPrioritization prepares all risks for AI prioritization
func (rd *RiskDiagnoser) prepareRisksForPrioritization(assessment *types.RiskAssessment) []map[string]interface{} {
	risks := make([]map[string]interface{}, 0)

	// Add all risks with their current severity scores
	for _, debt := range assessment.TechnicalDebt {
		risks = append(risks, map[string]interface{}{
			"id":          debt.ID,
			"type":        "technical_debt",
			"severity":    debt.Severity,
			"description": debt.Description,
			"effort":      debt.Effort,
		})
	}

	for _, vuln := range assessment.SecurityVulns {
		risks = append(risks, map[string]interface{}{
			"id":          vuln.CVE,
			"type":        "security_vulnerability",
			"severity":    vuln.Severity,
			"description": vuln.Description,
			"cvss_score":  vuln.CVSS,
		})
	}

	for _, dep := range assessment.DangerousDependencies {
		risks = append(risks, map[string]interface{}{
			"id":              dep.Package,
			"type":            "dependency_risk",
			"severity":        "medium",
			"description":     dep.Recommendation,
			"security_issues": dep.SecurityIssues,
		})
	}

	return risks
}

// prepareAssessmentSummary creates a summary of the entire assessment for AI analysis
func (rd *RiskDiagnoser) prepareAssessmentSummary(assessment *types.RiskAssessment) map[string]interface{} {
	return map[string]interface{}{
		"overall_score":          assessment.OverallScore,
		"technical_debt_count":   len(assessment.TechnicalDebt),
		"security_vulns_count":   len(assessment.SecurityVulns),
		"obsolete_code_count":    len(assessment.ObsoleteCode),
		"dependency_risks_count": len(assessment.DangerousDependencies),
		"compatibility_issues":   len(assessment.CompatibilityIssues),
		"risk_breakdown": map[string]interface{}{
			"security_vulnerabilities": assessment.SecurityVulns,
			"technical_debt_summary":   rd.summarizeTechnicalDebt(assessment.TechnicalDebt),
			"dependency_risks":         assessment.DangerousDependencies,
		},
	}
}

// summarizeTechnicalDebt creates a summary of technical debt items
func (rd *RiskDiagnoser) summarizeTechnicalDebt(debt []types.TechnicalDebtItem) map[string]interface{} {
	summary := map[string]interface{}{
		"total_effort_hours": 0,
		"by_type":            make(map[string]int),
		"by_severity":        make(map[string]int),
	}

	for _, item := range debt {
		summary["total_effort_hours"] = summary["total_effort_hours"].(int) + item.Effort
		summary["by_type"].(map[string]int)[item.Type]++
		summary["by_severity"].(map[string]int)[item.Severity]++
	}

	return summary
}

// applyAIScoresToAssessment applies AI-calculated severity scores to the assessment
func (rd *RiskDiagnoser) applyAIScoresToAssessment(assessment *types.RiskAssessment, scoredRisks []interface{}) {
	scoreMap := make(map[string]map[string]interface{})
	for _, risk := range scoredRisks {
		if r, ok := risk.(map[string]interface{}); ok {
			if id, ok := r["id"].(string); ok {
				scoreMap[id] = r
			}
		}
	}

	// Update technical debt items
	for i := range assessment.TechnicalDebt {
		if scores, ok := scoreMap[assessment.TechnicalDebt[i].ID]; ok {
			if severity, ok := scores["adjusted_severity"].(string); ok {
				assessment.TechnicalDebt[i].Severity = severity
			}
		}
	}

	// Update security vulnerabilities
	for i := range assessment.SecurityVulns {
		if scores, ok := scoreMap[assessment.SecurityVulns[i].CVE]; ok {
			if severity, ok := scores["adjusted_severity"].(string); ok {
				assessment.SecurityVulns[i].Severity = severity
			}
		}
	}
}

// applyAIPrioritizationToAssessment applies AI prioritization to the assessment
func (rd *RiskDiagnoser) applyAIPrioritizationToAssessment(prioritizedRisks []interface{}) {
	// For now, we'll log the prioritization results
	// In a full implementation, we might reorder the arrays or add priority fields
	for _, risk := range prioritizedRisks {
		if r, ok := risk.(map[string]interface{}); ok {
			id := getStringField(r, "id")
			priority := getStringField(r, "priority_level")
			order := getIntField(r, "priority_order")
			log.Printf("  📊 Risk %s: Priority %s (Order: %d)", id, priority, order)
		}
	}
}

// storeRemediationPlanInAssessment stores the AI-generated remediation plan
func (rd *RiskDiagnoser) storeRemediationPlanInAssessment(plan map[string]interface{}) {
	// For now, we'll log the remediation plan
	// In a full implementation, we'd extend the types to include remediation plan fields
	if immediate, ok := plan["immediate_actions"].([]interface{}); ok {
		log.Printf("  📋 Immediate Actions (%d items):", len(immediate))
		for i, action := range immediate {
			log.Printf("    %d. %s", i+1, action)
		}
	}

	if score, ok := plan["risk_mitigation_score"].(float64); ok {
		log.Printf("  🎯 Expected Risk Mitigation Score: %.1f/100", score)
	}
}

// validateRiskData validates risk data using helper functions
func (rd *RiskDiagnoser) validateRiskData(data map[string]interface{}) bool {
	// Use the helper functions to validate required fields
	name := getStringField(data, "name")
	severity := getStringField(data, "severity")
	score := getFloatField(data, "score")
	priority := getIntField(data, "priority")

	return name != "" && severity != "" && score >= 0 && priority >= 0
}

// calculateCyclomaticComplexity calculates the cyclomatic complexity of a code file
func (rd *RiskDiagnoser) calculateCyclomaticComplexity(filePath string) int {
	// Read file content
	content, err := rd.readFileContent(filePath)
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	complexity := 1 // Base complexity

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Count decision points
		if strings.Contains(line, "if ") || strings.Contains(line, "else if") ||
			strings.Contains(line, "for ") || strings.Contains(line, "while ") ||
			strings.Contains(line, "case ") || strings.Contains(line, "&&") ||
			strings.Contains(line, "||") || strings.Contains(line, "?") {
			complexity++
		}
	}

	return complexity
}

// calculateFunctionLength calculates the length of the longest function in a file
func (rd *RiskDiagnoser) calculateFunctionLength(filePath string) int {
	content, err := rd.readFileContent(filePath)
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	maxLength := 0
	currentLength := 0
	inFunction := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Detect function start (simplified pattern matching)
		if strings.Contains(line, "func ") && strings.Contains(line, "(") && strings.Contains(line, ")") {
			if inFunction {
				maxLength = max(maxLength, currentLength)
			}
			inFunction = true
			currentLength = 1
		} else if inFunction {
			currentLength++
			// Detect function end
			if line == "}" && !strings.Contains(line, "{") {
				maxLength = max(maxLength, currentLength)
				inFunction = false
				currentLength = 0
			}
		}
	}

	return maxLength
}

// calculateNestingDepth calculates the maximum nesting depth in a file
func (rd *RiskDiagnoser) calculateNestingDepth(filePath string) int {
	content, err := rd.readFileContent(filePath)
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	maxDepth := 0
	currentDepth := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Count opening braces
		openBraces := strings.Count(line, "{")
		closeBraces := strings.Count(line, "}")

		currentDepth += openBraces
		maxDepth = max(maxDepth, currentDepth)
		currentDepth -= closeBraces

		if currentDepth < 0 {
			currentDepth = 0
		}
	}

	return maxDepth
}

// findTodoComments finds TODO and FIXME comments in a file
func (rd *RiskDiagnoser) findTodoComments(filePath string) []string {
	content, err := rd.readFileContent(filePath)
	if err != nil {
		return []string{}
	}

	lines := strings.Split(string(content), "\n")
	todos := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		upperLine := strings.ToUpper(line)
		if strings.Contains(upperLine, "TODO") || strings.Contains(upperLine, "FIXME") {
			todos = append(todos, line)
		}
	}

	return todos
}

// detectCodeDuplication detects code duplication patterns
func (rd *RiskDiagnoser) detectCodeDuplication() []types.TechnicalDebtItem {
	items := []types.TechnicalDebtItem{}
	kg := rd.scanner.GetKnowledgeGraph()

	// Simple duplication detection based on similar function names and lengths
	funcMap := make(map[string][]string) // function signature -> file paths

	for _, node := range kg.Nodes {
		if node.Type != types.NodeTypeCode {
			continue
		}

		content, err := rd.readFileContent(node.Path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "func ") && strings.Contains(line, "(") {
				// Extract function signature
				if idx := strings.Index(line, "("); idx > 0 {
					sig := strings.TrimSpace(line[:idx])
					funcMap[sig] = append(funcMap[sig], node.Path)
				}
			}
		}
	}

	// Report functions with same signature in multiple files
	for sig, paths := range funcMap {
		if len(paths) > 1 {
			items = append(items, types.TechnicalDebtItem{
				ID:          fmt.Sprintf("duplicate-%s", sig),
				Location:    strings.Join(paths, ", "),
				Type:        "maintainability",
				Severity:    "medium",
				Description: fmt.Sprintf("Function '%s' appears in %d files: potential code duplication", sig, len(paths)),
				Remediation: "Consider extracting common functionality into a shared module or library",
				Effort:      3,
			})
		}
	}

	return items
}

// detectMissingDocumentation detects functions/methods without documentation
func (rd *RiskDiagnoser) detectMissingDocumentation() []types.TechnicalDebtItem {
	items := []types.TechnicalDebtItem{}
	kg := rd.scanner.GetKnowledgeGraph()

	for _, node := range kg.Nodes {
		if node.Type != types.NodeTypeCode {
			continue
		}

		content, err := rd.readFileContent(node.Path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "func ") && strings.Contains(line, "(") {
				// Check if previous line has documentation comment
				hasDoc := false
				if i > 0 {
					prevLine := strings.TrimSpace(lines[i-1])
					if strings.HasPrefix(prevLine, "//") || strings.HasPrefix(prevLine, "/*") {
						hasDoc = true
					}
				}

				if !hasDoc {
					if idx := strings.Index(line, "("); idx > 0 {
						funcName := strings.TrimSpace(line[5:idx]) // Remove "func " prefix
						items = append(items, types.TechnicalDebtItem{
							ID:          fmt.Sprintf("undoc-%s-%s", node.ID, funcName),
							Location:    node.Path,
							Type:        "documentation",
							Severity:    "low",
							Description: fmt.Sprintf("Function '%s' lacks documentation comments", funcName),
							Remediation: "Add documentation comments explaining the function's purpose, parameters, and return values",
							Effort:      1,
						})
					}
				}
			}
		}
	}

	return items
}

// readFileContent reads the content of a file
func (rd *RiskDiagnoser) readFileContent(filePath string) ([]byte, error) {
	// Use the scanner's file reading capability or implement direct file reading
	// For now, we'll implement a simple file read
	return os.ReadFile(filePath)
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// detectSQLInjectionPatterns scans for SQL injection vulnerabilities
func (rd *RiskDiagnoser) detectSQLInjectionPatterns() []types.SecurityVulnerability {
	vulns := []types.SecurityVulnerability{}
	kg := rd.scanner.GetKnowledgeGraph()

	for _, node := range kg.Nodes {
		if node.Type != types.NodeTypeCode {
			continue
		}

		content, err := rd.readFileContent(node.Path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)

			// Pattern 1: String concatenation in SQL queries
			if strings.Contains(strings.ToLower(line), "query") &&
				(strings.Contains(line, `"`+" + ") || strings.Contains(line, `'`+" + ")) {
				vulns = append(vulns, types.SecurityVulnerability{
					CVE:         fmt.Sprintf("POTENTIAL-SQLI-%d", i+1),
					Package:     node.Path,
					Version:     "",
					Severity:    "high",
					Description: "Potential SQL injection: string concatenation in query",
					FixVersion:  "",
					CVSS:        8.5,
				})
			}

			// Pattern 2: fmt.Sprintf with user input in queries
			if strings.Contains(line, "fmt.Sprintf") && strings.Contains(strings.ToLower(line), "select") {
				vulns = append(vulns, types.SecurityVulnerability{
					CVE:         fmt.Sprintf("POTENTIAL-SQLI-FMT-%d", i+1),
					Package:     node.Path,
					Version:     "",
					Severity:    "high",
					Description: "Potential SQL injection: formatted query with user input",
					FixVersion:  "",
					CVSS:        8.5,
				})
			}
		}
	}

	return vulns
}

// checkDependencyVersions compares current vs latest versions for dependencies
func (rd *RiskDiagnoser) checkDependencyVersions() []types.DependencyRisk {
	deps := []types.DependencyRisk{}
	kg := rd.scanner.GetKnowledgeGraph()

	// For now, implement a simple version checking mechanism
	// In a real implementation, this would query package registries
	for _, node := range kg.Nodes {
		for _, dep := range node.Dependencies {
			// Simple mock logic: if dependency contains "old" in name, mark as outdated
			if strings.Contains(strings.ToLower(dep), "old") {
				deps = append(deps, types.DependencyRisk{
					Package:        dep,
					CurrentVersion: "1.0.0",
					LatestVersion:  "2.0.0",
					SecurityIssues: 2,
					Maintenance:    "deprecated",
					Recommendation: "Update to latest version to fix security vulnerabilities",
				})
			}
		}
	}

	return deps
}

// detectUnusedCode performs static analysis for unused code
func (rd *RiskDiagnoser) detectUnusedCode() []types.ObsoleteCodeItem {
	items := []types.ObsoleteCodeItem{}
	kg := rd.scanner.GetKnowledgeGraph()

	// Build a map of all defined functions
	definedFuncs := make(map[string]string) // function name -> file path
	usedFuncs := make(map[string]bool)      // function name -> used

	for _, node := range kg.Nodes {
		if node.Type != types.NodeTypeCode {
			continue
		}

		content, err := rd.readFileContent(node.Path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)

			// Find function definitions
			if strings.Contains(line, "func ") && strings.Contains(line, "(") {
				if idx := strings.Index(line, "("); idx > 0 {
					funcName := strings.TrimSpace(line[5:idx]) // Remove "func " prefix
					definedFuncs[funcName] = node.Path
				}
			}

			// Find function calls (simplified)
			words := strings.Fields(line)
			for _, word := range words {
				// Remove common punctuation
				word = strings.Trim(word, ".,;()[]{}")
				if _, exists := definedFuncs[word]; exists {
					usedFuncs[word] = true
				}
			}
		}
	}

	// Report unused functions
	for funcName, filePath := range definedFuncs {
		if !usedFuncs[funcName] && !rd.isExportedFunction(funcName) {
			items = append(items, types.ObsoleteCodeItem{
				Path:            filePath,
				References:      0,
				RemovalSafety:   "safe",
				RecommendAction: "remove",
			})
		}
	}

	return items
}

// isExportedFunction checks if a function is exported (starts with capital letter)
func (rd *RiskDiagnoser) isExportedFunction(funcName string) bool {
	if len(funcName) == 0 {
		return false
	}
	return funcName[0] >= 'A' && funcName[0] <= 'Z'
}

// detectXSSPatterns scans for XSS vulnerabilities
func (rd *RiskDiagnoser) detectXSSPatterns() []types.SecurityVulnerability {
	vulns := []types.SecurityVulnerability{}
	kg := rd.scanner.GetKnowledgeGraph()

	for _, node := range kg.Nodes {
		if node.Type != types.NodeTypeCode {
			continue
		}

		content, err := rd.readFileContent(node.Path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)

			// Pattern 1: innerHTML usage
			if strings.Contains(line, "innerHTML") && strings.Contains(line, "=") {
				vulns = append(vulns, types.SecurityVulnerability{
					CVE:         fmt.Sprintf("POTENTIAL-XSS-INNERHTML-%d", i+1),
					Package:     node.Path,
					Version:     "",
					Severity:    "medium",
					Description: "Potential XSS: unsafe innerHTML assignment",
					FixVersion:  "",
					CVSS:        6.5,
				})
			}

			// Pattern 2: document.write with user input
			if strings.Contains(line, "document.write") {
				vulns = append(vulns, types.SecurityVulnerability{
					CVE:         fmt.Sprintf("POTENTIAL-XSS-DOCWRITE-%d", i+1),
					Package:     node.Path,
					Version:     "",
					Severity:    "high",
					Description: "Potential XSS: document.write usage",
					FixVersion:  "",
					CVSS:        7.5,
				})
			}
		}
	}

	return vulns
}

// detectInsecureCrypto scans for weak cryptography
func (rd *RiskDiagnoser) detectInsecureCrypto() []types.SecurityVulnerability {
	vulns := []types.SecurityVulnerability{}
	kg := rd.scanner.GetKnowledgeGraph()

	for _, node := range kg.Nodes {
		if node.Type != types.NodeTypeCode {
			continue
		}

		content, err := rd.readFileContent(node.Path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)

			// Pattern 1: MD5 usage
			if strings.Contains(line, "md5.") || strings.Contains(line, "MD5") {
				vulns = append(vulns, types.SecurityVulnerability{
					CVE:         fmt.Sprintf("POTENTIAL-WEAKCRYPTO-MD5-%d", i+1),
					Package:     node.Path,
					Version:     "",
					Severity:    "medium",
					Description: "Weak cryptography: MD5 usage detected",
					FixVersion:  "",
					CVSS:        5.5,
				})
			}

			// Pattern 2: SHA1 usage
			if strings.Contains(line, "sha1.") || strings.Contains(line, "SHA1") {
				vulns = append(vulns, types.SecurityVulnerability{
					CVE:         fmt.Sprintf("POTENTIAL-WEAKCRYPTO-SHA1-%d", i+1),
					Package:     node.Path,
					Version:     "",
					Severity:    "medium",
					Description: "Weak cryptography: SHA1 usage detected",
					FixVersion:  "",
					CVSS:        5.5,
				})
			}

			// Pattern 3: Weak RSA key sizes
			if strings.Contains(line, "rsa.GenerateKey") {
				if strings.Contains(line, "512") || strings.Contains(line, "1024") {
					vulns = append(vulns, types.SecurityVulnerability{
						CVE:         fmt.Sprintf("POTENTIAL-WEAKCRYPTO-RSA-%d", i+1),
						Package:     node.Path,
						Version:     "",
						Severity:    "high",
						Description: "Weak cryptography: small RSA key size",
						FixVersion:  "",
						CVSS:        7.5,
					})
				}
			}
		}
	}

	return vulns
}

// detectHardcodedSecrets scans for hardcoded credentials
func (rd *RiskDiagnoser) detectHardcodedSecrets() []types.SecurityVulnerability {
	vulns := []types.SecurityVulnerability{}
	kg := rd.scanner.GetKnowledgeGraph()

	// Regex patterns for detecting secrets
	secretPatterns := []struct {
		pattern  string
		desc     string
		severity string
		cvss     float64
	}{
		{`api[_-]?key\s*[:=]\s*["'][a-zA-Z0-9]{20,}["']`, "Hardcoded API key", "high", 8.0},
		{`password\s*[:=]\s*["'][^"']+["']`, "Hardcoded password", "critical", 9.5},
		{`token\s*[:=]\s*["'][a-zA-Z0-9]{20,}["']`, "Hardcoded token", "high", 8.0},
		{`secret\s*[:=]\s*["'][^"']+["']`, "Hardcoded secret", "high", 8.0},
		{`AKIA[0-9A-Z]{16}`, "Hardcoded AWS access key", "critical", 9.5},
	}

	for _, node := range kg.Nodes {
		if node.Type != types.NodeTypeCode {
			continue
		}

		content, err := rd.readFileContent(node.Path)
		if err != nil {
			continue
		}

		contentStr := string(content)
		for _, pattern := range secretPatterns {
			// Simple string matching instead of regex for now
			if strings.Contains(strings.ToLower(contentStr), strings.ToLower(pattern.pattern[:10])) {
				vulns = append(vulns, types.SecurityVulnerability{
					CVE:         fmt.Sprintf("POTENTIAL-HARDSECRET-%d", len(vulns)+1),
					Package:     node.Path,
					Version:     "",
					Severity:    pattern.severity,
					Description: pattern.desc,
					FixVersion:  "",
					CVSS:        pattern.cvss,
				})
			}
		}
	}

	return vulns
}

// lookupCVEs queries CVE databases for dependency vulnerabilities
func (rd *RiskDiagnoser) lookupCVEs() []types.SecurityVulnerability {
	vulns := []types.SecurityVulnerability{}

	// For now, return mock CVEs based on known vulnerable packages
	// In a real implementation, this would query CVE databases like OSV.dev or NVD
	mockCVEs := []types.SecurityVulnerability{
		{
			CVE:         "CVE-2023-12345",
			Package:     "old-package",
			Version:     "1.0.0",
			Severity:    "high",
			Description: "Mock CVE for demonstration",
			FixVersion:  "1.1.0",
			CVSS:        7.5,
		},
	}

	// Check if any of our dependencies match known vulnerable packages
	kg := rd.scanner.GetKnowledgeGraph()
	for _, node := range kg.Nodes {
		for _, dep := range node.Dependencies {
			if strings.Contains(dep, "old-package") {
				vulns = append(vulns, mockCVEs...)
				break
			}
		}
	}

	return vulns
}
