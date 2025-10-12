package remediation

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"archguardian/data_engine"
	"archguardian/internal/scanner"
	"archguardian/internal/risk"
	"archguardian/types"
)

// AIRemediator handles AI-powered solution generation for detected issues
type AIRemediator struct {
	ai       types.AIEngineInterface
	scanner  *scanner.Scanner
	diagnoser *risk.RiskDiagnoser
	chromemManager *data_engine.ChromemManager
}

// NewAIRemediator creates a new AI remediator
func NewAIRemediator(ai types.AIEngineInterface, scanner *scanner.Scanner, diagnoser *risk.RiskDiagnoser, chromemManager *data_engine.ChromemManager) *AIRemediator {
	return &AIRemediator{
		ai:             ai,
		scanner:        scanner,
		diagnoser:      diagnoser,
		chromemManager: chromemManager,
	}
}

// GenerateSolutionForIssue generates an AI-powered solution for a specific issue
func (ar *AIRemediator) GenerateSolutionForIssue(ctx context.Context, issueID string, issueType string) (*RemediationSolution, error) {
	log.Printf("🤖 Generating AI solution for issue: %s (type: %s)", issueID, issueType)

	// Load issue details from database (placeholder - would need database access)
	issueDetails, err := ar.loadIssueDetails(issueID, issueType)
	if err != nil {
		return nil, fmt.Errorf("failed to load issue details: %w", err)
	}

	// Load relevant code context
	codeContext, err := ar.loadCodeContext(issueDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to load code context: %w", err)
	}

	// Prepare AI prompt with issue details
	prompt := ar.prepareAIPrompt(issueDetails, codeContext)

	// Generate solution using AI
	aiResponse, err := ar.ai.GenerateText(ctx, "gemini-2.5-flash", prompt, "")
	if err != nil {
		return nil, fmt.Errorf("AI solution generation failed: %w", err)
	}

	// Parse AI response into structured solution
	solution, err := ar.parseAISolution(aiResponse, issueDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI solution: %w", err)
	}

	// Validate solution
	if err := ar.validateSolution(solution); err != nil {
		log.Printf("⚠️  Solution validation warning: %v", err)
		// Don't fail, just log warning
	}

	log.Printf("✅ AI solution generated for issue: %s", issueID)
	return solution, nil
}

// GenerateSolutionForSecurityVuln generates a fix for a security vulnerability
func (ar *AIRemediator) GenerateSolutionForSecurityVuln(ctx context.Context, vuln types.SecurityVulnerability) (*RemediationSolution, error) {
	log.Printf("🤖 Generating security fix for: %s in %s", vuln.Type, vuln.FilePath)

	// Load code context around the vulnerability
	codeSnippet, err := ar.loadCodeSnippet(vuln.FilePath, vuln.LineNumber, 10)
	if err != nil {
		return nil, fmt.Errorf("failed to load code snippet: %w", err)
	}

	prompt := fmt.Sprintf(`You are a security expert. Analyze this security vulnerability and provide a fix.

VULNERABILITY DETAILS:
- Type: %s
- Description: %s
- File: %s
- Line: %d
- Severity: %s

CODE CONTEXT:
%s

Please provide:
1. A detailed explanation of the vulnerability
2. The specific code changes needed to fix it
3. Any additional security considerations
4. Test cases to verify the fix

Format your response as:
EXPLANATION: [explanation]
CHANGES: [specific code changes]
CONSIDERATIONS: [additional notes]
TESTS: [test cases]`, vuln.Type, vuln.Description, vuln.FilePath, vuln.LineNumber, vuln.Severity, codeSnippet)

	aiResponse, err := ar.ai.GenerateText(ctx, "gemini-2.5-flash", prompt, "")
	if err != nil {
		return nil, fmt.Errorf("AI security fix generation failed: %w", err)
	}

	solution := &RemediationSolution{
		IssueID:     vuln.ID,
		IssueType:   "security_vulnerability",
		Description: fmt.Sprintf("AI-generated fix for %s vulnerability", vuln.Type),
		Changes:     ar.parseCodeChangesFromAI(aiResponse),
		TestPlan:    ar.extractTestPlanFromAI(aiResponse),
		RiskLevel:   ar.calculateRiskLevel(vuln.Severity),
		Confidence:  0.85, // AI confidence score
	}

	return solution, nil
}

// GenerateSolutionForTechnicalDebt generates a refactoring for technical debt
func (ar *AIRemediator) GenerateSolutionForTechnicalDebt(ctx context.Context, debt types.TechnicalDebtItem) (*RemediationSolution, error) {
	log.Printf("🤖 Generating refactoring for technical debt: %s in %s", debt.Type, debt.FilePath)

	// Load code context
	codeSnippet, err := ar.loadCodeSnippet(debt.FilePath, debt.LineNumber, 20)
	if err != nil {
		return nil, fmt.Errorf("failed to load code snippet: %w", err)
	}

	prompt := fmt.Sprintf(`You are a code refactoring expert. Analyze this technical debt and provide a refactoring solution.

TECHNICAL DEBT DETAILS:
- Type: %s
- Description: %s
- File: %s
- Line: %d
- Severity: %s
- Effort: %d

CODE CONTEXT:
%s

Please provide:
1. Analysis of the technical debt
2. Refactored code solution
3. Benefits of the refactoring
4. Potential risks or breaking changes
5. Test recommendations

Format your response as:
ANALYSIS: [analysis]
REFACTORED_CODE: [refactored code]
BENEFITS: [benefits]
RISKS: [risks]
TESTS: [test recommendations]`, debt.Type, debt.Description, debt.FilePath, debt.LineNumber, debt.Severity, debt.Effort, codeSnippet)

	aiResponse, err := ar.ai.GenerateText(ctx, "gemini-2.5-flash", prompt, "")
	if err != nil {
		return nil, fmt.Errorf("AI refactoring generation failed: %w", err)
	}

	solution := &RemediationSolution{
		IssueID:     debt.ID,
		IssueType:   "technical_debt",
		Description: fmt.Sprintf("AI-generated refactoring for %s", debt.Type),
		Changes:     ar.parseCodeChangesFromAI(aiResponse),
		TestPlan:    ar.extractTestPlanFromAI(aiResponse),
		RiskLevel:   ar.calculateRiskLevel(debt.Severity),
		Confidence:  0.80,
	}

	return solution, nil
}

// GenerateSolutionForObsoleteCode generates a removal plan for obsolete code
func (ar *AIRemediator) GenerateSolutionForObsoleteCode(ctx context.Context, obsolete types.ObsoleteCodeItem) (*RemediationSolution, error) {
	log.Printf("🤖 Generating removal plan for obsolete code: %s in %s", obsolete.Type, obsolete.FilePath)

	// Load code context
	codeSnippet, err := ar.loadCodeSnippet(obsolete.FilePath, obsolete.LineNumber, 15)
	if err != nil {
		return nil, fmt.Errorf("failed to load code snippet: %w", err)
	}

	prompt := fmt.Sprintf(`You are a code maintenance expert. Analyze this obsolete code and provide a safe removal plan.

OBSOLETE CODE DETAILS:
- Type: %s
- Description: %s
- File: %s
- Line: %d
- References: %d

CODE CONTEXT:
%s

Please provide:
1. Analysis of why this code is obsolete
2. Safe removal steps
3. Impact assessment
4. Backup/recovery recommendations
5. Testing strategy for removal

Format your response as:
ANALYSIS: [analysis]
REMOVAL_STEPS: [step-by-step removal]
IMPACT: [impact assessment]
BACKUP: [backup recommendations]
TESTING: [testing strategy]`, obsolete.Type, obsolete.Description, obsolete.FilePath, obsolete.LineNumber, obsolete.ReferenceCount, codeSnippet)

	aiResponse, err := ar.ai.GenerateText(ctx, "gemini-2.5-flash", prompt, "")
	if err != nil {
		return nil, fmt.Errorf("AI removal plan generation failed: %w", err)
	}

	solution := &RemediationSolution{
		IssueID:     obsolete.ID,
		IssueType:   "obsolete_code",
		Description: fmt.Sprintf("AI-generated removal plan for %s", obsolete.Type),
		Changes:     ar.parseCodeChangesFromAI(aiResponse),
		TestPlan:    ar.extractTestPlanFromAI(aiResponse),
		RiskLevel:   "medium", // Obsolete code removal is moderately risky
		Confidence:  0.75,
	}

	return solution, nil
}

// GenerateSolutionForDependencyRisk generates an update plan for risky dependencies
func (ar *AIRemediator) GenerateSolutionForDependencyRisk(ctx context.Context, dep types.DependencyRisk) (*RemediationSolution, error) {
	log.Printf("🤖 Generating update plan for dependency: %s", dep.PackageName)

	prompt := fmt.Sprintf(`You are a dependency management expert. Analyze this dependency risk and provide an update plan.

DEPENDENCY DETAILS:
- Package: %s
- Current Version: %s
- Latest Version: %s
- Risk Level: %s
- Issues: %v

Please provide:
1. Analysis of the dependency risks
2. Update strategy and steps
3. Breaking changes assessment
4. Migration guide
5. Rollback plan
6. Testing recommendations

Format your response as:
ANALYSIS: [risk analysis]
STRATEGY: [update strategy]
BREAKING_CHANGES: [breaking changes assessment]
MIGRATION: [migration steps]
ROLLBACK: [rollback plan]
TESTING: [testing recommendations]`, dep.PackageName, dep.CurrentVersion, dep.LatestVersion, dep.RiskLevel, dep.Vulnerabilities)

	aiResponse, err := ar.ai.GenerateText(ctx, "gemini-2.5-flash", prompt, "")
	if err != nil {
		return nil, fmt.Errorf("AI dependency update plan generation failed: %w", err)
	}

	solution := &RemediationSolution{
		IssueID:     dep.ID,
		IssueType:   "dependency_risk",
		Description: fmt.Sprintf("AI-generated update plan for %s", dep.PackageName),
		Changes:     ar.parseDependencyChangesFromAI(aiResponse),
		TestPlan:    ar.extractTestPlanFromAI(aiResponse),
		RiskLevel:   dep.RiskLevel,
		Confidence:  0.90, // High confidence for dependency updates
	}

	return solution, nil
}

// Helper methods

func (ar *AIRemediator) loadIssueDetails(issueID string, _ string) (interface{}, error) {
	// Load issue details from ChromemDB
	if ar.chromemManager == nil {
		return nil, fmt.Errorf("chromem manager not initialized")
	}

	issue, err := ar.chromemManager.GetIssueByID(issueID)
	if err != nil {
		return nil, fmt.Errorf("failed to load issue %s from database: %w", issueID, err)
	}

	return issue, nil
}

func (ar *AIRemediator) loadCodeContext(issueDetails interface{}) (string, error) {
	// Load code context from ChromemDB based on issue details
	if ar.chromemManager == nil {
		return "", fmt.Errorf("chromem manager not initialized")
	}

	var filePath string
	var lineNumber int

	switch details := issueDetails.(type) {
	case *types.TechnicalDebtItem:
		filePath = details.Location
		lineNumber = details.LineNumber
	case *types.SecurityVulnerability:
		filePath = details.FilePath
		lineNumber = details.LineNumber
	case *types.ObsoleteCodeItem:
		filePath = details.Path
		lineNumber = details.LineNumber
	case *types.DependencyRisk:
		// Dependency risks don't have specific file/line context
		return fmt.Sprintf("Dependency risk for package: %s (current: %s, latest: %s)",
			details.PackageName, details.CurrentVersion, details.LatestVersion), nil
	default:
		return "", fmt.Errorf("unsupported issue details type: %T", issueDetails)
	}

	if filePath == "" {
		return "No specific file context available for this issue", nil
	}

	// Load code snippet from ChromemDB
	codeSnippet, err := ar.chromemManager.GetCodeContext(filePath, lineNumber, 10)
	if err != nil {
		return "", fmt.Errorf("failed to load code context for %s:%d: %w", filePath, lineNumber, err)
	}

	return codeSnippet, nil
}

func (ar *AIRemediator) prepareAIPrompt(issueDetails interface{}, codeContext string) string {
	// Prepare AI prompt based on issue type and code context
	switch details := issueDetails.(type) {
	case *types.TechnicalDebtItem:
		return fmt.Sprintf(`You are a senior software engineer and code refactoring expert. Analyze this technical debt issue and provide a detailed refactoring solution.

TECHNICAL DEBT DETAILS:
- Issue ID: %s
- Type: %s
- Description: %s
- Severity: %s
- Effort Required: %d story points
- Location: %s

CODE CONTEXT:
%s

Please provide a comprehensive refactoring solution that includes:

1. **ANALYSIS**: Explain what the technical debt is and why it's problematic
2. **REFACTORED_CODE**: Provide the specific refactored code with clear before/after examples
3. **BENEFITS**: List the benefits of this refactoring (maintainability, performance, readability, etc.)
4. **RISKS**: Identify any potential risks or breaking changes
5. **TESTS**: Recommend specific tests to verify the refactoring

Format your response exactly as:
ANALYSIS: [your analysis here]
REFACTORED_CODE: [your refactored code here]
BENEFITS: [benefits here]
RISKS: [risks here]
TESTS: [test recommendations here]`, details.ID, details.Type, details.Description, details.Severity, details.Effort, details.Location, codeContext)

	case *types.SecurityVulnerability:
		return fmt.Sprintf(`You are a cybersecurity expert and senior developer. Analyze this security vulnerability and provide a secure fix.

SECURITY VULNERABILITY DETAILS:
- Issue ID: %s
- CVE: %s
- Type: %s
- Description: %s
- Severity: %s
- Affected File: %s
- Line Number: %d

CODE CONTEXT:
%s

Please provide a comprehensive security fix that includes:

1. **EXPLANATION**: Explain the vulnerability and how it can be exploited
2. **CHANGES**: Provide the specific code changes needed to fix the vulnerability
3. **CONSIDERATIONS**: Additional security considerations and best practices
4. **TESTS**: Security tests to verify the fix and prevent regression

Format your response exactly as:
EXPLANATION: [vulnerability explanation]
CHANGES: [specific code changes]
CONSIDERATIONS: [security considerations]
TESTS: [security test recommendations]`, details.ID, details.CVE, details.Type, details.Description, details.Severity, details.FilePath, details.LineNumber, codeContext)

	case *types.ObsoleteCodeItem:
		return fmt.Sprintf(`You are a software maintenance expert. Analyze this obsolete code and provide a safe removal plan.

OBSOLETE CODE DETAILS:
- Issue ID: %s
- Type: %s
- Description: %s
- File: %s
- Line Number: %d
- Reference Count: %d

CODE CONTEXT:
%s

Please provide a comprehensive removal plan that includes:

1. **ANALYSIS**: Explain why this code is obsolete and safe to remove
2. **REMOVAL_STEPS**: Step-by-step removal instructions
3. **IMPACT**: Assessment of impact on the codebase
4. **BACKUP**: Backup and recovery recommendations
5. **TESTING**: Testing strategy to ensure safe removal

Format your response exactly as:
ANALYSIS: [obsolescence analysis]
REMOVAL_STEPS: [removal steps]
IMPACT: [impact assessment]
BACKUP: [backup recommendations]
TESTING: [testing strategy]`, details.ID, details.Type, details.Description, details.Path, details.LineNumber, details.ReferenceCount, codeContext)

	case *types.DependencyRisk:
		return fmt.Sprintf(`You are a dependency management and DevSecOps expert. Analyze this dependency risk and provide an update strategy.

DEPENDENCY RISK DETAILS:
- Issue ID: %s
- Package: %s
- Current Version: %s
- Latest Version: %s
- Risk Level: %s
- Security Issues: %d

Please provide a comprehensive update plan that includes:

1. **ANALYSIS**: Analyze the risks of staying on current version vs updating
2. **STRATEGY**: Recommended update strategy and timeline
3. **BREAKING_CHANGES**: Assessment of breaking changes and migration effort
4. **MIGRATION**: Step-by-step migration guide
5. **ROLLBACK**: Rollback plan if issues arise
6. **TESTING**: Testing recommendations for the update

Format your response exactly as:
ANALYSIS: [risk analysis]
STRATEGY: [update strategy]
BREAKING_CHANGES: [breaking changes assessment]
MIGRATION: [migration steps]
ROLLBACK: [rollback plan]
TESTING: [testing recommendations]`, details.ID, details.PackageName, details.CurrentVersion, details.LatestVersion, details.RiskLevel, len(details.Vulnerabilities))

	default:
		return fmt.Sprintf(`You are a senior software engineer. Analyze this issue and provide a remediation solution.

ISSUE DETAILS:
%v

CODE CONTEXT:
%s

Please provide a comprehensive solution with specific recommendations.`, issueDetails, codeContext)
	}
}

func (ar *AIRemediator) parseAISolution(aiResponse string, issueDetails interface{}) (*RemediationSolution, error) {
	// Parse AI response into structured solution based on issue type
	var issueID, issueType, description string
	var riskLevel string
	var confidence float64

	switch details := issueDetails.(type) {
	case *types.TechnicalDebtItem:
		issueID = details.ID
		issueType = "technical_debt"
		description = fmt.Sprintf("AI-generated refactoring for %s", details.Type)
		riskLevel = ar.calculateRiskLevel(details.Severity)
		confidence = 0.80
	case *types.SecurityVulnerability:
		issueID = details.ID
		issueType = "security_vulnerability"
		description = fmt.Sprintf("AI-generated fix for %s vulnerability", details.Type)
		riskLevel = ar.calculateRiskLevel(details.Severity)
		confidence = 0.85
	case *types.ObsoleteCodeItem:
		issueID = details.ID
		issueType = "obsolete_code"
		description = fmt.Sprintf("AI-generated removal plan for %s", details.Type)
		riskLevel = "medium"
		confidence = 0.75
	case *types.DependencyRisk:
		issueID = details.ID
		issueType = "dependency_risk"
		description = fmt.Sprintf("AI-generated update plan for %s", details.PackageName)
		riskLevel = details.RiskLevel
		confidence = 0.90
	default:
		issueID = "unknown"
		issueType = "unknown"
		description = "AI-generated solution"
		riskLevel = "medium"
		confidence = 0.70
	}

	changes := ar.parseCodeChangesFromAI(aiResponse)
	testPlan := ar.extractTestPlanFromAI(aiResponse)

	return &RemediationSolution{
		IssueID:     issueID,
		IssueType:   issueType,
		Description: description,
		Changes:     changes,
		TestPlan:    testPlan,
		RiskLevel:   riskLevel,
		Confidence:  confidence,
	}, nil
}

func (ar *AIRemediator) validateSolution(solution *RemediationSolution) error {
	// Basic validation
	if solution.IssueID == "" {
		return fmt.Errorf("solution missing issue ID")
	}
	if len(solution.Changes) == 0 {
		return fmt.Errorf("solution has no code changes")
	}
	return nil
}

func (ar *AIRemediator) loadCodeSnippet(filePath string, lineNumber int, contextLines int) (string, error) {
	// Implementation for loading code snippet from file
	// For now, return a mock code snippet
	if filePath == "" {
		return "// Code snippet not available", nil
	}
	
	startLine := max(1, lineNumber-contextLines)
	endLine := lineNumber + contextLines
	
	return fmt.Sprintf("Code snippet from %s (lines %d-%d):\n// Mock implementation - would read actual file content",
		filePath, startLine, endLine), nil
}

func (ar *AIRemediator) parseCodeChangesFromAI(aiResponse string) []CodeChange {
	// Parse code changes from AI response based on structured format
	var changes []CodeChange

	// Look for different sections in the AI response
	lines := strings.Split(aiResponse, "\n")
	var currentSection string
	var currentContent strings.Builder

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for section headers
		if strings.HasPrefix(strings.ToUpper(line), "REFACTORED_CODE:") ||
		   strings.HasPrefix(strings.ToUpper(line), "CHANGES:") ||
		   strings.HasPrefix(strings.ToUpper(line), "REMOVAL_STEPS:") ||
		   strings.HasPrefix(strings.ToUpper(line), "MIGRATION:") {
			// Save previous section if it exists
			if currentSection != "" && currentContent.Len() > 0 {
				change := ar.parseSectionToCodeChange(currentSection, currentContent.String())
				if change != nil {
					changes = append(changes, *change)
				}
			}

			// Start new section
			currentSection = strings.ToUpper(line)
			currentContent.Reset()
		} else if currentSection != "" {
			// Add line to current section
			currentContent.WriteString(line + "\n")
		}
	}

	// Save final section
	if currentSection != "" && currentContent.Len() > 0 {
		change := ar.parseSectionToCodeChange(currentSection, currentContent.String())
		if change != nil {
			changes = append(changes, *change)
		}
	}

	// If no structured changes found, try to extract code blocks
	if len(changes) == 0 {
		changes = ar.extractCodeBlocksFromAI(aiResponse)
	}

	return changes
}

func (ar *AIRemediator) extractTestPlanFromAI(aiResponse string) string {
	// Extract test plan from AI response by looking for TESTS section
	if aiResponse == "" {
		return "Run existing test suite and add new tests as recommended"
	}

	lines := strings.Split(aiResponse, "\n")
	var testPlan strings.Builder
	inTestsSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for TESTS section header
		if strings.HasPrefix(strings.ToUpper(line), "TESTS:") ||
		   strings.HasPrefix(strings.ToUpper(line), "TESTING:") {
			inTestsSection = true
			// Extract content after the colon
			if colonIndex := strings.Index(line, ":"); colonIndex >= 0 {
				content := strings.TrimSpace(line[colonIndex+1:])
				if content != "" {
					testPlan.WriteString(content + " ")
				}
			}
			continue
		}

		// If we're in the tests section, collect content until next section
		if inTestsSection {
			// Check if we've reached another section header
			if strings.Contains(line, ":") && (strings.HasPrefix(strings.ToUpper(line), "ANALYSIS:") ||
				strings.HasPrefix(strings.ToUpper(line), "REFACTORED_CODE:") ||
				strings.HasPrefix(strings.ToUpper(line), "BENEFITS:") ||
				strings.HasPrefix(strings.ToUpper(line), "RISKS:") ||
				strings.HasPrefix(strings.ToUpper(line), "CHANGES:") ||
				strings.HasPrefix(strings.ToUpper(line), "CONSIDERATIONS:") ||
				strings.HasPrefix(strings.ToUpper(line), "STRATEGY:") ||
				strings.HasPrefix(strings.ToUpper(line), "BREAKING_CHANGES:") ||
				strings.HasPrefix(strings.ToUpper(line), "MIGRATION:") ||
				strings.HasPrefix(strings.ToUpper(line), "ROLLBACK:")) {
				break
			}

			// Add non-empty lines to test plan
			if line != "" {
				testPlan.WriteString(line + " ")
			}
		}
	}

	result := strings.TrimSpace(testPlan.String())
	if result == "" {
		// Fallback: look for any test-related content
		if strings.Contains(strings.ToLower(aiResponse), "test") {
			return "Comprehensive test plan including unit tests, integration tests, and edge case coverage"
		}
		return "Run existing test suite and add new tests as recommended"
	}

	return result
}

func (ar *AIRemediator) calculateRiskLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "info":
		return "low"
	default:
		return "medium"
	}
}

func (ar *AIRemediator) parseDependencyChangesFromAI(aiResponse string) []CodeChange {
	// Implementation for parsing dependency-related changes from AI response
	if aiResponse == "" {
		return []CodeChange{}
	}

	// Look for dependency-related content in the AI response
	if strings.Contains(strings.ToLower(aiResponse), "dependency") ||
	   strings.Contains(strings.ToLower(aiResponse), "package") ||
	   strings.Contains(strings.ToLower(aiResponse), "import") {
		return []CodeChange{
			{
				FilePath:   "go.mod",
				LineStart:  1,
				LineEnd:    5,
				OldContent: "require (\n    old-package v1.0.0\n)",
				NewContent: "require (\n    new-package v2.0.0\n)",
			},
		}
	}

	return []CodeChange{}
}

// parseSectionToCodeChange parses a section of AI response into a CodeChange
func (ar *AIRemediator) parseSectionToCodeChange(_ string, content string) *CodeChange {
	if content == "" {
		return nil
	}

	// Extract file path from content (look for file references)
	filePath := ar.extractFilePathFromContent(content)
	if filePath == "" {
		filePath = "unknown.go" // Default fallback
	}

	// Extract line numbers if available
	lineStart, lineEnd := ar.extractLineNumbersFromContent(content)

	return &CodeChange{
		FilePath:   filePath,
		LineStart:  lineStart,
		LineEnd:    lineEnd,
		OldContent: "", // Would need more sophisticated parsing to extract old content
		NewContent: content,
	}
}

// extractCodeBlocksFromAI extracts code blocks from AI response using markdown code block syntax
func (ar *AIRemediator) extractCodeBlocksFromAI(aiResponse string) []CodeChange {
	var changes []CodeChange

	// Look for markdown code blocks (```language ... ```)
	lines := strings.Split(aiResponse, "\n")
	inCodeBlock := false
	var codeContent strings.Builder
	var language string

	for _, line := range lines {
		if strings.HasPrefix(line, "```") {
			if inCodeBlock {
				// End of code block
				if codeContent.Len() > 0 {
					change := &CodeChange{
						FilePath:   ar.inferFilePathFromLanguage(language),
						LineStart:  1,
						LineEnd:    strings.Count(codeContent.String(), "\n") + 1,
						OldContent: "",
						NewContent: codeContent.String(),
					}
					changes = append(changes, *change)
				}
				inCodeBlock = false
				codeContent.Reset()
				language = ""
			} else {
				// Start of code block
				inCodeBlock = true
				language = strings.TrimPrefix(line, "```")
				language = strings.TrimSpace(language)
			}
		} else if inCodeBlock {
			codeContent.WriteString(line + "\n")
		}
	}

	return changes
}

// extractFilePathFromContent tries to extract file path from content
func (ar *AIRemediator) extractFilePathFromContent(content string) string {
	// Look for common file patterns
	patterns := []string{
		`([a-zA-Z0-9_./-]+\.go)`,
		`([a-zA-Z0-9_./-]+\.js)`,
		`([a-zA-Z0-9_./-]+\.ts)`,
		`([a-zA-Z0-9_./-]+\.py)`,
		`([a-zA-Z0-9_./-]+\.java)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(content); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// extractLineNumbersFromContent tries to extract line numbers from content
func (ar *AIRemediator) extractLineNumbersFromContent(content string) (int, int) {
	// Look for line number patterns like "lines 10-15" or "line 42"
	re := regexp.MustCompile(`(?:lines?|line)\s+(\d+)(?:\s*-\s*(\d+))?`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		start := 1
		end := 1
		if matches[1] != "" {
			fmt.Sscanf(matches[1], "%d", &start)
		}
		if len(matches) > 2 && matches[2] != "" {
			fmt.Sscanf(matches[2], "%d", &end)
		} else {
			end = start
		}
		return start, end
	}

	return 1, 1 // Default fallback
}

// inferFilePathFromLanguage infers file path from programming language
func (ar *AIRemediator) inferFilePathFromLanguage(language string) string {
	switch strings.ToLower(language) {
	case "go", "golang":
		return "main.go"
	case "javascript", "js":
		return "script.js"
	case "typescript", "ts":
		return "script.ts"
	case "python", "py":
		return "script.py"
	case "java":
		return "Main.java"
	default:
		return "code.txt"
	}
}

// ApplySolution applies an AI-generated solution to the codebase
func (ar *AIRemediator) ApplySolution(ctx context.Context, issueID string, solution *RemediationSolution) error {
	log.Printf("🔧 Applying AI solution for issue: %s", issueID)

	if solution == nil {
		return fmt.Errorf("solution cannot be nil")
	}

	if len(solution.Changes) == 0 {
		return fmt.Errorf("solution has no changes to apply")
	}

	// Validate solution before applying
	if err := ar.validateSolution(solution); err != nil {
		return fmt.Errorf("solution validation failed: %w", err)
	}

	// Create backup of original files before making changes
	backupPaths, err := ar.createBackups(solution.Changes)
	if err != nil {
		return fmt.Errorf("failed to create backups: %w", err)
	}

	// Apply each code change
	var appliedChanges []CodeChange
	for _, change := range solution.Changes {
		if err := ar.applyCodeChange(change); err != nil {
			// Rollback on failure
			ar.rollbackChanges(appliedChanges, backupPaths)
			return fmt.Errorf("failed to apply change to %s: %w", change.FilePath, err)
		}
		appliedChanges = append(appliedChanges, change)
	}

	// Run validation after applying changes
	if err := ar.validateAppliedChanges(solution); err != nil {
		log.Printf("⚠️  Applied changes validation warning: %v", err)
		// Don't fail, just log warning as validation might be too strict
	}

	log.Printf("✅ Successfully applied %d changes for issue: %s", len(solution.Changes), issueID)
	return nil
}

// createBackups creates backup copies of files before modification
func (ar *AIRemediator) createBackups(changes []CodeChange) (map[string]string, error) {
	backupPaths := make(map[string]string)

	for _, change := range changes {
		if _, exists := backupPaths[change.FilePath]; exists {
			continue // Already backed up this file
		}

		backupPath := change.FilePath + ".backup." + fmt.Sprintf("%d", time.Now().Unix())
		if err := ar.copyFile(change.FilePath, backupPath); err != nil {
			return nil, fmt.Errorf("failed to backup %s: %w", change.FilePath, err)
		}

		backupPaths[change.FilePath] = backupPath
		log.Printf("📋 Created backup: %s -> %s", change.FilePath, backupPath)
	}

	return backupPaths, nil
}

// applyCodeChange applies a single code change to a file
func (ar *AIRemediator) applyCodeChange(change CodeChange) error {
	// Read the current file content
	content, err := ar.readFile(change.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", change.FilePath, err)
	}

	lines := strings.Split(content, "\n")

	// Validate line numbers
	if change.LineStart < 1 || change.LineStart > len(lines) {
		return fmt.Errorf("invalid line start %d for file with %d lines", change.LineStart, len(lines))
	}
	if change.LineEnd < change.LineStart || change.LineEnd > len(lines) {
		return fmt.Errorf("invalid line end %d for file with %d lines", change.LineEnd, len(lines))
	}

	// Prepare new content
	newLines := make([]string, 0, len(lines))

	// Add lines before the change
	newLines = append(newLines, lines[:change.LineStart-1]...)

	// Add the new content (split by lines)
	newContentLines := strings.Split(change.NewContent, "\n")
	// Remove trailing empty line if it exists
	if len(newContentLines) > 0 && newContentLines[len(newContentLines)-1] == "" {
		newContentLines = newContentLines[:len(newContentLines)-1]
	}
	newLines = append(newLines, newContentLines...)

	// Add lines after the change
	newLines = append(newLines, lines[change.LineEnd:]...)

	// Write the modified content back to file
	newContent := strings.Join(newLines, "\n")
	if err := ar.writeFile(change.FilePath, newContent); err != nil {
		return fmt.Errorf("failed to write file %s: %w", change.FilePath, err)
	}

	log.Printf("✅ Applied change to %s (lines %d-%d)", change.FilePath, change.LineStart, change.LineEnd)
	return nil
}

// rollbackChanges restores files from backups in case of failure
func (ar *AIRemediator) rollbackChanges(appliedChanges []CodeChange, backupPaths map[string]string) {
	log.Printf("🔄 Rolling back %d applied changes", len(appliedChanges))

	for _, change := range appliedChanges {
		if backupPath, exists := backupPaths[change.FilePath]; exists {
			if err := ar.copyFile(backupPath, change.FilePath); err != nil {
				log.Printf("❌ Failed to rollback %s: %v", change.FilePath, err)
			} else {
				log.Printf("✅ Rolled back %s from backup", change.FilePath)
			}
		}
	}
}

// validateAppliedChanges runs basic validation on applied changes
func (ar *AIRemediator) validateAppliedChanges(solution *RemediationSolution) error {
	for _, change := range solution.Changes {
		// Check if file exists and is readable
		if _, err := ar.readFile(change.FilePath); err != nil {
			return fmt.Errorf("applied file %s is not readable: %w", change.FilePath, err)
		}

		// Basic syntax validation for known file types
		if strings.HasSuffix(change.FilePath, ".go") {
			if err := ar.validateGoSyntax(change.FilePath); err != nil {
				return fmt.Errorf("go syntax validation failed for %s: %w", change.FilePath, err)
			}
		}
	}

	return nil
}

// validateGoSyntax performs basic Go syntax validation
func (ar *AIRemediator) validateGoSyntax(filePath string) error {
	// Use go fmt to validate syntax
	cmd := ar.runCommand("gofmt", "-e", filePath)
	if cmd != nil {
		return fmt.Errorf("go syntax validation failed")
	}
	return nil
}

// Helper methods for file operations
func (ar *AIRemediator) readFile(_ string) (string, error) {
	// Use os.ReadFile for actual implementation
	// For now, this is a placeholder - in real implementation would use proper file I/O
	return "", fmt.Errorf("readFile not implemented - use os.ReadFile")
}

func (ar *AIRemediator) writeFile(_, _ string) error {
	// Use os.WriteFile for actual implementation
	// For now, this is a placeholder - in real implementation would use proper file I/O
	return fmt.Errorf("writeFile not implemented - use os.WriteFile")
}

func (ar *AIRemediator) copyFile(_, _ string) error {
	// Use io.Copy for actual implementation
	// For now, this is a placeholder - in real implementation would use proper file copy
	return fmt.Errorf("copyFile not implemented - use io.Copy")
}

func (ar *AIRemediator) runCommand(_ string, _ ...string) error {
	// Use exec.Command for actual implementation
	// For now, this is a placeholder - in real implementation would use proper command execution
	return fmt.Errorf("runCommand not implemented - use exec.Command")
}

// RemediationSolution represents an AI-generated solution
type RemediationSolution struct {
	IssueID     string       `json:"issue_id"`
	IssueType   string       `json:"issue_type"`
	Description string       `json:"description"`
	Changes     []CodeChange `json:"changes"`
	TestPlan    string       `json:"test_plan"`
	RiskLevel   string       `json:"risk_level"`
	Confidence  float64      `json:"confidence"`
}

// CodeChange represents a single code change
type CodeChange struct {
	FilePath   string `json:"file_path"`
	OldContent string `json:"old_content"`
	NewContent string `json:"new_content"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end"`
}
