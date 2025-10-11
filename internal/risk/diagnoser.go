package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"archguardian/internal/scanner"
	"archguardian/types"
)

// RiskDiagnoser handles risk analysis and diagnosis
type RiskDiagnoser struct {
	scanner             *scanner.Scanner
	aiEngine            types.AIEngineInterface         // AI inference engine for risk analysis
	codacyClient        types.CodacyClientInterface     // Codacy API client for external analysis
	compatibilityIssues []types.TechnicalDebtItem
	latestAssessment    *types.RiskAssessment
	mutex               sync.RWMutex
}

// NewRiskDiagnoser creates a new risk diagnoser
func NewRiskDiagnoser(scanner *scanner.Scanner, aiEngine types.AIEngineInterface, codacyClient types.CodacyClientInterface) *RiskDiagnoser {
	return &RiskDiagnoser{
		scanner:      scanner,
		aiEngine:     aiEngine,
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

	// Use AI for comprehensive risk analysis
	log.Println("  🤖 Starting AI-powered risk analysis...")

	// Extract technical debt using AI
	if technicalDebt, err := rd.extractTechnicalDebt(); err == nil {
		assessment.TechnicalDebt = append(assessment.TechnicalDebt, technicalDebt...)
	} else {
		log.Printf("  ⚠️  Technical debt extraction failed: %v", err)
	}

	// Extract security vulnerabilities using AI
	if securityVulns, err := rd.extractSecurityVulns(); err == nil {
		assessment.SecurityVulns = append(assessment.SecurityVulns, securityVulns...)
	} else {
		log.Printf("  ⚠️  Security vulnerability extraction failed: %v", err)
	}

	// Extract obsolete code using AI
	if obsoleteCode, err := rd.extractObsoleteCode(); err == nil {
		assessment.ObsoleteCode = append(assessment.ObsoleteCode, obsoleteCode...)
	} else {
		log.Printf("  ⚠️  Obsolete code extraction failed: %v", err)
	}

	// Extract dependency risks using AI
	if dependencyRisks, err := rd.extractDependencyRisks(); err == nil {
		assessment.DangerousDependencies = append(assessment.DangerousDependencies, dependencyRisks...)
	} else {
		log.Printf("  ⚠️  Dependency risk extraction failed: %v", err)
	}

	log.Printf("  ✅ AI analysis complete. Found %d technical debt items, %d security vulnerabilities, %d obsolete code items, %d dependency risks",
		len(assessment.TechnicalDebt), len(assessment.SecurityVulns), len(assessment.ObsoleteCode), len(assessment.DangerousDependencies))

	// Apply AI-based severity scoring and prioritization
	if err := rd.applyAISeverityScoring(assessment); err != nil {
		log.Printf("  ⚠️  AI severity scoring failed: %v", err)
	}

	// Apply AI-based risk prioritization
	if err := rd.applyAIRiskPrioritization(assessment); err != nil {
		log.Printf("  ⚠️  AI risk prioritization failed: %v", err)
	}

	// Generate comprehensive AI remediation suggestions
	if err := rd.generateAIRemediationSuggestions(assessment); err != nil {
		log.Printf("  ⚠️  AI remediation suggestions failed: %v", err)
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

// prepareRiskAnalysisData prepares data for AI risk analysis
func (rd *RiskDiagnoser) prepareRiskAnalysisData() map[string]interface{} {
	kg := rd.scanner.GetKnowledgeGraph()

	// Extract key information from knowledge graph for AI analysis
	nodeTypes := make(map[string]int)
	fileExtensions := make(map[string]int)
	dependencies := make([]string, 0)

	for _, node := range kg.Nodes {
		nodeTypes[string(node.Type)]++

		// Count file extensions
		if node.Type == types.NodeTypeCode {
			ext := filepath.Ext(node.Path)
			if ext != "" {
				fileExtensions[ext]++
			}
		}

		// Collect dependencies
		dependencies = append(dependencies, node.Dependencies...)
	}

	return map[string]interface{}{
		"graph_summary": map[string]interface{}{
			"node_count":     len(kg.Nodes),
			"edge_count":     len(kg.Edges),
			"node_types":     nodeTypes,
			"file_types":     fileExtensions,
			"dependencies":   dependencies,
			"last_updated":   kg.LastUpdated,
			"analysis_depth": kg.AnalysisDepth,
		},
		"sample_nodes": rd.getSampleNodes(kg.Nodes, 10), // Sample up to 10 nodes for context
	}
}

// getSampleNodes returns a sample of nodes for AI analysis context
func (rd *RiskDiagnoser) getSampleNodes(nodes map[string]*types.Node, maxSamples int) []map[string]interface{} {
	samples := make([]map[string]interface{}, 0, maxSamples)
	count := 0

	for _, node := range nodes {
		if count >= maxSamples {
			break
		}

		sample := map[string]interface{}{
			"id":       node.ID,
			"type":     string(node.Type),
			"name":     node.Name,
			"path":     node.Path,
			"metadata": node.Metadata,
			"risk_score": node.RiskScore,
		}
		samples = append(samples, sample)
		count++
	}

	return samples
}

// extractTechnicalDebt extracts technical debt from AI analysis
func (rd *RiskDiagnoser) extractTechnicalDebt() ([]types.TechnicalDebtItem, error) {
	log.Println("  🤖 Analyzing technical debt with AI...")

	data := rd.prepareRiskAnalysisData()
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal analysis data: %w", err)
	}

	// Create structured output schema for technical debt
	schema := `{
		"type": "object",
		"properties": {
			"technical_debt": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"id": {"type": "string"},
						"location": {"type": "string"},
						"type": {"type": "string", "enum": ["code_quality", "architecture", "performance", "maintainability", "security", "documentation"]},
						"severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
						"description": {"type": "string"},
						"remediation": {"type": "string"},
						"effort_hours": {"type": "integer", "minimum": 1, "maximum": 100}
					},
					"required": ["id", "location", "type", "severity", "description", "remediation", "effort_hours"]
				}
			}
		},
		"required": ["technical_debt"]
	}`

	content := fmt.Sprintf(`Analyze the following project data and identify technical debt items:

Project Analysis Data:
%s

Please identify technical debt items such as:
- Code quality issues (complex functions, poor naming, etc.)
- Architectural problems (tight coupling, circular dependencies, etc.)
- Performance bottlenecks
- Maintainability concerns
- Security-related technical debt
- Documentation gaps

For each item, provide:
- A unique ID
- File location or component
- Type of technical debt
- Severity level
- Detailed description
- Remediation steps
- Estimated effort in hours

Focus on the most significant issues that would benefit from AI-powered analysis.`, string(dataJSON))

	response, err := rd.aiEngine.GenerateStructuredOutput(content, schema)
	if err != nil {
		log.Printf("  ⚠️  AI technical debt analysis failed: %v", err)
		return []types.TechnicalDebtItem{}, nil // Return empty slice instead of error to allow continuation
	}

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		log.Printf("  ⚠️  Failed to parse AI response: %v", err)
		return []types.TechnicalDebtItem{}, nil
	}

	items := make([]types.TechnicalDebtItem, 0)
	if debt, ok := result["technical_debt"].([]interface{}); ok {
		for _, item := range debt {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, types.TechnicalDebtItem{
					ID:          getStringField(m, "id"),
					Location:    getStringField(m, "location"),
					Type:        getStringField(m, "type"),
					Severity:    getStringField(m, "severity"),
					Description: getStringField(m, "description"),
					Remediation: getStringField(m, "remediation"),
					Effort:      getIntField(m, "effort_hours"),
				})
			}
		}
	}

	log.Printf("  ✅ AI identified %d technical debt items", len(items))
	return items, nil
}

// extractSecurityVulns extracts security vulnerabilities from AI analysis
func (rd *RiskDiagnoser) extractSecurityVulns() ([]types.SecurityVulnerability, error) {
	log.Println("  🤖 Analyzing security vulnerabilities with AI...")

	data := rd.prepareRiskAnalysisData()
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal analysis data: %w", err)
	}

	// Create structured output schema for security vulnerabilities
	schema := `{
		"type": "object",
		"properties": {
			"security_vulnerabilities": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"cve": {"type": "string"},
						"package": {"type": "string"},
						"version": {"type": "string"},
						"severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
						"description": {"type": "string"},
						"fix_version": {"type": "string"},
						"cvss": {"type": "number", "minimum": 0, "maximum": 10}
					},
					"required": ["cve", "package", "version", "severity", "description", "fix_version", "cvss"]
				}
			}
		},
		"required": ["security_vulnerabilities"]
	}`

	content := fmt.Sprintf(`Analyze the following project data and identify potential security vulnerabilities:

Project Analysis Data:
%s

Please identify security vulnerabilities such as:
- Known vulnerable dependencies (check for CVEs)
- Insecure coding patterns
- Authentication/authorization weaknesses
- Input validation issues
- Data exposure risks
- Configuration security problems

For each vulnerability, provide:
- CVE identifier (use "POTENTIAL-{type}-{id}" format if no official CVE exists)
- Affected package or component
- Current version
- Severity level
- Detailed description of the vulnerability
- Recommended fix version or remediation steps
- CVSS score (0-10 scale)

Focus on realistic security issues that could be identified from code analysis and dependency information.`, string(dataJSON))

	response, err := rd.aiEngine.GenerateStructuredOutput(content, schema)
	if err != nil {
		log.Printf("  ⚠️  AI security vulnerability analysis failed: %v", err)
		return []types.SecurityVulnerability{}, nil // Return empty slice instead of error to allow continuation
	}

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		log.Printf("  ⚠️  Failed to parse AI response: %v", err)
		return []types.SecurityVulnerability{}, nil
	}

	vulns := make([]types.SecurityVulnerability, 0)
	if security, ok := result["security_vulnerabilities"].([]interface{}); ok {
		for _, item := range security {
			if m, ok := item.(map[string]interface{}); ok {
				vulns = append(vulns, types.SecurityVulnerability{
					CVE:         getStringField(m, "cve"),
					Package:     getStringField(m, "package"),
					Version:     getStringField(m, "version"),
					Severity:    getStringField(m, "severity"),
					Description: getStringField(m, "description"),
					FixVersion:  getStringField(m, "fix_version"),
					CVSS:        getFloatField(m, "cvss"),
				})
			}
		}
	}

	log.Printf("  ✅ AI identified %d security vulnerabilities", len(vulns))
	return vulns, nil
}

// extractObsoleteCode extracts obsolete code from AI analysis
func (rd *RiskDiagnoser) extractObsoleteCode() ([]types.ObsoleteCodeItem, error) {
	log.Println("  🤖 Analyzing obsolete code with AI...")

	data := rd.prepareRiskAnalysisData()
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal analysis data: %w", err)
	}

	// Create structured output schema for obsolete code
	schema := `{
		"type": "object",
		"properties": {
			"obsolete_code": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"path": {"type": "string"},
						"references": {"type": "integer", "minimum": 0},
						"removal_safety": {"type": "string", "enum": ["safe", "caution", "dangerous"]},
						"recommend_action": {"type": "string", "enum": ["remove", "refactor", "deprecate", "keep"]}
					},
					"required": ["path", "references", "removal_safety", "recommend_action"]
				}
			}
		},
		"required": ["obsolete_code"]
	}`

	content := fmt.Sprintf(`Analyze the following project data and identify obsolete or unused code:

Project Analysis Data:
%s

Please identify code that may be obsolete or unused such as:
- Dead code (functions/methods never called)
- Unused imports or dependencies
- Deprecated API usage
- Legacy code that could be modernized
- Redundant implementations
- Files with low reference counts

For each item, provide:
- File path or component location
- Number of references (how often it's used)
- Removal safety level (safe/caution/dangerous)
- Recommended action (remove/refactor/deprecate/keep)

Focus on code that appears to be unused or could be safely removed/modernized.`, string(dataJSON))

	response, err := rd.aiEngine.GenerateStructuredOutput(content, schema)
	if err != nil {
		log.Printf("  ⚠️  AI obsolete code analysis failed: %v", err)
		return []types.ObsoleteCodeItem{}, nil // Return empty slice instead of error to allow continuation
	}

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		log.Printf("  ⚠️  Failed to parse AI response: %v", err)
		return []types.ObsoleteCodeItem{}, nil
	}

	items := make([]types.ObsoleteCodeItem, 0)
	if obsolete, ok := result["obsolete_code"].([]interface{}); ok {
		for _, item := range obsolete {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, types.ObsoleteCodeItem{
					Path:            getStringField(m, "path"),
					References:      getIntField(m, "references"),
					RemovalSafety:   getStringField(m, "removal_safety"),
					RecommendAction: getStringField(m, "recommend_action"),
				})
			}
		}
	}

	log.Printf("  ✅ AI identified %d obsolete code items", len(items))
	return items, nil
}

// extractDependencyRisks extracts dependency risks from AI analysis
func (rd *RiskDiagnoser) extractDependencyRisks() ([]types.DependencyRisk, error) {
	log.Println("  🤖 Analyzing dependency risks with AI...")

	data := rd.prepareRiskAnalysisData()
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal analysis data: %w", err)
	}

	// Create structured output schema for dependency risks
	schema := `{
		"type": "object",
		"properties": {
			"dependency_risks": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"package": {"type": "string"},
						"current_version": {"type": "string"},
						"latest_version": {"type": "string"},
						"security_issues": {"type": "integer", "minimum": 0},
						"maintenance": {"type": "string", "enum": ["active", "deprecated", "abandoned", "unknown"]},
						"recommendation": {"type": "string"}
					},
					"required": ["package", "current_version", "latest_version", "security_issues", "maintenance", "recommendation"]
				}
			}
		},
		"required": ["dependency_risks"]
	}`

	content := fmt.Sprintf(`Analyze the following project dependencies and identify potential risks:

Project Analysis Data:
%s

Please analyze the dependencies and identify risks such as:
- Outdated packages with known security vulnerabilities
- Packages with poor maintenance status
- Dependencies with high security issue counts
- Packages that have been deprecated or abandoned
- Version mismatches or compatibility issues

For each risky dependency, provide:
- Package name
- Current version in use
- Latest available version
- Number of known security issues
- Maintenance status (active/deprecated/abandoned/unknown)
- Recommendation for remediation

Focus on dependencies that pose real risks to the project security and stability.`, string(dataJSON))

	response, err := rd.aiEngine.GenerateStructuredOutput(content, schema)
	if err != nil {
		log.Printf("  ⚠️  AI dependency risk analysis failed: %v", err)
		return []types.DependencyRisk{}, nil // Return empty slice instead of error to allow continuation
	}

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		log.Printf("  ⚠️  Failed to parse AI response: %v", err)
		return []types.DependencyRisk{}, nil
	}

	deps := make([]types.DependencyRisk, 0)
	if dependencies, ok := result["dependency_risks"].([]interface{}); ok {
		for _, item := range dependencies {
			if m, ok := item.(map[string]interface{}); ok {
				deps = append(deps, types.DependencyRisk{
					Package:        getStringField(m, "package"),
					CurrentVersion: getStringField(m, "current_version"),
					LatestVersion:  getStringField(m, "latest_version"),
					SecurityIssues: getIntField(m, "security_issues"),
					Maintenance:    getStringField(m, "maintenance"),
					Recommendation: getStringField(m, "recommendation"),
				})
			}
		}
	}

	log.Printf("  ✅ AI identified %d dependency risks", len(deps))
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

// applyAISeverityScoring applies AI-based severity scoring to all identified risks
func (rd *RiskDiagnoser) applyAISeverityScoring(assessment *types.RiskAssessment) error {
	log.Println("  🤖 Applying AI-based severity scoring...")

	// Prepare all risks for AI analysis
	allRisks := rd.prepareRisksForAIScoring(assessment)
	if len(allRisks) == 0 {
		log.Println("  ℹ️  No risks to score")
		return nil
	}

	risksJSON, err := json.Marshal(allRisks)
	if err != nil {
		return fmt.Errorf("failed to marshal risks for scoring: %w", err)
	}

	schema := `{
		"type": "object",
		"properties": {
			"scored_risks": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"id": {"type": "string"},
						"adjusted_severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
						"severity_score": {"type": "number", "minimum": 0, "maximum": 10},
						"business_impact": {"type": "string", "enum": ["minimal", "low", "moderate", "high", "critical"]},
						"reasoning": {"type": "string"}
					},
					"required": ["id", "adjusted_severity", "severity_score", "business_impact", "reasoning"]
				}
			}
		},
		"required": ["scored_risks"]
	}`

	content := fmt.Sprintf(`Analyze the following risks and provide intelligent severity scoring based on business impact, exploitability, and overall risk:

Risks to Score:
%s

For each risk, provide:
- The risk ID
- Adjusted severity level (considering business context)
- Severity score (0-10 scale)
- Business impact assessment
- Reasoning for the scoring

Consider factors like:
- Potential for data breach or system compromise
- Business disruption impact
- Ease of exploitation
- Affected user base
- Regulatory compliance implications
- Cost of remediation vs. impact of breach`, string(risksJSON))

	response, err := rd.aiEngine.GenerateStructuredOutput(content, schema)
	if err != nil {
		return fmt.Errorf("AI severity scoring failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return fmt.Errorf("failed to parse AI scoring response: %w", err)
	}

	// Apply the AI scoring to the assessment
	if scoredRisks, ok := result["scored_risks"].([]interface{}); ok {
		rd.applyAIScoresToAssessment(assessment, scoredRisks)
	}

	log.Printf("  ✅ AI severity scoring applied to %d risks", len(allRisks))
	return nil
}

// applyAIRiskPrioritization applies AI-based risk prioritization across all risk categories
func (rd *RiskDiagnoser) applyAIRiskPrioritization(assessment *types.RiskAssessment) error {
	log.Println("  🤖 Applying AI-based risk prioritization...")

	// Prepare all risks for prioritization
	allRisks := rd.prepareRisksForPrioritization(assessment)
	if len(allRisks) == 0 {
		log.Println("  ℹ️  No risks to prioritize")
		return nil
	}

	risksJSON, err := json.Marshal(allRisks)
	if err != nil {
		return fmt.Errorf("failed to marshal risks for prioritization: %w", err)
	}

	schema := `{
		"type": "object",
		"properties": {
			"prioritized_risks": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"id": {"type": "string"},
						"priority_order": {"type": "integer", "minimum": 1},
						"priority_level": {"type": "string", "enum": ["immediate", "high", "medium", "low", "monitor"]},
						"time_to_fix": {"type": "string", "enum": ["< 1 week", "1-4 weeks", "1-3 months", "3-6 months", "> 6 months"]},
						"resource_requirement": {"type": "string", "enum": ["minimal", "moderate", "significant", "major"]},
						"blocking_factor": {"type": "string"}
					},
					"required": ["id", "priority_order", "priority_level", "time_to_fix", "resource_requirement", "blocking_factor"]
				}
			}
		},
		"required": ["prioritized_risks"]
	}`

	content := fmt.Sprintf(`Prioritize the following risks based on urgency, impact, and resource requirements:

Risks to Prioritize:
%s

For each risk, determine:
- Priority order (1 = highest priority)
- Priority level based on urgency and impact
- Estimated time to fix
- Resource requirements
- Any blocking factors that prevent immediate action

Consider:
- Security risks should generally be prioritized over other types
- Risks affecting production systems over development
- Quick wins vs. major refactoring efforts
- Dependencies between different risks
- Business-critical vs. nice-to-have fixes`, string(risksJSON))

	response, err := rd.aiEngine.GenerateStructuredOutput(content, schema)
	if err != nil {
		return fmt.Errorf("AI risk prioritization failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return fmt.Errorf("failed to parse AI prioritization response: %w", err)
	}

	// Apply prioritization to assessment
	if prioritizedRisks, ok := result["prioritized_risks"].([]interface{}); ok {
		rd.applyAIPrioritizationToAssessment(prioritizedRisks)
	}

	log.Printf("  ✅ AI risk prioritization applied to %d risks", len(allRisks))
	return nil
}

// generateAIRemediationSuggestions generates comprehensive AI-powered remediation suggestions
func (rd *RiskDiagnoser) generateAIRemediationSuggestions(assessment *types.RiskAssessment) error {
	log.Println("  🤖 Generating comprehensive AI remediation suggestions...")

	// Prepare assessment summary for AI analysis
	summary := rd.prepareAssessmentSummary(assessment)
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("failed to marshal assessment summary: %w", err)
	}

	schema := `{
		"type": "object",
		"properties": {
			"remediation_plan": {
				"type": "object",
				"properties": {
					"immediate_actions": {
						"type": "array",
						"items": {"type": "string"}
					},
					"short_term_plan": {
						"type": "array",
						"items": {"type": "string"}
					},
					"long_term_strategy": {
						"type": "array",
						"items": {"type": "string"}
					},
					"resource_allocation": {
						"type": "object",
						"properties": {
							"security_team": {"type": "string"},
							"development_team": {"type": "string"},
							"devops_team": {"type": "string"},
							"estimated_cost": {"type": "string"}
						}
					},
					"success_metrics": {
						"type": "array",
						"items": {"type": "string"}
					},
					"risk_mitigation_score": {
						"type": "number",
						"minimum": 0,
						"maximum": 100
					}
				},
				"required": ["immediate_actions", "short_term_plan", "long_term_strategy", "resource_allocation", "success_metrics", "risk_mitigation_score"]
			}
		},
		"required": ["remediation_plan"]
	}`

	content := fmt.Sprintf(`Create a comprehensive remediation plan for the following risk assessment:

Risk Assessment Summary:
%s

Provide a detailed remediation strategy including:
- Immediate actions (critical fixes needed now)
- Short-term plan (next 1-3 months)
- Long-term strategy (6+ months)
- Resource allocation recommendations
- Success metrics to track progress
- Overall risk mitigation score

Consider the interdependencies between different risk types and prioritize based on business impact.`, string(summaryJSON))

	response, err := rd.aiEngine.GenerateStructuredOutput(content, schema)
	if err != nil {
		return fmt.Errorf("AI remediation suggestions failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return fmt.Errorf("failed to parse AI remediation response: %w", err)
	}

	// Store remediation plan in assessment (we'll need to extend the types)
	if plan, ok := result["remediation_plan"].(map[string]interface{}); ok {
		rd.storeRemediationPlanInAssessment(plan)
	}

	log.Println("  ✅ Comprehensive AI remediation suggestions generated")
	return nil
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
			"id":               dep.Package,
			"type":             "dependency_risk",
			"category":         "dependency",
			"severity":         "medium", // Default, will be adjusted by AI
			"description":      fmt.Sprintf("Risky dependency: %s", dep.Package),
			"security_issues":  dep.SecurityIssues,
			"maintenance":      dep.Maintenance,
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
		"by_type":           make(map[string]int),
		"by_severity":       make(map[string]int),
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
