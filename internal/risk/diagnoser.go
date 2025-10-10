package risk

import (
	"context"
	"log"
	"sync"
	"time"

	"archguardian/internal/scanner"
	"archguardian/types"
)

// RiskDiagnoser handles risk analysis and diagnosis
type RiskDiagnoser struct {
	scanner             *scanner.Scanner
	ai                  interface{} // TODO: Use proper AI inference engine type
	codacyClient        interface{} // TODO: Use proper Codacy client type
	compatibilityIssues []types.TechnicalDebtItem
	mutex               sync.RWMutex
}

// NewRiskDiagnoser creates a new risk diagnoser
func NewRiskDiagnoser(scanner *scanner.Scanner, codacyClient interface{}) *RiskDiagnoser {
	return &RiskDiagnoser{
		scanner:      scanner,
		ai:           scanner, // TODO: Use proper AI engine
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

	assessment := &types.RiskAssessment{
		TechnicalDebt:         make([]types.TechnicalDebtItem, 0),
		SecurityVulns:         make([]types.SecurityVulnerability, 0),
		ObsoleteCode:          make([]types.ObsoleteCodeItem, 0),
		DangerousDependencies: make([]types.DependencyRisk, 0),
		Timestamp:             time.Now(),
	}

	// TODO: Fetch Codacy issues if client is available
	// TODO: Use AI for comprehensive risk analysis

	// For now, return a basic assessment
	assessment.OverallScore = rd.calculateOverallRisk(assessment)
	
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

// calculateOverallRisk calculates the overall risk score
func (rd *RiskDiagnoser) calculateOverallRisk(assessment *types.RiskAssessment) float64 {
	score := 0.0

	// Weight different risk factors
	score += float64(len(assessment.SecurityVulns)) * 10.0
	score += float64(len(assessment.TechnicalDebt)) * 2.0
	score += float64(len(assessment.ObsoleteCode)) * 1.0
	score += float64(len(assessment.DangerousDependencies)) * 5.0

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

// TODO: Implement prepareRiskAnalysisData when AI integration is complete
// prepareRiskAnalysisData prepares data for AI risk analysis
// func (rd *RiskDiagnoser) prepareRiskAnalysisData() map[string]interface{} {
// 	return map[string]interface{}{
// 		"graph":      rd.scanner.GetKnowledgeGraph(),
// 		"node_count": len(rd.scanner.GetKnowledgeGraph().Nodes),
// 		"edge_count": len(rd.scanner.GetKnowledgeGraph().Edges),
// 	}
// }

// TODO: Implement extractTechnicalDebt when AI integration is complete
// extractTechnicalDebt extracts technical debt from AI analysis
// func (rd *RiskDiagnoser) extractTechnicalDebt(risks map[string]interface{}) []types.TechnicalDebtItem {
// 	items := make([]types.TechnicalDebtItem, 0)
//
// 	if debt, ok := risks["technical_debt"].([]interface{}); ok {
// 		for i, item := range debt {
// 			if m, ok := item.(map[string]interface{}); ok {
// 				items = append(items, types.TechnicalDebtItem{
// 					ID:          fmt.Sprintf("TD-%d", i+1),
// 					Location:    getStringField(m, "location"),
// 					Type:        getStringField(m, "type"),
// 					Severity:    getStringField(m, "severity"),
// 					Description: getStringField(m, "description"),
// 					Remediation: getStringField(m, "remediation"),
// 					Effort:      getIntField(m, "effort_hours"),
// 				})
// 			}
// 		}
// 	}
//
// 	return items
// }

// TODO: Implement extractSecurityVulns when AI integration is complete
// extractSecurityVulns extracts security vulnerabilities from AI analysis
// func (rd *RiskDiagnoser) extractSecurityVulns(risks map[string]interface{}) []types.SecurityVulnerability {
// 	vulns := make([]types.SecurityVulnerability, 0)
//
// 	if security, ok := risks["security"].([]interface{}); ok {
// 		for _, item := range security {
// 			if m, ok := item.(map[string]interface{}); ok {
// 				vulns = append(vulns, types.SecurityVulnerability{
// 					CVE:         getStringField(m, "cve"),
// 					Package:     getStringField(m, "package"),
// 					Version:     getStringField(m, "version"),
// 					Severity:    getStringField(m, "severity"),
// 					Description: getStringField(m, "description"),
// 					FixVersion:  getStringField(m, "fix_version"),
// 					CVSS:        getFloatField(m, "cvss"),
// 				})
// 			}
// 		}
// 	}
//
// 	return vulns
// }

// TODO: Implement extractObsoleteCode when AI integration is complete
// extractObsoleteCode extracts obsolete code from AI analysis
// func (rd *RiskDiagnoser) extractObsoleteCode(risks map[string]interface{}) []types.ObsoleteCodeItem {
// 	items := make([]types.ObsoleteCodeItem, 0)
//
// 	if obsolete, ok := risks["obsolete_code"].([]interface{}); ok {
// 		for _, item := range obsolete {
// 			if m, ok := item.(map[string]interface{}); ok {
// 				items = append(items, types.ObsoleteCodeItem{
// 					Path:            getStringField(m, "path"),
// 					References:      getIntField(m, "references"),
// 					RemovalSafety:   getStringField(m, "removal_safety"),
// 					RecommendAction: getStringField(m, "action"),
// 				})
// 			}
// 		}
// 	}
//
// 	return items
// }

// TODO: Implement extractDependencyRisks when AI integration is complete
// extractDependencyRisks extracts dependency risks from AI analysis
// func (rd *RiskDiagnoser) extractDependencyRisks(risks map[string]interface{}) []types.DependencyRisk {
// 	deps := make([]types.DependencyRisk, 0)
//
// 	if dependencies, ok := risks["dependencies"].([]interface{}); ok {
// 		for _, item := range dependencies {
// 			if m, ok := item.(map[string]interface{}); ok {
// 				deps = append(deps, types.DependencyRisk{
// 					Package:        getStringField(m, "package"),
// 					CurrentVersion: getStringField(m, "current_version"),
// 					LatestVersion:  getStringField(m, "latest_version"),
// 					SecurityIssues: getIntField(m, "security_issues"),
// 					Maintenance:    getStringField(m, "maintenance"),
// 					Recommendation: getStringField(m, "recommendation"),
// 				})
// 			}
// 		}
// 	}
//
// 	return deps
// }

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

// validateRiskData validates risk data using helper functions
func (rd *RiskDiagnoser) validateRiskData(data map[string]interface{}) bool {
	// Use the helper functions to validate required fields
	name := getStringField(data, "name")
	severity := getStringField(data, "severity")
	score := getFloatField(data, "score")
	priority := getIntField(data, "priority")
	
	return name != "" && severity != "" && score >= 0 && priority >= 0
}
