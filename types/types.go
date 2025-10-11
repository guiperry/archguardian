package types

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AIEngineInterface defines the interface for AI inference engines
type AIEngineInterface interface {
	GenerateText(ctx context.Context, modelName string, promptText string, instructionText string) (string, error)
	GenerateStructuredOutput(content string, schema string) (string, error)
	IsRunning() bool
}

// CodacyClientInterface defines the interface for Codacy API clients
type CodacyClientInterface interface {
	// TODO: Define Codacy client methods when Codacy integration is implemented
	// This is a placeholder interface for future Codacy API integration
	GetAnalysis(projectID string) (*CodacyAnalysis, error)
}

// CodacyAnalysis represents a Codacy analysis result
type CodacyAnalysis struct {
	ProjectID   string       `json:"projectId"`
	CommitID    string       `json:"commitId"`
	AnalysisID  string       `json:"analysisId"`
	Timestamp   time.Time    `json:"timestamp"`
	Issues      []CodacyIssue `json:"issues"`
}

// CodacyIssue represents a single issue from Codacy
type CodacyIssue struct {
	ID          string `json:"id"`
	PatternID   string `json:"patternId"`
	File        string `json:"file"`
	Line         int    `json:"line"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
}

// NodeType represents the type of a node in the knowledge graph
type NodeType string

// Node type constants
const (
	NodeTypeCode      NodeType = "code"
	NodeTypeAPI       NodeType = "api"
	NodeTypeDatabase  NodeType = "database"
	NodeTypeService   NodeType = "service"
	NodeTypeLibrary   NodeType = "library"
	NodeTypeDataFlow  NodeType = "dataflow"
	NodeTypeConfig    NodeType = "config"
	NodeTypeProcess   NodeType = "process"
	NodeTypeConnection NodeType = "connection"
	NodeTypeNetwork   NodeType = "network"
)

// Node represents a node in the knowledge graph
type Node struct {
	ID           string                 `json:"id"`
	Type         NodeType               `json:"type"`
	Name         string                 `json:"name"`
	Path         string                 `json:"path,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Dependencies []string               `json:"dependencies,omitempty"`
	Dependents   []string               `json:"dependents,omitempty"`
	RiskScore    float64                `json:"risk_score,omitempty"`
	LastModified time.Time              `json:"last_modified,omitempty"`
}

// Edge represents an edge in the knowledge graph
type Edge struct {
	From         string                 `json:"from"`
	To           string                 `json:"to"`
	Relationship string                 `json:"relationship"`
	Strength     float64                `json:"strength,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// KnowledgeGraph represents the complete knowledge graph
type KnowledgeGraph struct {
	Nodes         map[string]*Node `json:"nodes"`
	Edges         []*Edge          `json:"edges"`
	LastUpdated   time.Time        `json:"last_updated"`
	AnalysisDepth int              `json:"analysis_depth"`
}

// TechnicalDebtItem represents a technical debt item
type TechnicalDebtItem struct {
	ID          string `json:"id"`
	Location    string `json:"location"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Effort      int    `json:"effort"`
}

// SecurityVulnerability represents a security vulnerability
type SecurityVulnerability struct {
	CVE         string  `json:"cve"`
	Package     string  `json:"package"`
	Version     string  `json:"version"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	FixVersion  string  `json:"fix_version"`
	CVSS        float64 `json:"cvss"`
}

// ObsoleteCodeItem represents obsolete code
type ObsoleteCodeItem struct {
	Path            string    `json:"path"`
	LastUsed        time.Time `json:"last_used,omitempty"`
	References      int       `json:"references"`
	RemovalSafety   string    `json:"removal_safety"`
	RecommendAction string    `json:"recommend_action"`
}

// DependencyRisk represents a dependency risk
type DependencyRisk struct {
	Package        string `json:"package"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	SecurityIssues int    `json:"security_issues"`
	Maintenance    string `json:"maintenance"`
	Recommendation string `json:"recommendation"`
}

// RiskAssessment represents a complete risk assessment
type RiskAssessment struct {
	TechnicalDebt         []TechnicalDebtItem     `json:"technical_debt"`
	SecurityVulns         []SecurityVulnerability `json:"security_vulns"`
	ObsoleteCode          []ObsoleteCodeItem      `json:"obsolete_code"`
	DangerousDependencies []DependencyRisk        `json:"dangerous_dependencies"`
	CompatibilityIssues   []TechnicalDebtItem     `json:"compatibility_issues,omitempty"`
	OverallScore          float64                 `json:"overall_score"`
	Timestamp             time.Time               `json:"timestamp"`
}

// Document represents a document for vector storage
type Document struct {
	ID       string                 `json:"id"`
	Content  string                 `json:"content"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ToAPIFormat converts the knowledge graph to API format
func (kg *KnowledgeGraph) ToAPIFormat() map[string]interface{} {
	nodes := make([]map[string]interface{}, 0, len(kg.Nodes))
	edges := make([]map[string]interface{}, 0, len(kg.Edges))

	// Convert nodes
	for _, node := range kg.Nodes {
		nodeMap := map[string]interface{}{
			"id":       node.ID,
			"label":    node.Name,
			"type":     string(node.Type),
			"group":    string(node.Type),
			"metadata": node.Metadata,
		}
		nodes = append(nodes, nodeMap)
	}

	// Convert edges
	for _, edge := range kg.Edges {
		edgeMap := map[string]interface{}{
			"from":   edge.From,
			"to":     edge.To,
			"label":  edge.Relationship,
			"arrows": "to",
		}
		if edge.Strength > 0 {
			edgeMap["value"] = edge.Strength
		}
		edges = append(edges, edgeMap)
	}

	return map[string]interface{}{
		"nodes": nodes,
		"edges": edges,
	}
}

// ToDocument converts the knowledge graph to a document for storage
func (kg *KnowledgeGraph) ToDocument(projectID string) (*Document, error) {
	content, err := json.Marshal(kg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal knowledge graph: %w", err)
	}

	timestamp := kg.LastUpdated.Format("20060102_150405")
	docID := fmt.Sprintf("kg_%s_%s", projectID, timestamp)

	metadata := map[string]interface{}{
		"type":           "knowledge-graph",
		"project_id":     projectID,
		"timestamp":      kg.LastUpdated.Format(time.RFC3339),
		"node_count":     fmt.Sprintf("%d", len(kg.Nodes)),
		"edge_count":     fmt.Sprintf("%d", len(kg.Edges)),
		"analysis_depth": fmt.Sprintf("%d", kg.AnalysisDepth),
	}

	return &Document{
		ID:       docID,
		Content:  string(content),
		Metadata: metadata,
	}, nil
}

// ToDocument converts the risk assessment to a document for storage
func (ra *RiskAssessment) ToDocument(projectID string) (*Document, error) {
	content, err := json.Marshal(ra)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal risk assessment: %w", err)
	}

	timestamp := ra.Timestamp.Format("20060102_150405")
	docID := fmt.Sprintf("assessment_%s_%s", projectID, timestamp)

	metadata := map[string]interface{}{
		"type":                    "risk-assessment",
		"project_id":              projectID,
		"timestamp":               ra.Timestamp.Format(time.RFC3339),
		"overall_score":           fmt.Sprintf("%.2f", ra.OverallScore),
		"technical_debt_count":    fmt.Sprintf("%d", len(ra.TechnicalDebt)),
		"security_vulns_count":    fmt.Sprintf("%d", len(ra.SecurityVulns)),
		"obsolete_code_count":     fmt.Sprintf("%d", len(ra.ObsoleteCode)),
		"dependency_risks_count":  fmt.Sprintf("%d", len(ra.DangerousDependencies)),
	}

	return &Document{
		ID:       docID,
		Content:  string(content),
		Metadata: metadata,
	}, nil
}
