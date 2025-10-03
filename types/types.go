package types

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/philippgille/chromem-go"
)

// ============================================================================
// KNOWLEDGE GRAPH
// ============================================================================

type KnowledgeGraph struct {
	Nodes         map[string]*Node
	Edges         []*Edge
	LastUpdated   time.Time
	AnalysisDepth int
}

// ToAPIFormat converts the KnowledgeGraph to the format expected by the frontend
func (kg *KnowledgeGraph) ToAPIFormat() map[string]interface{} {
	nodes := make([]map[string]interface{}, 0, len(kg.Nodes))
	for _, node := range kg.Nodes {
		nodes = append(nodes, map[string]interface{}{
			"id":       node.ID,
			"label":    node.Name,
			"type":     string(node.Type),
			"group":    string(node.Type),
			"metadata": node.Metadata,
		})
	}

	edges := make([]map[string]interface{}, 0, len(kg.Edges))
	for _, edge := range kg.Edges {
		edges = append(edges, map[string]interface{}{
			"from":   edge.From,
			"to":     edge.To,
			"label":  edge.Relationship,
			"arrows": "to",
		})
	}

	return map[string]interface{}{
		"nodes": nodes,
		"edges": edges,
	}
}

// ToDocument converts the KnowledgeGraph to a chromem-go document for persistence
func (kg *KnowledgeGraph) ToDocument(projectID string) (chromem.Document, error) {
	graphJSON, err := json.Marshal(kg.ToAPIFormat())
	if err != nil {
		return chromem.Document{}, err
	}

	return chromem.Document{
		ID:      "kg_" + projectID + "_" + kg.LastUpdated.Format("20060102_150405"),
		Content: string(graphJSON),
		Metadata: map[string]string{
			"type":           "knowledge-graph",
			"project_id":     projectID,
			"timestamp":      kg.LastUpdated.Format(time.RFC3339),
			"node_count":     fmt.Sprintf("%d", len(kg.Nodes)),
			"edge_count":     fmt.Sprintf("%d", len(kg.Edges)),
			"analysis_depth": fmt.Sprintf("%d", kg.AnalysisDepth),
		},
	}, nil
}

type Node struct {
	ID           string
	Type         NodeType
	Name         string
	Path         string
	Metadata     map[string]interface{}
	Dependencies []string
	Dependents   []string
	RiskScore    float64
	LastModified time.Time
}

type NodeType string

const (
	NodeTypeCode       NodeType = "code"
	NodeTypeAPI        NodeType = "api"
	NodeTypeDatabase   NodeType = "database"
	NodeTypeService    NodeType = "service"
	NodeTypeLibrary    NodeType = "library"
	NodeTypeDataFlow   NodeType = "dataflow"
	NodeTypeConfig     NodeType = "config"
	NodeTypeProcess    NodeType = "process"
	NodeTypeConnection NodeType = "connection"
	NodeTypeNetwork    NodeType = "network"
)

type Edge struct {
	From         string
	To           string
	Relationship string
	Strength     float64
	Metadata     map[string]interface{}
}

// ============================================================================
// RISK ASSESSMENT
// ============================================================================

type RiskAssessment struct {
	TechnicalDebt         []TechnicalDebtItem
	SecurityVulns         []SecurityVulnerability
	ObsoleteCode          []ObsoleteCodeItem
	DangerousDependencies []DependencyRisk
	OverallScore          float64
	Timestamp             time.Time
}

// ToDocument converts the RiskAssessment to a chromem-go document for persistence
func (ra *RiskAssessment) ToDocument(projectID string) (chromem.Document, error) {
	assessmentJSON, err := json.Marshal(ra)
	if err != nil {
		return chromem.Document{}, err
	}

	return chromem.Document{
		ID:      "assessment_" + projectID + "_" + ra.Timestamp.Format("20060102_150405"),
		Content: string(assessmentJSON),
		Metadata: map[string]string{
			"type":                "risk-assessment",
			"project_id":          projectID,
			"timestamp":           ra.Timestamp.Format(time.RFC3339),
			"overall_score":       fmt.Sprintf("%.2f", ra.OverallScore),
			"technical_debt_count": fmt.Sprintf("%d", len(ra.TechnicalDebt)),
			"security_vulns_count": fmt.Sprintf("%d", len(ra.SecurityVulns)),
			"obsolete_code_count": fmt.Sprintf("%d", len(ra.ObsoleteCode)),
			"dependency_risks_count": fmt.Sprintf("%d", len(ra.DangerousDependencies)),
		},
	}, nil
}

type TechnicalDebtItem struct {
	ID          string
	Location    string
	Type        string
	Severity    string
	Description string
	Remediation string
	Effort      int // hours
}

type SecurityVulnerability struct {
	CVE         string
	Package     string
	Version     string
	Severity    string
	Description string
	FixVersion  string
	CVSS        float64
}

type ObsoleteCodeItem struct {
	Path            string
	LastUsed        time.Time
	References      int
	RemovalSafety   string
	RecommendAction string
}

type DependencyRisk struct {
	Package        string
	CurrentVersion string
	LatestVersion  string
	SecurityIssues int
	Maintenance    string // "active", "deprecated", "abandoned"
	Recommendation string
}
