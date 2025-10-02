package types

import "time"

// ============================================================================
// KNOWLEDGE GRAPH
// ============================================================================

type KnowledgeGraph struct {
	Nodes         map[string]*Node
	Edges         []*Edge
	LastUpdated   time.Time
	AnalysisDepth int
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
	NodeTypeCode     NodeType = "code"
	NodeTypeAPI      NodeType = "api"
	NodeTypeDatabase NodeType = "database"
	NodeTypeService  NodeType = "service"
	NodeTypeLibrary  NodeType = "library"
	NodeTypeDataFlow NodeType = "dataflow"
	NodeTypeConfig   NodeType = "config"
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

