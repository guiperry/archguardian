package types

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKnowledgeGraph_ToAPIFormat(t *testing.T) {
	// Create a test knowledge graph
	kg := &KnowledgeGraph{
		Nodes: map[string]*Node{
			"node1": {
				ID:   "node1",
				Name: "Test Node 1",
				Type: NodeTypeCode,
				Metadata: map[string]interface{}{
					"language": "go",
					"size":     100,
				},
			},
			"node2": {
				ID:   "node2",
				Name: "Test Node 2",
				Type: NodeTypeLibrary,
				Metadata: map[string]interface{}{
					"version": "1.0.0",
				},
			},
		},
		Edges: []*Edge{
			{
				From:         "node1",
				To:           "node2",
				Relationship: "depends_on",
				Strength:     0.8,
			},
		},
		LastUpdated:   time.Now(),
		AnalysisDepth: 3,
	}

	// Test ToAPIFormat
	apiFormat := kg.ToAPIFormat()

	// Verify structure
	nodes, ok := apiFormat["nodes"].([]map[string]interface{})
	require.True(t, ok, "nodes should be a slice of maps")
	assert.Len(t, nodes, 2, "should have 2 nodes")

	edges, ok := apiFormat["edges"].([]map[string]interface{})
	require.True(t, ok, "edges should be a slice of maps")
	assert.Len(t, edges, 1, "should have 1 edge")

	// Verify node structure
	var foundNode1, foundNode2 bool
	for _, node := range nodes {
		if node["id"] == "node1" {
			foundNode1 = true
			assert.Equal(t, "Test Node 1", node["label"])
			assert.Equal(t, "code", node["type"])
			assert.Equal(t, "code", node["group"])
			assert.NotNil(t, node["metadata"])
		}
		if node["id"] == "node2" {
			foundNode2 = true
			assert.Equal(t, "Test Node 2", node["label"])
			assert.Equal(t, "library", node["type"])
		}
	}
	assert.True(t, foundNode1, "should find node1")
	assert.True(t, foundNode2, "should find node2")

	// Verify edge structure
	edge := edges[0]
	assert.Equal(t, "node1", edge["from"])
	assert.Equal(t, "node2", edge["to"])
	assert.Equal(t, "depends_on", edge["label"])
	assert.Equal(t, "to", edge["arrows"])
}

func TestKnowledgeGraph_ToDocument(t *testing.T) {
	kg := &KnowledgeGraph{
		Nodes:         map[string]*Node{},
		Edges:         []*Edge{},
		LastUpdated:   time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		AnalysisDepth: 2,
	}

	projectID := "test-project"
	doc, err := kg.ToDocument(projectID)

	require.NoError(t, err)
	assert.Equal(t, "kg_test-project_20230101_120000", doc.ID)
	assert.Contains(t, doc.Content, "nodes")
	assert.Contains(t, doc.Content, "edges")

	// Verify metadata
	assert.Equal(t, "knowledge-graph", doc.Metadata["type"])
	assert.Equal(t, projectID, doc.Metadata["project_id"])
	assert.Equal(t, "2023-01-01T12:00:00Z", doc.Metadata["timestamp"])
	assert.Equal(t, "0", doc.Metadata["node_count"])
	assert.Equal(t, "0", doc.Metadata["edge_count"])
	assert.Equal(t, "2", doc.Metadata["analysis_depth"])
}

func TestRiskAssessment_ToDocument(t *testing.T) {
	ra := &RiskAssessment{
		TechnicalDebt: []TechnicalDebtItem{
			{
				ID:          "td1",
				Location:    "/path/to/file.go",
				Type:        "code_smell",
				Severity:    "medium",
				Description: "Complex function needs refactoring",
				Remediation: "Split into smaller functions",
				Effort:      4,
			},
		},
		SecurityVulns: []SecurityVulnerability{
			{
				CVE:         "CVE-2023-1234",
				Package:     "vulnerable-lib",
				Version:     "1.0.0",
				Severity:    "high",
				Description: "SQL injection vulnerability",
				FixVersion:  "1.0.1",
				CVSS:        7.5,
			},
		},
		ObsoleteCode: []ObsoleteCodeItem{
			{
				Path:            "/old/deprecated.go",
				LastUsed:        time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
				References:      0,
				RemovalSafety:   "safe",
				RecommendAction: "remove",
			},
		},
		DangerousDependencies: []DependencyRisk{
			{
				Package:        "risky-package",
				CurrentVersion: "0.1.0",
				LatestVersion:  "2.0.0",
				SecurityIssues: 3,
				Maintenance:    "deprecated",
				Recommendation: "migrate to alternative",
			},
		},
		OverallScore: 75.5,
		Timestamp:    time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
	}

	projectID := "test-project"
	doc, err := ra.ToDocument(projectID)

	require.NoError(t, err)
	assert.Equal(t, "assessment_test-project_20230101_120000", doc.ID)

	// Verify the content is valid JSON
	var parsedContent RiskAssessment
	err = json.Unmarshal([]byte(doc.Content), &parsedContent)
	require.NoError(t, err)

	// Verify metadata
	assert.Equal(t, "risk-assessment", doc.Metadata["type"])
	assert.Equal(t, projectID, doc.Metadata["project_id"])
	assert.Equal(t, "2023-01-01T12:00:00Z", doc.Metadata["timestamp"])
	assert.Equal(t, "75.50", doc.Metadata["overall_score"])
	assert.Equal(t, "1", doc.Metadata["technical_debt_count"])
	assert.Equal(t, "1", doc.Metadata["security_vulns_count"])
	assert.Equal(t, "1", doc.Metadata["obsolete_code_count"])
	assert.Equal(t, "1", doc.Metadata["dependency_risks_count"])
}

func TestNodeTypes(t *testing.T) {
	// Test all node type constants
	expectedTypes := []NodeType{
		NodeTypeCode,
		NodeTypeAPI,
		NodeTypeDatabase,
		NodeTypeService,
		NodeTypeLibrary,
		NodeTypeDataFlow,
		NodeTypeConfig,
		NodeTypeProcess,
		NodeTypeConnection,
		NodeTypeNetwork,
	}

	expectedValues := []string{
		"code",
		"api",
		"database",
		"service",
		"library",
		"dataflow",
		"config",
		"process",
		"connection",
		"network",
	}

	for i, nodeType := range expectedTypes {
		assert.Equal(t, expectedValues[i], string(nodeType))
	}
}

func TestStructSerialization(t *testing.T) {
	// Test that all main structs can be serialized/deserialized
	testCases := []struct {
		name string
		data interface{}
	}{
		{
			name: "TechnicalDebtItem",
			data: TechnicalDebtItem{
				ID:          "test",
				Location:    "/test",
				Type:        "smell",
				Severity:    "high",
				Description: "test desc",
				Remediation: "fix it",
				Effort:      5,
			},
		},
		{
			name: "SecurityVulnerability",
			data: SecurityVulnerability{
				CVE:         "CVE-2023-1234",
				Package:     "test-pkg",
				Version:     "1.0.0",
				Severity:    "critical",
				Description: "test vuln",
				FixVersion:  "1.0.1",
				CVSS:        9.0,
			},
		},
		{
			name: "ObsoleteCodeItem",
			data: ObsoleteCodeItem{
				Path:            "/old/file.go",
				LastUsed:        time.Now(),
				References:      0,
				RemovalSafety:   "safe",
				RecommendAction: "remove",
			},
		},
		{
			name: "DependencyRisk",
			data: DependencyRisk{
				Package:        "risky",
				CurrentVersion: "1.0.0",
				LatestVersion:  "2.0.0",
				SecurityIssues: 1,
				Maintenance:    "active",
				Recommendation: "update",
			},
		},
		{
			name: "Node",
			data: Node{
				ID:           "test-node",
				Type:         NodeTypeCode,
				Name:         "Test Node",
				Path:         "/test",
				Metadata:     map[string]interface{}{"key": "value"},
				Dependencies: []string{"dep1", "dep2"},
				Dependents:   []string{"dep3"},
				RiskScore:    0.5,
				LastModified: time.Now(),
			},
		},
		{
			name: "Edge",
			data: Edge{
				From:         "node1",
				To:           "node2",
				Relationship: "depends",
				Strength:     0.8,
				Metadata:     map[string]interface{}{"type": "strong"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tc.data)
			require.NoError(t, err, "should marshal without error")

			// Unmarshal back
			var result interface{}
			err = json.Unmarshal(jsonData, &result)
			require.NoError(t, err, "should unmarshal without error")

			// Basic validation that we got a map back
			resultMap, ok := result.(map[string]interface{})
			require.True(t, ok, "should unmarshal to a map")
			assert.NotEmpty(t, resultMap, "result should not be empty")
		})
	}
}

func TestKnowledgeGraphEdgeCases(t *testing.T) {
	// Test empty knowledge graph
	kg := &KnowledgeGraph{
		Nodes:         map[string]*Node{},
		Edges:         []*Edge{},
		LastUpdated:   time.Now(),
		AnalysisDepth: 0,
	}

	apiFormat := kg.ToAPIFormat()
	nodes := apiFormat["nodes"].([]map[string]interface{})
	edges := apiFormat["edges"].([]map[string]interface{})

	assert.Len(t, nodes, 0)
	assert.Len(t, edges, 0)

	// Test ToDocument with empty graph
	doc, err := kg.ToDocument("empty-project")
	require.NoError(t, err)
	assert.Contains(t, doc.Content, "nodes")
	assert.Contains(t, doc.Content, "edges")
	assert.Equal(t, "0", doc.Metadata["node_count"])
	assert.Equal(t, "0", doc.Metadata["edge_count"])
}

func TestRiskAssessmentEdgeCases(t *testing.T) {
	// Test empty risk assessment
	ra := &RiskAssessment{
		TechnicalDebt:         []TechnicalDebtItem{},
		SecurityVulns:         []SecurityVulnerability{},
		ObsoleteCode:          []ObsoleteCodeItem{},
		DangerousDependencies: []DependencyRisk{},
		OverallScore:          0.0,
		Timestamp:             time.Now(),
	}

	doc, err := ra.ToDocument("empty-assessment")
	require.NoError(t, err)
	assert.Equal(t, "0.00", doc.Metadata["overall_score"])
	assert.Equal(t, "0", doc.Metadata["technical_debt_count"])
	assert.Equal(t, "0", doc.Metadata["security_vulns_count"])
	assert.Equal(t, "0", doc.Metadata["obsolete_code_count"])
	assert.Equal(t, "0", doc.Metadata["dependency_risks_count"])
}
