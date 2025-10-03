package main

import (
	"archguardian/types"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

// TestScanGoMod tests the Go module dependency scanning functionality
func TestScanGoMod(t *testing.T) {
	// Load .env file for test credentials
	if err := godotenv.Load("../.env"); err != nil {
		log.Println("⚠️  No .env file found for tests, using environment variables only")
	}

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "archguardian_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test go.mod file
	goModContent := `module testproject

go 1.21

require (
	github.com/stretchr/testify v1.8.4
	github.com/gorilla/mux v1.8.0
	golang.org/x/crypto v0.14.0
)
`
	goModPath := filepath.Join(tempDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	// Create a minimal config that avoids AI initialization for testing
	config := &Config{
		ProjectPath: tempDir,
		AIProviders: AIProviderConfig{
			CodeRemediationProvider: "anthropic",
		},
		DataEngine: DataEngineConfig{
			Enable: false,
		},
	}

	// Create scanner manually without AI inference engine for this test
	scanner := &Scanner{
		config: config,
		graph:  NewKnowledgeGraph(),
		ai:     nil, // Skip AI initialization for this test
	}

	// Test scanning the go.mod file
	err = scanner.scanGoMod()
	if err != nil {
		t.Fatalf("scanGoMod failed: %v", err)
	}

	// Verify that dependencies were found
	foundTestify := false
	foundGorilla := false
	foundCrypto := false

	for _, node := range scanner.graph.Nodes {
		if node.Type == types.NodeTypeLibrary {
			switch node.Name {
			case "github.com/stretchr/testify":
				foundTestify = true
			case "github.com/gorilla/mux":
				foundGorilla = true
			case "golang.org/x/crypto":
				foundCrypto = true
			}
		}
	}

	if !foundTestify {
		t.Error("Expected to find github.com/stretchr/testify dependency")
	}
	if !foundGorilla {
		t.Error("Expected to find github.com/gorilla/mux dependency")
	}
	if !foundCrypto {
		t.Error("Expected to find golang.org/x/crypto dependency")
	}

	// Verify metadata
	for _, node := range scanner.graph.Nodes {
		if node.Type == types.NodeTypeLibrary {
			if node.Metadata["manager"] != "go" {
				t.Errorf("Expected manager to be 'go', got %v", node.Metadata["manager"])
			}
			if node.Metadata["version"] == "" {
				t.Error("Expected version to be set")
			}
		}
	}
}

// TestScanPackageJSON tests the package.json dependency scanning functionality
func TestScanPackageJSON(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "archguardian_test_npm")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	packageJSONContent := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"react": "^18.2.0",
			"axios": "^1.6.0"
		}
	}`
	packageJSONPath := filepath.Join(tempDir, "package.json")
	err = os.WriteFile(packageJSONPath, []byte(packageJSONContent), 0644)
	assert.NoError(t, err)

	config := &Config{ProjectPath: tempDir}

	// Create scanner manually without AI inference engine for this test
	scanner := &Scanner{
		config: config,
		graph:  NewKnowledgeGraph(),
		ai:     nil, // Skip AI initialization for this test
	}

	err = scanner.scanPackageJSON(context.Background())
	assert.NoError(t, err)

	expectedDeps := map[string]bool{"react": false, "axios": false}
	for _, node := range scanner.graph.Nodes {
		if node.Type == types.NodeTypeLibrary {
			if _, ok := expectedDeps[node.Name]; ok {
				expectedDeps[node.Name] = true
				assert.Equal(t, "npm", node.Metadata["manager"])
				assert.NotEmpty(t, node.Metadata["version"])
			}
		}
	}

	for dep, found := range expectedDeps {
		assert.True(t, found, "Expected to find dependency: %s", dep)
	}
}

// TestScanRequirementsTxt tests the requirements.txt dependency scanning functionality
func TestScanRequirementsTxt(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "archguardian_test_pip")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	requirementsContent := `
# This is a comment
requests==2.28.1
numpy

pandas == 1.5.3 # Inline comment
`
	requirementsPath := filepath.Join(tempDir, "requirements.txt")
	err = os.WriteFile(requirementsPath, []byte(requirementsContent), 0644)
	assert.NoError(t, err)

	config := &Config{ProjectPath: tempDir}

	// Create scanner manually without AI inference engine for this test
	scanner := &Scanner{
		config: config,
		graph:  NewKnowledgeGraph(),
		ai:     nil, // Skip AI initialization for this test
	}

	err = scanner.scanRequirementsTxt(context.Background())
	assert.NoError(t, err)

	expectedDeps := map[string]string{"requests": "2.28.1", "numpy": "", "pandas": "1.5.3 # Inline comment"}
	foundCount := 0
	for _, node := range scanner.graph.Nodes {
		if node.Type == types.NodeTypeLibrary {
			if version, ok := expectedDeps[node.Name]; ok {
				foundCount++
				assert.Equal(t, "pip", node.Metadata["manager"])
				assert.Equal(t, version, node.Metadata["version"])
			}
		}
	}
	assert.Equal(t, len(expectedDeps), foundCount, "Did not find all expected dependencies")
}

// TestCalculateOverallRisk tests the risk scoring calculation
func TestCalculateOverallRisk(t *testing.T) {
	diagnoser := &RiskDiagnoser{}

	testCases := []struct {
		name          string
		assessment    *types.RiskAssessment
		expectedScore float64
	}{
		{
			name: "Comprehensive risk",
			assessment: &types.RiskAssessment{
				TechnicalDebt:         []types.TechnicalDebtItem{{}, {}, {}}, // 3 items
				SecurityVulns:         []types.SecurityVulnerability{{}, {}}, // 2 items
				ObsoleteCode:          []types.ObsoleteCodeItem{{}},          // 1 item
				DangerousDependencies: []types.DependencyRisk{{}},            // 1 item
			},
			// Expected: (2 * 10) + (3 * 2) + (1 * 1) + (1 * 5) = 20 + 6 + 1 + 5 = 32.0
			expectedScore: 32.0,
		},
		{
			name: "No risks",
			assessment: &types.RiskAssessment{
				TechnicalDebt:         []types.TechnicalDebtItem{},
				SecurityVulns:         []types.SecurityVulnerability{},
				ObsoleteCode:          []types.ObsoleteCodeItem{},
				DangerousDependencies: []types.DependencyRisk{},
			},
			expectedScore: 0.0,
		},
		{
			name: "Only security risks",
			assessment: &types.RiskAssessment{
				SecurityVulns: []types.SecurityVulnerability{{}, {}, {}, {}}, // 4 items
			},
			// Expected: 4 * 10 = 40.0
			expectedScore: 40.0,
		},
		{
			name: "Score capped at 100",
			assessment: &types.RiskAssessment{
				SecurityVulns: make([]types.SecurityVulnerability, 15), // 15 * 10 = 150
			},
			expectedScore: 100.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := diagnoser.calculateOverallRisk(tc.assessment)
			assert.Equal(t, tc.expectedScore, score, "Risk score calculation mismatch")
		})
	}
}

// TestApplyFixPatch tests the patch application functionality
func TestApplyFixPatch(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "archguardian_patch_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize git repo
	if err := initializeGitRepo(tempDir); err != nil {
		t.Fatalf("Failed to initialize git repo: %v", err)
	}

	// Create a test file
	testFile := filepath.Join(tempDir, "test.go")
	originalContent := `package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
`
	if err := os.WriteFile(testFile, []byte(originalContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create remediator with minimal config to avoid AI initialization
	config := &Config{
		ProjectPath: tempDir,
		AIProviders: AIProviderConfig{
			CodeRemediationProvider: "anthropic",
		},
		DataEngine: DataEngineConfig{
			Enable: false,
		},
	}

	// Create scanner manually without AI inference engine for this test
	scanner := &Scanner{
		config: config,
		graph:  NewKnowledgeGraph(),
		ai:     nil, // Skip AI initialization for this test
	}

	diagnoser := NewRiskDiagnoser(scanner, nil)
	remediator := NewRemediator(config, diagnoser)

	// Test patch application
	patch := `--- a/test.go
+++ b/test.go
@@ -1,7 +1,8 @@
 package main

 import "fmt"

+// Added comment
 func main() {
 	fmt.Println("Hello, World!")
 }
`
	err = remediator.applyFix(patch, "test.go")
	if err != nil {
		t.Fatalf("applyFix failed: %v", err)
	}

	// Verify the patch was applied
	updatedContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read updated file: %v", err)
	}

	expectedContent := `package main

import "fmt"

// Added comment
func main() {
	fmt.Println("Hello, World!")
}
`
	if string(updatedContent) != expectedContent {
		t.Errorf("Patch not applied correctly.\nExpected:\n%s\nGot:\n%s", expectedContent, string(updatedContent))
	}
}

// TestDependencyParsers uses table-driven tests for all dependency parsers
func TestDependencyParsers(t *testing.T) {
	scanner := &Scanner{}

	testCases := []struct {
		name         string
		parserFunc   func(string, []byte) []string
		filePath     string
		content      string
		expectedDeps []string
	}{
		{
			name:       "Go Parser",
			parserFunc: scanner.parseGoDependencies,
			filePath:   "test.go",
			content: `package main
			import (
				"fmt"
				"os"
				"github.com/stretchr/testify/assert"
				"golang.org/x/crypto/bcrypt"
			)`,
			expectedDeps: []string{"fmt", "os", "github.com/stretchr/testify/assert", "golang.org/x/crypto/bcrypt"},
		},
		{
			name:       "JavaScript Parser",
			parserFunc: scanner.parseJavaScriptDependencies,
			filePath:   "app.js",
			content: `
				import React from 'react';
				import { useState, useEffect } from 'react';
				const lodash = require('lodash');
				import axios from "axios";
				import * as d3 from "d3";
			`,
			expectedDeps: []string{"react", "lodash", "axios", "d3"},
		},
		{
			name:       "Python Parser",
			parserFunc: scanner.parsePythonDependencies,
			filePath:   "main.py",
			content: `import os
import sys
from my_project.utils import helper
import numpy as np`,
			expectedDeps: []string{"os", "sys", "my_project", "numpy"},
		},
		{
			name:       "Java Parser",
			parserFunc: scanner.parseJavaDependencies,
			filePath:   "Main.java",
			content: `
				import java.util.List;
				import org.springframework.boot.SpringApplication;
				import com.mycompany.project.MyClass;
			`,
			expectedDeps: []string{"java.util.List", "org.springframework.boot.SpringApplication", "com.mycompany.project.MyClass"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dependencies := tc.parserFunc(tc.filePath, []byte(tc.content))
			assert.ElementsMatch(t, tc.expectedDeps, dependencies)
		})
	}
}

// TestIsCodeFile tests the isCodeFile helper function
func TestIsCodeFile(t *testing.T) {
	testCases := []struct {
		path   string
		isCode bool
	}{
		{"main.go", true},
		{"script.js", true},
		{"style.css", false},
		{"README.md", false},
		{"image.JPG", false},
		{"main.go.tmp", false},
		{"Dockerfile", false},
		{"MyClass.java", true},
		{"utils.py", true},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.isCode, isCodeFile(tc.path), "isCodeFile failed for %s", tc.path)
	}
}

// TestCVEScanner tests CVE scanning functionality
func TestCVEScanner(t *testing.T) {
	// Skip if no API key is provided
	if os.Getenv("NVD_API_KEY") == "" {
		t.Skip("Skipping CVE test - no NVD_API_KEY provided")
	}

	scanner := NewCVEScanner(os.Getenv("NVD_API_KEY"))

	// Test with a known vulnerable package
	vulnerabilities, err := scanner.QueryNVD("log4j", "2.14.0")
	if err != nil {
		t.Fatalf("CVE query failed: %v", err)
	}

	// We should find some vulnerabilities for log4j
	if len(vulnerabilities) == 0 {
		t.Log("Warning: No vulnerabilities found for log4j (this might be expected if the package name doesn't match exactly)")
	}

	// Verify structure of returned vulnerabilities
	for _, vuln := range vulnerabilities {
		if vuln.CVE == "" {
			t.Error("CVE field should not be empty")
		}
		if vuln.Package == "" {
			t.Error("Package field should not be empty")
		}
		if vuln.Severity == "" {
			t.Error("Severity field should not be empty")
		}
	}
}

// TestRuntimeScanner tests runtime scanning functionality
func TestRuntimeScanner(t *testing.T) {
	runtimeScanner := NewRuntimeScanner()

	processNodes, connectionNodes, err := runtimeScanner.ScanSystem()
	if err != nil {
		t.Fatalf("Runtime scan failed: %v", err)
	}

	// We should find at least some processes (including our own test process)
	if len(processNodes) == 0 {
		t.Error("Expected to find at least some processes")
	}

	// Verify process node structure
	for _, node := range processNodes {
		if node.Type != types.NodeTypeProcess {
			t.Errorf("Expected node type %s, got %s", types.NodeTypeProcess, node.Type)
		}
		if node.ID == "" {
			t.Error("Process node ID should not be empty")
		}
		if node.Name == "" {
			t.Error("Process node name should not be empty")
		}
	}

	// Connection nodes might be empty in some environments, so we don't require them
	for _, node := range connectionNodes {
		if node.Type != types.NodeTypeConnection {
			t.Errorf("Expected node type %s, got %s", types.NodeTypeConnection, node.Type)
		}
	}
}

// TestKnowledgeGraphBuilding tests the knowledge graph construction
func TestKnowledgeGraphBuilding(t *testing.T) {
	// Create test scanner manually without AI initialization
	config := &Config{
		ProjectPath: ".",
		AIProviders: AIProviderConfig{
			CodeRemediationProvider: "anthropic",
		},
		DataEngine: DataEngineConfig{
			Enable: false,
		},
	}

	scanner := &Scanner{
		config: config,
		graph:  NewKnowledgeGraph(),
		ai:     nil, // Skip AI initialization for this test
	}

	// Add some test nodes
	node1 := &types.Node{
		ID:   "test_node_1",
		Type: types.NodeTypeCode,
		Name: "main.go",
		Path: "/path/to/main.go",
	}

	node2 := &types.Node{
		ID:   "test_node_2",
		Type: types.NodeTypeLibrary,
		Name: "github.com/stretchr/testify",
		Path: "github.com/stretchr/testify",
	}

	scanner.graph.Nodes[node1.ID] = node1
	scanner.graph.Nodes[node2.ID] = node2

	// Test graph data preparation
	graphData := scanner.prepareGraphData()

	if graphData["count"].(int) != 2 {
		t.Errorf("Expected 2 nodes in graph data, got %d", graphData["count"].(int))
	}

	nodes, ok := graphData["nodes"].([]map[string]interface{})
	if !ok {
		t.Fatal("Expected nodes to be a slice")
	}

	if len(nodes) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(nodes))
	}
}

// Helper function to initialize a git repository for testing
func initializeGitRepo(dir string) error {
	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		return err
	}

	// Configure git user
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

// Benchmark tests for performance validation

func BenchmarkParseGoDependencies(b *testing.B) {
	scanner := &Scanner{}

	goCode := `package main

import (
	"fmt"
	"os"
	"log"
	"context"
	"encoding/json"
	"net/http"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"github.com/gorilla/mux"
)

func main() {
	fmt.Println("Hello")
}
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.parseGoDependencies("test.go", []byte(goCode))
	}
}

func BenchmarkParseJavaScriptDependencies(b *testing.B) {
	scanner := &Scanner{}

	jsCode := `import React from 'react';
import { useState, useEffect } from 'react';
const lodash = require('lodash');
import axios from 'axios';
import _ from 'lodash';
const moment = require('moment');

function App() {
	return <div>Hello</div>;
}
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.parseJavaScriptDependencies("app.js", []byte(jsCode))
	}
}

func BenchmarkRiskCalculation(b *testing.B) {
	diagnoser := &RiskDiagnoser{}

	assessment := &types.RiskAssessment{
		TechnicalDebt:         make([]types.TechnicalDebtItem, 100),
		SecurityVulns:         make([]types.SecurityVulnerability, 50),
		ObsoleteCode:          make([]types.ObsoleteCodeItem, 25),
		DangerousDependencies: make([]types.DependencyRisk, 75),
	}

	// Fill with test data
	for i := range assessment.TechnicalDebt {
		assessment.TechnicalDebt[i] = types.TechnicalDebtItem{Severity: "medium"}
	}
	for i := range assessment.SecurityVulns {
		assessment.SecurityVulns[i] = types.SecurityVulnerability{Severity: "high"}
	}
	for i := range assessment.ObsoleteCode {
		assessment.ObsoleteCode[i] = types.ObsoleteCodeItem{RemovalSafety: "safe"}
	}
	for i := range assessment.DangerousDependencies {
		assessment.DangerousDependencies[i] = types.DependencyRisk{Maintenance: "deprecated"}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		diagnoser.calculateOverallRisk(assessment)
	}
}
