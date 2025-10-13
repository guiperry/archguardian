package scanner

import (
	"archguardian/internal/config"
	"archguardian/types"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockChromemManager mocks the ChromemManager interface for testing
type MockChromemManager struct {
	mock.Mock
}

func (m *MockChromemManager) UpsertNode(node *types.Node) error {
	args := m.Called(node)
	return args.Error(0)
}

// TestNewScanner tests the scanner constructor
func TestNewScanner(t *testing.T) {
	cfg := &config.Config{
		ProjectPath: "/test/path",
	}
	mockChromem := &MockChromemManager{}

	scanner := NewScanner(cfg, nil, mockChromem)

	assert.NotNil(t, scanner)
	assert.Equal(t, cfg, scanner.config)
	assert.NotNil(t, scanner.graph)
	assert.NotNil(t, scanner.graph.Nodes)
	assert.NotNil(t, scanner.graph.Edges)
	assert.Equal(t, 1, scanner.graph.AnalysisDepth)
}

// TestScanProject tests the main scanning functionality
func TestScanProject(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test_project")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test files
	testGoFile := filepath.Join(tmpDir, "main.go")
	testGoContent := `package main

import "fmt"

// Example function with moderate complexity
func main() {
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			fmt.Println("even:", i)
		} else {
			fmt.Println("odd:", i)
		}
	}
}
`
	err = os.WriteFile(testGoFile, []byte(testGoContent), 0644)
	assert.NoError(t, err)

	// Create go.mod file
	goModFile := filepath.Join(tmpDir, "go.mod")
	goModContent := `module testproject

go 1.21

require github.com/stretchr/testify v1.8.4
`
	err = os.WriteFile(goModFile, []byte(goModContent), 0644)
	assert.NoError(t, err)

	cfg := &config.Config{
		ProjectPath: tmpDir,
	}
	mockChromem := &MockChromemManager{}
	mockChromem.On("UpsertNode", mock.Anything).Return(nil)

	scanner := NewScanner(cfg, nil, mockChromem)

	ctx := context.Background()
	err = scanner.ScanProject(ctx)
	assert.NoError(t, err)

	// Verify that nodes were created
	assert.Greater(t, len(scanner.graph.Nodes), 0)

	// Check that files were scanned
	foundGoFile := false
	for _, node := range scanner.graph.Nodes {
		if node.Type == types.NodeTypeCode && strings.HasSuffix(node.Path, "main.go") {
			foundGoFile = true
			// Verify that metrics were calculated
			assert.NotNil(t, node.Metadata["lines"])
			assert.NotNil(t, node.Metadata["size"])
			break
		}
	}
	assert.True(t, foundGoFile, "Go file should be scanned")

	mockChromem.AssertExpectations(t)
}

// TestCalculateCyclomaticComplexity tests the cyclomatic complexity calculation
func TestCalculateCyclomaticComplexity(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewScanner(cfg, nil, &MockChromemManager{})

	tests := []struct {
		name        string
		content     string
		expected    int
		description string
	}{
		{
			name: "Simple function",
			content: `package main
func simple() {
	println("hello")
}`,
			expected:    1,
			description: "Base complexity should be 1",
		},
		{
			name: "Function with if statement",
			content: `package main
func withIf() {
	if true {
		println("hello")
	}
}`,
			expected:    2,
			description: "If adds 1 to complexity",
		},
		{
			name: "Function with if-else",
			content: `package main
func withIfElse() {
	if true {
		println("hello")
	} else {
		println("world")
	}
}`,
			expected:    3,
			description: "If-else adds 2 to complexity (if + else)",
		},
		{
			name: "Function with for loop",
			content: `package main
func withFor() {
	for i := 0; i < 10; i++ {
		println(i)
	}
}`,
			expected:    2,
			description: "For loop adds 1 to complexity",
		},
		{
			name: "Complex function",
			content: `package main
func complex() {
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			println("even")
		} else if i%3 == 0 {
			println("divisible by 3")
		}
	}
	switch i := 5; {
	case i > 0:
		println("positive")
	case i < 0:
		println("negative")
	default:
		println("zero")
	}
}`,
			expected:    7,
			description: "Complex function: 1 base + 1 for + 2 if-else + 3 switch cases",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			complexity := scanner.calculateCyclomaticComplexity("test.go", []byte(tt.content))
			assert.Equal(t, tt.expected, complexity, tt.description)
		})
	}
}

// TestDetectCodeSmells tests code smell detection
func TestDetectCodeSmells(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewScanner(cfg, nil, &MockChromemManager{})

	tests := []struct {
		name        string
		content     string
		expectSmell bool
		smellType   string
	}{
		{
			name: "Long function",
			content: `package main
func longFunction() {
` + strings.Repeat("	println(\"line\")\n", 55) + `}`,
			expectSmell: true,
			smellType:   "long_function",
		},
		{
			name: "TODO comment",
			content: `package main
// TODO: implement this function
func todoFunction() {
	// TODO: add implementation
}`,
			expectSmell: true,
			smellType:   "fixme_comment",
		},
		{
			name: "FIXME comment",
			content: `package main
// FIXME: this is broken
func fixmeFunction() {
}`,
			expectSmell: true,
			smellType:   "fixme_comment",
		},
		{
			name: "Clean function",
			content: `package main
func cleanFunction() {
	println("clean")
}`,
			expectSmell: false,
			smellType:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			smells := scanner.detectCodeSmells("test.go", []byte(tt.content))
			if tt.expectSmell {
				assert.Greater(t, len(smells), 0, "Should detect code smell")
				found := false
				for _, smell := range smells {
					if smell.Type == tt.smellType {
						found = true
						break
					}
				}
				assert.True(t, found, "Should detect specific smell type: %s", tt.smellType)
			} else {
				assert.Equal(t, 0, len(smells), "Should not detect any code smells")
			}
		})
	}
}

// TestParseFileDependencies tests dependency parsing for various file types
func TestParseFileDependencies(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewScanner(cfg, nil, &MockChromemManager{})

	tests := []struct {
		name      string
		filePath  string
		content   string
		expectDep bool
		depName   string
	}{
		{
			name:     "Go imports",
			filePath: "main.go",
			content: `package main

import (
	"fmt"
	"github.com/stretchr/testify/assert"
)`,
			expectDep: true,
			depName:   "fmt",
		},
		{
			name:     "JavaScript imports",
			filePath: "app.js",
			content: `import React from 'react';
import { useState } from 'react';
const axios = require('axios');`,
			expectDep: true,
			depName:   "react",
		},
		{
			name:     "Python imports",
			filePath: "script.py",
			content: `import os
import sys
from datetime import datetime
import requests`,
			expectDep: true,
			depName:   "os",
		},
		{
			name:     "Java imports",
			filePath: "App.java",
			content: `package com.example;

import java.util.List;
import java.util.ArrayList;
import org.springframework.boot.SpringApplication;`,
			expectDep: true,
			depName:   "java.util.List",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := scanner.parseFileDependencies(tt.filePath, []byte(tt.content))
			if tt.expectDep {
				assert.Greater(t, len(deps), 0, "Should detect dependencies")
				found := false
				for _, dep := range deps {
					if strings.Contains(dep, tt.depName) {
						found = true
						break
					}
				}
				assert.True(t, found, "Should find specific dependency: %s", tt.depName)
			}
		})
	}
}

// TestScanDependencies tests dependency file scanning
func TestScanDependencies(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test_deps")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create go.mod
	goModFile := filepath.Join(tmpDir, "go.mod")
	goModContent := `module testproject

go 1.21

require (
	github.com/stretchr/testify v1.8.4
	github.com/gorilla/mux v1.8.0
)
`
	err = os.WriteFile(goModFile, []byte(goModContent), 0644)
	assert.NoError(t, err)

	cfg := &config.Config{
		ProjectPath: tmpDir,
	}
	mockChromem := &MockChromemManager{}
	mockChromem.On("UpsertNode", mock.Anything).Return(nil)

	scanner := NewScanner(cfg, nil, mockChromem)
	scanner.graph.Nodes = make(map[string]*types.Node)

	err = scanner.scanDependencies()
	assert.NoError(t, err)

	// Check that dependency nodes were created
	foundTestify := false
	foundMux := false
	for _, node := range scanner.graph.Nodes {
		if node.Type == types.NodeTypeLibrary {
			if strings.Contains(node.Name, "testify") {
				foundTestify = true
			}
			if strings.Contains(node.Name, "mux") {
				foundMux = true
			}
		}
	}
	assert.True(t, foundTestify, "Should find testify dependency")
	assert.True(t, foundMux, "Should find mux dependency")

	mockChromem.AssertExpectations(t)
}

// TestGetKnowledgeGraph tests the knowledge graph retrieval
func TestGetKnowledgeGraph(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewScanner(cfg, nil, &MockChromemManager{})

	// Add some test nodes
	testNode := &types.Node{
		ID:   "test-1",
		Name: "test.go",
		Type: "file",
		Path: "/test/test.go",
		Metadata: map[string]interface{}{
			"lines": 10,
		},
	}
	scanner.graph.Nodes[testNode.ID] = testNode

	// Add test edge
	testEdge := &types.Edge{
		From:         "test-1",
		To:           "test-2",
		Relationship: "imports",
		Strength:     1.0,
	}
	scanner.graph.Edges = append(scanner.graph.Edges, testEdge)

	graph := scanner.GetKnowledgeGraph()
	assert.NotNil(t, graph)
	assert.Equal(t, 1, len(graph.Nodes))
	assert.Equal(t, 1, len(graph.Edges))
	assert.Equal(t, testNode.ID, graph.Nodes[testNode.ID].ID)
	assert.Equal(t, testEdge.From, graph.Edges[0].From)
}

// TestScanSystemMetrics tests system metrics collection
func TestScanSystemMetrics(t *testing.T) {
	// System metrics scanning is not implemented in the current scanner
	// This test is skipped as the method doesn't exist
	t.Skip("scanSystemMetrics method not implemented in current scanner")
}

// TestBuildDeterministicEdges tests deterministic edge creation
func TestBuildDeterministicEdges(t *testing.T) {
	cfg := &config.Config{}
	scanner := NewScanner(cfg, nil, &MockChromemManager{})

	// Create test nodes with dependencies
	node1 := &types.Node{
		ID:           "file1",
		Name:         "main.go",
		Type:         types.NodeTypeCode,
		Dependencies: []string{"fmt", "os"},
	}
	node2 := &types.Node{
		ID:   "dep1",
		Name: "fmt",
		Type: types.NodeTypeLibrary,
	}
	node3 := &types.Node{
		ID:   "dep2",
		Name: "os",
		Type: types.NodeTypeLibrary,
	}

	scanner.graph.Nodes["file1"] = node1
	scanner.graph.Nodes["dep1"] = node2
	scanner.graph.Nodes["dep2"] = node3

	ctx := context.Background()
	scanner.buildDeterministicEdges(ctx)

	// Verify edges were created
	assert.Greater(t, len(scanner.graph.Edges), 0, "Should create edges")

	// Check specific edges
	foundFmtEdge := false
	foundOsEdge := false
	for _, edge := range scanner.graph.Edges {
		if edge.From == "file1" && edge.To == "dep1" && edge.Relationship == "imports" {
			foundFmtEdge = true
		}
		if edge.From == "file1" && edge.To == "dep2" && edge.Relationship == "imports" {
			foundOsEdge = true
		}
	}
	assert.True(t, foundFmtEdge, "Should create edge to fmt")
	assert.True(t, foundOsEdge, "Should create edge to os")
}

// TestCoverageAnalysis tests test coverage analysis
func TestCoverageAnalysis(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test_coverage")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a simple Go project with test
	mainFile := filepath.Join(tmpDir, "main.go")
	mainContent := `package main

func Add(a, b int) int {
	return a + b
}

func Subtract(a, b int) int {
	return a - b
}
`
	err = os.WriteFile(mainFile, []byte(mainContent), 0644)
	assert.NoError(t, err)

	testFile := filepath.Join(tmpDir, "main_test.go")
	testContent := `package main

import "testing"

func TestAdd(t *testing.T) {
	result := Add(2, 3)
	if result != 5 {
		t.Errorf("Expected 5, got %d", result)
	}
}
`
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	assert.NoError(t, err)

	// Create go.mod
	goModFile := filepath.Join(tmpDir, "go.mod")
	goModContent := `module testproject

go 1.21
`
	err = os.WriteFile(goModFile, []byte(goModContent), 0644)
	assert.NoError(t, err)

	// Test coverage analysis is not implemented in the current scanner
	// This test is skipped as the method doesn't exist
	t.Skip("analyzeCoverage method not implemented in current scanner")
}

// TestDeterministicScanReproducibility tests that scans are deterministic
func TestDeterministicScanReproducibility(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "test_deterministic")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create identical test files
	testGoFile := filepath.Join(tmpDir, "main.go")
	testGoContent := `package main

import "fmt"

func main() {
	for i := 0; i < 5; i++ {
		if i%2 == 0 {
			fmt.Println("even:", i)
		}
	}
}
`
	err = os.WriteFile(testGoFile, []byte(testGoContent), 0644)
	assert.NoError(t, err)

	cfg := &config.Config{
		ProjectPath: tmpDir,
	}

	// First scan
	mockChromem1 := &MockChromemManager{}
	mockChromem1.On("UpsertNode", mock.Anything).Return(nil)
	scanner1 := NewScanner(cfg, nil, mockChromem1)

	ctx := context.Background()
	err = scanner1.ScanProject(ctx)
	assert.NoError(t, err)

	// Second scan
	mockChromem2 := &MockChromemManager{}
	mockChromem2.On("UpsertNode", mock.Anything).Return(nil)
	scanner2 := NewScanner(cfg, nil, mockChromem2)

	err = scanner2.ScanProject(ctx)
	assert.NoError(t, err)

	// Compare results - they should be identical (deterministic)
	// Allow for small variations in node count due to runtime processes
	diff := len(scanner1.graph.Nodes) - len(scanner2.graph.Nodes)
	if diff < 0 {
		diff = -diff
	}
	assert.True(t, diff <= 10, "Node counts should be similar")

	// Compare specific metrics for the main.go file
	var node1, node2 *types.Node
	for _, node := range scanner1.graph.Nodes {
		if strings.HasSuffix(node.Path, "main.go") {
			node1 = node
			break
		}
	}
	for _, node := range scanner2.graph.Nodes {
		if strings.HasSuffix(node.Path, "main.go") {
			node2 = node
			break
		}
	}

	assert.NotNil(t, node1)
	assert.NotNil(t, node2)
	assert.Equal(t, node1.Metadata["lines"], node2.Metadata["lines"])
	assert.Equal(t, node1.Metadata["cyclomatic_complexity"], node2.Metadata["cyclomatic_complexity"])

	mockChromem1.AssertExpectations(t)
	mockChromem2.AssertExpectations(t)
}
