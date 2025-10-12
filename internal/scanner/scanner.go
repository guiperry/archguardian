package scanner

import (
	"archguardian/inference_engine"
	"archguardian/internal/config"
	"archguardian/types"
	"context"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Scanner handles comprehensive code scanning operations
type Scanner struct {
	config *config.Config
	graph  *types.KnowledgeGraph
	ai     *inference_engine.InferenceService
}

// NewScanner creates a new scanner instance
func NewScanner(cfg *config.Config, ai *inference_engine.InferenceService) *Scanner {
	return &Scanner{
		config: cfg,
		graph: &types.KnowledgeGraph{
			Nodes:         make(map[string]*types.Node),
			Edges:         make([]*types.Edge, 0),
			LastUpdated:   time.Now(),
			AnalysisDepth: 1,
		},
		ai: ai,
	}
}

// ScanProject performs a comprehensive project scan with 7 phases
func (s *Scanner) ScanProject(ctx context.Context) error {
	log.Println("🔍 Starting comprehensive project scan...")

	// Phase 1: Static Code Analysis
	if err := s.scanStaticCode(ctx); err != nil {
		return fmt.Errorf("static code scan failed: %w", err)
	}

	// Phase 2: Dependency Analysis
	if err := s.scanDependencies(); err != nil {
		return fmt.Errorf("dependency scan failed: %w", err)
	}

	// Phase 3: Runtime Inspection
	if err := s.scanRuntime(); err != nil {
		return fmt.Errorf("runtime scan failed: %w", err)
	}

	// Phase 4: Database Schema Analysis
	if err := s.scanDatabaseModels(ctx); err != nil {
		return fmt.Errorf("database scan failed: %w", err)
	}

	// Phase 5: API Discovery
	if err := s.scanAPIs(ctx); err != nil {
		return fmt.Errorf("API scan failed: %w", err)
	}

	// Phase 6: Test Coverage Analysis
	if err := s.scanTestCoverage(ctx); err != nil {
		return fmt.Errorf("test coverage scan failed: %w", err)
	}

	// Phase 7: Build Knowledge Graph
	if err := s.buildKnowledgeGraph(ctx); err != nil {
		return fmt.Errorf("knowledge graph build failed: %w", err)
	}

	s.graph.LastUpdated = time.Now()
	log.Println("✅ Project scan complete")
	return nil
}

// scanStaticCode performs static code analysis on all code files
func (s *Scanner) scanStaticCode(ctx context.Context) error {
	log.Println("  📄 Scanning static code...")

	err := filepath.Walk(s.config.ProjectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip vendor, node_modules, etc.
		if info.IsDir() && (info.Name() == "vendor" || info.Name() == "node_modules" ||
			info.Name() == ".git" || info.Name() == "dist" || info.Name() == "build") {
			return filepath.SkipDir
		}

		if !info.IsDir() && s.isCodeFile(path) {
			node := &types.Node{
				ID:           s.generateNodeID(path),
				Type:         types.NodeTypeCode,
				Name:         filepath.Base(path),
				Path:         path,
				Metadata:     make(map[string]interface{}),
				LastModified: info.ModTime(),
				Dependencies: make([]string, 0),
				Dependents:   make([]string, 0),
			}

			// Parse file for imports/dependencies using AST parsing
			content, err := os.ReadFile(path)
			if err == nil {
				node.Metadata["lines"] = strings.Count(string(content), "\n")
				node.Metadata["size"] = info.Size()

				// Use AST parsing for accurate dependency extraction
				dependencies := s.parseFileDependencies(path, content)
				node.Dependencies = dependencies

				// Use AI for analysis if available - context strategist will handle large files via chunking
				if s.ai != nil && s.ai.IsRunning() {
					// Create a timeout context for AI analysis
					// Timeout is generous to allow for chunking of large files
					// The context strategist will automatically chunk files that exceed token limits
					aiCtx, aiCancel := context.WithTimeout(ctx, 2*time.Minute)
					defer aiCancel()

					log.Printf("  🔍 Analyzing %s (%d bytes) with AI...", filepath.Base(path), info.Size())
					analysis, err := s.ai.GenerateText(aiCtx, "gemini-2.5-flash", fmt.Sprintf("Analyze this code file for complexity and quality:\n\n%s", string(content)), "")
					if err != nil {
						// Log warning but continue - AI analysis is optional
						log.Printf("  ⚠️  AI analysis failed for %s: %v", filepath.Base(path), err)
					} else if analysis != "" {
						node.Metadata["ai_analysis"] = analysis
						log.Printf("  ✅ AI analysis completed for %s", filepath.Base(path))
					}
				}
			}

			s.graph.Nodes[node.ID] = node
		}

		return nil
	})

	return err
}

// scanDependencies scans for project dependencies
func (s *Scanner) scanDependencies() error {
	log.Println("  📦 Scanning dependencies...")

	// Scan go.mod
	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "go.mod")); err == nil {
		return s.scanGoMod()
	}

	// Scan package.json
	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "package.json")); err == nil {
		return s.scanPackageJSON()
	}

	// Scan requirements.txt
	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "requirements.txt")); err == nil {
		return s.scanRequirementsTxt()
	}

	return nil
}

// scanGoMod scans go.mod file for dependencies
func (s *Scanner) scanGoMod() error {
	goModPath := filepath.Join(s.config.ProjectPath, "go.mod")

	content, err := s.readFileSafely(goModPath)
	if err != nil {
		return fmt.Errorf("failed to read go.mod file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require") || strings.Contains(line, "/") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pkg := parts[0]
				version := ""
				if len(parts) >= 2 {
					version = parts[1]
				}

				node := &types.Node{
					ID:   s.generateNodeID("dep:" + pkg),
					Type: types.NodeTypeLibrary,
					Name: pkg,
					Path: pkg,
					Metadata: map[string]interface{}{
						"version": version,
						"manager": "go",
					},
				}
				s.graph.Nodes[node.ID] = node
			}
		}
	}

	return nil
}

// scanPackageJSON scans package.json for dependencies
func (s *Scanner) scanPackageJSON() error {
	content, err := s.readFileSafely(filepath.Join(s.config.ProjectPath, "package.json"))
	if err != nil {
		return fmt.Errorf("failed to read package.json file: %w", err)
	}

	var pkg map[string]interface{}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return fmt.Errorf("failed to parse package.json: %w", err)
	}

	// Process dependencies
	if deps, ok := pkg["dependencies"].(map[string]interface{}); ok {
		for name, version := range deps {
			node := &types.Node{
				ID:   s.generateNodeID("dep:" + name),
				Type: types.NodeTypeLibrary,
				Name: name,
				Path: name,
				Metadata: map[string]interface{}{
					"version": version,
					"manager": "npm",
				},
			}
			s.graph.Nodes[node.ID] = node
		}
	}

	return nil
}

// scanRequirementsTxt scans requirements.txt for Python dependencies
func (s *Scanner) scanRequirementsTxt() error {
	reqPath := filepath.Join(s.config.ProjectPath, "requirements.txt")

	content, err := s.readFileSafely(reqPath)
	if err != nil {
		return fmt.Errorf("failed to read requirements.txt file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "==")
		name := strings.TrimSpace(parts[0])
		version := ""
		if len(parts) > 1 {
			version = strings.TrimSpace(parts[1])
		}

		node := &types.Node{
			ID:   s.generateNodeID("dep:" + name),
			Type: types.NodeTypeLibrary,
			Name: name,
			Path: name,
			Metadata: map[string]interface{}{
				"version": version,
				"manager": "pip",
			},
		}
		s.graph.Nodes[node.ID] = node
	}

	return nil
}

// scanRuntime performs runtime environment scanning
func (s *Scanner) scanRuntime() error {
	log.Println("  🔄 Scanning runtime environment...")

	runtimeScanner := NewRuntimeScanner()
	processNodes, connectionNodes, err := runtimeScanner.ScanSystem()
	if err != nil {
		log.Printf("  ⚠️  Runtime scan failed: %v", err)
		return nil // Don't fail the entire scan for runtime issues
	}

	// Add runtime nodes to knowledge graph
	for _, node := range processNodes {
		s.graph.Nodes[node.ID] = node
	}

	for _, node := range connectionNodes {
		s.graph.Nodes[node.ID] = node
	}

	log.Printf("  📊 Runtime scan complete: %d processes, %d connections",
		len(processNodes), len(connectionNodes))
	return nil
}

// scanDatabaseModels scans for database models and schemas
func (s *Scanner) scanDatabaseModels(ctx context.Context) error {
	log.Println("  🗄️  Scanning database models...")

	// Look for common ORM patterns
	patterns := []string{
		"**/models/*.go",
		"**/entity/*.go",
		"**/models.py",
		"**/schemas/*.ts",
	}

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(s.config.ProjectPath, pattern))
		for _, path := range matches {
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			// Get file info for size check
			fileInfo, err := os.Stat(path)
			if err != nil {
				continue
			}

			// Create node structure
			node := &types.Node{
				ID:       s.generateNodeID(path),
				Type:     types.NodeTypeDatabase,
				Name:     filepath.Base(path),
				Path:     path,
				Metadata: make(map[string]interface{}),
			}

			// Use AI for deep analysis of database models if available
			// Context strategist will handle large files via chunking
			if s.ai != nil && s.ai.IsRunning() {
				// Create a timeout context for AI analysis
				// Timeout is generous to allow for chunking of large files
				aiCtx, aiCancel := context.WithTimeout(ctx, 2*time.Minute)
				defer aiCancel()

				log.Printf("  🔍 Analyzing database model %s (%d bytes) with AI...", filepath.Base(path), fileInfo.Size())
				analysis, err := s.ai.GenerateText(aiCtx, "gemini-2.5-flash", fmt.Sprintf("Analyze this database model for structure and relationships:\n\n%s", string(content)), "")
				if err != nil {
					log.Printf("  ⚠️  AI analysis failed for database model %s: %v", filepath.Base(path), err)
				} else if analysis != "" {
					node.Metadata["analysis"] = analysis
					log.Printf("  ✅ AI analysis completed for database model %s", filepath.Base(path))
				}
			}

			// Add node to graph (with or without AI analysis)
			s.graph.Nodes[node.ID] = node
		}
	}

	return nil
}

// scanAPIs scans for API definitions and endpoints
func (s *Scanner) scanAPIs(ctx context.Context) error {
	_ = ctx // Acknowledge context for future use
	log.Println("  🌐 Scanning API definitions...")

	// Look for API definitions
	patterns := []string{
		"**/routes/*.go",
		"**/api/*.go",
		"**/controllers/*.go",
		"**/openapi.yaml",
		"**/swagger.json",
	}

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(s.config.ProjectPath, pattern))
		for _, path := range matches {
			node := &types.Node{
				ID:       s.generateNodeID(path),
				Type:     types.NodeTypeAPI,
				Name:     filepath.Base(path),
				Path:     path,
				Metadata: make(map[string]interface{}),
			}
			s.graph.Nodes[node.ID] = node
		}
	}

	return nil
}

// scanTestCoverage performs test coverage analysis
func (s *Scanner) scanTestCoverage(ctx context.Context) error {
	log.Println("  📊 Scanning test coverage...")

	// Determine project type and run appropriate coverage command
	var coverageData map[string]interface{}

	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "go.mod")); err == nil {
		coverageData, err = s.scanGoCoverage(ctx)
		if err != nil {
			log.Printf("  ⚠️  Go coverage scan failed: %v", err)
			return nil
		}
	} else if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "package.json")); err == nil {
		coverageData, err = s.scanNodeCoverage(ctx)
		if err != nil {
			log.Printf("  ⚠️  Node.js coverage scan failed: %v", err)
			return nil
		}
	} else if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "requirements.txt")); err == nil {
		coverageData, err = s.scanPythonCoverage(ctx)
		if err != nil {
			log.Printf("  ⚠️  Python coverage scan failed: %v", err)
			return nil
		}
	} else {
		log.Println("  ⚠️  No supported project type found for coverage analysis")
		return nil
	}

	// Store coverage data in knowledge graph
	if coverageData != nil {
		// Create a coverage node
		coverageNode := &types.Node{
			ID:   "coverage_analysis",
			Type: types.NodeTypeCode,
			Name: "Test Coverage",
			Path: "coverage",
			Metadata: map[string]interface{}{
				"coverage_data": coverageData,
				"scan_time":     time.Now(),
			},
		}
		s.graph.Nodes[coverageNode.ID] = coverageNode

		log.Printf("  📊 Coverage scan complete: %.1f%% coverage", coverageData["overall_coverage"].(float64))
	}

	return nil
}

// buildKnowledgeGraph builds relationships between nodes using AI
func (s *Scanner) buildKnowledgeGraph(ctx context.Context) error {
	log.Println("  🕸️  Building knowledge graph...")

	// Use AI for deep reasoning about relationships if available
	if s.ai != nil && s.ai.IsRunning() {
		graphData := s.prepareGraphData()
		relationships, err := s.inferRelationshipsWithAI(ctx, graphData)
		if err != nil {
			log.Printf("Warning: relationship inference failed: %v", err)
		} else {
			// Build edges based on AI inference
			for _, rel := range relationships {
				edge := &types.Edge{
					From:         rel.From,
					To:           rel.To,
					Relationship: rel.Type,
					Strength:     rel.Confidence,
					Metadata:     rel.Metadata,
				}
				s.graph.Edges = append(s.graph.Edges, edge)
			}
		}
	}

	return nil
}

// prepareGraphData prepares graph data for AI analysis
func (s *Scanner) prepareGraphData() map[string]interface{} {
	nodes := make([]map[string]interface{}, 0)
	for _, node := range s.graph.Nodes {
		nodes = append(nodes, map[string]interface{}{
			"id":   node.ID,
			"type": node.Type,
			"name": node.Name,
			"path": node.Path,
		})
	}

	return map[string]interface{}{
		"nodes": nodes,
		"count": len(nodes),
	}
}

// inferRelationshipsWithAI uses AI to infer relationships between nodes
func (s *Scanner) inferRelationshipsWithAI(ctx context.Context, graphData map[string]interface{}) ([]Relationship, error) {
	graphJSON, _ := json.Marshal(graphData)
	prompt := fmt.Sprintf("Analyze these code elements and infer relationships between them. Return JSON with from, to, type, confidence fields:\n\n%s", string(graphJSON))

	response, err := s.ai.GenerateText(ctx, "gemini", prompt, "")
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var relationships []Relationship
	if err := json.Unmarshal([]byte(response), &relationships); err != nil {
		log.Printf("⚠️  Could not parse AI relationship inference: %v", err)
		return nil, fmt.Errorf("failed to parse relationships: %w", err)
	}

	return relationships, nil
}

// Relationship represents a relationship between code elements (local version)
type Relationship struct {
	From       string                 `json:"from"`
	To         string                 `json:"to"`
	Type       string                 `json:"type"`
	Confidence float64                `json:"confidence"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// parseFileDependencies uses AST parsing to extract accurate dependencies from source files
func (s *Scanner) parseFileDependencies(filePath string, content []byte) []string {
	var dependencies []string

	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".go":
		dependencies = s.parseGoDependencies(filePath, content)
	case ".js", ".ts", ".jsx", ".tsx":
		dependencies = s.parseJavaScriptDependencies(filePath, content)
	case ".py":
		dependencies = s.parsePythonDependencies(filePath, content)
	case ".java":
		dependencies = s.parseJavaDependencies(filePath, content)
	default:
		// Fallback to simple regex parsing for unknown file types
		dependencies = s.parseDependenciesWithRegex(filePath, content)
	}

	return dependencies
}

// parseGoDependencies uses go/parser to extract import declarations from Go files
func (s *Scanner) parseGoDependencies(filePath string, content []byte) []string {
	var dependencies []string

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, content, parser.ImportsOnly)
	if err != nil {
		log.Printf("  ⚠️  Failed to parse Go file %s: %v", filePath, err)
		return s.parseDependenciesWithRegex(filePath, content)
	}

	for _, imp := range node.Imports {
		depPath := strings.Trim(imp.Path.Value, "\"")
		if depPath != "" {
			dependencies = append(dependencies, depPath)
		}
	}

	return dependencies
}

// parseJavaScriptDependencies uses regex to extract import/require statements from JS/TS files
func (s *Scanner) parseJavaScriptDependencies(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Match ES6 imports: import ... from 'module'
	importRegex := regexp.MustCompile(`import\s+.*?\s+from\s+['"]([^'"]+)['"]`)
	matches := importRegex.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) > 1 && match[1] != "" {
			dependencies = append(dependencies, match[1])
		}
	}

	// Match CommonJS requires: require('module')
	requireRegex := regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	requireMatches := requireRegex.FindAllStringSubmatch(text, -1)
	for _, match := range requireMatches {
		if len(match) > 1 && match[1] != "" {
			dependencies = append(dependencies, match[1])
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// parsePythonDependencies uses regex to extract import statements from Python files
func (s *Scanner) parsePythonDependencies(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Match import statements: import module or from module import ...
	importRegex := regexp.MustCompile(`(?m)^(?:import\s+(\S+)|from\s+(\S+)\s+import)`)
	matches := importRegex.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				// Extract the module name (first part before dots)
				moduleName := strings.Split(match[i], ".")[0]
				if moduleName != "" {
					dependencies = append(dependencies, moduleName)
				}
				break
			}
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// parseJavaDependencies uses regex to extract import statements from Java files
func (s *Scanner) parseJavaDependencies(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Match Java import statements: import package.Class;
	importRegex := regexp.MustCompile(`import\s+([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)*)\s*;`)
	matches := importRegex.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 && match[1] != "" {
			dependencies = append(dependencies, match[1])
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// parseDependenciesWithRegex is a fallback method using regex for unknown file types
func (s *Scanner) parseDependenciesWithRegex(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Generic patterns for various languages
	patterns := []string{
		`import\s+['"]([^'"]+)['"]`,
		`from\s+['"]([^'"]+)['"]`,
		`require\s*\(\s*['"]([^'"]+)['"]\s*\)`,
		`#include\s+[<"]([^>"]+)[>"]`,
		`use\s+(\S+)`,
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				dependencies = append(dependencies, match[1])
			}
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// scanGoCoverage runs Go test coverage analysis
func (s *Scanner) scanGoCoverage(ctx context.Context) (map[string]interface{}, error) {
	_ = ctx // Acknowledge context for future use

	// Run go test with coverage
	cmd := exec.Command("go", "test", "-coverprofile=coverage.out", "./...")
	cmd.Dir = s.config.ProjectPath
	_, err := cmd.CombinedOutput()
	if err != nil {
		// Some packages might not have tests, which is okay
		log.Printf("  ⚠️  Go test failed (some packages may not have tests): %v", err)
	}

	// Parse coverage output
	coverageFile := filepath.Join(s.config.ProjectPath, "coverage.out")
	if _, err := os.Stat(coverageFile); err != nil {
		return map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
		}, nil
	}

	// Read and parse coverage file
	content, err := os.ReadFile(coverageFile)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	totalLines := 0
	coveredLines := 0

	// Count total and covered lines
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 3 {
			// Parse coverage count (number of times line was executed)
			count := 0
			fmt.Sscanf(parts[2], "%d", &count)
			totalLines++

			if count > 0 {
				coveredLines++
			}
		}
	}

	// Calculate coverage percentage
	var coveragePercent float64
	if totalLines > 0 {
		coveragePercent = (float64(coveredLines) / float64(totalLines)) * 100
	}

	// Count test files
	testFiles := 0
	err = filepath.Walk(s.config.ProjectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			testFiles++
		}
		return nil
	})

	if err != nil {
		log.Printf("  ⚠️  Failed to count test files: %v", err)
	}

	// Clean up coverage file
	os.Remove(coverageFile)

	return map[string]interface{}{
		"overall_coverage": coveragePercent,
		"lines_covered":    coveredLines,
		"total_lines":      totalLines,
		"test_files":       testFiles,
		"language":         "go",
	}, nil
}

// scanNodeCoverage runs Node.js test coverage analysis
func (s *Scanner) scanNodeCoverage(ctx context.Context) (map[string]interface{}, error) {
	_ = ctx // Acknowledge context for future use

	// Check if Jest or other testing framework is available
	var cmd *exec.Cmd

	// Try Jest first
	if s.hasJestConfig() {
		cmd = exec.Command("npx", "jest", "--coverage", "--coverageReporters=json")
	} else if s.hasVitestConfig() {
		cmd = exec.Command("npx", "vitest", "run", "--coverage")
	} else {
		// Fallback to basic test command
		cmd = exec.Command("npm", "test")
	}

	cmd.Dir = s.config.ProjectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("  ⚠️  Node.js test failed: %v", err)
		log.Printf("  Output: %s", string(output))
		// Return zero coverage data instead of failing
		return map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
		}, nil
	}

	// Log successful test output for debugging
	log.Printf("  ✅ Node.js tests completed successfully")

	// Try to read coverage report
	coverageReport := filepath.Join(s.config.ProjectPath, "coverage", "coverage-final.json")
	if _, err := os.Stat(coverageReport); err != nil {
		// Try alternative locations
		coverageReport = filepath.Join(s.config.ProjectPath, "coverage.json")
		if _, err := os.Stat(coverageReport); err != nil {
			return map[string]interface{}{
				"overall_coverage": 0.0,
				"lines_covered":    0,
				"total_lines":      0,
				"test_files":       0,
			}, nil
		}
	}

	// Parse coverage report
	content, err := os.ReadFile(coverageReport)
	if err != nil {
		return nil, err
	}

	var coverage map[string]interface{}
	if err := json.Unmarshal(content, &coverage); err != nil {
		return nil, err
	}

	// Extract coverage data
	totalLines := 0
	coveredLines := 0

	// Parse Jest/Vitest coverage format
	if coverageData, ok := coverage["total"].(map[string]interface{}); ok {
		if lines, ok := coverageData["lines"].(map[string]interface{}); ok {
			if total, ok := lines["total"].(float64); ok {
				totalLines = int(total)
			}
			if covered, ok := lines["covered"].(float64); ok {
				coveredLines = int(covered)
			}
		}
	}

	var coveragePercent float64
	if totalLines > 0 {
		coveragePercent = (float64(coveredLines) / float64(totalLines)) * 100
	}

	// Count test files
	testFiles := 0
	testPatterns := []string{"**/*.test.js", "**/*.test.ts", "**/*.spec.js", "**/*.spec.ts"}
	for _, pattern := range testPatterns {
		matches, _ := filepath.Glob(filepath.Join(s.config.ProjectPath, pattern))
		testFiles += len(matches)
	}

	return map[string]interface{}{
		"overall_coverage": coveragePercent,
		"lines_covered":    coveredLines,
		"total_lines":      totalLines,
		"test_files":       testFiles,
		"language":         "javascript",
		"raw_output":       string(output),
	}, nil
}

// scanPythonCoverage runs Python test coverage analysis
func (s *Scanner) scanPythonCoverage(ctx context.Context) (map[string]interface{}, error) {
	_ = ctx // Acknowledge context for future use

	// Check if pytest is available
	cmd := exec.Command("python", "-m", "pytest", "--cov=.", "--cov-report=json", "--cov-report=term-missing")
	cmd.Dir = s.config.ProjectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("  ⚠️  Python test failed: %v", err)
		return map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
		}, nil
	}

	// Try to read coverage report
	coverageReport := filepath.Join(s.config.ProjectPath, "coverage.json")
	if _, err := os.Stat(coverageReport); err != nil {
		return map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
		}, nil
	}

	// Parse coverage report
	content, err := os.ReadFile(coverageReport)
	if err != nil {
		return nil, err
	}

	var coverage map[string]interface{}
	if err := json.Unmarshal(content, &coverage); err != nil {
		return nil, err
	}

	// Extract coverage data from pytest-cov format
	totalLines := 0
	coveredLines := 0

	if totals, ok := coverage["totals"].(map[string]interface{}); ok {
		if lines, ok := totals["lines"].(map[string]interface{}); ok {
			if total, ok := lines["total"].(float64); ok {
				totalLines = int(total)
			}
			if covered, ok := lines["covered"].(float64); ok {
				coveredLines = int(covered)
			}
		}
	}

	var coveragePercent float64
	if totalLines > 0 {
		coveragePercent = (float64(coveredLines) / float64(totalLines)) * 100
	}

	// Count test files
	testFiles := 0
	testPatterns := []string{"**/test_*.py", "**/*_test.py"}
	for _, pattern := range testPatterns {
		matches, _ := filepath.Glob(filepath.Join(s.config.ProjectPath, pattern))
		testFiles += len(matches)
	}

	return map[string]interface{}{
		"overall_coverage": coveragePercent,
		"lines_covered":    coveredLines,
		"total_lines":      totalLines,
		"test_files":       testFiles,
		"language":         "python",
		"raw_output":       string(output),
	}, nil
}

// Helper functions

func (s *Scanner) hasJestConfig() bool {
	configFiles := []string{"jest.config.js", "jest.config.ts", "jest.config.json"}
	for _, file := range configFiles {
		if _, err := os.Stat(filepath.Join(s.config.ProjectPath, file)); err == nil {
			return true
		}
	}
	return false
}

func (s *Scanner) hasVitestConfig() bool {
	configFiles := []string{"vitest.config.js", "vitest.config.ts", "vite.config.ts"}
	for _, file := range configFiles {
		if _, err := os.Stat(filepath.Join(s.config.ProjectPath, file)); err == nil {
			return true
		}
	}
	return false
}

func (s *Scanner) isCodeFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	codeExts := []string{".go", ".py", ".js", ".ts", ".java", ".cpp", ".c", ".rs", ".rb",
		".php", ".cs", ".swift", ".kt", ".scala", ".sql"}

	for _, codeExt := range codeExts {
		if ext == codeExt {
			return true
		}
	}
	return false
}

func (s *Scanner) generateNodeID(path string) string {
	// Simple hash-based ID generation
	return fmt.Sprintf("node_%x", []byte(path))
}

func (s *Scanner) readFileSafely(filePath string) ([]byte, error) {
	// Basic validation - ensure path doesn't contain dangerous patterns
	if strings.Contains(filePath, "..") {
		return nil, fmt.Errorf("invalid file path: contains path traversal")
	}

	// Check for absolute paths that aren't in safe locations
	if filepath.IsAbs(filePath) {
		// Allow only specific safe directories
		safePrefixes := []string{"/home/", "/Users/", "/opt/", "/app/", "/workspace/", "/project/", "/tmp/", "/var/tmp/"}
		isSafe := false
		for _, prefix := range safePrefixes {
			if strings.HasPrefix(filePath, prefix) {
				isSafe = true
				break
			}
		}
		if !isSafe {
			return nil, fmt.Errorf("invalid file path: absolute path in unsafe location")
		}
	}

	// Read the file
	return os.ReadFile(filePath)
}

// GetKnowledgeGraph returns the current knowledge graph
func (s *Scanner) GetKnowledgeGraph() *types.KnowledgeGraph {
	return s.graph
}

// RuntimeScanner handles runtime system inspection
type RuntimeScanner struct{}

// NewRuntimeScanner creates a new runtime scanner instance
func NewRuntimeScanner() *RuntimeScanner {
	return &RuntimeScanner{}
}

// ScanSystem performs comprehensive runtime inspection of the host system
func (rs *RuntimeScanner) ScanSystem() ([]*types.Node, []*types.Node, error) {
	var processNodes []*types.Node
	var connectionNodes []*types.Node

	// Scan running processes
	processes, err := rs.scanProcesses()
	if err != nil {
		log.Printf("  ⚠️  Failed to scan processes: %v", err)
	} else {
		processNodes = append(processNodes, processes...)
	}

	// Scan network connections
	connections, err := rs.scanNetworkConnections()
	if err != nil {
		log.Printf("  ⚠️  Failed to scan network connections: %v", err)
	} else {
		connectionNodes = append(connectionNodes, connections...)
	}

	// Scan system resources (CPU, Memory, Disk)
	resourceNodes, err := rs.scanSystemResources()
	if err != nil {
		log.Printf("  ⚠️  Failed to scan system resources: %v", err)
	} else {
		processNodes = append(processNodes, resourceNodes...)
	}

	log.Printf("  📊 Runtime scan found: %d processes, %d connections, %d resource nodes",
		len(processNodes), len(connectionNodes), len(resourceNodes))

	return processNodes, connectionNodes, nil
}

// scanProcesses inspects all running processes on the system
func (rs *RuntimeScanner) scanProcesses() ([]*types.Node, error) {
	var nodes []*types.Node

	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %w", err)
	}

	for _, proc := range processes {
		name, err := proc.Name()
		if err != nil {
			continue // Skip processes we can't read
		}

		cmdLine, _ := proc.Cmdline()
		exe, _ := proc.Exe()
		cpuPercent, _ := proc.CPUPercent()
		memoryInfo, _ := proc.MemoryInfo()

		node := &types.Node{
			ID:   fmt.Sprintf("process_%d", proc.Pid),
			Type: types.NodeTypeProcess,
			Name: name,
			Path: exe,
			Metadata: map[string]interface{}{
				"pid":         proc.Pid,
				"cmdline":     cmdLine,
				"cpu_percent": cpuPercent,
				"status":      "running",
			},
		}

		if memoryInfo != nil {
			node.Metadata["memory_rss"] = memoryInfo.RSS
			node.Metadata["memory_vms"] = memoryInfo.VMS
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// scanNetworkConnections inspects active network connections
func (rs *RuntimeScanner) scanNetworkConnections() ([]*types.Node, error) {
	var nodes []*types.Node

	connections, err := net.Connections("all")
	if err != nil {
		return nil, fmt.Errorf("failed to get network connections: %w", err)
	}

	// Group connections by local address to create network nodes
	connectionMap := make(map[string]*types.Node)

	for _, conn := range connections {
		localAddr := fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port)
		remoteAddr := fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port)

		if existingNode, exists := connectionMap[localAddr]; exists {
			// Add to existing connection node
			if conns, ok := existingNode.Metadata["connections"].([]map[string]interface{}); ok {
				conns = append(conns, map[string]interface{}{
					"remote_address": remoteAddr,
					"status":         conn.Status,
					"protocol":       rs.getProtocolName(conn.Type),
				})
				existingNode.Metadata["connections"] = conns
			}
		} else {
			// Create new connection node
			node := &types.Node{
				ID:   fmt.Sprintf("connection_%s", localAddr),
				Type: types.NodeTypeConnection,
				Name: fmt.Sprintf("Connection %s", localAddr),
				Path: localAddr,
				Metadata: map[string]interface{}{
					"local_address": localAddr,
					"connections": []map[string]interface{}{
						{
							"remote_address": remoteAddr,
							"status":         conn.Status,
							"protocol":       rs.getProtocolName(conn.Type),
						},
					},
				},
			}
			connectionMap[localAddr] = node
			nodes = append(nodes, node)
		}
	}

	return nodes, nil
}

// scanSystemResources scans system-wide resource utilization
func (rs *RuntimeScanner) scanSystemResources() ([]*types.Node, error) {
	var nodes []*types.Node

	// CPU information
	cpuPercent, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercent) > 0 {
		node := &types.Node{
			ID:   "resource_cpu",
			Type: types.NodeTypeProcess,
			Name: "CPU Usage",
			Path: "system",
			Metadata: map[string]interface{}{
				"resource_type": "cpu",
				"usage_percent": cpuPercent[0],
			},
		}
		nodes = append(nodes, node)
	}

	// Memory information
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		node := &types.Node{
			ID:   "resource_memory",
			Type: types.NodeTypeProcess,
			Name: "Memory Usage",
			Path: "system",
			Metadata: map[string]interface{}{
				"resource_type":   "memory",
				"total_bytes":     memInfo.Total,
				"available_bytes": memInfo.Available,
				"used_bytes":      memInfo.Used,
				"usage_percent":   memInfo.UsedPercent,
			},
		}
		nodes = append(nodes, node)
	}

	// Disk information
	diskInfo, err := disk.Usage("/")
	if err == nil {
		node := &types.Node{
			ID:   "resource_disk",
			Type: types.NodeTypeProcess,
			Name: "Disk Usage",
			Path: "system",
			Metadata: map[string]interface{}{
				"resource_type": "disk",
				"total_bytes":   diskInfo.Total,
				"free_bytes":    diskInfo.Free,
				"used_bytes":    diskInfo.Used,
				"usage_percent": diskInfo.UsedPercent,
			},
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// getProtocolName converts connection type number to protocol name
func (rs *RuntimeScanner) getProtocolName(connType uint32) string {
	switch connType {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return fmt.Sprintf("Type_%d", connType)
	}
}
