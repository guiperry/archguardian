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

// ChromemManager interface for database operations
type ChromemManager interface {
	UpsertNode(node *types.Node) error
}

// Scanner handles comprehensive code scanning operations
type Scanner struct {
	config         *config.Config
	graph          *types.KnowledgeGraph
	ai             *inference_engine.InferenceService
	chromemManager ChromemManager
}

// NewScanner creates a new scanner instance
func NewScanner(cfg *config.Config, ai *inference_engine.InferenceService, chromemManager ChromemManager) *Scanner {
	return &Scanner{
		config: cfg,
		graph: &types.KnowledgeGraph{
			Nodes:         make(map[string]*types.Node),
			Edges:         make([]*types.Edge, 0),
			LastUpdated:   time.Now(),
			AnalysisDepth: 1,
		},
		ai:             ai,
		chromemManager: chromemManager,
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
func (s *Scanner) scanStaticCode(_ context.Context) error {
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

				// Calculate deterministic code quality metrics
				complexity := s.calculateCyclomaticComplexity(path, content)
				node.Metadata["cyclomatic_complexity"] = complexity

				// Detect code smells using rule-based patterns
				codeSmells := s.detectCodeSmells(path, content)
				if len(codeSmells) > 0 {
					node.Metadata["code_smells"] = codeSmells
				}

				log.Printf("  📊 Analyzed %s: %d lines, complexity %d, %d code smells",
					filepath.Base(path), node.Metadata["lines"], complexity, len(codeSmells))
			}

			s.graph.Nodes[node.ID] = node

			// Persist node to database immediately for real-time dashboard updates
			s.persistNodeToDatabase(node)
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
				s.persistNodeToDatabase(node)
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
			s.persistNodeToDatabase(node)
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
		s.persistNodeToDatabase(node)
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
		s.persistNodeToDatabase(node)
	}

	for _, node := range connectionNodes {
		s.graph.Nodes[node.ID] = node
		s.persistNodeToDatabase(node)
	}

	log.Printf("  📊 Runtime scan complete: %d processes, %d connections",
		len(processNodes), len(connectionNodes))
	return nil
}

// scanDatabaseModels scans for database models and schemas
func (s *Scanner) scanDatabaseModels(_ context.Context) error {
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

			// Create node structure
			node := &types.Node{
				ID:       s.generateNodeID(path),
				Type:     types.NodeTypeDatabase,
				Name:     filepath.Base(path),
				Path:     path,
				Metadata: make(map[string]interface{}),
			}

			// Extract deterministic database relationships
			relationships := s.extractDatabaseRelationships(path, content)
			if len(relationships) > 0 {
				node.Metadata["relationships"] = relationships
			}

			log.Printf("  📊 Analyzed database model %s: %d relationships", filepath.Base(path), len(relationships))

			// Add node to graph (with or without AI analysis)
			s.graph.Nodes[node.ID] = node

			// Persist node to database immediately
			s.persistNodeToDatabase(node)
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

			// Persist node to database immediately
			s.persistNodeToDatabase(node)
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

// buildKnowledgeGraph builds relationships between nodes deterministically
func (s *Scanner) buildKnowledgeGraph(ctx context.Context) error {
	log.Println("  🕸️  Building knowledge graph...")

	// Prepare graph data for relationship analysis
	graphData := s.prepareGraphData()
	log.Printf("  📊 Prepared graph data with %d nodes", graphData["count"])

	// Infer relationships using deterministic rule-based analysis
	relationships := s.inferRelationshipsDeterministically(graphData)

	// Convert relationships to graph edges
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

	// Also build edges from existing deterministic methods
	s.buildDeterministicEdges(ctx)

	log.Printf("  🕸️  Knowledge graph complete: %d nodes, %d edges", len(s.graph.Nodes), len(s.graph.Edges))
	return nil
}

// prepareGraphData prepares graph data for deterministic relationship analysis
func (s *Scanner) prepareGraphData() map[string]interface{} {
	nodes := make([]map[string]interface{}, 0)
	for _, node := range s.graph.Nodes {
		nodes = append(nodes, map[string]interface{}{
			"id":           node.ID,
			"type":         node.Type,
			"name":         node.Name,
			"path":         node.Path,
			"dependencies": node.Dependencies,
			"metadata":     node.Metadata,
		})
	}

	return map[string]interface{}{
		"nodes": nodes,
		"count": len(nodes),
	}
}

// inferRelationshipsDeterministically uses rule-based analysis to infer relationships between nodes
func (s *Scanner) inferRelationshipsDeterministically(graphData map[string]interface{}) []Relationship {
	var relationships []Relationship

	nodes, ok := graphData["nodes"].([]map[string]interface{})
	if !ok {
		return relationships
	}

	// Create a map for quick node lookup
	nodeMap := make(map[string]map[string]interface{})
	for _, node := range nodes {
		nodeMap[node["id"].(string)] = node
	}

	// Rule 1: File import relationships
	for _, node := range nodes {
		if deps, ok := node["dependencies"].([]string); ok {
			for _, dep := range deps {
				// Find the dependency node
				for _, targetNode := range nodes {
					if targetNode["name"] == dep || strings.Contains(targetNode["path"].(string), dep) {
						relationships = append(relationships, Relationship{
							From:       node["id"].(string),
							To:         targetNode["id"].(string),
							Type:       "imports",
							Confidence: 1.0,
							Metadata: map[string]interface{}{
								"dependency": dep,
								"rule":       "import_analysis",
							},
						})
						break
					}
				}
			}
		}
	}

	// Rule 2: Directory structure relationships
	for _, node := range nodes {
		nodePath := node["path"].(string)
		dir := filepath.Dir(nodePath)

		// Find other nodes in the same directory
		for _, otherNode := range nodes {
			if otherNode["id"] == node["id"] {
				continue
			}
			otherPath := otherNode["path"].(string)
			otherDir := filepath.Dir(otherPath)

			if dir == otherDir {
				relationships = append(relationships, Relationship{
					From:       node["id"].(string),
					To:         otherNode["id"].(string),
					Type:       "co_located",
					Confidence: 0.8,
					Metadata: map[string]interface{}{
						"directory": dir,
						"rule":      "directory_co_location",
					},
				})
			}
		}
	}

	// Rule 3: Type-based relationships
	for _, node := range nodes {
		nodeType := node["type"]

		// Find nodes of related types
		for _, otherNode := range nodes {
			if otherNode["id"] == node["id"] {
				continue
			}

			otherType := otherNode["type"]

			// Define type relationship rules using string comparison
			if (nodeType == "code" && otherType == "api") ||
				(nodeType == "api" && otherType == "code") {
				relationships = append(relationships, Relationship{
					From:       node["id"].(string),
					To:         otherNode["id"].(string),
					Type:       "implements",
					Confidence: 0.7,
					Metadata: map[string]interface{}{
						"rule": "type_complementarity",
					},
				})
			}
		}
	}

	// Rule 4: Database relationship inference
	for _, node := range nodes {
		if metadata, ok := node["metadata"].(map[string]interface{}); ok {
			if relationshipsData, ok := metadata["relationships"].([]DatabaseRelationship); ok {
				for _, dbRel := range relationshipsData {
					// Find the target table node
					for _, targetNode := range nodes {
						if targetNode["name"] == dbRel.ToTable || strings.Contains(targetNode["path"].(string), dbRel.ToTable) {
							relationships = append(relationships, Relationship{
								From:       node["id"].(string),
								To:         targetNode["id"].(string),
								Type:       dbRel.Type,
								Confidence: 0.9,
								Metadata: map[string]interface{}{
									"database_relationship": true,
									"column":                dbRel.Column,
									"description":           dbRel.Description,
									"rule":                  "database_relationship_extraction",
								},
							})
							break
						}
					}
				}
			}
		}
	}

	// Remove duplicate relationships
	seen := make(map[string]bool)
	var uniqueRelationships []Relationship
	for _, rel := range relationships {
		key := fmt.Sprintf("%s->%s:%s", rel.From, rel.To, rel.Type)
		if !seen[key] {
			seen[key] = true
			uniqueRelationships = append(uniqueRelationships, rel)
		}
	}

	log.Printf("  🔍 Deterministic relationship inference found %d relationships", len(uniqueRelationships))
	return uniqueRelationships
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

// persistNodeToDatabase persists a node to the database for real-time dashboard updates
func (s *Scanner) persistNodeToDatabase(node *types.Node) {
	if s.chromemManager != nil {
		if err := s.chromemManager.UpsertNode(node); err != nil {
			log.Printf("  ⚠️  Failed to persist node %s to database: %v", node.ID, err)
		}
	}
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

// calculateCyclomaticComplexity calculates the cyclomatic complexity of a code file
func (s *Scanner) calculateCyclomaticComplexity(_ string, content []byte) int {
	text := string(content)
	complexity := 1 // Base complexity

	// Decision points that increase complexity
	patterns := []string{
		`\bif\s*\(`,        // if statements
		`\belse\s+if\s*\(`, // else if statements
		`\bfor\s*\(`,       // for loops
		`\bwhile\s*\(`,     // while loops
		`\bcase\s+.*:`,     // switch cases
		`\bcatch\s*\(`,     // catch blocks
		`\b\|\|`,           // logical OR
		`\b&&`,             // logical AND
		`\?`,               // ternary operator
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllString(text, -1)
		complexity += len(matches)
	}

	return complexity
}

// CodeSmell represents a detected code smell
type CodeSmell struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Line        int    `json:"line"`
	Severity    string `json:"severity"`
}

// detectCodeSmells performs rule-based code smell detection
func (s *Scanner) detectCodeSmells(_ string, content []byte) []CodeSmell {
	var smells []CodeSmell
	text := string(content)
	lines := strings.Split(text, "\n")

	// Rule 1: Long methods/functions (>50 lines)
	methodStart := -1
	methodName := ""
	braceCount := 0

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Detect method/function start
		if strings.Contains(line, "func ") && strings.Contains(line, "(") && strings.Contains(line, ")") {
			if methodStart != -1 {
				// End previous method
				methodLength := i - methodStart
				if methodLength > 50 {
					smells = append(smells, CodeSmell{
						Type:        "LongMethod",
						Description: fmt.Sprintf("Method '%s' is too long (%d lines)", methodName, methodLength),
						Line:        methodStart + 1,
						Severity:    "Medium",
					})
				}
			}
			methodStart = i
			methodName = strings.Split(line, " ")[1]
			if idx := strings.Index(methodName, "("); idx != -1 {
				methodName = methodName[:idx]
			}
			braceCount = 0
		}

		// Count braces to detect method end
		for _, char := range line {
			switch char {
			case '{':
				braceCount++
			case '}':
				braceCount--
				if braceCount == 0 && methodStart != -1 {
					methodLength := i - methodStart + 1
					if methodLength > 50 {
						smells = append(smells, CodeSmell{
							Type:        "LongMethod",
							Description: fmt.Sprintf("Method '%s' is too long (%d lines)", methodName, methodLength),
							Line:        methodStart + 1,
							Severity:    "Medium",
						})
					}
					methodStart = -1
					methodName = ""
				}
			}
		}
	}

	// Rule 2: Deep nesting (>3 levels)
	for i, line := range lines {
		leadingSpaces := len(line) - len(strings.TrimLeft(line, " \t"))
		nestingLevel := leadingSpaces / 4 // Assuming 4 spaces per indent level
		if nestingLevel > 3 {
			smells = append(smells, CodeSmell{
				Type:        "DeepNesting",
				Description: fmt.Sprintf("Deep nesting detected (level %d)", nestingLevel),
				Line:        i + 1,
				Severity:    "Medium",
			})
		}
	}

	// Rule 3: Long lines (>120 characters)
	for i, line := range lines {
		if len(line) > 120 {
			smells = append(smells, CodeSmell{
				Type:        "LongLine",
				Description: fmt.Sprintf("Line too long (%d characters)", len(line)),
				Line:        i + 1,
				Severity:    "Low",
			})
		}
	}

	// Rule 4: TODO/FIXME comments
	todoRegex := regexp.MustCompile(`(?i)(TODO|FIXME|XXX|HACK)`)
	for i, line := range lines {
		if todoRegex.MatchString(line) {
			smells = append(smells, CodeSmell{
				Type:        "TodoComment",
				Description: "TODO/FIXME comment found",
				Line:        i + 1,
				Severity:    "Low",
			})
		}
	}

	// Rule 5: Magic numbers (excluding common values)
	magicNumRegex := regexp.MustCompile(`\b\d{2,}\b`)
	for i, line := range lines {
		matches := magicNumRegex.FindAllString(line, -1)
		for _, match := range matches {
			// Skip common non-magic numbers
			if match == "0" || match == "1" || match == "10" || match == "100" || match == "1000" {
				continue
			}
			smells = append(smells, CodeSmell{
				Type:        "MagicNumber",
				Description: fmt.Sprintf("Magic number '%s' detected", match),
				Line:        i + 1,
				Severity:    "Low",
			})
		}
	}

	// Rule 6: Empty catch blocks
	catchRegex := regexp.MustCompile(`\bcatch\s*\([^)]*\)\s*\{\s*\}`)
	for i, line := range lines {
		if catchRegex.MatchString(line) {
			smells = append(smells, CodeSmell{
				Type:        "EmptyCatch",
				Description: "Empty catch block",
				Line:        i + 1,
				Severity:    "High",
			})
		}
	}

	return smells
}

// DatabaseRelationship represents a relationship extracted from database models
type DatabaseRelationship struct {
	Type        string `json:"type"` // "belongs_to", "has_many", "has_one", "foreign_key"
	FromTable   string `json:"from_table"`
	ToTable     string `json:"to_table"`
	Column      string `json:"column"`
	Reference   string `json:"reference"`
	Description string `json:"description"`
}

// extractDatabaseRelationships parses ORM models for relationships
func (s *Scanner) extractDatabaseRelationships(filePath string, content []byte) []DatabaseRelationship {
	var relationships []DatabaseRelationship
	text := string(content)
	lines := strings.Split(text, "\n")

	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".go":
		relationships = s.extractGoRelationships(lines)
	case ".py":
		relationships = s.extractPythonRelationships(lines)
	case ".js", ".ts":
		relationships = s.extractJavaScriptRelationships(lines)
	default:
		// Generic extraction for unknown ORM patterns
		relationships = s.extractGenericRelationships(lines)
	}

	return relationships
}

// extractGoRelationships extracts relationships from Go ORM models (e.g., GORM)
func (s *Scanner) extractGoRelationships(lines []string) []DatabaseRelationship {
	var relationships []DatabaseRelationship

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// GORM foreign key patterns
		if strings.Contains(line, "gorm:\"foreignKey:") {
			// Extract foreign key information
			parts := strings.Split(line, "gorm:\"foreignKey:")
			if len(parts) > 1 {
				fkInfo := strings.Split(parts[1], "\"")[0]
				relationships = append(relationships, DatabaseRelationship{
					Type:        "foreign_key",
					Column:      s.extractFieldName(lines, i),
					Reference:   fkInfo,
					Description: fmt.Sprintf("Foreign key reference: %s", fkInfo),
				})
			}
		}

		// GORM relationship patterns
		if strings.Contains(line, "gorm:\"references:") {
			parts := strings.Split(line, "gorm:\"references:")
			if len(parts) > 1 {
				refInfo := strings.Split(parts[1], "\"")[0]
				relationships = append(relationships, DatabaseRelationship{
					Type:        "references",
					Column:      s.extractFieldName(lines, i),
					Reference:   refInfo,
					Description: fmt.Sprintf("References: %s", refInfo),
				})
			}
		}
	}

	return relationships
}

// extractPythonRelationships extracts relationships from Python ORM models (e.g., SQLAlchemy, Django)
func (s *Scanner) extractPythonRelationships(lines []string) []DatabaseRelationship {
	var relationships []DatabaseRelationship

	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Django ForeignKey
		if strings.Contains(line, "models.ForeignKey(") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				fieldName := strings.TrimSpace(parts[0])
				fkPattern := regexp.MustCompile(`models\.ForeignKey\(['"]([^'"]+)['"]`)
				matches := fkPattern.FindStringSubmatch(line)
				if len(matches) > 1 {
					relationships = append(relationships, DatabaseRelationship{
						Type:        "foreign_key",
						FromTable:   s.extractClassName(lines, i),
						ToTable:     matches[1],
						Column:      fieldName,
						Description: fmt.Sprintf("Django ForeignKey to %s", matches[1]),
					})
				}
			}
		}

		// SQLAlchemy relationship
		if strings.Contains(line, "relationship(") {
			relPattern := regexp.MustCompile(`relationship\(['"]([^'"]+)['"]`)
			matches := relPattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				relationships = append(relationships, DatabaseRelationship{
					Type:        "relationship",
					FromTable:   s.extractClassName(lines, i),
					ToTable:     matches[1],
					Description: fmt.Sprintf("SQLAlchemy relationship to %s", matches[1]),
				})
			}
		}
	}

	return relationships
}

// extractJavaScriptRelationships extracts relationships from JS/TS ORM models
func (s *Scanner) extractJavaScriptRelationships(lines []string) []DatabaseRelationship {
	var relationships []DatabaseRelationship

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Sequelize belongsTo
		if strings.Contains(line, ".belongsTo(") {
			belongsToPattern := regexp.MustCompile(`(\w+)\.belongsTo\((\w+)`)
			matches := belongsToPattern.FindStringSubmatch(line)
			if len(matches) > 2 {
				relationships = append(relationships, DatabaseRelationship{
					Type:        "belongs_to",
					FromTable:   matches[1],
					ToTable:     matches[2],
					Description: fmt.Sprintf("Sequelize belongsTo relationship: %s -> %s", matches[1], matches[2]),
				})
			}
		}

		// Sequelize hasMany
		if strings.Contains(line, ".hasMany(") {
			hasManyPattern := regexp.MustCompile(`(\w+)\.hasMany\((\w+)`)
			matches := hasManyPattern.FindStringSubmatch(line)
			if len(matches) > 2 {
				relationships = append(relationships, DatabaseRelationship{
					Type:        "has_many",
					FromTable:   matches[1],
					ToTable:     matches[2],
					Description: fmt.Sprintf("Sequelize hasMany relationship: %s -> %s", matches[1], matches[2]),
				})
			}
		}
	}

	return relationships
}

// extractGenericRelationships extracts relationships using generic patterns
func (s *Scanner) extractGenericRelationships(lines []string) []DatabaseRelationship {
	var relationships []DatabaseRelationship

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Generic foreign key patterns
		fkPatterns := []string{
			`foreign[_-]?key`,
			`references`,
			`belongs[_-]?to`,
			`has[_-]?many`,
			`has[_-]?one`,
		}

		for _, pattern := range fkPatterns {
			regex := regexp.MustCompile(`(?i)` + pattern)
			if regex.MatchString(line) {
				relationships = append(relationships, DatabaseRelationship{
					Type:        "generic_relationship",
					Description: fmt.Sprintf("Potential relationship pattern: %s", line),
				})
			}
		}
	}

	return relationships
}

// Helper functions for relationship extraction

// buildDeterministicEdges creates graph edges from parsed relationships
func (s *Scanner) buildDeterministicEdges(ctx context.Context) {
	_ = ctx // Acknowledge context for future use

	// Build edges from import/dependency relationships
	for _, node := range s.graph.Nodes {
		if node.Type == types.NodeTypeCode {
			for _, dep := range node.Dependencies {
				// Find dependency node
				for _, depNode := range s.graph.Nodes {
					if depNode.Type == types.NodeTypeLibrary && strings.Contains(depNode.Name, dep) {
						edge := &types.Edge{
							From:         node.ID,
							To:           depNode.ID,
							Relationship: "imports",
							Strength:     1.0,
							Metadata: map[string]interface{}{
								"type": "dependency",
							},
						}
						s.graph.Edges = append(s.graph.Edges, edge)
						break
					}
				}
			}
		}
	}

	// Build edges from database relationships
	for _, node := range s.graph.Nodes {
		if node.Type == types.NodeTypeDatabase {
			if relationships, ok := node.Metadata["relationships"].([]DatabaseRelationship); ok {
				for _, rel := range relationships {
					// Create edge based on relationship type
					edge := &types.Edge{
						From:         node.ID,
						To:           s.generateNodeID(rel.ToTable), // Target table node
						Relationship: rel.Type,
						Strength:     1.0,
						Metadata: map[string]interface{}{
							"type":        "database_relationship",
							"column":      rel.Column,
							"description": rel.Description,
						},
					}
					s.graph.Edges = append(s.graph.Edges, edge)
				}
			}
		}
	}

	log.Printf("  🕸️  Created %d deterministic edges", len(s.graph.Edges))
}

func (s *Scanner) extractFieldName(lines []string, currentLine int) string {
	// Look backwards for field name
	for i := currentLine; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.Contains(line, "struct") || strings.Contains(line, "class") {
			break
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			return parts[0] // First word is usually the field name
		}
	}
	return "unknown_field"
}

func (s *Scanner) extractClassName(lines []string, currentLine int) string {
	// Look backwards for class/struct name
	for i := currentLine; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.Contains(line, "class ") {
			parts := strings.Split(line, "class ")
			if len(parts) > 1 {
				className := strings.Fields(parts[1])[0]
				return className
			}
		}
		if strings.Contains(line, "type ") && strings.Contains(line, "struct") {
			parts := strings.Split(line, "type ")
			if len(parts) > 1 {
				typeName := strings.Fields(parts[1])[0]
				return typeName
			}
		}
	}
	return "unknown_class"
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
