package main

import (
	"archguardian/data_engine"
	"archguardian/inference_engine"
	"archguardian/types"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

//go:embed dashboard/index.html
var dashboardHTML string

//go:embed dashboard/style.css
var dashboardCSS string

//go:embed dashboard/app.js
var dashboardJS string

// ============================================================================
// CONFIGURATION
// ============================================================================

type Config struct {
	ProjectPath       string
	GitHubToken       string
	GitHubRepo        string
	AIProviders       AIProviderConfig
	Orchestrator      OrchestratorConfig
	DataEngine        DataEngineConfig
	ScanInterval      time.Duration
	RemediationBranch string
}

type AIProviderConfig struct {
	Cerebras  ProviderCredentials // Fast, short context tasks
	Gemini    ProviderCredentials // Deep reasoning, long context
	Anthropic ProviderCredentials // Code remediation
	OpenAI    ProviderCredentials // Code remediation (fallback)
	DeepSeek  ProviderCredentials // Code remediation (fallback)

	CodeRemediationProvider string // "anthropic", "openai", or "deepseek"
}

// OrchestratorConfig defines the models used for each role in the task orchestrator.
type OrchestratorConfig struct {
	PlannerModel   string
	ExecutorModels []string
	FinalizerModel string
	VerifierModel  string
}

type ProviderCredentials struct {
	APIKey   string
	Endpoint string
	Model    string
}

type DataEngineConfig struct {
	Enable           bool
	EnableKafka      bool
	EnableChromaDB   bool
	EnableWebSocket  bool
	EnableRESTAPI    bool
	KafkaBrokers     []string
	ChromaDBURL      string
	ChromaCollection string
	WebSocketPort    int
	RESTAPIPort      int
}

// ============================================================================
// SCANNER SYSTEM
// ============================================================================

type Scanner struct {
	config *Config
	graph  *types.KnowledgeGraph // This should be *types.KnowledgeGraph
	ai     *AIInferenceEngine    // This should be *AIInferenceEngine
}

func NewScanner(cfg *Config, ai *AIInferenceEngine) *Scanner {
	return &Scanner{
		config: cfg,
		graph:  NewKnowledgeGraph(),
		ai:     NewAIInferenceEngine(cfg),
	}
}

func NewKnowledgeGraph() *types.KnowledgeGraph {
	return &types.KnowledgeGraph{
		Nodes: make(map[string]*types.Node),
		Edges: make([]*types.Edge, 0),
	}
}

func (s *Scanner) ScanProject(ctx context.Context) error {
	log.Println("🔍 Starting comprehensive project scan...")

	// Phase 1: Static Code Analysis
	if err := s.scanStaticCode(ctx); err != nil {
		return fmt.Errorf("static code scan failed: %w", err)
	}

	// Phase 2: Dependency Analysis
	if err := s.scanDependencies(ctx); err != nil {
		return fmt.Errorf("dependency scan failed: %w", err)
	}

	// Phase 3: Runtime Inspection
	if err := s.scanRuntime(ctx); err != nil {
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

		if !info.IsDir() && isCodeFile(path) {
			node := &types.Node{
				ID:           generateNodeID(path),
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

				// Use Cerebras for quick analysis
				analysis, _ := s.ai.AnalyzeCodeFile(ctx, string(content), AIProviderCerebras)
				if analysis != nil {
					node.Metadata["complexity"] = analysis["complexity"]
					node.Metadata["quality_score"] = analysis["quality_score"]
				}
			}

			s.graph.Nodes[node.ID] = node
		}

		return nil
	})

	return err
}

func (s *Scanner) scanDependencies(ctx context.Context) error {
	log.Println("  📦 Scanning dependencies...")

	// Scan go.mod
	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "go.mod")); err == nil {
		return s.scanGoMod()
	}

	// Scan package.json
	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "package.json")); err == nil {
		return s.scanPackageJSON(ctx)
	}

	// Scan requirements.txt
	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "requirements.txt")); err == nil {
		return s.scanRequirementsTxt(ctx)
	}

	return nil
}

// scanGoMod scans go.mod file for dependencies
func (s *Scanner) scanGoMod() error {
	content, err := os.ReadFile(filepath.Join(s.config.ProjectPath, "go.mod"))
	if err != nil {
		return err
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
					ID:   generateNodeID("dep:" + pkg),
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

func (s *Scanner) scanPackageJSON(_ context.Context) error {
	content, err := os.ReadFile(filepath.Join(s.config.ProjectPath, "package.json"))
	if err != nil {
		return err
	}

	var pkg map[string]interface{}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return err
	}

	// Process dependencies
	if deps, ok := pkg["dependencies"].(map[string]interface{}); ok {
		for name, version := range deps {
			node := &types.Node{
				ID:   generateNodeID("dep:" + name),
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

func (s *Scanner) scanRequirementsTxt(_ context.Context) error {
	content, err := os.ReadFile(filepath.Join(s.config.ProjectPath, "requirements.txt"))
	if err != nil {
		return err
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
			ID:   generateNodeID("dep:" + name),
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

			// Use Gemini for deep analysis of database models
			analysis, _ := s.ai.AnalyzeDatabaseModel(context.Background(), string(content), AIProviderGemini)

			node := &types.Node{
				ID:   generateNodeID(path),
				Type: types.NodeTypeDatabase,
				Name: filepath.Base(path),
				Path: path,
				Metadata: map[string]interface{}{
					"analysis": analysis,
				},
			}
			s.graph.Nodes[node.ID] = node
		}
	}

	return nil
}

func (s *Scanner) scanRuntime(ctx context.Context) error {
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
				ID:       generateNodeID(path),
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

func (s *Scanner) buildKnowledgeGraph(ctx context.Context) error {
	log.Println("  🕸️  Building knowledge graph...")

	// Use Gemini for deep reasoning about relationships
	graphData := s.prepareGraphData()
	relationships, err := s.ai.InferRelationships(ctx, graphData, AIProviderGemini)
	if err != nil {
		log.Printf("Warning: relationship inference failed: %v", err)
		return nil
	}

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

	return nil
}

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
		// imp.Path.Value is the import path (e.g., "\"fmt\"")
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
		`import\s+['"]([^'"]+)['"]`,            // import 'module'
		`from\s+['"]([^'"]+)['"]`,              // from 'module'
		`require\s*\(\s*['"]([^'"]+)['"]\s*\)`, // require('module')
		`#include\s+[<"]([^>"]+)[>"]`,          // #include <header>
		`use\s+(\S+)`,                          // use module (Perl)
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

// scanTestCoverage performs test coverage analysis and stores results in knowledge graph
func (s *Scanner) scanTestCoverage(ctx context.Context) error {
	log.Println("  📊 Scanning test coverage...")

	// Determine project type and run appropriate coverage command
	var coverageData map[string]interface{}

	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "go.mod")); err == nil {
		coverageData, err = s.scanGoCoverage(ctx)
		if err != nil {
			log.Printf("  ⚠️  Go coverage scan failed: %v", err)
			return nil // Don't fail the entire scan
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
			Type: types.NodeTypeCode, // Using code type for coverage data
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

// Helper functions for coverage scanning

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

// ============================================================================
// CVE SCANNER
// ============================================================================

// CVEScanner handles querying CVE databases like the NVD
type CVEScanner struct {
	httpClient *http.Client
	apiKey     string // For NVD API v2
	baseURL    string
}

// NewCVEScanner creates a new CVE scanner
func NewCVEScanner(apiKey string) *CVEScanner {
	return &CVEScanner{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
		baseURL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

// QueryNVD queries the National Vulnerability Database for a given package
func (cs *CVEScanner) QueryNVD(packageName, version string) ([]types.SecurityVulnerability, error) {
	log.Printf("  🔍 Querying NVD for vulnerabilities in %s@%s...", packageName, version)

	// Construct NVD API URL for keyword search
	// Note: NVD API doesn't directly support package name search, but we can search by keyword
	url := fmt.Sprintf("%s?keyword=%s&resultsPerPage=20", cs.baseURL, packageName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add API key if provided (NVD API v2.0 doesn't require API key for basic queries)
	if cs.apiKey != "" {
		req.Header.Set("apiKey", cs.apiKey)
	}

	resp, err := cs.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query NVD: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	// Parse NVD response
	var nvdResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&nvdResponse); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	// Extract vulnerabilities from response
	vulnerabilities, err := cs.parseNVDResponse(nvdResponse, packageName, version)
	if err != nil {
		log.Printf("  ⚠️  Failed to parse NVD response: %v", err)
		return []types.SecurityVulnerability{}, nil
	}

	log.Printf("  📊 Found %d vulnerabilities for %s@%s", len(vulnerabilities), packageName, version)
	return vulnerabilities, nil
}

// parseNVDResponse extracts vulnerability information from NVD API response
func (cs *CVEScanner) parseNVDResponse(response map[string]interface{}, packageName, version string) ([]types.SecurityVulnerability, error) {
	var vulnerabilities []types.SecurityVulnerability

	// Navigate to vulnerabilities array in NVD response
	vulnData, ok := response["vulnerabilities"].([]interface{})
	if !ok {
		return vulnerabilities, nil
	}

	for _, item := range vulnData {
		vulnMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		cve, ok := vulnMap["cve"].(map[string]interface{})
		if !ok {
			continue
		}

		// Extract CVE ID
		id := ""
		if idMap, ok := cve["id"].(string); ok {
			id = idMap
		}

		// Extract description
		description := ""
		if descArray, ok := cve["descriptions"].([]interface{}); ok && len(descArray) > 0 {
			if descMap, ok := descArray[0].(map[string]interface{}); ok {
				if desc, ok := descMap["value"].(string); ok {
					description = desc
				}
			}
		}

		// Extract CVSS metrics
		cvss := 0.0
		severity := "unknown"
		if metrics, ok := cve["metrics"].(map[string]interface{}); ok {
			if cvssData, ok := metrics["cvssMetricV31"].([]interface{}); ok && len(cvssData) > 0 {
				if cvssMap, ok := cvssData[0].(map[string]interface{}); ok {
					if baseData, ok := cvssMap["cvssData"].(map[string]interface{}); ok {
						if baseScore, ok := baseData["baseScore"].(float64); ok {
							cvss = baseScore
						}
						if severityData, ok := baseData["baseSeverity"].(string); ok {
							severity = severityData
						}
					}
				}
			}
		}

		// Only include vulnerabilities that match our package
		if cs.isRelevantVulnerability(description, packageName) {
			vuln := types.SecurityVulnerability{
				CVE:         id,
				Package:     packageName,
				Version:     version,
				Severity:    severity,
				Description: description,
				FixVersion:  "latest", // NVD doesn't provide fix versions directly
				CVSS:        cvss,
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities, nil
}

// isRelevantVulnerability checks if a vulnerability description mentions the package
func (cs *CVEScanner) isRelevantVulnerability(description, packageName string) bool {
	// Simple heuristic: check if package name appears in description
	// In a real implementation, this would use more sophisticated matching
	descLower := strings.ToLower(description)
	packageLower := strings.ToLower(packageName)

	// Check for exact package name match
	if strings.Contains(descLower, packageLower) {
		return true
	}

	// Check for common package name variations
	parts := strings.Split(packageName, "/")
	if len(parts) > 0 {
		packageBaseName := strings.ToLower(parts[len(parts)-1])
		if strings.Contains(descLower, packageBaseName) {
			return true
		}
	}

	return false
}

// ============================================================================
// RUNTIME SCANNER
// ============================================================================

// RuntimeScanner inspects live system runtime for processes, connections, and resource usage
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
					"protocol":       getProtocolName(conn.Type),
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
							"protocol":       getProtocolName(conn.Type),
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
			Type: types.NodeTypeProcess, // Using process type for system resources
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
func getProtocolName(connType uint32) string {
	switch connType {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return fmt.Sprintf("Type_%d", connType)
	}
}

// ============================================================================
// RISK DIAGNOSIS
// ============================================================================

type RiskDiagnoser struct {
	scanner      *Scanner
	ai           *AIInferenceEngine
	codacyClient *CodacyClient
}

func NewRiskDiagnoser(scanner *Scanner, codacyClient *CodacyClient) *RiskDiagnoser {
	return &RiskDiagnoser{
		scanner:      scanner,
		ai:           scanner.ai,
		codacyClient: codacyClient,
	}
}

func (rd *RiskDiagnoser) DiagnoseRisks(ctx context.Context) (*types.RiskAssessment, error) {
	log.Println("🔬 Diagnosing system risks...")

	assessment := &types.RiskAssessment{
		TechnicalDebt:         make([]types.TechnicalDebtItem, 0),
		SecurityVulns:         make([]types.SecurityVulnerability, 0),
		ObsoleteCode:          make([]types.ObsoleteCodeItem, 0),
		DangerousDependencies: make([]types.DependencyRisk, 0),
		Timestamp:             time.Now(),
	}

	// Fetch Codacy issues if client is available
	if rd.codacyClient != nil {
		codacyIssues, err := rd.codacyClient.GetIssues()
		if err != nil {
			log.Printf("  ⚠️  Failed to fetch Codacy issues: %v", err)
		} else {
			log.Printf("  🔗 Integrating %d Codacy issues into risk assessment", len(codacyIssues))
			for _, codacyIssue := range codacyIssues {
				// Convert Codacy issue to technical debt item
				debtItem := rd.codacyClient.ConvertCodacyIssueToTechnicalDebt(codacyIssue)
				assessment.TechnicalDebt = append(assessment.TechnicalDebt, debtItem)
			}
		}
	}

	// Use Gemini for comprehensive risk analysis
	riskData := rd.prepareRiskAnalysisData()
	risks, err := rd.ai.AnalyzeRisks(ctx, riskData, AIProviderGemini)
	if err != nil {
		return nil, fmt.Errorf("risk analysis failed: %w", err)
	}

	// Parse and categorize risks from AI analysis
	aiTechnicalDebt := rd.extractTechnicalDebt(risks)
	aiSecurityVulns := rd.extractSecurityVulns(risks)
	aiObsoleteCode := rd.extractObsoleteCode(risks)
	aiDependencyRisks := rd.extractDependencyRisks(risks)

	// Merge AI results with Codacy results (avoiding duplicates)
	assessment.TechnicalDebt = append(assessment.TechnicalDebt, aiTechnicalDebt...)
	assessment.SecurityVulns = aiSecurityVulns
	assessment.ObsoleteCode = aiObsoleteCode
	assessment.DangerousDependencies = aiDependencyRisks

	// Calculate overall risk score
	assessment.OverallScore = rd.calculateOverallRisk(assessment)

	log.Printf("  ⚠️  Found: %d technical debt items (%d from Codacy, %d from AI), %d security vulnerabilities, %d obsolete code items",
		len(assessment.TechnicalDebt), len(assessment.TechnicalDebt)-len(aiTechnicalDebt), len(aiTechnicalDebt), len(assessment.SecurityVulns), len(assessment.ObsoleteCode))

	return assessment, nil
}

func (rd *RiskDiagnoser) prepareRiskAnalysisData() map[string]interface{} {
	return map[string]interface{}{
		"graph":      rd.scanner.graph,
		"node_count": len(rd.scanner.graph.Nodes),
		"edge_count": len(rd.scanner.graph.Edges),
	}
}

func (rd *RiskDiagnoser) extractTechnicalDebt(risks map[string]interface{}) []types.TechnicalDebtItem {
	items := make([]types.TechnicalDebtItem, 0)

	if debt, ok := risks["technical_debt"].([]interface{}); ok {
		for i, item := range debt {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, types.TechnicalDebtItem{
					ID:          fmt.Sprintf("TD-%d", i+1),
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

	return items
}

func (rd *RiskDiagnoser) extractSecurityVulns(risks map[string]interface{}) []types.SecurityVulnerability {
	vulns := make([]types.SecurityVulnerability, 0)

	if security, ok := risks["security"].([]interface{}); ok {
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

	return vulns
}

func (rd *RiskDiagnoser) extractObsoleteCode(risks map[string]interface{}) []types.ObsoleteCodeItem {
	items := make([]types.ObsoleteCodeItem, 0)

	if obsolete, ok := risks["obsolete_code"].([]interface{}); ok {
		for _, item := range obsolete {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, types.ObsoleteCodeItem{
					Path:            getStringField(m, "path"),
					References:      getIntField(m, "references"),
					RemovalSafety:   getStringField(m, "removal_safety"),
					RecommendAction: getStringField(m, "action"),
				})
			}
		}
	}

	return items
}

func (rd *RiskDiagnoser) extractDependencyRisks(risks map[string]interface{}) []types.DependencyRisk {
	deps := make([]types.DependencyRisk, 0)

	if dependencies, ok := risks["dependencies"].([]interface{}); ok {
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

	return deps
}

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

// ============================================================================
// AI INFERENCE ENGINE
// ============================================================================

type AIProviderType string

const (
	AIProviderCerebras  AIProviderType = "cerebras"
	AIProviderGemini    AIProviderType = "gemini"
	AIProviderAnthropic AIProviderType = "anthropic"
	AIProviderOpenAI    AIProviderType = "openai"
	AIProviderDeepSeek  AIProviderType = "deepseek"
)

type AIInferenceEngine struct {
	service *inference_engine.InferenceService
}

type Relationship struct {
	From       string
	To         string
	Type       string
	Confidence float64
	Metadata   map[string]interface{}
}

func NewAIInferenceEngine(config *Config) *AIInferenceEngine {
	log.Println("🧠 Initializing Multi-Model AI Inference Engine...")

	// The inference service needs a DB accessor, but doesn't use it. We can pass nil.
	service, err := inference_engine.NewInferenceService(nil)
	if err != nil {
		log.Fatalf("❌ Failed to create inference service: %v", err)
	}

	// Dynamically build the list of available LLMs from the application's configuration
	var attemptConfigs []inference_engine.LLMAttemptConfig
	if config.AIProviders.Cerebras.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "cerebras", ModelName: config.AIProviders.Cerebras.Model, APIKeyEnvVar: "CEREBRAS_API_KEY", MaxTokens: 4000, IsPrimary: true,
		})
	}
	if config.AIProviders.Gemini.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "gemini", ModelName: config.AIProviders.Gemini.Model, APIKeyEnvVar: "GEMINI_API_KEY", MaxTokens: 100000, IsPrimary: false,
		})
	}
	if config.AIProviders.DeepSeek.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "deepseek", ModelName: config.AIProviders.DeepSeek.Model, APIKeyEnvVar: "DEEPSEEK_API_KEY", MaxTokens: 8000, IsPrimary: false,
		})
	}
	if config.AIProviders.Anthropic.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "anthropic", ModelName: config.AIProviders.Anthropic.Model, APIKeyEnvVar: "ANTHROPIC_API_KEY", MaxTokens: 4000, IsPrimary: false,
		})
	}
	if config.AIProviders.OpenAI.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "openai", ModelName: config.AIProviders.OpenAI.Model, APIKeyEnvVar: "OPENAI_API_KEY", MaxTokens: 4000, IsPrimary: false,
		})
	}

	// Start the service with the dynamic configuration
	// Pass the orchestrator config to the service
	err = service.StartWithConfig(attemptConfigs, config.Orchestrator.PlannerModel, config.Orchestrator.ExecutorModels, config.Orchestrator.FinalizerModel, config.Orchestrator.VerifierModel)
	if err != nil {
		log.Fatalf("❌ Failed to start inference service: %v", err)
	}

	log.Println("✅ AI Inference Engine started successfully.")
	return &AIInferenceEngine{service: service}
}

func (ai *AIInferenceEngine) AnalyzeCodeFile(ctx context.Context, content string, provider AIProviderType) (map[string]interface{}, error) {
	prompt := inference_engine.GetCodeFileAnalysisPrompt(content)

	response, err := ai.service.GenerateText(ctx, string(provider), prompt, "")
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var analysis map[string]interface{}
	if err := json.Unmarshal([]byte(response), &analysis); err != nil {
		log.Printf("⚠️  Could not parse AI analysis for code file: %v", err)
		return map[string]interface{}{"raw_analysis": response}, nil
	}

	return analysis, nil
}

func (ai *AIInferenceEngine) AnalyzeDatabaseModel(ctx context.Context, content string, provider AIProviderType) (map[string]interface{}, error) {
	prompt := inference_engine.GetDatabaseModelAnalysisPrompt(content)

	response, err := ai.service.GenerateText(ctx, string(provider), prompt, "")
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var analysis map[string]interface{}
	if err := json.Unmarshal([]byte(response), &analysis); err != nil {
		log.Printf("⚠️  Could not parse AI analysis for database model: %v", err)
		return map[string]interface{}{"raw_analysis": response}, nil
	}

	return analysis, nil
}

func (ai *AIInferenceEngine) InferRelationships(ctx context.Context, graphData map[string]interface{}, provider AIProviderType) ([]Relationship, error) {
	// Use the real inference service with reflection for deep reasoning about relationships
	graphJSON, _ := json.Marshal(graphData) // Error handling omitted for brevity
	prompt := inference_engine.GetRelationshipInferencePrompt(string(graphJSON))

	response, err := ai.service.GenerateTextWithReflection(ctx, prompt)
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

func (ai *AIInferenceEngine) AnalyzeRisks(ctx context.Context, riskData map[string]interface{}, provider AIProviderType) (map[string]interface{}, error) {
	// Use the real inference service with reflection for comprehensive risk analysis
	riskJSON, _ := json.Marshal(riskData) // Error handling omitted for brevity
	prompt := inference_engine.GetRiskAnalysisPrompt(string(riskJSON))

	response, err := ai.service.GenerateTextWithReflection(ctx, prompt)
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var risks map[string]interface{}
	if err := json.Unmarshal([]byte(response), &risks); err != nil {
		log.Printf("⚠️  Could not parse AI risk analysis: %v", err)
		return map[string]interface{}{
			"technical_debt": []interface{}{},
			"security":       []interface{}{},
			"obsolete_code":  []interface{}{},
			"dependencies":   []interface{}{},
			"raw_analysis":   response,
		}, nil
	}

	return risks, nil
}

func (ai *AIInferenceEngine) GenerateRemediation(ctx context.Context, issue interface{}, provider AIProviderType) (string, error) {
	// Use the real inference service with the configured code remediation provider
	issueJSON, _ := json.Marshal(issue) // Error handling omitted for brevity
	prompt := inference_engine.GetRemediationPrompt(string(issueJSON))

	response, err := ai.service.GenerateText(ctx, string(provider), prompt, "")
	if err != nil {
		return "", err
	}

	return response, nil
}

// GenerateRemediationWithOrchestrator uses the multi-step TaskOrchestrator to generate a fix.
func (ai *AIInferenceEngine) GenerateRemediationWithOrchestrator(ctx context.Context, issue interface{}) (string, error) {
	issueJSON, err := json.Marshal(issue)
	if err != nil {
		return "", fmt.Errorf("failed to marshal issue for orchestrator: %w", err)
	}

	// Create a complex prompt that gives the orchestrator the full context to plan and execute a fix.
	complexPrompt := fmt.Sprintf(
		"Generate a code patch or full file replacement to fix the following issue. Plan the change, generate the code, and format the final output as a patch or complete file.\n\n--- ISSUE ---\n%s\n--- END ISSUE ---",
		string(issueJSON),
	)

	// Delegate the entire complex task to the orchestrator.
	return ai.service.ExecuteComplexTask(ctx, complexPrompt)
}

// ============================================================================
// AUTOMATED REMEDIATION
// ============================================================================

type Remediator struct {
	config    *Config
	diagnoser *RiskDiagnoser
	ai        *AIInferenceEngine
	git       *GitManager
}

func NewRemediator(config *Config, diagnoser *RiskDiagnoser) *Remediator {
	return &Remediator{
		config:    config,
		diagnoser: diagnoser,
		ai:        diagnoser.ai,
		git:       NewGitManager(config),
	}
}

func (r *Remediator) RemediateRisks(ctx context.Context, assessment *types.RiskAssessment) error {
	log.Println("🔧 Starting automated remediation...")

	// Create remediation branch
	branchName := fmt.Sprintf("%s-%s", r.config.RemediationBranch, time.Now().Format("20060102-150405"))
	if err := r.git.CreateBranch(branchName); err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	remediationCount := 0

	// Fix security vulnerabilities
	for _, vuln := range assessment.SecurityVulns {
		if err := r.remediateSecurityVuln(ctx, vuln); err != nil {
			log.Printf("  ⚠️  Failed to remediate %s: %v", vuln.CVE, err)
			continue
		}
		remediationCount++
	}

	// Update dependencies
	for _, dep := range assessment.DangerousDependencies {
		if err := r.updateDependency(dep); err != nil {
			log.Printf("  ⚠️  Failed to update %s: %v", dep.Package, err)
			continue
		}
		remediationCount++
	}

	// Remove obsolete code
	for _, obsolete := range assessment.ObsoleteCode {
		if obsolete.RemovalSafety == "safe" {
			if err := r.removeObsoleteCode(ctx, obsolete); err != nil {
				log.Printf("  ⚠️  Failed to remove %s: %v", obsolete.Path, err)
				continue
			}
			remediationCount++
		}
	}

	// Address technical debt
	for _, debt := range assessment.TechnicalDebt {
		if debt.Severity == "critical" || debt.Severity == "high" {
			if err := r.fixTechnicalDebt(ctx, debt); err != nil {
				log.Printf("  ⚠️  Failed to fix %s: %v", debt.ID, err)
				continue
			}
			remediationCount++
		}
	}

	// Advanced Codacy integration: Manage toolchain configuration
	if r.diagnoser.codacyClient != nil {
		if err := r.manageCodacyConfiguration(ctx, assessment); err != nil {
			log.Printf("  ⚠️  Failed to manage Codacy configuration: %v", err)
		}
	}

	// Commit and push changes
	if remediationCount > 0 {
		commitMsg := fmt.Sprintf("🤖 Automated remediation: Fixed %d issues\n\n", remediationCount)
		commitMsg += fmt.Sprintf("- Security vulnerabilities: %d\n", len(assessment.SecurityVulns))
		commitMsg += fmt.Sprintf("- Dependency updates: %d\n", len(assessment.DangerousDependencies))
		commitMsg += fmt.Sprintf("- Obsolete code removed: %d\n", len(assessment.ObsoleteCode))
		commitMsg += fmt.Sprintf("- Technical debt addressed: %d\n", len(assessment.TechnicalDebt))

		if err := r.git.CommitAndPush(branchName, commitMsg); err != nil {
			return fmt.Errorf("failed to commit changes: %w", err)
		}

		log.Printf("✅ Remediation complete: %d issues fixed on branch %s", remediationCount, branchName)
	} else {
		log.Println("✅ No issues required remediation")
	}

	return nil
}

func (r *Remediator) remediateSecurityVuln(ctx context.Context, vuln types.SecurityVulnerability) error {
	log.Printf("  🔒 Remediating %s in %s...", vuln.CVE, vuln.Package)

	// Use the TaskOrchestrator for a more robust, multi-step remediation process.
	fix, err := r.ai.GenerateRemediationWithOrchestrator(ctx, map[string]interface{}{
		"type":    "security_vulnerability",
		"cve":     vuln.CVE,
		"package": vuln.Package,
		"version": vuln.Version,
	})

	if err != nil {
		return err
	}

	// Apply the fix
	return r.applyFix(fix, vuln.Package)
}

// updateDependency updates a dependency to the latest version
func (r *Remediator) updateDependency(dep types.DependencyRisk) error {
	log.Printf("  📦 Updating %s from %s to %s...", dep.Package, dep.CurrentVersion, dep.LatestVersion)

	// Determine package manager and update
	if strings.Contains(dep.Package, "/") {
		// Go module
		return r.updateGoModule(dep.Package, dep.LatestVersion)
	} else if fileExists(filepath.Join(r.config.ProjectPath, "package.json")) {
		// NPM package
		return r.updateNPMPackage(dep.Package, dep.LatestVersion)
	} else if fileExists(filepath.Join(r.config.ProjectPath, "requirements.txt")) {
		// Python package
		return r.updatePythonPackage(dep.Package, dep.LatestVersion)
	}

	return nil
}

func (r *Remediator) updateGoModule(pkg, version string) error {
	cmd := exec.Command("go", "get", fmt.Sprintf("%s@%s", pkg, version))
	cmd.Dir = r.config.ProjectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go get failed: %w\n%s", err, output)
	}

	// Run go mod tidy
	tidyCmd := exec.Command("go", "mod", "tidy")
	tidyCmd.Dir = r.config.ProjectPath
	_, err = tidyCmd.CombinedOutput()
	return err
}

func (r *Remediator) updateNPMPackage(pkg, version string) error {
	cmd := exec.Command("npm", "install", fmt.Sprintf("%s@%s", pkg, version))
	cmd.Dir = r.config.ProjectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("npm install failed: %w\n%s", err, output)
	}
	return nil
}

func (r *Remediator) updatePythonPackage(pkg, version string) error {
	// Update requirements.txt
	reqPath := filepath.Join(r.config.ProjectPath, "requirements.txt")
	content, err := os.ReadFile(reqPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	updated := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), pkg) {
			lines[i] = fmt.Sprintf("%s==%s", pkg, version)
			updated = true
			break
		}
	}

	if updated {
		return os.WriteFile(reqPath, []byte(strings.Join(lines, "\n")), 0644)
	}

	return nil
}

func (r *Remediator) removeObsoleteCode(ctx context.Context, obsolete types.ObsoleteCodeItem) error {
	_ = ctx // Acknowledge context for future use
	log.Printf("  🗑️  Removing obsolete code: %s...", obsolete.Path)

	// Safety check
	if obsolete.References > 0 {
		return fmt.Errorf("code still has %d references", obsolete.References)
	}

	// Remove the file
	return os.Remove(obsolete.Path)
}

func (r *Remediator) fixTechnicalDebt(ctx context.Context, debt types.TechnicalDebtItem) error {
	log.Printf("  🔨 Fixing technical debt: %s...", debt.ID)

	// Use the TaskOrchestrator for a more robust, multi-step remediation process.
	fix, err := r.ai.GenerateRemediationWithOrchestrator(ctx, map[string]interface{}{
		"type":        "technical_debt",
		"location":    debt.Location,
		"description": debt.Description,
		"remediation": debt.Remediation,
	})

	if err != nil {
		return err
	}

	return r.applyFix(fix, debt.Location)
}

func (r *Remediator) applyFix(fix, target string) error {
	if fix == "" {
		return fmt.Errorf("AI returned an empty fix for %s", target)
	}

	// If the target is not a file path (e.g., a package name for a dependency update), we can't apply a file-based fix.
	absPath := filepath.Join(r.config.ProjectPath, target)
	if !fileExists(absPath) {
		log.Printf("    Skipping file-based fix for non-file target: %s", target)
		return nil
	}

	// Check if the fix is a patch (starts with --- or diff --git)
	trimmedFix := strings.TrimSpace(fix)
	if strings.HasPrefix(trimmedFix, "---") || strings.HasPrefix(trimmedFix, "diff --git") {
		log.Printf("    Applying patch to %s", target)
		// Use `git apply` to handle the patch
		cmd := exec.Command("git", "apply", "-")
		cmd.Dir = r.config.ProjectPath
		cmd.Stdin = strings.NewReader(fix)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Log the patch and the error for debugging
			log.Printf("    Failed to apply patch:\n--- PATCH START ---\n%s\n--- PATCH END ---\n", fix)
			return fmt.Errorf("git apply failed for %s: %w\nOutput: %s", target, err, string(output))
		}
		log.Printf("    Successfully applied patch to %s", target)
		return nil
	}

	// If not a patch, assume it's the full file content and overwrite
	log.Printf("    Overwriting file %s with AI-generated content", target)
	return os.WriteFile(absPath, []byte(fix), 0644)
}

// manageCodacyConfiguration handles advanced Codacy toolchain management
func (r *Remediator) manageCodacyConfiguration(ctx context.Context, assessment *types.RiskAssessment) error {
	log.Println("  🔧 Managing Codacy configuration...")

	// Analyze technical debt items to identify potential false positives
	falsePositiveCandidates := r.identifyFalsePositiveCandidates(assessment)

	if len(falsePositiveCandidates) == 0 {
		log.Println("  ✅ No false positive candidates identified")
		return nil
	}

	// Get current Codacy rules
	rules, err := r.diagnoser.codacyClient.GetRules()
	if err != nil {
		return fmt.Errorf("failed to fetch Codacy rules: %w", err)
	}

	// Identify rules that should be disabled
	rulesToDisable := r.identifyRulesToDisable(rules, falsePositiveCandidates)

	disabledCount := 0
	for _, rule := range rulesToDisable {
		if err := r.diagnoser.codacyClient.UpdateRule(rule.ID, false, rule.Severity); err != nil {
			log.Printf("  ⚠️  Failed to disable Codacy rule %s: %v", rule.ID, err)
			continue
		}
		disabledCount++
		log.Printf("  🔕 Disabled Codacy rule: %s (%s)", rule.Name, rule.ID)
	}

	if disabledCount > 0 {
		log.Printf("  ✅ Disabled %d Codacy rules to reduce false positives", disabledCount)
	} else {
		log.Println("  ✅ No rules needed to be disabled")
	}

	return nil
}

// identifyFalsePositiveCandidates analyzes technical debt items to find potential false positives
func (r *Remediator) identifyFalsePositiveCandidates(assessment *types.RiskAssessment) []types.TechnicalDebtItem {
	var candidates []types.TechnicalDebtItem

	for _, debt := range assessment.TechnicalDebt {
		// Look for patterns that might indicate false positives
		isFalsePositiveCandidate := false

		// Check if it's a Codacy-generated issue (starts with CODACY-)
		if strings.HasPrefix(debt.ID, "CODACY-") {
			// Check for common false positive patterns
			lowerDesc := strings.ToLower(debt.Description)

			// Pattern 1: Issues in generated code or vendor directories
			if r.isInGeneratedOrVendorCode(debt.Location) {
				isFalsePositiveCandidate = true
			}

			// Pattern 2: Issues that are consistently marked as low impact but high effort
			if debt.Severity == "low" && debt.Effort > 3 {
				isFalsePositiveCandidate = true
			}

			// Pattern 3: Issues with specific keywords that often indicate false positives
			falsePositiveKeywords := []string{
				"auto-generated",
				"vendor/",
				"node_modules/",
				"third_party/",
				"generated",
				"protoc-gen",
				"swagger generate",
			}

			for _, keyword := range falsePositiveKeywords {
				if strings.Contains(lowerDesc, keyword) {
					isFalsePositiveCandidate = true
					break
				}
			}
		}

		if isFalsePositiveCandidate {
			candidates = append(candidates, debt)
		}
	}

	log.Printf("  🔍 Identified %d potential false positive candidates", len(candidates))
	return candidates
}

// isInGeneratedOrVendorCode checks if a file location is in generated or vendor code
func (r *Remediator) isInGeneratedOrVendorCode(location string) bool {
	generatedPatterns := []string{
		"vendor/",
		"node_modules/",
		"generated/",
		"gen/",
		"build/",
		"dist/",
		"target/",
		"out/",
		".git/",
	}

	locationLower := strings.ToLower(location)
	for _, pattern := range generatedPatterns {
		if strings.Contains(locationLower, pattern) {
			return true
		}
	}

	return false
}

// identifyRulesToDisable maps false positive candidates to specific Codacy rules
func (r *Remediator) identifyRulesToDisable(rules []CodacyRule, candidates []types.TechnicalDebtItem) []CodacyRule {
	var rulesToDisable []CodacyRule

	// Create a map of rule patterns to rules for quick lookup
	ruleMap := make(map[string]*CodacyRule)
	for _, rule := range rules {
		ruleMap[rule.ID] = &rule
		ruleMap[rule.Name] = &rule
	}

	// Analyze candidates to identify problematic rules
	problematicRuleIDs := make(map[string]bool)

	for _, candidate := range candidates {
		// Extract rule information from the debt item description
		// Format: "[RuleName] Category: Message"
		if strings.Contains(candidate.Description, "[") && strings.Contains(candidate.Description, "]") {
			start := strings.Index(candidate.Description, "[")
			end := strings.Index(candidate.Description, "]")
			if start != -1 && end != -1 && end > start {
				ruleName := candidate.Description[start+1 : end]

				// Look for the rule by name or pattern
				for _, rule := range rules {
					if strings.Contains(strings.ToLower(rule.Name), strings.ToLower(ruleName)) ||
						strings.Contains(strings.ToLower(rule.Description), strings.ToLower(ruleName)) {
						problematicRuleIDs[rule.ID] = true
						break
					}
				}
			}
		}
	}

	// Convert problematic rule IDs to rules
	for _, rule := range rules {
		if problematicRuleIDs[rule.ID] {
			rulesToDisable = append(rulesToDisable, rule)
		}
	}

	log.Printf("  🔍 Identified %d Codacy rules to disable", len(rulesToDisable))
	return rulesToDisable
}

// ============================================================================
// GIT MANAGER
// ============================================================================

type GitManager struct {
	config *Config
}

func NewGitManager(config *Config) *GitManager {
	return &GitManager{config: config}
}

func (gm *GitManager) CreateBranch(branchName string) error {
	log.Printf("🌿 Creating branch: %s", branchName)

	// Checkout to main/master first
	checkoutCmd := exec.Command("git", "checkout", "main")
	checkoutCmd.Dir = gm.config.ProjectPath
	if err := checkoutCmd.Run(); err != nil {
		// Try master if main doesn't exist
		checkoutCmd = exec.Command("git", "checkout", "master")
		checkoutCmd.Dir = gm.config.ProjectPath
		if err := checkoutCmd.Run(); err != nil {
			return fmt.Errorf("failed to checkout base branch: %w", err)
		}
	}

	// Pull latest changes
	pullCmd := exec.Command("git", "pull")
	pullCmd.Dir = gm.config.ProjectPath
	_ = pullCmd.Run() // Ignore errors

	// Create and checkout new branch
	branchCmd := exec.Command("git", "checkout", "-b", branchName)
	branchCmd.Dir = gm.config.ProjectPath
	output, err := branchCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create branch: %w\n%s", err, output)
	}

	return nil
}

func (gm *GitManager) CommitAndPush(branchName, message string) error {
	log.Printf("💾 Committing changes...")

	// Add all changes
	addCmd := exec.Command("git", "add", ".")
	addCmd.Dir = gm.config.ProjectPath
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add changes: %w", err)
	}

	// Commit
	commitCmd := exec.Command("git", "commit", "-m", message)
	commitCmd.Dir = gm.config.ProjectPath
	output, err := commitCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to commit: %w\n%s", err, output)
	}

	// Push to remote
	log.Printf("⬆️  Pushing to remote...")
	pushCmd := exec.Command("git", "push", "-u", "origin", branchName)
	pushCmd.Dir = gm.config.ProjectPath
	output, err = pushCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to push: %w\n%s", err, output)
	}

	log.Printf("✅ Changes committed and pushed to branch: %s", branchName)
	return nil
}

// ============================================================================
// GIT MANAGER
// ============================================================================

type ArchGuardian struct {
	config      *Config
	scanner     *Scanner
	diagnoser   *RiskDiagnoser
	remediator  *Remediator
	dataEngine  *data_engine.DataEngine
	triggerScan chan bool // Channel to trigger manual scans
}

func NewArchGuardian(config *Config, aiEngine *AIInferenceEngine) *ArchGuardian {
	var de *data_engine.DataEngine
	if config.DataEngine.Enable {
		log.Println("📈 Initializing Data Engine...")
		// Convert main.go config to data_engine config
		deConfig := data_engine.DataEngineConfig{
			EnableKafka:      config.DataEngine.EnableKafka,
			KafkaBrokers:     config.DataEngine.KafkaBrokers,
			ChromaDBURL:      config.DataEngine.ChromaDBURL,
			ChromaCollection: config.DataEngine.ChromaCollection,
			EnableChromaDB:   config.DataEngine.EnableChromaDB,
			EnableWebSocket:  config.DataEngine.EnableWebSocket,
			WebSocketPort:    config.DataEngine.WebSocketPort,
			EnableRESTAPI:    config.DataEngine.EnableRESTAPI,
			RESTAPIPort:      config.DataEngine.RESTAPIPort,
			WindowSize:       1 * time.Minute,
			MetricsInterval:  30 * time.Second,
		}
		de = data_engine.NewDataEngine(deConfig)
		if err := de.Start(); err != nil {
			log.Printf("⚠️  Data Engine failed to start: %v. Continuing without it.", err)
			de = nil // Ensure data engine is nil if it fails
		} else {
			log.Println("✅ Data Engine started successfully.")
		}
	}

	scanner := NewScanner(config, aiEngine)

	// Initialize Codacy client if API token is provided
	var codacyClient *CodacyClient
	if codacyToken := getEnv("CODACY_API_TOKEN", ""); codacyToken != "" {
		codacyProvider := getEnv("CODACY_PROVIDER", "gh") // Default to GitHub
		codacyRepo := getEnv("CODACY_REPOSITORY", "")
		if codacyRepo != "" {
			codacyClient = NewCodacyClient(codacyToken, codacyProvider, codacyRepo)
			log.Println("🔗 Codacy integration enabled")
		}
	}

	diagnoser := NewRiskDiagnoser(scanner, codacyClient)
	remediator := NewRemediator(config, diagnoser)

	return &ArchGuardian{
		config:      config,
		scanner:     scanner,
		diagnoser:   diagnoser,
		remediator:  remediator,
		dataEngine:  de,
		triggerScan: make(chan bool), // Initialize the channel
	}
}

func (ag *ArchGuardian) Run(ctx context.Context) error {
	log.Println("🚀 ArchGuardian starting...")
	log.Printf("📁 Project: %s", ag.config.ProjectPath)
	log.Printf("🤖 AI Providers: Cerebras (fast), Gemini (reasoning), %s (remediation)",
		ag.config.AIProviders.CodeRemediationProvider)
	log.Println("✅ ArchGuardian is running. Waiting for scan trigger from API or periodic schedule...")

	ticker := time.NewTicker(ag.config.ScanInterval)
	defer ticker.Stop()

	// Run scans based on ticker or manual trigger
	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 ArchGuardian shutting down...")
			return ctx.Err()
		case <-ag.triggerScan: // Handle manual scan trigger
			log.Println("⚡ Manual scan triggered via API.")
			if err := ag.runCycle(ctx); err != nil {
				log.Printf("❌ Manual scan cycle failed: %v", err)
			}
			// Reset the ticker to align with the manual scan time, preventing immediate double scan
			ticker.Reset(ag.config.ScanInterval)
		case <-ticker.C:
			if err := ag.runCycle(ctx); err != nil {
				log.Printf("❌ Scan cycle failed: %v", err)
			}
		}
	}
}

func (ag *ArchGuardian) runCycle(ctx context.Context) error {
	log.Println("\n" + strings.Repeat("=", 80))
	log.Printf("🔄 Starting scan cycle at %s", time.Now().Format(time.RFC3339))
	log.Println(strings.Repeat("=", 80))

	ag.produceSystemEvent(data_engine.SystemEventType, "scan_cycle_started", nil)

	// Phase 1: Scan project
	if err := ag.scanner.ScanProject(ctx); err != nil {
		ag.produceSystemEvent(data_engine.ErrorEvent, "scan_project_failed", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("scan failed: %w", err)
	}
	ag.produceSystemEvent(data_engine.SystemEventType, "scan_project_completed", map[string]interface{}{"node_count": len(ag.scanner.graph.Nodes)})

	// Export knowledge graph
	if err := ag.exportKnowledgeGraph(); err != nil {
		log.Printf("⚠️  Failed to export knowledge graph: %v", err)
	}

	// Phase 2: Diagnose risks
	assessment, err := ag.diagnoser.DiagnoseRisks(ctx)
	if err != nil {
		ag.produceSystemEvent(data_engine.ErrorEvent, "diagnose_risks_failed", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("risk diagnosis failed: %w", err)
	}
	ag.produceSystemEvent(data_engine.SystemEventType, "diagnose_risks_completed", map[string]interface{}{"overall_score": assessment.OverallScore})
	for _, vuln := range assessment.SecurityVulns {
		ag.produceSystemEvent(data_engine.ErrorEvent, "security_vulnerability_found", map[string]interface{}{"cve": vuln.CVE, "package": vuln.Package, "severity": vuln.Severity})
	}

	// Export risk assessment
	if err := ag.exportRiskAssessment(assessment); err != nil {
		log.Printf("⚠️  Failed to export risk assessment: %v", err)
	}

	// Phase 3: Automated remediation
	if assessment.OverallScore > 20.0 { // Only remediate if risk score is significant
		if err := ag.remediator.RemediateRisks(ctx, assessment); err != nil {
			ag.produceSystemEvent(data_engine.ErrorEvent, "remediation_failed", map[string]interface{}{"error": err.Error()})
			log.Printf("⚠️  Remediation failed: %v", err)
		}
		ag.produceSystemEvent(data_engine.SystemEventType, "remediation_completed", nil)
	} else {
		ag.produceSystemEvent(data_engine.SystemEventType, "remediation_skipped", map[string]interface{}{"reason": "System health is good", "overall_score": assessment.OverallScore})
		log.Println("✅ System health is good, no remediation needed")
	}

	log.Println(strings.Repeat("=", 80))
	log.Printf("✅ Scan cycle complete. Overall risk score: %.2f/100", assessment.OverallScore)
	log.Println(strings.Repeat("=", 80) + "\n")

	ag.produceSystemEvent(data_engine.SystemEventType, "scan_cycle_completed", map[string]interface{}{"overall_score": assessment.OverallScore})
	return nil
}

func (ag *ArchGuardian) exportKnowledgeGraph() error {
	outputPath := filepath.Join(ag.config.ProjectPath, ".archguardian", "knowledge-graph.json")
	os.MkdirAll(filepath.Dir(outputPath), 0755)

	data, err := json.MarshalIndent(ag.scanner.graph, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	log.Printf("📊 Knowledge graph exported to: %s", outputPath)
	return nil
}

func (ag *ArchGuardian) exportRiskAssessment(assessment *types.RiskAssessment) error {
	outputPath := filepath.Join(ag.config.ProjectPath, ".archguardian", "risk-assessment.json")
	os.MkdirAll(filepath.Dir(outputPath), 0755)

	data, err := json.MarshalIndent(assessment, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	log.Printf("📊 Risk assessment exported to: %s", outputPath)
	return nil
}

func (ag *ArchGuardian) produceSystemEvent(eventType data_engine.EventType, subType string, data map[string]interface{}) {
	if ag.dataEngine == nil {
		return
	}

	if data == nil {
		data = make(map[string]interface{})
	}
	data["sub_type"] = subType

	event := data_engine.Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Source:    "archguardian_core",
		Data:      data,
	}

	if err := ag.dataEngine.ProcessEvent(event); err != nil {
		log.Printf("⚠️  Failed to produce system event to data engine: %v", err)
	}
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func isCodeFile(path string) bool {
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

func generateNodeID(path string) string {
	// Simple hash-based ID generation
	return fmt.Sprintf("node_%x", []byte(path))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

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

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

var guardianInstance *ArchGuardian // Global ArchGuardian instance for API access

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

func main() {
	log.Println("╔════════════════════════════════════════════════════════════════╗")
	log.Println("║            ArchGuardian - AI-Powered Code Guardian            ║")
	log.Println("║          Deep Visibility • Risk Detection • Auto-Fix           ║")
	log.Println("╚════════════════════════════════════════════════════════════════╝")

	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  No .env file found or failed to load, using environment variables only")
	} else {
		log.Println("✅ .env file loaded successfully")
	}

	// Load configuration from environment variables
	config := &Config{
		ProjectPath:       getEnv("PROJECT_PATH", "."),
		GitHubToken:       getEnv("GITHUB_TOKEN", ""),
		GitHubRepo:        getEnv("GITHUB_REPO", ""),
		ScanInterval:      time.Duration(getEnvInt("SCAN_INTERVAL_HOURS", 24)) * time.Hour,
		RemediationBranch: getEnv("REMEDIATION_BRANCH", "archguardian-fixes"),
		AIProviders: AIProviderConfig{
			Cerebras: ProviderCredentials{
				APIKey:   getEnv("CEREBRAS_API_KEY", ""),
				Endpoint: getEnv("CEREBRAS_ENDPOINT", "https://api.cerebras.ai/v1"),
				Model:    getEnv("CEREBRAS_MODEL", "llama3.1-8b"),
			},
			Gemini: ProviderCredentials{
				APIKey:   getEnv("GEMINI_API_KEY", ""),
				Endpoint: getEnv("GEMINI_ENDPOINT", "https://generativelanguage.googleapis.com/v1"),
				Model:    getEnv("GEMINI_MODEL", "gemini-pro"),
			},
			Anthropic: ProviderCredentials{
				APIKey:   getEnv("ANTHROPIC_API_KEY", ""),
				Endpoint: getEnv("ANTHROPIC_ENDPOINT", "https://api.anthropic.com/v1"),
				Model:    getEnv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929"),
			},
			OpenAI: ProviderCredentials{
				APIKey:   getEnv("OPENAI_API_KEY", ""),
				Endpoint: getEnv("OPENAI_ENDPOINT", "https://api.openai.com/v1"),
				Model:    getEnv("OPENAI_MODEL", "gpt-4"),
			},
			DeepSeek: ProviderCredentials{
				APIKey:   getEnv("DEEPSEEK_API_KEY", ""),
				Endpoint: getEnv("DEEPSEEK_ENDPOINT", "https://api.deepseek.com/v1"),
				Model:    getEnv("DEEPSEEK_MODEL", "deepseek-coder"),
			},
			CodeRemediationProvider: getEnv("CODE_REMEDIATION_PROVIDER", "anthropic"),
		},
		Orchestrator: OrchestratorConfig{
			PlannerModel:   getEnv("ORCHESTRATOR_PLANNER_MODEL", "gemini-pro"),
			ExecutorModels: strings.Split(getEnv("ORCHESTRATOR_EXECUTOR_MODELS", "llama3.1-8b,deepseek-coder"), ","),
			FinalizerModel: getEnv("ORCHESTRATOR_FINALIZER_MODEL", "claude-3-sonnet-20240229"),
			VerifierModel:  getEnv("ORCHESTRATOR_VERIFIER_MODEL", "gemini-pro"),
		},
		DataEngine: DataEngineConfig{
			Enable:           getEnvBool("DATA_ENGINE_ENABLE", true),
			EnableKafka:      getEnvBool("KAFKA_ENABLE", false),
			EnableChromaDB:   getEnvBool("CHROMADB_ENABLE", true),
			EnableWebSocket:  getEnvBool("WEBSOCKET_ENABLE", true),
			EnableRESTAPI:    getEnvBool("RESTAPI_ENABLE", true),
			KafkaBrokers:     strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ","),
			ChromaDBURL:      getEnv("CHROMADB_URL", "http://localhost:8000"),
			ChromaCollection: getEnv("CHROMADB_COLLECTION", "archguardian_events"),
			WebSocketPort:    getEnvInt("WEBSOCKET_PORT", 8080),
			RESTAPIPort:      getEnvInt("RESTAPI_PORT", 7080),
		},
	}

	// Validate configuration
	if config.ProjectPath == "" {
		log.Fatal("❌ PROJECT_PATH is required")
	}

	if config.AIProviders.Cerebras.APIKey == "" {
		log.Println("⚠️  Warning: CEREBRAS_API_KEY not set")
	}

	if config.AIProviders.Gemini.APIKey == "" {
		log.Println("⚠️  Warning: GEMINI_API_KEY not set")
	}

	// Create a single AIInferenceEngine instance to be shared
	aiEngine := NewAIInferenceEngine(config)

	// Create ArchGuardian instance
	guardian := NewArchGuardian(config, aiEngine)
	guardianInstance = guardian // Assign to global variable

	// Initialize Log Analyzer for log stream processing
	logAnalyzer := NewLogAnalyzer(config, aiEngine)

	// Start dashboard server in a goroutine
	go func() {
		if err := startDashboardServer(guardianInstance); err != nil {
			log.Printf("⚠️  Dashboard server failed: %v", err)
		}
	}()

	// Start log ingestion server in a goroutine
	go func() {
		if err := startLogIngestionServer(logAnalyzer); err != nil {
			log.Printf("⚠️  Log ingestion server failed: %v", err)
		}
	}()

	// Run with context
	ctx := context.Background()
	if err := guardianInstance.Run(ctx); err != nil {
		log.Fatalf("❌ ArchGuardian failed: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intVal int
		if _, err := fmt.Sscanf(value, "%d", &intVal); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// ============================================================================
// CODACY CLIENT
// ============================================================================

// CodacyClient handles interactions with the Codacy API
type CodacyClient struct {
	httpClient *http.Client
	apiToken   string
	baseURL    string
	provider   string // "gh" for GitHub, "gl" for GitLab, etc.
	repository string // owner/repo format
}

// CodacyIssue represents an issue from Codacy API
type CodacyIssue struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	FilePath    string                 `json:"file_path"`
	Line        int                    `json:"line"`
	Column      int                    `json:"column"`
	PatternID   string                 `json:"pattern_id"`
	PatternName string                 `json:"pattern_name"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// CodacyRepository represents a repository in Codacy
type CodacyRepository struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	URL      string `json:"url"`
}

// CodacyRule represents a Codacy rule configuration
type CodacyRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Severity    string `json:"severity"`
}

// NewCodacyClient creates a new Codacy client
func NewCodacyClient(apiToken, provider, repository string) *CodacyClient {
	return &CodacyClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiToken:   apiToken,
		baseURL:    "https://api.codacy.com/api/v3",
		provider:   provider,
		repository: repository,
	}
}

// GetIssues fetches all open issues for the repository from Codacy
func (cc *CodacyClient) GetIssues() ([]CodacyIssue, error) {
	log.Printf("  🔍 Fetching Codacy issues for repository: %s", cc.repository)

	url := fmt.Sprintf("%s/analysis/repositories/%s/%s/issues", cc.baseURL, cc.provider, cc.repository)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-token", cc.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issues: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("codacy API returned status %d", resp.StatusCode)
	}

	var response struct {
		Data []CodacyIssue `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	log.Printf("  📊 Retrieved %d issues from Codacy", len(response.Data))
	return response.Data, nil
}

// GetRepositories fetches all repositories for the account
func (cc *CodacyClient) GetRepositories() ([]CodacyRepository, error) {
	log.Println("  🔍 Fetching Codacy repositories...")

	url := fmt.Sprintf("%s/repositories", cc.baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-token", cc.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repositories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("codacy API returned status %d", resp.StatusCode)
	}

	var response struct {
		Data []CodacyRepository `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	log.Printf("  📊 Retrieved %d repositories from Codacy", len(response.Data))
	return response.Data, nil
}

// GetRules fetches all rules for the repository
func (cc *CodacyClient) GetRules() ([]CodacyRule, error) {
	log.Printf("  🔍 Fetching Codacy rules for repository: %s", cc.repository)

	url := fmt.Sprintf("%s/analysis/repositories/%s/%s/rules", cc.baseURL, cc.provider, cc.repository)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-token", cc.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch rules: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("codacy API returned status %d", resp.StatusCode)
	}

	var response struct {
		Data []CodacyRule `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	log.Printf("  📊 Retrieved %d rules from Codacy", len(response.Data))
	return response.Data, nil
}

// UpdateRule updates a specific rule configuration
func (cc *CodacyClient) UpdateRule(ruleID string, enabled bool, severity string) error {
	log.Printf("  🔧 Updating Codacy rule %s: enabled=%t, severity=%s", ruleID, enabled, severity)

	url := fmt.Sprintf("%s/analysis/repositories/%s/%s/rules/%s", cc.baseURL, cc.provider, cc.repository, ruleID)

	rule := CodacyRule{
		ID:       ruleID,
		Enabled:  enabled,
		Severity: severity,
	}

	jsonData, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule data: %w", err)
	}

	req, err := http.NewRequest("PUT", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-token", cc.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("codacy API returned status %d", resp.StatusCode)
	}

	log.Printf("  ✅ Successfully updated Codacy rule %s", ruleID)
	return nil
}

// ConvertCodacyIssueToTechnicalDebt converts a Codacy issue to a TechnicalDebtItem
func (cc *CodacyClient) ConvertCodacyIssueToTechnicalDebt(issue CodacyIssue) types.TechnicalDebtItem {
	// Map Codacy severity to our severity levels
	severity := "medium"
	switch issue.Severity {
	case "Error", "Critical":
		severity = "high"
	case "Warning":
		severity = "medium"
	case "Info":
		severity = "low"
	}

	// Map Codacy category to our type
	debtType := "code_quality"
	switch issue.Category {
	case "CodeStyle", "BestPractice":
		debtType = "code_style"
	case "ErrorProne", "BugRisk":
		debtType = "error_prone"
	case "Performance":
		debtType = "performance"
	case "Security":
		debtType = "security"
	case "UnusedCode":
		debtType = "unused_code"
	case "Complexity":
		debtType = "complexity"
	case "Duplication":
		debtType = "duplication"
	}

	// Estimate effort based on severity and category
	effort := 2 // default
	if issue.Severity == "Critical" || issue.Severity == "Error" {
		effort = 4
	} else if issue.Category == "Complexity" || issue.Category == "Duplication" {
		effort = 3
	}

	location := issue.FilePath
	if issue.Line > 0 {
		location = fmt.Sprintf("%s:%d", issue.FilePath, issue.Line)
	}

	return types.TechnicalDebtItem{
		ID:          fmt.Sprintf("CODACY-%s", issue.ID),
		Location:    location,
		Type:        debtType,
		Severity:    severity,
		Description: fmt.Sprintf("[%s] %s: %s", issue.PatternName, issue.Category, issue.Message),
		Remediation: fmt.Sprintf("Fix the %s issue identified by Codacy rule: %s", issue.Category, issue.PatternName),
		Effort:      effort,
	}
}

// ============================================================================
// LOG ANALYZER
// ============================================================================

// LogMsg represents a log message from external applications
type LogMsg struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Service   string                 `json:"service"`
	Component string                 `json:"component"`
	TraceID   string                 `json:"trace_id,omitempty"`
	SpanID    string                 `json:"span_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Error     *LogError              `json:"error,omitempty"`
}

// LogError represents error information in log messages
type LogError struct {
	Type  string `json:"type"`
	Code  string `json:"code,omitempty"`
	Stack string `json:"stack,omitempty"`
	Cause string `json:"cause,omitempty"`
}

// LogAnalyzer processes log streams to identify issues and create remediation tasks
type LogAnalyzer struct {
	config         *Config
	ai             *AIInferenceEngine
	errorBuffer    map[string][]LogMsg // Buffer of recent errors per component
	alertThreshold int
}

// NewLogAnalyzer creates a new log analyzer instance
func NewLogAnalyzer(config *Config, ai *AIInferenceEngine) *LogAnalyzer {
	return &LogAnalyzer{
		config:         config,
		ai:             ai,
		errorBuffer:    make(map[string][]LogMsg),
		alertThreshold: 5, // Alert after 5 errors from same component
	}
}

// ProcessLog processes a single log message and identifies potential issues
func (la *LogAnalyzer) ProcessLog(ctx context.Context, logMsg LogMsg) error {
	// Add to error buffer for pattern analysis
	componentKey := fmt.Sprintf("%s:%s", logMsg.Service, logMsg.Component)
	if logMsg.Level == "ERROR" || logMsg.Level == "FATAL" || logMsg.Level == "CRITICAL" {
		la.errorBuffer[componentKey] = append(la.errorBuffer[componentKey], logMsg)

		// Keep only recent errors (last 50 per component)
		if len(la.errorBuffer[componentKey]) > 50 {
			la.errorBuffer[componentKey] = la.errorBuffer[componentKey][len(la.errorBuffer[componentKey])-50:]
		}
	}

	// Check if we should analyze this component for issues
	if len(la.errorBuffer[componentKey]) >= la.alertThreshold {
		return la.analyzeErrorPattern(ctx, componentKey)
	}

	return nil
}

// analyzeErrorPattern uses AI to analyze error patterns and identify root causes
func (la *LogAnalyzer) analyzeErrorPattern(ctx context.Context, componentKey string) error {
	log.Printf("  🔍 Analyzing error pattern for component: %s", componentKey)

	errors := la.errorBuffer[componentKey]

	// Prepare error data for AI analysis
	errorData := map[string]interface{}{
		"component":   componentKey,
		"error_count": len(errors),
		"errors":      errors,
		"time_range": map[string]interface{}{
			"start": errors[0].Timestamp,
			"end":   errors[len(errors)-1].Timestamp,
		},
	}

	// Use AI to analyze the error pattern
	provider := AIProviderGemini // Use Gemini for deep error analysis
	analysis, err := la.ai.AnalyzeRisks(ctx, errorData, provider)
	if err != nil {
		log.Printf("  ⚠️  Failed to analyze error pattern: %v", err)
		return nil
	}

	// Extract actionable issues from analysis
	issues := la.extractIssuesFromAnalysis(analysis, componentKey)

	// Create technical debt items for identified issues
	for _, issue := range issues {
		if err := la.createTechnicalDebtItem(issue); err != nil {
			log.Printf("  ⚠️  Failed to create technical debt item: %v", err)
		}
	}

	// Clear error buffer after analysis
	delete(la.errorBuffer, componentKey)

	log.Printf("  ✅ Error pattern analysis complete for %s: %d issues identified", componentKey, len(issues))
	return nil
}

// extractIssuesFromAnalysis extracts actionable issues from AI analysis
func (la *LogAnalyzer) extractIssuesFromAnalysis(analysis map[string]interface{}, componentKey string) []map[string]interface{} {
	var issues []map[string]interface{}

	// Extract issues from AI analysis
	if issuesData, ok := analysis["log_issues"].([]interface{}); ok {
		for _, issue := range issuesData {
			if issueMap, ok := issue.(map[string]interface{}); ok {
				issueMap["component"] = componentKey
				issueMap["source"] = "log_analysis"
				issues = append(issues, issueMap)
			}
		}
	}

	return issues
}

// createTechnicalDebtItem creates a technical debt item from log analysis findings
func (la *LogAnalyzer) createTechnicalDebtItem(issue map[string]interface{}) error {
	// In a real implementation, this would integrate with the RiskDiagnoser
	// For now, we'll log the issue and could trigger remediation

	log.Printf("  📋 Created technical debt item from log analysis:")
	log.Printf("    Component: %v", issue["component"])
	log.Printf("    Type: %v", issue["type"])
	log.Printf("    Description: %v", issue["description"])
	log.Printf("    Severity: %v", issue["severity"])

	// Here we could trigger immediate remediation for critical log-identified issues
	if severity, ok := issue["severity"].(string); ok && severity == "critical" {
		log.Printf("  🚨 Critical issue detected in logs, triggering immediate remediation...")
		// In a real implementation, this would trigger the remediation cycle
	}

	return nil
}

// ============================================================================
// DASHBOARD SERVER
// ============================================================================

// startDashboardServer starts the web dashboard server with embedded files
func startDashboardServer(ag *ArchGuardian) error {
	log.Println("🌐 Starting ArchGuardian Dashboard Server...")

	router := mux.NewRouter()
	// Add CORS middleware to the router directly
	router.Use(corsMiddleware)

	// Serve embedded dashboard files
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedFile(w, r, "index.html", "text/html")
	})

	router.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedFile(w, r, "style.css", "text/css")
	})

	router.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedFile(w, r, "app.js", "application/javascript")
	})

	// API endpoints for dashboard data
	router.HandleFunc("/api/v1/knowledge-graph", handleKnowledgeGraph).Methods("GET")
	router.HandleFunc("/api/v1/risk-assessment", handleRiskAssessment).Methods("GET")
	router.HandleFunc("/api/v1/issues", handleIssues).Methods("GET")
	router.HandleFunc("/api/v1/coverage", handleCoverage).Methods("GET")
	router.HandleFunc("/api/v1/scan/start", func(w http.ResponseWriter, r *http.Request) {
		handleStartScan(w, r, ag)
	}).Methods("POST")
	router.HandleFunc("/api/v1/settings", handleSettings).Methods("GET", "POST")

	// Health check endpoint
	router.HandleFunc("/health", handleHealth).Methods("GET")

	log.Println("✅ Dashboard server started on http://localhost:3000")
	log.Println("📊 API endpoints available on http://localhost:3000/api/v1/")
	log.Println("📁 Dashboard files served from embedded resources")
	return http.ListenAndServe(":3000", router)
}

// corsMiddleware adds CORS headers to all responses
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveEmbeddedFile serves embedded dashboard files with proper content types
func serveEmbeddedFile(w http.ResponseWriter, r *http.Request, filename, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")

	var content string
	switch filename {
	case "index.html":
		content = dashboardHTML
	case "style.css":
		content = dashboardCSS
	case "app.js":
		content = dashboardJS
	default:
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
}

// handleKnowledgeGraph returns the current knowledge graph data
func handleKnowledgeGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// In a real implementation, this would get data from the current scan
	// For now, return a sample response
	response := map[string]interface{}{
		"nodes": []map[string]interface{}{
			{
				"id":   "sample_node_1",
				"type": "code",
				"name": "main.go",
				"path": "/path/to/main.go",
			},
		},
		"edges": []map[string]interface{}{},
	}

	json.NewEncoder(w).Encode(response)
}

// startLogIngestionServer starts the log ingestion server for receiving external log streams
func startLogIngestionServer(logAnalyzer *LogAnalyzer) error {
	log.Println("📝 Starting Log Ingestion Server...")

	router := mux.NewRouter()

	// Log ingestion endpoints
	router.HandleFunc("/api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		handleLogIngestion(w, r, logAnalyzer)
	}).Methods("POST")

	router.HandleFunc("/api/v1/logs/batch", func(w http.ResponseWriter, r *http.Request) {
		handleBatchLogIngestion(w, r, logAnalyzer)
	}).Methods("POST")

	// Health check for log ingestion
	router.HandleFunc("/api/v1/logs/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"service":   "log_ingestion",
			"timestamp": time.Now(),
		})
	}).Methods("GET")

	log.Println("✅ Log ingestion server started on http://localhost:4000")
	log.Println("📝 Log endpoints available on http://localhost:4000/api/v1/logs")
	return http.ListenAndServe(":4000", router)
}

// handleLogIngestion processes a single log message
func handleLogIngestion(w http.ResponseWriter, r *http.Request, logAnalyzer *LogAnalyzer) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var logMsg LogMsg
	if err := json.NewDecoder(r.Body).Decode(&logMsg); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Set timestamp if not provided
	if logMsg.Timestamp.IsZero() {
		logMsg.Timestamp = time.Now()
	}

	// Process the log message
	ctx := context.Background()
	if err := logAnalyzer.ProcessLog(ctx, logMsg); err != nil {
		log.Printf("  ⚠️  Failed to process log message: %v", err)
		http.Error(w, "Failed to process log", http.StatusInternalServerError)
		return
	}

	// Respond with success
	response := map[string]interface{}{
		"status":    "accepted",
		"timestamp": time.Now(),
		"message":   "Log message processed successfully",
	}

	json.NewEncoder(w).Encode(response)
}

// handleBatchLogIngestion processes multiple log messages at once
func handleBatchLogIngestion(w http.ResponseWriter, r *http.Request, logAnalyzer *LogAnalyzer) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var logBatch struct {
		Logs []LogMsg `json:"logs"`
	}

	if err := json.NewDecoder(r.Body).Decode(&logBatch); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	processed := 0
	errors := 0

	// Process each log message
	for _, logMsg := range logBatch.Logs {
		// Set timestamp if not provided
		if logMsg.Timestamp.IsZero() {
			logMsg.Timestamp = time.Now()
		}

		if err := logAnalyzer.ProcessLog(ctx, logMsg); err != nil {
			log.Printf("  ⚠️  Failed to process log message: %v", err)
			errors++
		} else {
			processed++
		}
	}

	// Respond with processing summary
	response := map[string]interface{}{
		"status":    "completed",
		"timestamp": time.Now(),
		"processed": processed,
		"errors":    errors,
		"total":     len(logBatch.Logs),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleRiskAssessment returns the current risk assessment data
func handleRiskAssessment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// In a real implementation, this would get data from the current scan
	// For now, return a sample response
	response := map[string]interface{}{
		"overall_score": 15.5,
		"technical_debt": []map[string]interface{}{
			{
				"id":          "TD-1",
				"location":    "main.go:100",
				"type":        "complex_function",
				"severity":    "medium",
				"description": "Function is too complex",
				"remediation": "Break down into smaller functions",
				"effort":      4,
			},
		},
		"security_vulns":         []map[string]interface{}{},
		"obsolete_code":          []map[string]interface{}{},
		"dangerous_dependencies": []map[string]interface{}{},
		"timestamp":              time.Now(),
	}

	json.NewEncoder(w).Encode(response)
}

// handleIssues returns filtered issues based on type
func handleIssues(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issueType := r.URL.Query().Get("type")
	if issueType == "" {
		issueType = "technical-debt"
	}

	// In a real implementation, this would get data from the current scan
	// For now, return sample data based on type
	var response map[string]interface{}

	switch issueType {
	case "technical-debt":
		response = map[string]interface{}{
			"technical_debt": []map[string]interface{}{
				{
					"id":          "TD-1",
					"location":    "main.go:100",
					"type":        "complex_function",
					"severity":    "medium",
					"description": "Function is too complex",
					"remediation": "Break down into smaller functions",
					"effort":      4,
				},
			},
		}
	case "security":
		response = map[string]interface{}{
			"security_vulns": []map[string]interface{}{
				{
					"cve":         "CVE-2023-1234",
					"package":     "example-package",
					"version":     "1.0.0",
					"severity":    "high",
					"description": "Buffer overflow vulnerability",
					"fix_version": "1.0.1",
					"cvss":        7.5,
				},
			},
		}
	case "obsolete":
		response = map[string]interface{}{
			"obsolete_code": []map[string]interface{}{
				{
					"path":             "old_file.go",
					"references":       0,
					"removal_safety":   "safe",
					"recommend_action": "File is no longer used and can be removed",
				},
			},
		}
	case "dependencies":
		response = map[string]interface{}{
			"dangerous_dependencies": []map[string]interface{}{
				{
					"package":         "old-package",
					"current_version": "1.0.0",
					"latest_version":  "2.0.0",
					"security_issues": 3,
					"maintenance":     "deprecated",
					"recommendation":  "Update to latest version",
				},
			},
		}
	}

	json.NewEncoder(w).Encode(response)
}

// handleCoverage returns test coverage data
func handleCoverage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// In a real implementation, this would get data from test coverage analysis
	// For now, return sample data
	response := map[string]interface{}{
		"overall_coverage": 78.5,
		"lines_covered":    1250,
		"total_lines":      1600,
		"test_files":       15,
		"file_coverage": map[string]float64{
			"main.go":       85.0,
			"scanner.go":    92.0,
			"remediator.go": 78.0,
		},
	}

	json.NewEncoder(w).Encode(response)
}

// handleSettings handles GET and POST for settings
func handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	switch r.Method {
	case "GET":
		// Return current settings
		response := map[string]interface{}{
			"scan_interval":         24,
			"remediation_threshold": 20,
			"remediation_provider":  "anthropic",
		}
		json.NewEncoder(w).Encode(response)

	case "POST":
		// Update settings
		var settings map[string]interface{}
		json.NewDecoder(r.Body).Decode(&settings)

		// In a real implementation, this would save settings
		log.Printf("Settings updated: %+v", settings)

		response := map[string]interface{}{
			"success": true,
			"message": "Settings updated successfully",
		}
		json.NewEncoder(w).Encode(response)
	}
}

// handleStartScan triggers a new scan cycle
func handleStartScan(w http.ResponseWriter, r *http.Request, ag *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	// CORS headers are now handled by the middleware

	// Send a signal to the trigger channel
	// Use a non-blocking send in case no one is listening (e.g., if a scan is already in progress)
	select {
	case ag.triggerScan <- true:
		log.Println("API: Scan trigger signal sent.")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "message": "Scan triggered successfully."})
	default:
		log.Println("API: Scan trigger channel is busy or not ready.")
		http.Error(w, "Scan trigger channel is busy or a scan is already in progress.", http.StatusServiceUnavailable)
	}
}

// handleHealth returns health check status
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
	}

	json.NewEncoder(w).Encode(response)
}
