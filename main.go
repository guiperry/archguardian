package main

import (
	"archgardian/data_engine"
	"archgardian/inference_engine"
	"archgardian/types"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

type Config struct {
	ProjectPath       string
	GitHubToken       string
	GitHubRepo        string
	AIProviders       AIProviderConfig
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
	graph  *types.KnowledgeGraph
	ai     *AIInferenceEngine
}

func NewScanner(cfg *Config) *Scanner {
	return &Scanner{
		config: cfg,
		graph:  NewKnowledgeGraph(),
		ai:     NewAIInferenceEngine(&cfg.AIProviders),
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

	// Phase 3: Database Schema Analysis
	if err := s.scanDatabaseModels(ctx); err != nil {
		return fmt.Errorf("database scan failed: %w", err)
	}

	// Phase 4: API Discovery
	if err := s.scanAPIs(ctx); err != nil {
		return fmt.Errorf("API scan failed: %w", err)
	}

	// Phase 5: Build Knowledge Graph
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

			// Parse file for imports/dependencies
			content, err := os.ReadFile(path)
			if err == nil {
				node.Metadata["lines"] = strings.Count(string(content), "\n")
				node.Metadata["size"] = info.Size()

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
		return s.scanGoMod(ctx)
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

func (s *Scanner) scanGoMod(ctx context.Context) error {
	_ = ctx // Acknowledge context for future use
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

func (s *Scanner) scanPackageJSON(ctx context.Context) error {
	_ = ctx // Acknowledge context for future use
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

func (s *Scanner) scanRequirementsTxt(ctx context.Context) error {
	_ = ctx // Acknowledge context for future use
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

			// Use Gemini for deep analysis of database models
			analysis, _ := s.ai.AnalyzeDatabaseModel(ctx, string(content), AIProviderGemini)

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

// ============================================================================
// RISK DIAGNOSIS
// ============================================================================

type RiskDiagnoser struct {
	scanner *Scanner
	ai      *AIInferenceEngine
}

func NewRiskDiagnoser(scanner *Scanner) *RiskDiagnoser {
	return &RiskDiagnoser{
		scanner: scanner,
		ai:      scanner.ai,
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

	// Use Gemini for comprehensive risk analysis
	riskData := rd.prepareRiskAnalysisData()
	risks, err := rd.ai.AnalyzeRisks(ctx, riskData, AIProviderGemini)
	if err != nil {
		return nil, fmt.Errorf("risk analysis failed: %w", err)
	}

	// Parse and categorize risks
	assessment.TechnicalDebt = rd.extractTechnicalDebt(risks)
	assessment.SecurityVulns = rd.extractSecurityVulns(risks)
	assessment.ObsoleteCode = rd.extractObsoleteCode(risks)
	assessment.DangerousDependencies = rd.extractDependencyRisks(risks)

	// Calculate overall risk score
	assessment.OverallScore = rd.calculateOverallRisk(assessment)

	log.Printf("  ⚠️  Found: %d technical debt items, %d security vulnerabilities, %d obsolete code items",
		len(assessment.TechnicalDebt), len(assessment.SecurityVulns), len(assessment.ObsoleteCode))

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

func NewAIInferenceEngine(config *AIProviderConfig) *AIInferenceEngine {
	log.Println("🧠 Initializing Multi-Model AI Inference Engine...")

	// The inference service needs a DB accessor, but doesn't use it. We can pass nil.
	service, err := inference_engine.NewInferenceService(nil)
	if err != nil {
		log.Fatalf("❌ Failed to create inference service: %v", err)
	}

	// Dynamically build the list of available LLMs from the application's configuration
	var attemptConfigs []inference_engine.LLMAttemptConfig
	if config.Cerebras.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "cerebras", ModelName: config.Cerebras.Model, APIKeyEnvVar: "CEREBRAS_API_KEY", MaxTokens: 4000, IsPrimary: true,
		})
	}
	if config.Gemini.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "gemini", ModelName: config.Gemini.Model, APIKeyEnvVar: "GEMINI_API_KEY", MaxTokens: 100000, IsPrimary: false,
		})
	}
	if config.DeepSeek.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "deepseek", ModelName: config.DeepSeek.Model, APIKeyEnvVar: "DEEPSEEK_API_KEY", MaxTokens: 8000, IsPrimary: false,
		})
	}
	if config.Anthropic.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "anthropic", ModelName: config.Anthropic.Model, APIKeyEnvVar: "ANTHROPIC_API_KEY", MaxTokens: 4000, IsPrimary: false,
		})
	}
	if config.OpenAI.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "openai", ModelName: config.OpenAI.Model, APIKeyEnvVar: "OPENAI_API_KEY", MaxTokens: 4000, IsPrimary: false,
		})
	}

	// Start the service with the dynamic configuration
	err = service.StartWithConfig(attemptConfigs)
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
		if err := r.updateDependency(ctx, dep); err != nil {
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

	// Use configured code remediation provider
	provider := r.getRemediationProvider()

	fix, err := r.ai.GenerateRemediation(ctx, map[string]interface{}{
		"type":        "security_vulnerability",
		"cve":         vuln.CVE,
		"package":     vuln.Package,
		"version":     vuln.Version,
		"fix_version": vuln.FixVersion,
	}, provider)

	if err != nil {
		return err
	}

	// Apply the fix
	return r.applyFix(fix, vuln.Package)
}

func (r *Remediator) updateDependency(ctx context.Context, dep types.DependencyRisk) error {
	_ = ctx // Acknowledge context for future use in command execution
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

	provider := r.getRemediationProvider()

	fix, err := r.ai.GenerateRemediation(ctx, map[string]interface{}{
		"type":        "technical_debt",
		"location":    debt.Location,
		"description": debt.Description,
		"remediation": debt.Remediation,
	}, provider)

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

func (r *Remediator) getRemediationProvider() AIProviderType {
	switch r.config.AIProviders.CodeRemediationProvider {
	case "anthropic":
		return AIProviderAnthropic
	case "openai":
		return AIProviderOpenAI
	case "deepseek":
		return AIProviderDeepSeek
	default:
		return AIProviderAnthropic // Default to Claude
	}
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
// MAIN APPLICATION
// ============================================================================

type ArchGuardian struct {
	config     *Config
	scanner    *Scanner
	diagnoser  *RiskDiagnoser
	remediator *Remediator
	dataEngine *data_engine.DataEngine
}

func NewArchGuardian(config *Config) *ArchGuardian {
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

	scanner := NewScanner(config)
	diagnoser := NewRiskDiagnoser(scanner)
	remediator := NewRemediator(config, diagnoser)

	return &ArchGuardian{
		config:     config,
		scanner:    scanner,
		diagnoser:  diagnoser,
		remediator: remediator,
		dataEngine: de,
	}
}

func (ag *ArchGuardian) Run(ctx context.Context) error {
	log.Println("🚀 ArchGuardian starting...")
	log.Printf("📁 Project: %s", ag.config.ProjectPath)
	log.Printf("🤖 AI Providers: Cerebras (fast), Gemini (reasoning), %s (remediation)",
		ag.config.AIProviders.CodeRemediationProvider)

	ticker := time.NewTicker(ag.config.ScanInterval)
	defer ticker.Stop()

	// Run initial scan immediately
	if err := ag.runCycle(ctx); err != nil {
		log.Printf("❌ Initial scan failed: %v", err)
	}

	// Run periodic scans
	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 ArchGuardian shutting down...")
			return ctx.Err()
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
// MAIN ENTRY POINT
// ============================================================================

func main() {
	log.Println("╔════════════════════════════════════════════════════════════════╗")
	log.Println("║            ArchGuardian - AI-Powered Code Guardian            ║")
	log.Println("║          Deep Visibility • Risk Detection • Auto-Fix           ║")
	log.Println("╚════════════════════════════════════════════════════════════════╝")

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

	// Create ArchGuardian instance
	guardian := NewArchGuardian(config)

	// Run with context
	ctx := context.Background()
	if err := guardian.Run(ctx); err != nil {
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
