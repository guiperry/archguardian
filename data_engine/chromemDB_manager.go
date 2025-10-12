package data_engine

import (
	"archguardian/types"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	chromem "github.com/philippgille/chromem-go"
)

// ChromemManager handles ChromemDB operations
type ChromemManager struct {
	client         *chromem.DB // Use chromem.DB as the client
	nodeCollection *chromem.Collection
	riskCollection *chromem.Collection
	dbPath         string
	mu             sync.RWMutex
	ef             chromem.EmbeddingFunc // Embedding function adapter
}

// NewChromemManager creates a new ChromemDB manager
func NewChromemManager(dbPath string) (*ChromemManager, error) {
	// Initialize ChromemDB persistent client
	if dbPath == "" {
		return nil, fmt.Errorf("dbPath is required for persistent client")
	}
	log.Printf("ChromemDB Manager: Initializing persistent client at path: %s", dbPath)

	// Ensure the directory for ChromemDB exists before trying to open/create the DB
	if errMkdir := os.MkdirAll(dbPath, 0700); errMkdir != nil {
		// If we can't even create the directory, it's a fatal issue for this manager.
		return nil, fmt.Errorf("ChromemDB Manager: failed to create directory for persistent client at %s: %w", dbPath, errMkdir)
	}

	// Attempt to remove a stale LOCK file if it exists, before trying to open.
	lockFilePath := filepath.Join(dbPath, "LOCK")
	if _, errStat := os.Stat(lockFilePath); errStat == nil {
		log.Printf("ChromemDB Manager: Found existing LOCK file at %s, attempting to remove.", lockFilePath)
		if errRemove := os.Remove(lockFilePath); errRemove != nil {
			log.Printf("ChromemDB Manager: Warning - Failed to remove existing LOCK file: %v. Proceeding with open attempt.", errRemove)
		}
	}

	client, errDb := chromem.NewPersistentDB(dbPath, false)
	if errDb != nil {
		return nil, fmt.Errorf("failed to create Chromem client: %w", errDb)
	}

	// Get or create node collection (using nil for embedding function for now)
	nodeColl, err := client.GetOrCreateCollection("nodes", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create nodes collection: %w", err)
	}
	log.Printf("ChromemDB Manager: 'nodes' collection ready.")

	// Get or create risk collection (using nil for embedding function for now)
	riskColl, err := client.GetOrCreateCollection("risks", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create risks collection: %w", err)
	}
	log.Printf("ChromemDB Manager: 'risks' collection ready.")

	return &ChromemManager{
		client:         client,
		nodeCollection: nodeColl,
		riskCollection: riskColl,
		dbPath:         dbPath,
		ef:             nil, // Will generate embeddings manually
	}, nil
}

// Close cleans up resources
func (m *ChromemManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Println("ChromemDB Manager: Closing database.")
	// chromem.DB does not have an explicit Close method.
	// The underlying leveldb is closed when the process exits.
	m.client = nil
	return nil
}

// UpsertNode adds or updates a knowledge graph node in the database.
func (m *ChromemManager) UpsertNode(node *types.Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	docID := node.ID
	documentContent := fmt.Sprintf("Code component of type %s named %s located at %s.", node.Type, node.Name, node.Path)

	nodeJSON, err := json.Marshal(node)
	if err != nil {
		return fmt.Errorf("failed to marshal node: %w", err)
	}

	// Metadata for filtering and retrieval
	metadata := map[string]interface{}{
		"id":           node.ID,
		"type":         string(node.Type),
		"name":         node.Name,
		"path":         node.Path,
		"risk_score":   node.RiskScore,
		"lastModified": node.LastModified.Format(time.RFC3339),
		"node_data":    string(nodeJSON), // Store the full node object
	}

	// Generate embeddings for the document
	embeddings64, err := createEmbeddingFunction()([]string{documentContent})
	if err != nil {
		return fmt.Errorf("failed to generate embeddings for node %s: %w", docID, err)
	}

	// Convert float64 to float32
	embeddings := make([][]float32, len(embeddings64))
	for i, emb := range embeddings64 {
		embeddings[i] = make([]float32, len(emb))
		for j, val := range emb {
			embeddings[i][j] = float32(val)
		}
	}

	// chromem-go's Add method also performs an upsert if the ID exists.
	err = m.nodeCollection.Add(
		context.Background(),
		[]string{docID}, // ids
		embeddings,      // embeddings
		[]map[string]string{stringifyMetadata(metadata)},
		[]string{documentContent}, // documents
	)
	if err != nil {
		return fmt.Errorf("failed to upsert node %s: %w", docID, err)
	}
	return err
}

// StoreRiskAssessment stores a risk assessment, creating a document for each risk item.
func (m *ChromemManager) StoreRiskAssessment(assessment *types.RiskAssessment) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var ids []string
	var documents []string
	var metadatas []map[string]string

	ts := assessment.Timestamp.Format(time.RFC3339)

	// Process Technical Debt
	for _, item := range assessment.TechnicalDebt {
		docID := fmt.Sprintf("td-%s-%d", item.ID, assessment.Timestamp.Unix())
		content := fmt.Sprintf("Technical debt item: %s. Severity: %s. Location: %s. Description: %s", item.ID, item.Severity, item.Location, item.Description)
		itemJSON, _ := json.Marshal(item)
		metadata := map[string]interface{}{
			"id":            docID,
			"risk_type":     "technical_debt",
			"severity":      item.Severity,
			"location":      item.Location,
			"assessment_ts": ts,
			"risk_data":     string(itemJSON),
		}
		ids = append(ids, docID)
		documents = append(documents, content)
		metadatas = append(metadatas, stringifyMetadata(metadata))
	}

	// Process Security Vulnerabilities
	for _, item := range assessment.SecurityVulns {
		docID := fmt.Sprintf("sec-%s-%d", item.CVE, assessment.Timestamp.Unix())
		content := fmt.Sprintf("Security vulnerability: %s in package %s. Severity: %s. Description: %s", item.CVE, item.Package, item.Severity, item.Description)
		itemJSON, _ := json.Marshal(item)
		metadata := map[string]interface{}{
			"id":            docID,
			"risk_type":     "security",
			"cve":           item.CVE,
			"package":       item.Package,
			"severity":      item.Severity,
			"assessment_ts": ts,
			"risk_data":     string(itemJSON),
		}
		ids = append(ids, docID)
		documents = append(documents, content)
		metadatas = append(metadatas, stringifyMetadata(metadata))
	}

	// Process Obsolete Code
	for i, item := range assessment.ObsoleteCode {
		docID := fmt.Sprintf("obs-%d-%d", i, assessment.Timestamp.Unix())
		content := fmt.Sprintf("Obsolete code at %s. Last used: %s. References: %d. Recommended action: %s",
			item.Path, item.LastUsed.Format("2006-01-02"), item.References, item.RecommendAction)
		itemJSON, _ := json.Marshal(item)
		metadata := map[string]interface{}{
			"id":            docID,
			"risk_type":     "obsolete_code",
			"path":          item.Path,
			"severity":      item.RemovalSafety,
			"assessment_ts": ts,
			"risk_data":     string(itemJSON),
		}
		ids = append(ids, docID)
		documents = append(documents, content)
		metadatas = append(metadatas, stringifyMetadata(metadata))
	}

	// Process Dangerous Dependencies
	for _, item := range assessment.DangerousDependencies {
		docID := fmt.Sprintf("dep-%s-%d", item.Package, assessment.Timestamp.Unix())
		severity := "medium"
		if item.SecurityIssues > 0 {
			severity = "high"
		}
		if item.Maintenance == "abandoned" {
			severity = "critical"
		}
		content := fmt.Sprintf("Dangerous dependency: %s (current: %s, latest: %s). Maintenance: %s. Security issues: %d. Recommendation: %s",
			item.Package, item.CurrentVersion, item.LatestVersion, item.Maintenance, item.SecurityIssues, item.Recommendation)
		itemJSON, _ := json.Marshal(item)
		metadata := map[string]interface{}{
			"id":            docID,
			"risk_type":     "dependency",
			"package":       item.Package,
			"severity":      severity,
			"assessment_ts": ts,
			"risk_data":     string(itemJSON),
		}
		ids = append(ids, docID)
		documents = append(documents, content)
		metadatas = append(metadatas, stringifyMetadata(metadata))
	}

	// Process Compatibility Issues
	for i, item := range assessment.CompatibilityIssues {
		docID := fmt.Sprintf("compat-%d-%d", i, assessment.Timestamp.Unix())
		content := fmt.Sprintf("Compatibility issue: %s. Severity: %s. Location: %s. Description: %s",
			item.Type, item.Severity, item.Location, item.Description)
		itemJSON, _ := json.Marshal(item)
		metadata := map[string]interface{}{
			"id":            docID,
			"risk_type":     "compatibility",
			"severity":      item.Severity,
			"location":      item.Location,
			"assessment_ts": ts,
			"risk_data":     string(itemJSON),
		}
		ids = append(ids, docID)
		documents = append(documents, content)
		metadatas = append(metadatas, stringifyMetadata(metadata))
	}

	if len(ids) == 0 {
		return nil // Nothing to store
	}

	// Generate embeddings for all documents
	embeddings64, err := createEmbeddingFunction()(documents)
	if err != nil {
		return fmt.Errorf("failed to generate embeddings for risk assessment: %w", err)
	}

	// Convert float64 to float32
	embeddings := make([][]float32, len(embeddings64))
	for i, emb := range embeddings64 {
		embeddings[i] = make([]float32, len(emb))
		for j, val := range emb {
			embeddings[i][j] = float32(val)
		}
	}

	err = m.riskCollection.Add(context.Background(), ids, embeddings, metadatas, documents)
	if err != nil {
		return fmt.Errorf("failed to store risk assessment items: %w", err)
	}

	log.Printf("ChromemDB Manager: Stored %d risk items.", len(ids))
	return nil
}

// QueryNodes performs a vector search for nodes based on a query string.
func (m *ChromemManager) QueryNodes(query string, limit int) ([]*types.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results, err := m.nodeCollection.Query(context.Background(), query, limit, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w", err)
	}

	var nodes []*types.Node
	for _, res := range results {
		if nodeData, ok := res.Metadata["node_data"]; ok {
			var node types.Node
			if err := json.Unmarshal([]byte(nodeData), &node); err == nil {
				nodes = append(nodes, &node)
			}
		}
	}
	return nodes, nil
}

// GetAllNodes retrieves all nodes from the database
func (m *ChromemManager) GetAllNodes() ([]*types.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Query with empty string to get all nodes, with a high limit
	results, err := m.nodeCollection.Query(context.Background(), "", 10000, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get all nodes: %w", err)
	}

	var nodes []*types.Node
	for _, res := range results {
		if nodeData, ok := res.Metadata["node_data"]; ok {
			var node types.Node
			if err := json.Unmarshal([]byte(nodeData), &node); err == nil {
				nodes = append(nodes, &node)
			}
		}
	}

	log.Printf("ChromemDB Manager: Retrieved %d nodes from database", len(nodes))
	return nodes, nil
}

// GetLatestRiskAssessment retrieves the most recent risk assessment from the database
func (m *ChromemManager) GetLatestRiskAssessment() (*types.RiskAssessment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Query all risk items
	results, err := m.riskCollection.Query(context.Background(), "", 10000, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to query risk assessments: %w", err)
	}

	if len(results) == 0 {
		return nil, nil // No risk assessments found
	}

	// Group risk items by assessment timestamp
	assessmentMap := make(map[string]*types.RiskAssessment)

	for _, res := range results {
		assessmentTS, ok := res.Metadata["assessment_ts"]
		if !ok {
			continue
		}

		// Get or create assessment for this timestamp
		assessment, exists := assessmentMap[assessmentTS]
		if !exists {
			ts, err := time.Parse(time.RFC3339, assessmentTS)
			if err != nil {
				log.Printf("⚠️  Failed to parse timestamp %s: %v", assessmentTS, err)
				continue
			}
			assessment = &types.RiskAssessment{
				Timestamp:             ts,
				TechnicalDebt:         []types.TechnicalDebtItem{},
				SecurityVulns:         []types.SecurityVulnerability{},
				ObsoleteCode:          []types.ObsoleteCodeItem{},
				DangerousDependencies: []types.DependencyRisk{},
				CompatibilityIssues:   []types.TechnicalDebtItem{},
			}
			assessmentMap[assessmentTS] = assessment
		}

		// Parse the risk data based on type
		riskType, ok := res.Metadata["risk_type"]
		if !ok {
			continue
		}

		riskData, ok := res.Metadata["risk_data"]
		if !ok {
			continue
		}

		switch riskType {
		case "technical_debt":
			var item types.TechnicalDebtItem
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				assessment.TechnicalDebt = append(assessment.TechnicalDebt, item)
			}
		case "security":
			var item types.SecurityVulnerability
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				assessment.SecurityVulns = append(assessment.SecurityVulns, item)
			}
		case "obsolete_code":
			var item types.ObsoleteCodeItem
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				assessment.ObsoleteCode = append(assessment.ObsoleteCode, item)
			}
		case "dependency":
			var item types.DependencyRisk
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				assessment.DangerousDependencies = append(assessment.DangerousDependencies, item)
			}
		case "compatibility":
			var item types.TechnicalDebtItem
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				assessment.CompatibilityIssues = append(assessment.CompatibilityIssues, item)
			}
		}
	}

	// Find the most recent assessment
	var latestAssessment *types.RiskAssessment
	var latestTime time.Time

	for _, assessment := range assessmentMap {
		if assessment.Timestamp.After(latestTime) {
			latestTime = assessment.Timestamp
			latestAssessment = assessment
		}
	}

	if latestAssessment != nil {
		// Calculate overall score based on the items
		latestAssessment.OverallScore = calculateOverallScore(latestAssessment)
		log.Printf("ChromemDB Manager: Retrieved latest risk assessment from %s with score %.2f",
			latestAssessment.Timestamp.Format(time.RFC3339), latestAssessment.OverallScore)
	}

	return latestAssessment, nil
}

// calculateOverallScore calculates the overall risk score from assessment items
func calculateOverallScore(assessment *types.RiskAssessment) float64 {
	if assessment == nil {
		return 0.0
	}

	totalScore := 0.0
	itemCount := 0

	// Score technical debt items
	for _, item := range assessment.TechnicalDebt {
		score := severityToScore(item.Severity)
		totalScore += score
		itemCount++
	}

	// Score security vulnerabilities (weighted higher)
	for _, vuln := range assessment.SecurityVulns {
		score := severityToScore(vuln.Severity) * 1.5 // Security issues weighted 1.5x
		totalScore += score
		itemCount++
	}

	// Score obsolete code
	for range assessment.ObsoleteCode {
		totalScore += 30.0 // Medium severity
		itemCount++
	}

	// Score dangerous dependencies
	for _, dep := range assessment.DangerousDependencies {
		score := 50.0 // Default medium-high
		if dep.SecurityIssues > 0 {
			score = 80.0
		}
		if dep.Maintenance == "abandoned" {
			score = 90.0
		}
		totalScore += score
		itemCount++
	}

	// Score compatibility issues
	for _, item := range assessment.CompatibilityIssues {
		score := severityToScore(item.Severity)
		totalScore += score
		itemCount++
	}

	if itemCount == 0 {
		return 0.0
	}

	return totalScore / float64(itemCount)
}

// severityToScore converts severity string to numeric score
func severityToScore(severity string) float64 {
	switch severity {
	case "critical":
		return 100.0
	case "high":
		return 80.0
	case "medium":
		return 50.0
	case "low":
		return 20.0
	default:
		return 30.0
	}
}

// createEmbeddingFunction creates an embedding function that calls the CloudFlare worker with fallback
func createEmbeddingFunction() func([]string) ([][]float64, error) {
	return func(texts []string) ([][]float64, error) {
		if len(texts) == 0 {
			return [][]float64{}, nil
		}

		// Try external embedding service first
		embeddings, err := createExternalEmbeddings(texts)
		if err == nil {
			return embeddings, nil
		}

		// Log the error and fall back to local embeddings
		log.Printf("⚠️  External embedding service failed (%v), falling back to local embeddings", err)

		// Fallback to local embeddings
		return createLocalEmbeddings(texts)
	}
}

// createExternalEmbeddings calls the external embedding service
func createExternalEmbeddings(texts []string) ([][]float64, error) {
	// Check if external embeddings are disabled
	if os.Getenv("USE_LOCAL_EMBEDDINGS") == "true" {
		return nil, fmt.Errorf("external embeddings disabled via USE_LOCAL_EMBEDDINGS=true")
	}

	// Prepare request payload
	reqBody := map[string]interface{}{
		"texts": texts,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal embedding request: %w", err)
	}

	// Create HTTP request with timeout
	req, err := http.NewRequest("POST", "https://embeddings.knirv.com", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create embedding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add API key for authentication if available
	if apiKey := os.Getenv("EMBEDDING_API_KEY"); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	// Make HTTP request with shorter timeout for faster fallback
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call embedding service: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedding response: %w", err)
	}

	// Check status code
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("embedding service authentication failed (401 Unauthorized). Consider setting USE_LOCAL_EMBEDDINGS=true for local fallback")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedding service returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response struct {
		Success    bool        `json:"success"`
		Embeddings [][]float64 `json:"embeddings"`
		Error      string      `json:"error,omitempty"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse embedding response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("embedding service error: %s", response.Error)
	}

	return response.Embeddings, nil
}

// createLocalEmbeddings creates simple local embeddings as fallback
func createLocalEmbeddings(texts []string) ([][]float64, error) {
	// Simple TF-IDF style embeddings - just use text length and character frequencies
	// This is a basic fallback to ensure functionality when external service is unavailable
	const embeddingDim = 128 // Standard embedding dimension

	embeddings := make([][]float64, len(texts))
	for i, text := range texts {
		embedding := make([]float64, embeddingDim)

		// Simple features: text length, character counts, etc.
		embedding[0] = float64(len(text)) / 1000.0 // Normalized text length

		// Character frequency features (simplified)
		charCounts := make(map[rune]int)
		for _, char := range text {
			charCounts[char]++
		}

		// Use some common characters as features
		commonChars := []rune{'a', 'e', 'i', 'o', 'u', ' ', '.', ',', '\n'}
		for j, char := range commonChars {
			if j+1 < embeddingDim {
				embedding[j+1] = float64(charCounts[char]) / float64(len(text)+1)
			}
		}

		// Add some randomness to avoid identical embeddings
		// In a real implementation, you'd use a proper hashing or TF-IDF approach
		for j := len(commonChars) + 1; j < embeddingDim; j++ {
			// Simple hash-based pseudo-random value
			hash := 0
			for _, char := range text {
				hash = (hash*31 + int(char)) % 1000
			}
			embedding[j] = float64(hash%100) / 100.0
		}

		embeddings[i] = embedding
	}

	log.Printf("✅ Generated local embeddings for %d texts", len(texts))
	return embeddings, nil
}

// queryWithFallback performs a query with progressive fallback for ChromemDB limitations
func (m *ChromemManager) queryWithFallback(collection *chromem.Collection, searchTerm string) ([]chromem.Result, error) {
	// Try progressively smaller limits until one works
	limits := []int{10, 5, 3, 1}

	for _, limit := range limits {
		results, err := collection.Query(
			context.Background(),
			searchTerm,
			limit,
			nil, // No where clause - causes errors with chromem-go
			nil,
		)

		if err == nil {
			return results, nil
		}

		// If it's an nResults error, try smaller limit
		if strings.Contains(err.Error(), "nResults") {
			continue
		}

		// Other errors are not recoverable
		return nil, err
	}

	return nil, fmt.Errorf("all query attempts failed")
}

// GetIssueByID retrieves a specific issue by ID from the risk assessment collection
func (m *ChromemManager) GetIssueByID(issueID string) (interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Query with generic term to get risk items
	results, err := m.queryWithFallback(m.riskCollection, "risk")
	if err != nil {
		return nil, fmt.Errorf("failed to query risk collection: %w", err)
	}

	// Manual filtering for exact ID match
	for _, result := range results {
		riskData, ok := result.Metadata["risk_data"]
		if !ok {
			continue
		}

		// Try to unmarshal as different issue types to find the matching ID
		if tdItem := m.tryParseAsTechnicalDebt(riskData, issueID); tdItem != nil {
			return tdItem, nil
		}
		if secVuln := m.tryParseAsSecurityVuln(riskData, issueID); secVuln != nil {
			return secVuln, nil
		}
		if obsCode := m.tryParseAsObsoleteCode(riskData, issueID); obsCode != nil {
			return obsCode, nil
		}
		if depRisk := m.tryParseAsDependencyRisk(riskData, issueID); depRisk != nil {
			return depRisk, nil
		}
	}

	return nil, fmt.Errorf("issue with ID %s not found", issueID)
}

// GetIssuesByType retrieves all issues of a specific type
func (m *ChromemManager) GetIssuesByType(issueType string) ([]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Map issue type to risk_type metadata value
	var riskType string
	switch issueType {
	case "technical_debt":
		riskType = "technical_debt"
	case "security_vulnerability":
		riskType = "security"
	case "obsolete_code":
		riskType = "obsolete_code"
	case "dependency_risk":
		riskType = "dependency"
	case "compatibility":
		riskType = "compatibility"
	default:
		return nil, fmt.Errorf("unsupported issue type: %s", issueType)
	}

	// Query with generic term to get risk items
	results, err := m.queryWithFallback(m.riskCollection, "risk")
	if err != nil {
		return nil, fmt.Errorf("failed to query risk collection: %w", err)
	}

	var issues []interface{}

	// Manual filtering for type match
	for _, result := range results {
		resultRiskType, ok := result.Metadata["risk_type"]
		if !ok || resultRiskType != riskType {
			continue
		}

		riskData, ok := result.Metadata["risk_data"]
		if !ok {
			continue
		}

		// Parse based on type
		var issue interface{}
		switch riskType {
		case "technical_debt":
			var item types.TechnicalDebtItem
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				issue = &item
			}
		case "security":
			var item types.SecurityVulnerability
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				issue = &item
			}
		case "obsolete_code":
			var item types.ObsoleteCodeItem
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				issue = &item
			}
		case "dependency":
			var item types.DependencyRisk
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				issue = &item
			}
		case "compatibility":
			var item types.TechnicalDebtItem
			if err := json.Unmarshal([]byte(riskData), &item); err == nil {
				issue = &item
			}
		}

		if issue != nil {
			issues = append(issues, issue)
		}
	}

	return issues, nil
}

// Helper methods for parsing different issue types

func (m *ChromemManager) tryParseAsTechnicalDebt(riskData string, targetID string) *types.TechnicalDebtItem {
	var item types.TechnicalDebtItem
	if err := json.Unmarshal([]byte(riskData), &item); err != nil {
		return nil
	}
	if item.ID == targetID {
		return &item
	}
	return nil
}

func (m *ChromemManager) tryParseAsSecurityVuln(riskData string, targetID string) *types.SecurityVulnerability {
	var item types.SecurityVulnerability
	if err := json.Unmarshal([]byte(riskData), &item); err != nil {
		return nil
	}
	if item.ID == targetID || item.CVE == targetID {
		return &item
	}
	return nil
}

func (m *ChromemManager) tryParseAsObsoleteCode(riskData string, targetID string) *types.ObsoleteCodeItem {
	var item types.ObsoleteCodeItem
	if err := json.Unmarshal([]byte(riskData), &item); err != nil {
		return nil
	}
	if item.ID == targetID {
		return &item
	}
	return nil
}

func (m *ChromemManager) tryParseAsDependencyRisk(riskData string, targetID string) *types.DependencyRisk {
	var item types.DependencyRisk
	if err := json.Unmarshal([]byte(riskData), &item); err != nil {
		return nil
	}
	if item.ID == targetID {
		return &item
	}
	return nil
}

// GetCodeContext retrieves code context for a given file path and line number
func (m *ChromemManager) GetCodeContext(filePath string, lineNumber int, contextLines int) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Query nodes collection for the specific file
	results, err := m.queryWithFallback(m.nodeCollection, filePath)
	if err != nil {
		return "", fmt.Errorf("failed to query nodes collection: %w", err)
	}

	// Find the matching file node
	for _, result := range results {
		nodePath, ok := result.Metadata["path"]
		if !ok || nodePath != filePath {
			continue
		}

		nodeData, ok := result.Metadata["node_data"]
		if !ok {
			continue
		}

		var node types.Node
		if err := json.Unmarshal([]byte(nodeData), &node); err != nil {
			continue
		}

		// Read the actual file to get code context
		return m.extractCodeSnippet(filePath, lineNumber, contextLines)
	}

	return "", fmt.Errorf("file %s not found in knowledge graph", filePath)
}

// extractCodeSnippet reads a code snippet from a file around a specific line
func (m *ChromemManager) extractCodeSnippet(filePath string, lineNumber int, contextLines int) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	lines := strings.Split(string(content), "\n")
	totalLines := len(lines)

	// Validate line number
	if lineNumber < 1 || lineNumber > totalLines {
		return "", fmt.Errorf("line number %d is out of range for file %s", lineNumber, filePath)
	}

	// Calculate start and end lines with context
	startLine := max(1, lineNumber-contextLines)
	endLine := min(totalLines, lineNumber+contextLines)

	// Extract the snippet
	var snippetLines []string
	for i := startLine - 1; i < endLine; i++ {
		snippetLines = append(snippetLines, fmt.Sprintf("%d: %s", i+1, lines[i]))
	}

	return fmt.Sprintf("Code snippet from %s (lines %d-%d):\n%s",
		filePath, startLine, endLine, strings.Join(snippetLines, "\n")), nil
}

// stringifyMetadata converts map[string]interface{} to map[string]string for chromem-go.
func stringifyMetadata(metadata map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range metadata {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}
