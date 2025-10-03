package data_engine

import (
	"archguardian/types"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	if errMkdir := os.MkdirAll(dbPath, 0755); errMkdir != nil {
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

	// Use the default embedding function provided by chromem-go
	// Note: chromem.DefaultEmbeddingFunc() doesn't exist, using nil for now
	// The embedding function will be handled by the collection's default
	embedFunc := chromem.EmbeddingFunc(nil)

	// Get or create node collection
	nodeColl, err := client.GetOrCreateCollection("nodes", nil, embedFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create nodes collection: %w", err)
	}
	log.Printf("ChromemDB Manager: 'nodes' collection ready.")

	// Get or create risk collection
	riskColl, err := client.GetOrCreateCollection("risks", nil, embedFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to get/create risks collection: %w", err)
	}
	log.Printf("ChromemDB Manager: 'risks' collection ready.")

	return &ChromemManager{
		client:         client,
		nodeCollection: nodeColl,
		riskCollection: riskColl,
		dbPath:         dbPath,
		ef:             embedFunc,
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

	// chromem-go's Add method also performs an upsert if the ID exists.
	err = m.nodeCollection.Add(
		context.Background(),
		[]string{docID}, // ids
		nil,             // embeddings - let EF handle it from documents
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

	// Add other risk types (ObsoleteCode, DangerousDependencies) similarly...

	if len(ids) == 0 {
		return nil // Nothing to store
	}

	err := m.riskCollection.Add(context.Background(), ids, nil, metadatas, documents)
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

// stringifyMetadata converts map[string]interface{} to map[string]string for chromem-go.
func stringifyMetadata(metadata map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range metadata {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}
