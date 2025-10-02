package data_engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ChromaDB provides integration with ChromaDB for vector storage and retrieval
type ChromaDB struct {
	url        string
	collection string
	client     *http.Client
	connected  bool
	mutex      sync.RWMutex
}

// ChromaDocument represents a document stored in ChromaDB
type ChromaDocument struct {
	ID        string                 `json:"id"`
	Embedding []float64              `json:"embedding,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	Document  string                 `json:"document"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
}

// ChromaQueryResult represents a query result from ChromaDB
type ChromaQueryResult struct {
	IDs        []string                 `json:"ids"`
	Embeddings [][]float64              `json:"embeddings,omitempty"`
	Metadatas  []map[string]interface{} `json:"metadatas"`
	Documents  []string                 `json:"documents"`
	Distances  []float64                `json:"distances"`
}

// NewChromaDB creates a new ChromaDB client
func NewChromaDB(url, collection string) *ChromaDB {
	return &ChromaDB{
		url:        url,
		collection: collection,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Connect connects to ChromaDB and creates the collection if it doesn't exist
func (c *ChromaDB) Connect(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if ChromaDB is running
	req, err := http.NewRequestWithContext(ctx, "GET", c.url+"/api/v1", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to ChromaDB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ChromaDB returned status code %d", resp.StatusCode)
	}

	// Create collection if it doesn't exist
	err = c.createCollection(ctx)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}

	c.connected = true
	return nil
}

// createCollection creates a collection in ChromaDB
func (c *ChromaDB) createCollection(ctx context.Context) error {
	// Check if collection exists
	collections, err := c.listCollections(ctx)
	if err != nil {
		return fmt.Errorf("failed to list collections: %w", err)
	}

	for _, collection := range collections {
		if collection == c.collection {
			// Collection already exists
			return nil
		}
	}

	// Create collection
	reqBody := fmt.Sprintf(`{"name": "%s", "metadata": {"description": "KNIRVORACLE events collection"}}`, c.collection)
	req, err := http.NewRequestWithContext(ctx, "POST", c.url+"/api/v1/collections", strings.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("ChromaDB returned status code %d", resp.StatusCode)
	}

	return nil
}

// listCollections lists all collections in ChromaDB
func (c *ChromaDB) listCollections(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.url+"/api/v1/collections", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list collections: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ChromaDB returned status code %d", resp.StatusCode)
	}

	var result struct {
		Collections []struct {
			Name string `json:"name"`
		} `json:"collections"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	collections := make([]string, len(result.Collections))
	for i, collection := range result.Collections {
		collections[i] = collection.Name
	}

	return collections, nil
}

// AddEvent adds an event to ChromaDB
func (c *ChromaDB) AddEvent(ctx context.Context, event Event) error {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if !c.connected {
		return fmt.Errorf("not connected to ChromaDB")
	}

	// Convert event to document
	doc := ChromaDocument{
		ID:        fmt.Sprintf("%s-%d", event.Type, event.Timestamp.UnixNano()),
		Metadata:  event.Data,
		Document:  fmt.Sprintf("%s event at %s", event.Type, event.Timestamp.Format(time.RFC3339)),
		Type:      string(event.Type),
		Timestamp: event.Timestamp,
	}

	// Add metadata fields
	if doc.Metadata == nil {
		doc.Metadata = make(map[string]interface{})
	}
	doc.Metadata["type"] = string(event.Type)
	doc.Metadata["timestamp"] = event.Timestamp.Format(time.RFC3339)

	// Add document to ChromaDB
	return c.addDocuments(ctx, []ChromaDocument{doc})
}

// addDocuments adds documents to ChromaDB
func (c *ChromaDB) addDocuments(ctx context.Context, docs []ChromaDocument) error {
	// Prepare request body
	ids := make([]string, len(docs))
	documents := make([]string, len(docs))
	metadatas := make([]map[string]interface{}, len(docs))

	for i, doc := range docs {
		ids[i] = doc.ID
		documents[i] = doc.Document
		metadatas[i] = doc.Metadata
	}

	reqBody := map[string]interface{}{
		"ids":       ids,
		"documents": documents,
		"metadatas": metadatas,
	}

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/collections/%s/add", c.url, c.collection), strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to add documents: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("ChromaDB returned status code %d", resp.StatusCode)
	}

	return nil
}

// QueryEvents queries events in ChromaDB
func (c *ChromaDB) QueryEvents(ctx context.Context, query string, limit int) ([]ChromaDocument, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected to ChromaDB")
	}

	// Prepare request body
	reqBody := map[string]interface{}{
		"query_texts": []string{query},
		"n_results":   limit,
		"include":     []string{"documents", "metadatas", "distances"},
	}

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/collections/%s/query", c.url, c.collection), strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ChromaDB returned status code %d", resp.StatusCode)
	}

	// Parse response
	var result ChromaQueryResult
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to documents
	docs := make([]ChromaDocument, len(result.IDs))
	for i, id := range result.IDs {
		docs[i] = ChromaDocument{
			ID:       id,
			Metadata: result.Metadatas[i],
			Document: result.Documents[i],
		}

		// Extract type and timestamp from metadata
		if typeStr, ok := docs[i].Metadata["type"].(string); ok {
			docs[i].Type = typeStr
		}

		if timestampStr, ok := docs[i].Metadata["timestamp"].(string); ok {
			timestamp, err := time.Parse(time.RFC3339, timestampStr)
			if err == nil {
				docs[i].Timestamp = timestamp
			}
		}
	}

	return docs, nil
}

// GetEventsByType gets events of a specific type from ChromaDB
func (c *ChromaDB) GetEventsByType(ctx context.Context, eventType EventType, limit int) ([]ChromaDocument, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected to ChromaDB")
	}

	// Prepare request body
	reqBody := map[string]interface{}{
		"where": map[string]interface{}{
			"type": string(eventType),
		},
		"limit":   limit,
		"include": []string{"documents", "metadatas"},
	}

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/collections/%s/get", c.url, c.collection), strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ChromaDB returned status code %d", resp.StatusCode)
	}

	// Parse response
	var result struct {
		IDs       []string                 `json:"ids"`
		Documents []string                 `json:"documents"`
		Metadatas []map[string]interface{} `json:"metadatas"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to documents
	docs := make([]ChromaDocument, len(result.IDs))
	for i, id := range result.IDs {
		docs[i] = ChromaDocument{
			ID:       id,
			Metadata: result.Metadatas[i],
			Document: result.Documents[i],
			Type:     string(eventType),
		}

		// Extract timestamp from metadata
		if timestampStr, ok := docs[i].Metadata["timestamp"].(string); ok {
			timestamp, err := time.Parse(time.RFC3339, timestampStr)
			if err == nil {
				docs[i].Timestamp = timestamp
			}
		}
	}

	return docs, nil
}

// GetRecentEvents gets recent events from ChromaDB
func (c *ChromaDB) GetRecentEvents(ctx context.Context, limit int) ([]ChromaDocument, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected to ChromaDB")
	}

	// Prepare request body
	reqBody := map[string]interface{}{
		"limit":   limit,
		"include": []string{"documents", "metadatas"},
	}

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/collections/%s/get", c.url, c.collection), strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ChromaDB returned status code %d", resp.StatusCode)
	}

	// Parse response
	var result struct {
		IDs       []string                 `json:"ids"`
		Documents []string                 `json:"documents"`
		Metadatas []map[string]interface{} `json:"metadatas"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to documents
	docs := make([]ChromaDocument, len(result.IDs))
	for i, id := range result.IDs {
		docs[i] = ChromaDocument{
			ID:       id,
			Metadata: result.Metadatas[i],
			Document: result.Documents[i],
		}

		// Extract type and timestamp from metadata
		if typeStr, ok := docs[i].Metadata["type"].(string); ok {
			docs[i].Type = typeStr
		}

		if timestampStr, ok := docs[i].Metadata["timestamp"].(string); ok {
			timestamp, err := time.Parse(time.RFC3339, timestampStr)
			if err == nil {
				docs[i].Timestamp = timestamp
			}
		}
	}

	// Sort by timestamp (newest first)
	// Note: This is a simple implementation, in a real-world scenario
	// you would want to use a more efficient sorting algorithm
	for i := 0; i < len(docs); i++ {
		for j := i + 1; j < len(docs); j++ {
			if docs[i].Timestamp.Before(docs[j].Timestamp) {
				docs[i], docs[j] = docs[j], docs[i]
			}
		}
	}

	return docs, nil
}

// Close closes the ChromaDB connection
func (c *ChromaDB) Close() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.connected = false
}

// IsConnected returns whether the ChromaDB connection is active
func (c *ChromaDB) IsConnected() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.connected
}
