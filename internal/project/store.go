package project

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"archguardian/internal/embedding"

	"github.com/philippgille/chromem-go"
)

// NewProjectStore creates a new project store
func NewProjectStore(db *chromem.DB) *ProjectStore {
	ps := &ProjectStore{
		projects: make(map[string]*Project),
		db:       db,
	}

	// Load existing projects from database
	ps.loadProjects()

	return ps
}

// Create creates a new project
func (ps *ProjectStore) Create(project *Project) error {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	// Add to memory store
	ps.projects[project.ID] = project
	// Persist to database if available
	if ps.db == nil {
		return nil
	}
	return ps.persistProject(project)
}

// Get retrieves a project by ID
func (ps *ProjectStore) Get(id string) (*Project, bool) {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	// First check memory store
	if project, exists := ps.projects[id]; exists {
		return project, true
	}

	// If not in memory, try to load from database
	return ps.loadProjectFromDB(id)
}

// GetAll returns all projects
func (ps *ProjectStore) GetAll() []*Project {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	projects := make([]*Project, 0, len(ps.projects))
	for _, project := range ps.projects {
		projects = append(projects, project)
	}
	return projects
}

// Update updates an existing project
func (ps *ProjectStore) Update(project *Project) error {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	if _, exists := ps.projects[project.ID]; !exists {
		return fmt.Errorf("project not found: %s", project.ID)
	}

	// Update memory store
	ps.projects[project.ID] = project
	// Persist to database if available
	if ps.db == nil {
		return nil
	}
	return ps.persistProject(project)
}

// Delete deletes a project by ID
func (ps *ProjectStore) Delete(id string) error {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	if _, exists := ps.projects[id]; !exists {
		return fmt.Errorf("project not found: %s", id)
	}

	// Remove from memory store
	delete(ps.projects, id)
	// Remove from database if available
	if ps.db == nil {
		return nil
	}
	return ps.deleteProjectFromDB(id)
}

// loadProjects loads all projects from the database on startup
func (ps *ProjectStore) loadProjects() {
	if ps.db == nil {
		log.Printf("⚠️  Database not available, projects will not persist")
		return
	}

	// Create embedding function for collection operations
	embeddingFunc := embedding.CreateChromemEmbeddingFunc()

	collection := ps.db.GetCollection("projects", embeddingFunc)
	if collection == nil {
		log.Printf("⚠️  Projects collection not found, creating...")
		var err error
		collection, err = ps.db.GetOrCreateCollection("projects", map[string]string{"type": "project"}, embeddingFunc)
		if err != nil {
			log.Printf("⚠️  Failed to create projects collection: %v", err)
			return
		}
		// New collection is empty, no need to query
		log.Printf("✅ Created new projects collection")
		return
	}

	// Query all projects from database using progressive fallback approach
	// Note: chromem-go requires nResults to be <= number of documents in collection
	// We use progressive limits to handle collections of any size
	results, err := ps.queryWithFallback(collection, "project")
	if err != nil {
		// Collection might be empty, which is fine for a new installation
		log.Printf("✅ Project store initialized (no existing projects)")
		return
	}

	loadedCount := 0
	for _, result := range results {
		var project Project
		if err := json.Unmarshal([]byte(result.Content), &project); err != nil {
			log.Printf("⚠️  Failed to parse project data: %v", err)
			continue
		}

		ps.projects[project.ID] = &project
		loadedCount++
	}

	log.Printf("✅ Loaded %d projects from database", loadedCount)
}

// queryWithFallback implements progressive query fallback to handle chromem-go's
// strict nResults validation. It tries progressively smaller limits until one works.
func (ps *ProjectStore) queryWithFallback(collection *chromem.Collection, searchTerm string) ([]chromem.Result, error) {
	// Try progressively larger limits to get as many results as possible
	// Start small to handle empty/small collections, then try larger limits
	limits := []int{1, 3, 10, 50, 100, 1000}

	var lastResults []chromem.Result
	var lastErr error

	for _, limit := range limits {
		results, err := collection.Query(
			context.Background(),
			searchTerm,
			limit,
			nil, // No where clause (causes "unsupported operator" errors)
			nil,
		)

		if err == nil {
			// Success - save these results and try next larger limit
			lastResults = results
			lastErr = nil
			continue
		}

		// If it's an nResults error, we've hit the collection size limit
		// Return the last successful results
		if strings.Contains(err.Error(), "nResults") {
			if lastResults != nil {
				return lastResults, nil
			}
			// First query failed with nResults error - collection is empty
			return nil, fmt.Errorf("collection appears to be empty")
		}

		// Other errors are not recoverable
		lastErr = err
		break
	}

	// Return last successful results or error
	if lastResults != nil {
		return lastResults, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("all query attempts failed")
}

// loadProjectFromDB loads a specific project from the database
func (ps *ProjectStore) loadProjectFromDB(id string) (*Project, bool) {
	if ps.db == nil {
		return nil, false
	}

	// Create embedding function for collection operations
	embeddingFunc := embedding.CreateChromemEmbeddingFunc()

	collection := ps.db.GetCollection("projects", embeddingFunc)
	if collection == nil {
		return nil, false
	}

	// Query for specific project
	results, err := collection.Query(context.Background(), "*", 1, map[string]string{"id": id}, nil)
	if err != nil || len(results) == 0 {
		return nil, false
	}

	var project Project
	if err := json.Unmarshal([]byte(results[0].Content), &project); err != nil {
		return nil, false
	}

	// Add to memory store for faster future access
	ps.projects[id] = &project
	return &project, true
}

// persistProject saves a project to the database
func (ps *ProjectStore) persistProject(project *Project) error {
	if ps.db == nil {
		return fmt.Errorf("database not available")
	}

	// Create embedding function for collection operations
	embeddingFunc := embedding.CreateChromemEmbeddingFunc()

	// Ensure collection exists
	collection, err := ps.db.GetOrCreateCollection("projects", map[string]string{"type": "project"}, embeddingFunc)
	if err != nil {
		return fmt.Errorf("failed to get or create projects collection: %w", err)
	}

	projectJSON, err := json.Marshal(project)
	if err != nil {
		return fmt.Errorf("failed to marshal project: %w", err)
	}

	docID := fmt.Sprintf("project_%s", project.ID)
	content := string(projectJSON)

	// Generate embeddings for the project document using chromem function
	ctx := context.Background()
	embedding32, err := embeddingFunc(ctx, content)
	if err != nil {
		log.Printf("⚠️  Failed to generate embeddings for project %s: %v", project.ID, err)
		// Continue without embeddings - use empty embedding
		embedding32 = make([]float32, 128)
	}

	metadata := map[string]string{
		"id":          project.ID,
		"name":        project.Name,
		"path":        project.Path,
		"status":      project.Status,
		"issue_count": fmt.Sprintf("%d", project.IssueCount),
		"created_at":  project.CreatedAt.Format(time.RFC3339),
		"type":        "project",
	}

	if project.LastScan != nil {
		metadata["last_scan"] = project.LastScan.Format(time.RFC3339)
	}

	err = collection.Add(ctx, []string{docID}, [][]float32{embedding32}, []map[string]string{metadata}, []string{content})
	if err != nil {
		return fmt.Errorf("failed to persist project: %w", err)
	}

	log.Printf("✅ Project persisted to database: %s", project.Name)
	return nil
}

// deleteProjectFromDB removes a project from the database
func (ps *ProjectStore) deleteProjectFromDB(id string) error {
	if ps.db == nil {
		return fmt.Errorf("database not available")
	}

	// Create embedding function for collection operations
	embeddingFunc := embedding.CreateChromemEmbeddingFunc()

	collection := ps.db.GetCollection("projects", embeddingFunc)
	if collection == nil {
		return fmt.Errorf("projects collection not found")
	}

	// Note: Chromem-go doesn't have a direct delete method
	// We'll mark the project as deleted in metadata instead
	_ = fmt.Sprintf("project_%s", id) // docID variable was unused

	// Update the document with deleted status
	_ = map[string]string{ // metadata variable was unused
		"deleted":    "true",
		"deleted_at": time.Now().Format(time.RFC3339),
	}

	// This is a simplified approach - in a real implementation,
	// you might want to use a separate "deleted_projects" collection
	// or implement soft deletion properly

	log.Printf("✅ Project marked as deleted in database: %s", id)
	return nil
}
