package main

import (
	"archguardian/types"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProjectStore(t *testing.T) {
	store := NewProjectStore(nil)

	assert.NotNil(t, store)
	assert.NotNil(t, store.projects)
	assert.Equal(t, 0, len(store.projects))
}

func TestProjectStore_Create(t *testing.T) {
	store := NewProjectStore(nil)

	project := &Project{
		ID:         "test-project-1",
		Name:       "Test Project",
		Path:       "/path/to/project",
		Status:     "idle",
		IssueCount: 0,
		CreatedAt:  time.Now(),
	}

	// Verify all fields are properly set
	assert.Equal(t, "test-project-1", project.ID)
	assert.Equal(t, "Test Project", project.Name)
	assert.Equal(t, "/path/to/project", project.Path)
	assert.Equal(t, "idle", project.Status)
	assert.Equal(t, 0, project.IssueCount)
	assert.NotNil(t, project.CreatedAt)

	store.Create(project)

	assert.Equal(t, 1, len(store.projects))
	stored, exists := store.projects[project.ID]
	assert.True(t, exists)
	assert.Equal(t, project, stored)
}

func TestProjectStore_Get(t *testing.T) {
	store := NewProjectStore(nil)

	project := &Project{
		ID:         "test-project-1",
		Name:       "Test Project",
		Path:       "/path/to/project",
		Status:     "idle",
		IssueCount: 0,
		CreatedAt:  time.Now(),
	}

	// Verify all fields are properly set
	assert.Equal(t, "test-project-1", project.ID)
	assert.Equal(t, "Test Project", project.Name)
	assert.Equal(t, "/path/to/project", project.Path)
	assert.Equal(t, "idle", project.Status)
	assert.Equal(t, 0, project.IssueCount)
	assert.NotNil(t, project.CreatedAt)

	store.Create(project)

	// Test getting existing project
	retrieved, exists := store.Get("test-project-1")
	assert.True(t, exists)
	assert.Equal(t, project, retrieved)

	// Test getting non-existent project
	_, exists = store.Get("non-existent")
	assert.False(t, exists)
}

func TestProjectStore_GetAll(t *testing.T) {
	store := NewProjectStore(nil)

	// Test empty store
	projects := store.GetAll()
	assert.Equal(t, 0, len(projects))

	// Add some projects
	project1 := &Project{
		ID:        "project-1",
		Name:      "Project 1",
		Path:      "/path/1",
		Status:    "idle",
		CreatedAt: time.Now(),
	}

	// Validate project1 fields
	assert.Equal(t, "project-1", project1.ID)
	assert.Equal(t, "Project 1", project1.Name)
	assert.Equal(t, "/path/1", project1.Path)
	assert.Equal(t, "idle", project1.Status)
	assert.NotNil(t, project1.CreatedAt)

	project2 := &Project{
		ID:        "project-2",
		Name:      "Project 2",
		Path:      "/path/2",
		Status:    "scanning",
		CreatedAt: time.Now(),
	}

	// Validate project2 fields
	assert.Equal(t, "project-2", project2.ID)
	assert.Equal(t, "Project 2", project2.Name)
	assert.Equal(t, "/path/2", project2.Path)
	assert.Equal(t, "scanning", project2.Status)
	assert.NotNil(t, project2.CreatedAt)

	store.Create(project1)
	store.Create(project2)

	projects = store.GetAll()
	assert.Equal(t, 2, len(projects))

	// Verify both projects are returned
	foundProject1 := false
	foundProject2 := false
	for _, p := range projects {
		if p.ID == "project-1" {
			foundProject1 = true
			assert.Equal(t, project1, p)
		}
		if p.ID == "project-2" {
			foundProject2 = true
			assert.Equal(t, project2, p)
		}
	}
	assert.True(t, foundProject1)
	assert.True(t, foundProject2)
}

func TestProjectStore_Update(t *testing.T) {
	store := NewProjectStore(nil)

	project := &Project{
		ID:         "test-project-1",
		Name:       "Test Project",
		Path:       "/path/to/project",
		Status:     "idle",
		IssueCount: 0,
		CreatedAt:  time.Now(),
	}

	store.Create(project)

	// Update existing project
	updatedProject := &Project{
		ID:         "test-project-1",
		Name:       "Updated Test Project",
		Path:       "/new/path/to/project",
		Status:     "scanning",
		IssueCount: 5,
		CreatedAt:  project.CreatedAt,
	}

	success := store.Update(updatedProject)
	assert.True(t, success == nil)

	// Verify update
	retrieved, exists := store.Get("test-project-1")
	assert.True(t, exists)
	assert.Equal(t, updatedProject, retrieved)

	// Test updating non-existent project
	nonExistentProject := &Project{
		ID:        "non-existent",
		Name:      "Non-existent",
		CreatedAt: time.Now(),
	}

	success = store.Update(nonExistentProject)
	assert.False(t, success == nil)
}

func TestProjectStore_Delete(t *testing.T) {
	store := NewProjectStore(nil)

	project := &Project{
		ID:         "test-project-1",
		Name:       "Test Project",
		Path:       "/path/to/project",
		Status:     "idle",
		IssueCount: 0,
		CreatedAt:  time.Now(),
	}

	store.Create(project)
	assert.Equal(t, 1, len(store.projects))

	// Delete existing project
	success := store.Delete("test-project-1")
	assert.True(t, success == nil)
	assert.Equal(t, 0, len(store.projects))

	// Test deleting non-existent project
	success = store.Delete("non-existent")
	assert.False(t, success == nil)
}

func TestProjectStore_ConcurrentAccess(t *testing.T) {
	store := NewProjectStore(nil)

	const numGoroutines = 10
	const numOperations = 100

	// Test concurrent operations
	done := make(chan bool, numGoroutines)

	// Create projects concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				project := &Project{
					ID:        fmt.Sprintf("project-%d-%d", id, j),
					Name:      fmt.Sprintf("Project %d-%d", id, j),
					Path:      fmt.Sprintf("/path/%d/%d", id, j),
					Status:    "idle",
					CreatedAt: time.Now(),
				}
				store.Create(project)
			}
			done <- true
		}(i)
	}

	// Wait for all creation goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all projects were created
	projects := store.GetAll()
	assert.Equal(t, numGoroutines*numOperations, len(projects))

	// Test concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				projectID := fmt.Sprintf("project-%d-%d", id, j)
				project, exists := store.Get(projectID)
				assert.True(t, exists)
				assert.Equal(t, projectID, project.ID)
			}
			done <- true
		}(i)
	}

	// Wait for all read goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestProject_StatusTransitions(t *testing.T) {
	store := NewProjectStore(nil)

	project := &Project{
		ID:        "test-project",
		Name:      "Test Project",
		Path:      "/path/to/project",
		Status:    "idle",
		CreatedAt: time.Now(),
	}

	store.Create(project)

	// Test status transitions
	statusTransitions := []string{"scanning", "error", "idle", "scanning", "idle"}

	for _, status := range statusTransitions {
		project.Status = status
		success := store.Update(project)
		assert.True(t, success == nil)

		retrieved, exists := store.Get(project.ID)
		assert.True(t, exists)
		assert.Equal(t, status, retrieved.Status)
	}
}

func TestProject_WithKnowledgeGraph(t *testing.T) {
	graph := &types.KnowledgeGraph{
		Nodes: map[string]*types.Node{
			"node1": {
				ID:   "node1",
				Type: types.NodeTypeCode,
				Name: "main.go",
				Path: "/project/main.go",
			},
		},
		Edges:         []*types.Edge{},
		LastUpdated:   time.Now(),
		AnalysisDepth: 1,
	}

	project := &Project{
		ID:        "project-with-graph",
		Name:      "Project with Graph",
		Path:      "/path/to/project",
		Status:    "idle",
		Graph:     graph,
		CreatedAt: time.Now(),
	}

	assert.NotNil(t, project.Graph)
	assert.Equal(t, 1, len(project.Graph.Nodes))
	assert.Equal(t, "main.go", project.Graph.Nodes["node1"].Name)

	// Validate all assigned fields
	assert.Equal(t, "project-with-graph", project.ID)
	assert.Equal(t, "Project with Graph", project.Name)
	assert.Equal(t, "/path/to/project", project.Path)
	assert.Equal(t, "idle", project.Status)
	assert.NotNil(t, project.CreatedAt)
}

func TestProject_WithConfig(t *testing.T) {
	config := &Config{
		ProjectPath:  "/test/project",
		GitHubToken:  "test-token",
		GitHubRepo:   "test/repo",
		ScanInterval: time.Hour,
	}

	project := &Project{
		ID:        "project-with-config",
		Name:      "Project with Config",
		Path:      "/path/to/project",
		Status:    "idle",
		Config:    config,
		CreatedAt: time.Now(),
	}

	assert.NotNil(t, project.Config)
	assert.Equal(t, "/test/project", project.Config.ProjectPath)
	assert.Equal(t, "test-token", project.Config.GitHubToken)
	assert.Equal(t, time.Hour, project.Config.ScanInterval)

	// Validate all assigned fields
	assert.Equal(t, "project-with-config", project.ID)
	assert.Equal(t, "Project with Config", project.Name)
	assert.Equal(t, "/path/to/project", project.Path)
	assert.Equal(t, "idle", project.Status)
	assert.NotNil(t, project.CreatedAt)
}

func TestProject_LastScanHandling(t *testing.T) {
	store := NewProjectStore(nil)

	project := &Project{
		ID:        "test-project",
		Name:      "Test Project",
		Path:      "/path/to/project",
		Status:    "idle",
		LastScan:  nil, // Initially no scan
		CreatedAt: time.Now(),
	}

	store.Create(project)

	// Verify no last scan initially
	retrieved, _ := store.Get(project.ID)
	assert.Nil(t, retrieved.LastScan)

	// Update with last scan time
	scanTime := time.Now()
	project.LastScan = &scanTime
	store.Update(project)

	retrieved, _ = store.Get(project.ID)
	require.NotNil(t, retrieved.LastScan)
	assert.Equal(t, scanTime.Unix(), retrieved.LastScan.Unix())
}

func TestProject_IssueCountTracking(t *testing.T) {
	store := NewProjectStore(nil)

	project := &Project{
		ID:         "test-project",
		Name:       "Test Project",
		Path:       "/path/to/project",
		Status:     "idle",
		IssueCount: 0,
		CreatedAt:  time.Now(),
	}

	store.Create(project)

	// Simulate finding issues during scans
	issueCounts := []int{5, 10, 3, 0, 7}

	for _, count := range issueCounts {
		project.IssueCount = count
		store.Update(project)

		retrieved, exists := store.Get(project.ID)
		assert.True(t, exists)
		assert.Equal(t, count, retrieved.IssueCount)
	}
}

// Test project store behavior with edge cases
func TestProjectStore_EdgeCases(t *testing.T) {
	store := NewProjectStore(nil)

	// Test creating project with same ID twice
	project1 := &Project{
		ID:        "duplicate-id",
		Name:      "Project 1",
		CreatedAt: time.Now(),
	}

	// Validate project1 fields
	assert.Equal(t, "duplicate-id", project1.ID)
	assert.Equal(t, "Project 1", project1.Name)
	assert.NotNil(t, project1.CreatedAt)

	project2 := &Project{
		ID:        "duplicate-id",
		Name:      "Project 2",
		CreatedAt: time.Now(),
	}

	// Validate project2 fields
	assert.Equal(t, "duplicate-id", project2.ID)
	assert.Equal(t, "Project 2", project2.Name)
	assert.NotNil(t, project2.CreatedAt)

	store.Create(project1)
	store.Create(project2) // Should overwrite project1

	retrieved, exists := store.Get("duplicate-id")
	assert.True(t, exists)
	assert.Equal(t, "Project 2", retrieved.Name) // Should have the second project

	// Test with empty project ID
	emptyProject := &Project{
		ID:        "",
		Name:      "Empty ID Project",
		CreatedAt: time.Now(),
	}

	// Validate empty project fields
	assert.Equal(t, "", emptyProject.ID)
	assert.Equal(t, "Empty ID Project", emptyProject.Name)
	assert.NotNil(t, emptyProject.CreatedAt)

	store.Create(emptyProject)
	retrieved, exists = store.Get("")
	assert.True(t, exists)
	assert.Equal(t, "Empty ID Project", retrieved.Name)
}

func BenchmarkProjectStore_Create(b *testing.B) {
	store := NewProjectStore(nil)

	for i := 0; i < b.N; i++ {
		project := &Project{
			ID:        fmt.Sprintf("project-%d", i),
			Name:      fmt.Sprintf("Project %d", i),
			Path:      fmt.Sprintf("/path/%d", i),
			Status:    "idle",
			CreatedAt: time.Now(),
		}
		store.Create(project)
	}
}

func BenchmarkProjectStore_Get(b *testing.B) {
	store := NewProjectStore(nil)

	// Pre-populate with projects
	for i := 0; i < 1000; i++ {
		project := &Project{
			ID:        fmt.Sprintf("project-%d", i),
			Name:      fmt.Sprintf("Project %d", i),
			CreatedAt: time.Now(),
		}
		store.Create(project)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Get(fmt.Sprintf("project-%d", i%1000))
	}
}

func BenchmarkProjectStore_GetAll(b *testing.B) {
	store := NewProjectStore(nil)

	// Pre-populate with projects
	for i := 0; i < 1000; i++ {
		project := &Project{
			ID:        fmt.Sprintf("project-%d", i),
			Name:      fmt.Sprintf("Project %d", i),
			CreatedAt: time.Now(),
		}
		store.Create(project)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.GetAll()
	}
}
