package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"archguardian/dashboard"
	"archguardian/internal/auth"
	"archguardian/internal/config"
	"archguardian/internal/guardian"
	"archguardian/internal/project"
	"archguardian/internal/scan"
	"archguardian/internal/websocket"

	"github.com/gorilla/mux"
)

// Server represents the HTTP server
type Server struct {
	router *mux.Router
	server *http.Server
}

// ArchGuardian represents the main application instance
type ArchGuardian struct {
	Config       *config.Config
	ProjectStore *project.ProjectStore
	AuthService  *auth.AuthService
	WSManager    *websocket.WebSocketManager
	Guardian     *guardian.ArchGuardian
	ScanManager  *scan.ScanManager // Scan job manager
	FS           fs.FS             // For serving embedded files
}

// NewServer creates a new HTTP server
func NewServer(port int) *Server {
	router := mux.NewRouter()

	// Create server with timeouts
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           router,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return &Server{
		router: router,
		server: server,
	}
}

// Start starts the server
func Start(ctx context.Context, guardian *ArchGuardian, authService *auth.AuthService) error {
	port := guardian.Config.ServerPort
	server := NewServer(port)

	// Apply global middleware
	rateLimiter := NewRateLimiter(time.Minute, 100)
	server.router.Use(corsMiddleware)
	server.router.Use(securityHeadersMiddleware)
	server.router.Use(rateLimitMiddleware(rateLimiter))
	server.router.Use(validationMiddleware)

	// Setup routes
	setupRoutes(server.router, guardian, authService)

	log.Printf("🌐 Starting ArchGuardian Consolidated Server on port %d...", port)
	log.Printf("✅ Consolidated server started on http://localhost:%d", port)
	log.Printf("📊 All API endpoints available on http://localhost:%d/api/v1/", port)
	log.Printf("📁 Dashboard files served from embedded resources")
	log.Printf("🔗 WebSocket available on ws://localhost:%d/ws", port)

	// Start server
	return server.server.ListenAndServe()
}

// setupRoutes configures all the HTTP routes
func setupRoutes(router *mux.Router, guardian *ArchGuardian, authService *auth.AuthService) {
	// API routes should be prefixed to avoid conflicts with static files
	api := router.PathPrefix("/api/v1").Subrouter()

	// WebSocket endpoint for dashboard log streaming
	router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		guardian.WSManager.HandleConnection(w, r, guardian.Guardian)
	})

	// Health check
	router.HandleFunc("/health", handleHealth).Methods("GET")

	// Authentication routes
	router.HandleFunc("/api/v1/auth/github", func(w http.ResponseWriter, r *http.Request) {
		handleGitHubAuth(w, r, authService)
	}).Methods("GET")

	router.HandleFunc("/api/v1/auth/github/callback", func(w http.ResponseWriter, r *http.Request) {
		handleGitHubCallback(w, r, authService)
	}).Methods("GET")

	api.HandleFunc("/auth/github/status", func(w http.ResponseWriter, r *http.Request) {
		handleGitHubAuthStatus(w, r, authService)
	}).Methods("GET")

	api.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		handleLogout(w, r, authService)
	}).Methods("POST")

	// Project routes
	api.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		handleGetProjects(w, r, guardian.ProjectStore)
	}).Methods("GET")

	api.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		handleCreateProject(w, r, guardian.ProjectStore)
	}).Methods("POST")

	api.HandleFunc("/projects/{id}", func(w http.ResponseWriter, r *http.Request) {
		handleGetProject(w, r, guardian.ProjectStore)
	}).Methods("GET")

	api.HandleFunc("/projects/{id}", func(w http.ResponseWriter, r *http.Request) {
		handleDeleteProject(w, r, guardian.ProjectStore)
	}).Methods("DELETE")

	api.HandleFunc("/projects/{id}/scan", func(w http.ResponseWriter, r *http.Request) {
		handleStartProjectScan(w, r, guardian)
	}).Methods("POST")

	// Dashboard data endpoints
	api.HandleFunc("/knowledge-graph", authService.OptionalAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handleEnhancedKnowledgeGraph(w, r, guardian)
	})).Methods("GET")
	api.HandleFunc("/risk-assessment", authService.OptionalAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handleEnhancedRiskAssessment(w, r, guardian)
	})).Methods("GET")
	api.HandleFunc("/issues", authService.OptionalAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handleEnhancedIssues(w, r, guardian)
	})).Methods("GET")
	api.HandleFunc("/coverage", authService.OptionalAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handleEnhancedCoverage(w, r, guardian)
	})).Methods("GET")
	api.HandleFunc("/settings", authService.OptionalAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handleEnhancedSettings(w, r, guardian)
	})).Methods("GET", "POST")

	// Scan history and search endpoints
	api.HandleFunc("/scans/history", func(w http.ResponseWriter, r *http.Request) {
		handleEnhancedScanHistory(w, r, guardian)
	}).Methods("GET")
	api.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		handleEnhancedSemanticSearch(w, r, guardian)
	}).Methods("GET")

	// System metrics endpoint
	api.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		handleEnhancedSystemMetrics(w, r, guardian)
	}).Methods("GET")

	// API Documentation endpoint
	api.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		handleEnhancedAPIDocs(w, r, guardian)
	}).Methods("GET")

	// Guardian-specific endpoints
	api.HandleFunc("/guardian/status", func(w http.ResponseWriter, r *http.Request) {
		handleGuardianStatus(w, r, guardian)
	}).Methods("GET")
	api.HandleFunc("/scan/trigger", func(w http.ResponseWriter, r *http.Request) {
		handleTriggerScan(w, r, guardian)
	}).Methods("POST")

	// Alerts endpoints
	api.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		handleGetAlerts(w, r, guardian)
	}).Methods("GET")
	api.HandleFunc("/alerts/clear-resolved", func(w http.ResponseWriter, r *http.Request) {
		handleClearResolvedAlerts(w, r, guardian)
	}).Methods("POST")
	api.HandleFunc("/alerts/{id}/resolve", func(w http.ResponseWriter, r *http.Request) {
		handleResolveAlert(w, r, guardian)
	}).Methods("POST")

	// Serve the embedded dashboard files as the fallback
	router.PathPrefix("/").Handler(http.FileServer(http.FS(dashboard.Dist)))
}

// handleHealth returns health check status
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","timestamp":"` + time.Now().Format(time.RFC3339) + `","version":"1.0.0"}`))
}

// handleGitHubAuth handles GitHub authentication
func handleGitHubAuth(w http.ResponseWriter, r *http.Request, authService *auth.AuthService) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET": // Only handle GET for auth URL
		authURL, csrfToken, err := authService.HandleGitHubAuth(w, r)
		if err != nil {
			log.Printf("GitHub auth error: %v", err)
			response := map[string]interface{}{
				"error": map[string]string{
					"message": err.Error(),
				},
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		response := map[string]interface{}{
			"data": map[string]string{
				"auth_url":   authURL,
				"csrf_token": csrfToken,
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

	case "POST":
		http.Error(w, "Not implemented", http.StatusNotImplemented)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGitHubCallback handles GitHub OAuth callback
func handleGitHubCallback(w http.ResponseWriter, r *http.Request, authService *auth.AuthService) {
	redirectURL, err := authService.HandleGitHubCallback(r)
	if err != nil {
		log.Printf("GitHub callback error: %v", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// handleGitHubAuthStatus handles GitHub authentication status check
func handleGitHubAuthStatus(w http.ResponseWriter, r *http.Request, authService *auth.AuthService) {
	authService.HandleGitHubAuthStatus(w, r)
}

// handleLogout handles user logout
func handleLogout(w http.ResponseWriter, r *http.Request, authService *auth.AuthService) {
	authService.HandleLogout(w, r)
}

// handleGetProjects returns all projects
func handleGetProjects(w http.ResponseWriter, _ *http.Request, projectStore *project.ProjectStore) {
	w.Header().Set("Content-Type", "application/json")

	projects := projectStore.GetAll()

	// Create proper JSON response
	response := map[string]interface{}{
		"projects": projects,
		"total":    len(projects),
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal projects", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

// handleCreateProject creates a new project
func handleCreateProject(w http.ResponseWriter, r *http.Request, projectStore *project.ProjectStore) {
	w.Header().Set("Content-Type", "application/json")

	var newProject struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&newProject); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	project := &project.Project{
		ID:        generateProjectID(),
		Name:      newProject.Name,
		Path:      newProject.Path,
		Status:    "idle",
		CreatedAt: time.Now(),
	}

	if err := projectStore.Create(project); err != nil {
		http.Error(w, "Failed to create project", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"project": project,
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write(jsonData)
}

// handleGetProject returns a specific project
func handleGetProject(w http.ResponseWriter, r *http.Request, projectStore *project.ProjectStore) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	id := vars["id"]

	project, exists := projectStore.Get(id)
	if !exists {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	jsonData, err := json.Marshal(project)
	if err != nil {
		http.Error(w, "Failed to marshal project", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

// handleDeleteProject deletes a project
func handleDeleteProject(w http.ResponseWriter, r *http.Request, projectStore *project.ProjectStore) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	id := vars["id"]

	if err := projectStore.Delete(id); err != nil {
		http.Error(w, "Failed to delete project", http.StatusInternalServerError)
		return
	}

	response := map[string]bool{"success": true}
	jsonData, _ := json.Marshal(response)
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

// handleStartProjectScan starts a scan for a specific project
func handleStartProjectScan(w http.ResponseWriter, r *http.Request, guardian *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	projectID := vars["id"]

	// Verify project exists
	proj, exists := guardian.ProjectStore.Get(projectID)
	if !exists {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	// Update project status to scanning
	proj.Status = "scanning"
	if err := guardian.ProjectStore.Update(proj); err != nil {
		log.Printf("Failed to update project status: %v", err)
	}

	// Log the scan trigger
	log.Printf("🔄 Scan triggered for project: %s (ID: %s, Path: %s)", proj.Name, projectID, proj.Path)

	// Create and start a scan job using the ScanManager
	var jobID string
	if guardian.ScanManager != nil {
		job, err := guardian.ScanManager.CreateJob(projectID, proj.Path)
		if err != nil {
			log.Printf("❌ Failed to create scan job: %v", err)
			http.Error(w, fmt.Sprintf("Failed to create scan job: %v", err), http.StatusInternalServerError)
			return
		}
		jobID = job.GetID()

		// Start the job
		if err := guardian.ScanManager.StartJob(jobID); err != nil {
			log.Printf("❌ Failed to start scan job: %v", err)
			http.Error(w, fmt.Sprintf("Failed to start scan job: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("✅ Scan job %s created and started for project %s", jobID, projectID)
	} else {
		log.Printf("⚠️  ScanManager not available, cannot start scan")
		http.Error(w, "Scan manager not available", http.StatusInternalServerError)
		return
	}

	// Broadcast scan started event via WebSocket
	if guardian.WSManager != nil {
		guardian.WSManager.BroadcastMessage("scan_started", map[string]interface{}{
			"project_id":   projectID,
			"project_name": proj.Name,
			"job_id":       jobID,
			"timestamp":    time.Now().Format(time.RFC3339),
		})
	}

	response := map[string]interface{}{
		"success":    true,
		"message":    "Scan started successfully",
		"project_id": projectID,
		"job_id":     jobID,
		"status":     "scanning",
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	jsonData, _ := json.Marshal(response)
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

// generateProjectID generates a unique project ID
func generateProjectID() string {
	return fmt.Sprintf("project_%d", time.Now().UnixNano())
}

// handleKnowledgeGraph returns knowledge graph data
func handleKnowledgeGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Log the request for debugging
	log.Printf("📊 Knowledge graph request from %s", r.RemoteAddr)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"nodes":[],"edges":[],"message":"No knowledge graph available. Run a scan first."}`))
}

// handleRiskAssessment returns risk assessment data
func handleRiskAssessment(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"risk_score":0,"issues":[]}`))
}

// handleIssues returns security issues
func handleIssues(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"issues":[],"total":0}`))
}

// handleCoverage returns test coverage data
func handleCoverage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"coverage":0,"files":[]}`))
}

// handleSettings handles settings get/update
func handleSettings(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"settings":{}}`))
}

// handleScanHistory returns scan history
func handleScanHistory(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"scans":[],"total":0}`))
}

// handleSemanticSearch performs semantic search
func handleSemanticSearch(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"results":[],"total":0}`))
}

// handleSystemMetrics returns system metrics
func handleSystemMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"cpu":0,"memory":0,"disk":0}`))
}

// handleAPIDocs returns API documentation
func handleAPIDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"version":"1.0.0","endpoints":[]}`))
}

// handleGetAlerts returns all alerts
func handleGetAlerts(w http.ResponseWriter, _ *http.Request, _ *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	
	// For now, return empty alerts array with proper JSON structure
	// In a real implementation, this would fetch from the data engine
	response := map[string]interface{}{
		"alerts": []interface{}{},
	}
	
	jsonData, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal alerts", http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

// handleResolveAlert resolves a specific alert
func handleResolveAlert(w http.ResponseWriter, r *http.Request, _ *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	
	vars := mux.Vars(r)
	alertID := vars["id"]
	
	// For now, just return success
	// In a real implementation, this would resolve the alert in the data engine
	response := map[string]interface{}{
		"id":       alertID,
		"resolved": true,
	}
	
	jsonData, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

// handleClearResolvedAlerts clears all resolved alerts
func handleClearResolvedAlerts(w http.ResponseWriter, _ *http.Request, _ *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	
	// For now, just return success
	// In a real implementation, this would clear resolved alerts in the data engine
	response := map[string]interface{}{
		"success": true,
		"cleared": 0,
	}
	
	jsonData, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}
