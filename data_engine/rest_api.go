package data_engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// RESTAPIServer handles REST API requests for data access
type RESTAPIServer struct {
	router     *mux.Router
	server     *http.Server
	dataEngine *DataEngine
	isRunning  bool
	ctx        context.Context
	cancel     context.CancelFunc
	mutex      sync.RWMutex
	config     RESTAPIConfig
}

// RESTAPIConfig contains configuration for the REST API server
type RESTAPIConfig struct {
	Port           int
	EnableCORS     bool
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxHeaderBytes int
}

// NewRESTAPIServer creates a new REST API server
func NewRESTAPIServer(config RESTAPIConfig, dataEngine *DataEngine) *RESTAPIServer {
	if config.Port == 0 {
		config.Port = 7080
	}

	if config.ReadTimeout == 0 {
		config.ReadTimeout = 10 * time.Second
	}

	if config.WriteTimeout == 0 {
		config.WriteTimeout = 10 * time.Second
	}

	if config.MaxHeaderBytes == 0 {
		config.MaxHeaderBytes = 1 << 20 // 1MB
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &RESTAPIServer{
		router:     mux.NewRouter(),
		dataEngine: dataEngine,
		ctx:        ctx,
		cancel:     cancel,
		config:     config,
	}
}

// Start starts the REST API server
func (s *RESTAPIServer) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.isRunning {
		return fmt.Errorf("REST API server is already running")
	}

	// Set up routes
	s.setupRoutes()

	// Create HTTP server
	s.server = &http.Server{
		Addr:           fmt.Sprintf(":%d", s.config.Port),
		Handler:        s.router,
		ReadTimeout:    s.config.ReadTimeout,
		WriteTimeout:   s.config.WriteTimeout,
		MaxHeaderBytes: s.config.MaxHeaderBytes,
	}

	// Start HTTP server in a goroutine
	go func() {
		log.Printf("Starting REST API server on %s...", s.server.Addr)
		err := s.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Printf("REST API server error: %s\n", err.Error())
		} else {
			log.Println("REST API server shut down.")
		}
	}()

	s.isRunning = true
	return nil
}

// Stop stops the REST API server
func (s *RESTAPIServer) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isRunning {
		return nil
	}

	// Cancel context
	s.cancel()

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.server.Shutdown(ctx)
	if err != nil {
		return fmt.Errorf("failed to shutdown REST API server: %w", err)
	}

	s.isRunning = false
	return nil
}

// setupRoutes sets up the API routes
func (s *RESTAPIServer) setupRoutes() {
	// API version prefix
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Health check
	api.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Metrics
	api.HandleFunc("/metrics", s.handleGetMetrics).Methods("GET")

	// Alerts
	api.HandleFunc("/alerts", s.handleGetAlerts).Methods("GET")
	api.HandleFunc("/alerts/{id}", s.handleResolveAlert).Methods("PUT")

	// Events
	api.HandleFunc("/events", s.handleGetEvents).Methods("GET")
	api.HandleFunc("/events/search", s.handleSearchEvents).Methods("GET")
	api.HandleFunc("/events/types", s.handleGetEventTypes).Methods("GET")

	// Windows
	api.HandleFunc("/windows", s.handleGetWindows).Methods("GET")
	api.HandleFunc("/windows/range", s.handleGetWindowsInRange).Methods("GET")

	// Analytics
	api.HandleFunc("/analytics/users", s.handleGetActiveUsers).Methods("GET")
	api.HandleFunc("/analytics/rates", s.handleGetEventRates).Methods("GET")

	// Add middleware
	s.router.Use(s.loggingMiddleware)

	// Add CORS middleware if enabled
	s.router.Use(s.corsMiddleware)
}

// loggingMiddleware logs API requests
func (s *RESTAPIServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Call the next handler
		next.ServeHTTP(w, r)

		// Log the request
		fmt.Printf(
			"[%s] %s %s %s\n",
			time.Now().Format("2006-01-02 15:04:05"),
			r.Method,
			r.RequestURI,
			time.Since(start),
		)
	})
}

// corsMiddleware adds CORS headers
func (s *RESTAPIServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// handleHealth handles health check requests
func (s *RESTAPIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Create health status
	health := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "rest-api",
	}

	// Add data engine status
	if s.dataEngine != nil {
		health["data_engine"] = map[string]interface{}{
			"running": s.dataEngine.IsRunning(),
		}

		// Add Kafka status
		if s.dataEngine.producer != nil {
			health["kafka"] = map[string]interface{}{
				"connected": s.dataEngine.producer.IsConnected(),
			}
		}

		// Add ChromaDB status
		if s.dataEngine.chromaDB != nil {
			health["chromadb"] = map[string]interface{}{
				"connected": s.dataEngine.chromaDB.IsConnected(),
			}
		}
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(health)
}

// handleGetMetrics handles requests for metrics
func (s *RESTAPIServer) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil {
		http.Error(w, "Data engine not available", http.StatusServiceUnavailable)
		return
	}

	// Get stream processor metrics
	streamMetrics := s.dataEngine.GetMetrics()

	// Collect system metrics
	systemMetrics, err := s.collectSystemMetrics(r.Context())
	if err != nil {
		log.Printf("⚠️  Failed to collect system metrics: %v", err)
		systemMetrics = map[string]interface{}{
			"error": err.Error(),
		}
	}

	// Combine metrics
	combinedMetrics := map[string]interface{}{
		"stream_processor": streamMetrics,
		"system":           systemMetrics,
		"timestamp":        time.Now(),
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(combinedMetrics)
}

// handleGetAlerts handles requests for alerts
func (s *RESTAPIServer) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	// If alerting subsystem is not available, return empty list (200) to keep API consumer-friendly
	if s.dataEngine == nil || s.dataEngine.alerting == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]Alert{})
		return
	}

	// Parse query parameters
	activeOnly := r.URL.Query().Get("active") == "true"

	var alerts []Alert
	if activeOnly {
		alerts = s.dataEngine.alerting.GetActiveAlerts()
	} else {
		alerts = s.dataEngine.alerting.GetAlerts()
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(alerts)
}

// handleResolveAlert handles requests to resolve an alert
func (s *RESTAPIServer) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil || s.dataEngine.alerting == nil {
		http.Error(w, "Alerting system not available", http.StatusServiceUnavailable)
		return
	}

	// Get alert ID from URL
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Resolve alert
	resolved := s.dataEngine.alerting.ResolveAlert(alertID)

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       alertID,
		"resolved": resolved,
	})
}

// handleGetEvents handles requests for events
func (s *RESTAPIServer) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil || s.dataEngine.chromaDB == nil || !s.dataEngine.chromaDB.IsConnected() {
		http.Error(w, "ChromaDB not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	eventType := r.URL.Query().Get("type")

	// Set default limit
	limit := 10
	if limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			limit = 10
		}
		if limit > 100 {
			limit = 100
		}
	}

	var docs []ChromaDocument
	var err error

	// Query events
	if eventType != "" {
		// Filter by event type
		docs, err = s.dataEngine.chromaDB.GetEventsByType(r.Context(), EventType(eventType), limit)
	} else {
		// Get recent events
		docs, err = s.dataEngine.chromaDB.GetRecentEvents(r.Context(), limit)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to query events: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(docs)
}

// handleSearchEvents handles requests to search events
func (s *RESTAPIServer) handleSearchEvents(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil || s.dataEngine.chromaDB == nil || !s.dataEngine.chromaDB.IsConnected() {
		http.Error(w, "ChromaDB not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}

	limitStr := r.URL.Query().Get("limit")

	// Set default limit
	limit := 10
	if limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			limit = 10
		}
		if limit > 100 {
			limit = 100
		}
	}

	// Search events
	docs, err := s.dataEngine.chromaDB.QueryEvents(r.Context(), query, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to search events: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(docs)
}

// handleGetEventTypes handles requests for event types
func (s *RESTAPIServer) handleGetEventTypes(w http.ResponseWriter, r *http.Request) {
	// Define event types
	eventTypes := []string{
		string(ScanCycleEventType),
		string(ScanStartedEvent),
		string(ScanCompletedEvent),
		string(RiskAnalysisEvent),
		string(RemediationEvent),
		string(SystemEventType),
		string(ErrorEvent),
		string(WarningEvent),
		string(InfoEvent),
		// Add other relevant event types as they are defined and used
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(eventTypes)
}

// handleGetWindows handles requests for windows
func (s *RESTAPIServer) handleGetWindows(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil || s.dataEngine.aggregator == nil {
		http.Error(w, "Windowed aggregator not available", http.StatusServiceUnavailable)
		return
	}

	// Get windows
	windows := s.dataEngine.aggregator.GetWindows()

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(windows)
}

// handleGetWindowsInRange handles requests for windows in a time range
func (s *RESTAPIServer) handleGetWindowsInRange(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil || s.dataEngine.aggregator == nil {
		http.Error(w, "Windowed aggregator not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	if startStr == "" || endStr == "" {
		http.Error(w, "Query parameters 'start' and 'end' are required", http.StatusBadRequest)
		return
	}

	// Parse timestamps
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid start time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid end time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Get windows in range
	windows := s.dataEngine.aggregator.GetWindowsInRange(start, end)

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(windows)
}

// handleGetActiveUsers handles requests for active users
func (s *RESTAPIServer) handleGetActiveUsers(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil || s.dataEngine.aggregator == nil {
		http.Error(w, "Windowed aggregator not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	if startStr == "" || endStr == "" {
		http.Error(w, "Query parameters 'start' and 'end' are required", http.StatusBadRequest)
		return
	}

	// Parse timestamps
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid start time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid end time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Get active users
	activeUsers := s.dataEngine.aggregator.GetActiveUsers(start, end)

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"start":        start.Format(time.RFC3339),
		"end":          end.Format(time.RFC3339),
		"active_users": activeUsers,
	})
}

// handleGetEventRates handles requests for event rates
func (s *RESTAPIServer) handleGetEventRates(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil || s.dataEngine.aggregator == nil {
		http.Error(w, "Windowed aggregator not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	if startStr == "" || endStr == "" {
		http.Error(w, "Query parameters 'start' and 'end' are required", http.StatusBadRequest)
		return
	}

	// Parse timestamps
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid start time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid end time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Get event rate
	eventRate := s.dataEngine.aggregator.GetEventRate(start, end)

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"start":      start.Format(time.RFC3339),
		"end":        end.Format(time.RFC3339),
		"event_rate": eventRate,
		"unit":       "events/second",
	})
}

// IsRunning returns whether the REST API server is running
func (s *RESTAPIServer) IsRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.isRunning
}

// collectSystemMetrics collects system metrics using gopsutil
func (s *RESTAPIServer) collectSystemMetrics(ctx context.Context) (map[string]interface{}, error) {
	metrics := make(map[string]interface{})

	// CPU usage
	cpuPercent, err := cpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU metrics: %w", err)
	}
	if len(cpuPercent) > 0 {
		metrics["cpu"] = cpuPercent[0]
	} else {
		metrics["cpu"] = 0.0
	}

	// Memory usage
	memInfo, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get memory metrics: %w", err)
	}
	metrics["memory"] = memInfo.UsedPercent

	// Disk usage
	diskInfo, err := disk.UsageWithContext(ctx, "/")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk metrics: %w", err)
	}
	metrics["disk"] = diskInfo.UsedPercent

	// Network I/O
	netInfo, err := net.IOCountersWithContext(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get network metrics: %w", err)
	}
	if len(netInfo) > 0 {
		metrics["network"] = map[string]interface{}{
			"in":  netInfo[0].BytesRecv,
			"out": netInfo[0].BytesSent,
		}
	} else {
		metrics["network"] = map[string]interface{}{
			"in":  0,
			"out": 0,
		}
	}

	// Process information
	processes, err := process.ProcessesWithContext(ctx)
	if err == nil {
		metrics["processes"] = len(processes)
	} else {
		metrics["processes"] = 0
	}

	metrics["timestamp"] = time.Now()
	return metrics, nil
}
