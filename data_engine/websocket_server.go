package data_engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketServer handles WebSocket connections for real-time updates
type WebSocketServer struct {
	clients      map[*websocket.Conn]bool
	clientsMutex sync.RWMutex
	broadcast    chan interface{}
	upgrader     websocket.Upgrader
	server       *http.Server
	dataEngine   *DataEngine
	isRunning    bool
	ctx          context.Context
	cancel       context.CancelFunc
}

// WebSocketConfig contains configuration for the WebSocket server
type WebSocketConfig struct {
	Port            int
	ReadBufferSize  int
	WriteBufferSize int
	CheckOrigin     bool
}

// NewWebSocketServer creates a new WebSocket server
func NewWebSocketServer(config WebSocketConfig, dataEngine *DataEngine) *WebSocketServer {
	if config.Port == 0 {
		config.Port = 8080
	}

	if config.ReadBufferSize == 0 {
		config.ReadBufferSize = 1024
	}

	if config.WriteBufferSize == 0 {
		config.WriteBufferSize = 1024
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &WebSocketServer{
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan interface{}, 100),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  config.ReadBufferSize,
			WriteBufferSize: config.WriteBufferSize,
			CheckOrigin: func(r *http.Request) bool {
				return config.CheckOrigin
			},
		},
		dataEngine: dataEngine,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the WebSocket server
func (s *WebSocketServer) Start() error {
	if s.isRunning {
		return fmt.Errorf("WebSocket server is already running")
	}

	// Create HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/alerts", s.handleAlerts)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/health", s.handleHealth)

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", 8080),
		Handler: mux,
	}

	// Start HTTP server in a goroutine
	go func() {
		err := s.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("WebSocket server error: %s\n", err.Error())
		}
	}()

	// Start broadcast handler
	go s.handleBroadcasts()

	// Subscribe to data engine events
	if s.dataEngine != nil {
		// Handle alerts
		go func() {
			alertChan := s.dataEngine.GetAlertChannel()
			for {
				select {
				case <-s.ctx.Done():
					return
				case alert := <-alertChan:
					s.broadcast <- map[string]interface{}{
						"type":  "alert",
						"alert": alert,
					}
				}
			}
		}()

		// Handle metrics
		go func() {
			metricsChan := s.dataEngine.GetMetricsChannel()
			for {
				select {
				case <-s.ctx.Done():
					return
				case metrics := <-metricsChan:
					s.broadcast <- map[string]interface{}{
						"type":    "metrics",
						"metrics": metrics,
					}
				}
			}
		}()
	}

	s.isRunning = true
	return nil
}

// Stop stops the WebSocket server
func (s *WebSocketServer) Stop() error {
	if !s.isRunning {
		return nil
	}

	// Cancel context
	s.cancel()

	// Close all client connections
	s.clientsMutex.Lock()
	for client := range s.clients {
		client.Close()
	}
	s.clients = make(map[*websocket.Conn]bool)
	s.clientsMutex.Unlock()

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.server.Shutdown(ctx)
	if err != nil {
		return fmt.Errorf("failed to shutdown WebSocket server: %w", err)
	}

	s.isRunning = false
	return nil
}

// handleWebSocket handles WebSocket connections
func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("Failed to upgrade connection: %s\n", err.Error())
		return
	}

	// Register client
	s.clientsMutex.Lock()
	s.clients[conn] = true
	s.clientsMutex.Unlock()

	// Send initial data
	if s.dataEngine != nil {
		// Send metrics
		metrics := s.dataEngine.GetMetrics()
		if metrics != nil {
			err := conn.WriteJSON(map[string]interface{}{
				"type":    "metrics",
				"metrics": metrics,
			})
			if err != nil {
				fmt.Printf("Failed to send initial metrics: %s\n", err.Error())
			}
		}

		// Send alerts
		alerts := s.dataEngine.GetActiveAlerts()
		if len(alerts) > 0 {
			err := conn.WriteJSON(map[string]interface{}{
				"type":   "alerts",
				"alerts": alerts,
			})
			if err != nil {
				fmt.Printf("Failed to send initial alerts: %s\n", err.Error())
			}
		}
	}

	// Handle client messages
	go s.handleClient(conn)
}

// handleClient handles messages from a WebSocket client
func (s *WebSocketServer) handleClient(conn *websocket.Conn) {
	defer func() {
		// Unregister client on disconnect
		s.clientsMutex.Lock()
		delete(s.clients, conn)
		s.clientsMutex.Unlock()
		conn.Close()
	}()

	for {
		// Read message
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				fmt.Printf("WebSocket error: %s\n", err.Error())
			}
			break
		}

		// Parse message
		var data map[string]interface{}
		err = json.Unmarshal(message, &data)
		if err != nil {
			fmt.Printf("Failed to parse message: %s\n", err.Error())
			continue
		}

		// Handle message
		s.handleClientMessage(conn, data)
	}
}

// handleClientMessage handles a message from a WebSocket client
func (s *WebSocketServer) handleClientMessage(conn *websocket.Conn, data map[string]interface{}) {
	// Check message type
	msgType, ok := data["type"].(string)
	if !ok {
		fmt.Printf("Invalid message type\n")
		return
	}

	switch msgType {
	case "ping":
		// Respond with pong
		err := conn.WriteJSON(map[string]interface{}{
			"type": "pong",
			"time": time.Now().Format(time.RFC3339),
		})
		if err != nil {
			fmt.Printf("Failed to send pong: %s\n", err.Error())
		}

	case "subscribe":
		// Handle subscription
		topic, ok := data["topic"].(string)
		if !ok {
			fmt.Printf("Invalid subscription topic\n")
			return
		}

		// Acknowledge subscription
		err := conn.WriteJSON(map[string]interface{}{
			"type":   "subscribed",
			"topic":  topic,
			"status": "success",
		})
		if err != nil {
			fmt.Printf("Failed to acknowledge subscription: %s\n", err.Error())
		}

	case "resolve_alert":
		// Handle alert resolution
		if s.dataEngine == nil {
			return
		}

		alertID, ok := data["alert_id"].(string)
		if !ok {
			fmt.Printf("Invalid alert ID\n")
			return
		}

		// Resolve alert
		resolved := s.dataEngine.ResolveAlert(alertID)

		// Send response
		err := conn.WriteJSON(map[string]interface{}{
			"type":     "alert_resolved",
			"alert_id": alertID,
			"success":  resolved,
		})
		if err != nil {
			fmt.Printf("Failed to send alert resolution response: %s\n", err.Error())
		}
	}
}

// handleBroadcasts handles broadcasting messages to all clients
func (s *WebSocketServer) handleBroadcasts() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case message := <-s.broadcast:
			// Broadcast message to all clients
			s.clientsMutex.RLock()
			for client := range s.clients {
				err := client.WriteJSON(message)
				if err != nil {
					fmt.Printf("Failed to broadcast message: %s\n", err.Error())
					client.Close()
					s.clientsMutex.RUnlock()
					s.clientsMutex.Lock()
					delete(s.clients, client)
					s.clientsMutex.Unlock()
					s.clientsMutex.RLock()
				}
			}
			s.clientsMutex.RUnlock()
		}
	}
}

// handleMetrics handles HTTP requests for metrics
func (s *WebSocketServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil {
		http.Error(w, "Data engine not available", http.StatusServiceUnavailable)
		return
	}

	// Get metrics
	metrics := s.dataEngine.GetMetrics()
	if metrics == nil {
		http.Error(w, "No metrics available", http.StatusNotFound)
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	err := json.NewEncoder(w).Encode(metrics)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode metrics: %s", err.Error()), http.StatusInternalServerError)
	}
}

// handleAlerts handles HTTP requests for alerts
func (s *WebSocketServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil {
		http.Error(w, "Data engine not available", http.StatusServiceUnavailable)
		return
	}

	// Get alerts
	alerts := s.dataEngine.GetActiveAlerts()

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	err := json.NewEncoder(w).Encode(alerts)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode alerts: %s", err.Error()), http.StatusInternalServerError)
	}
}

// handleEvents handles HTTP requests for events
func (s *WebSocketServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.dataEngine == nil || s.dataEngine.chromaDB == nil || !s.dataEngine.chromaDB.IsConnected() {
		http.Error(w, "ChromaDB not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	query := r.URL.Query().Get("query")
	limitStr := r.URL.Query().Get("limit")
	eventType := r.URL.Query().Get("type")

	// Set default limit
	limit := 10
	if limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
		if limit <= 0 {
			limit = 10
		}
		if limit > 100 {
			limit = 100
		}
	}

	var docs []ChromaDocument
	var err error

	// Query events
	if query != "" {
		// Search by query
		docs, err = s.dataEngine.chromaDB.QueryEvents(r.Context(), query, limit)
	} else if eventType != "" {
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
	err = json.NewEncoder(w).Encode(docs)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode events: %s", err.Error()), http.StatusInternalServerError)
	}
}

// handleHealth handles HTTP requests for health check
func (s *WebSocketServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Create health status
	health := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
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

	// Add WebSocket status
	health["websocket"] = map[string]interface{}{
		"running":      s.isRunning,
		"client_count": len(s.clients),
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Write response
	err := json.NewEncoder(w).Encode(health)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode health status: %s", err.Error()), http.StatusInternalServerError)
	}
}

// Broadcast broadcasts a message to all clients
func (s *WebSocketServer) Broadcast(message interface{}) {
	select {
	case s.broadcast <- message:
		// Message sent successfully
	default:
		// Channel is full, log and continue
		fmt.Printf("Broadcast channel is full, dropping message\n")
	}
}

// GetClientCount returns the number of connected clients
func (s *WebSocketServer) GetClientCount() int {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	return len(s.clients)
}

// IsRunning returns whether the WebSocket server is running
func (s *WebSocketServer) IsRunning() bool {
	return s.isRunning
}
