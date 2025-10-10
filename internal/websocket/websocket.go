package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"archguardian/internal/guardian"

	"github.com/gorilla/websocket"
)

// WebSocketManager manages WebSocket connections for real-time updates
type WebSocketManager struct {
	connections map[*websocket.Conn]bool
	mutex       sync.RWMutex
	upgrader    websocket.Upgrader
}

// WSMessage represents a WebSocket message
type WSMessage struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
	ID        string      `json:"id,omitempty"`
}

// NewWebSocketManager creates a new WebSocket manager
func NewWebSocketManager() *WebSocketManager {
	return &WebSocketManager{
		connections: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// Allow connections from localhost for development
				return true
			},
		},
	}
}

// HandleConnection handles a new WebSocket connection
func (wsm *WebSocketManager) HandleConnection(w http.ResponseWriter, r *http.Request, archGuardian *guardian.ArchGuardian) {
	// Upgrade HTTP connection to WebSocket
	conn, err := wsm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %s", err.Error())
		return
	}
	defer conn.Close()

	log.Println("WebSocket client connected")

	// Register the connection with ArchGuardian
	if archGuardian != nil {
		archGuardian.AddDashboardConnection(conn)
	}

	// Register the connection locally for broadcasting
	wsm.mutex.Lock()
	wsm.connections[conn] = true
	wsm.mutex.Unlock()

	// Handle client messages
	for {
		// Read message
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %s", err.Error())
			}
			break
		}

		// Parse message
		var data map[string]interface{}
		err = json.Unmarshal(message, &data)
		if err != nil {
			log.Printf("Failed to parse message: %s", err.Error())
			continue
		}

		// Handle message
		msgType, ok := data["type"].(string)
		if !ok {
			continue
		}

		switch msgType {
		case "client_ready":
			// Client is ready to receive logs - flush buffered logs
			log.Println("WebSocket client ready")
			if archGuardian != nil {
				archGuardian.FlushInitialLogs()
			}
		case "ping":
			// Respond to ping
			wsm.sendMessage(conn, WSMessage{
				Type:      "pong",
				Timestamp: time.Now(),
				Data:      map[string]interface{}{"status": "ok"},
			})
		case "trigger_scan":
			// Manual scan trigger from dashboard
			log.Println("Manual scan triggered from dashboard")
			if archGuardian != nil {
				archGuardian.TriggerScan()
			}
		}
	}

	log.Println("WebSocket client disconnected")

	// Unregister the connection from ArchGuardian
	if archGuardian != nil {
		archGuardian.RemoveDashboardConnection(conn)
	}

	// Unregister the connection locally
	wsm.mutex.Lock()
	delete(wsm.connections, conn)
	wsm.mutex.Unlock()
}

// BroadcastMessage broadcasts a message to all connected clients
func (wsm *WebSocketManager) BroadcastMessage(msgType string, data interface{}) {
	wsm.mutex.RLock()
	connections := make([]*websocket.Conn, 0, len(wsm.connections))
	for conn := range wsm.connections {
		connections = append(connections, conn)
	}
	wsm.mutex.RUnlock()

	message := WSMessage{
		Type:      msgType,
		Timestamp: time.Now(),
		Data:      data,
	}

	for _, conn := range connections {
		wsm.sendMessage(conn, message)
	}
}

// sendMessage sends a message to a specific connection
func (wsm *WebSocketManager) sendMessage(conn *websocket.Conn, message WSMessage) {
	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal WebSocket message: %v", err)
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("Failed to send WebSocket message: %v", err)
		// Remove broken connection
		wsm.mutex.Lock()
		delete(wsm.connections, conn)
		wsm.mutex.Unlock()
	}
}

// GetConnectionCount returns the number of active connections
func (wsm *WebSocketManager) GetConnectionCount() int {
	wsm.mutex.RLock()
	defer wsm.mutex.RUnlock()
	return len(wsm.connections)
}

// BroadcastScanProgress broadcasts scan progress updates
func (wsm *WebSocketManager) BroadcastScanProgress(phase string, progress float64, message string) {
	data := map[string]interface{}{
		"phase":    phase,
		"progress": progress,
		"message":  message,
	}

	wsm.BroadcastMessage("scan_progress", data)
}

// BroadcastSecurityAlert broadcasts security vulnerability alerts
func (wsm *WebSocketManager) BroadcastSecurityAlert(vuln interface{}) {
	wsm.BroadcastMessage("security_alert", vuln)
}

// BroadcastRemediationComplete broadcasts remediation completion notifications
func (wsm *WebSocketManager) BroadcastRemediationComplete(data interface{}) {
	wsm.BroadcastMessage("remediation_complete", data)
}

// BroadcastLogMessage broadcasts log messages
func (wsm *WebSocketManager) BroadcastLogMessage(level, message string) {
	data := map[string]interface{}{
		"level":   level,
		"message": message,
	}

	wsm.BroadcastMessage("log", data)
}

// BroadcastSystemEvent broadcasts system events
func (wsm *WebSocketManager) BroadcastSystemEvent(eventType, subType string, data interface{}) {
	messageData := map[string]interface{}{
		"event_type": eventType,
		"sub_type":   subType,
		"data":       data,
	}

	wsm.BroadcastMessage("system_event", messageData)
}
