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

// wsConnection wraps a WebSocket connection with a mutex for safe concurrent writes
type wsConnection struct {
	conn  *websocket.Conn
	mutex sync.Mutex
}

// WriteMessage safely writes a message to the WebSocket connection
func (wsc *wsConnection) WriteMessage(messageType int, data []byte) error {
	wsc.mutex.Lock()
	defer wsc.mutex.Unlock()
	return wsc.conn.WriteMessage(messageType, data)
}

// WebSocketManager manages WebSocket connections for real-time updates
type WebSocketManager struct {
	connections  map[*websocket.Conn]*wsConnection
	mutex        sync.RWMutex
	upgrader     websocket.Upgrader
	archGuardian *guardian.ArchGuardian // Reference to ArchGuardian for delegating broadcasts
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
		connections: make(map[*websocket.Conn]*wsConnection),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// Allow connections from localhost for development
				return true
			},
		},
	}
}

// SetArchGuardian sets the ArchGuardian reference for delegating broadcasts
func (wsm *WebSocketManager) SetArchGuardian(ag *guardian.ArchGuardian) {
	wsm.archGuardian = ag
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

	// Register with ArchGuardian for log streaming
	// ArchGuardian uses a dedicated broadcastWorker goroutine that handles all writes sequentially,
	// preventing concurrent write panics. The WebSocketManager should NOT write to these connections
	// directly - only ArchGuardian's broadcastWorker should write to them.
	if archGuardian != nil {
		archGuardian.AddDashboardConnection(conn)
	}

	// Register the connection locally for tracking only (not for broadcasting)
	wsConn := &wsConnection{conn: conn}
	wsm.mutex.Lock()
	wsm.connections[conn] = wsConn
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
			wsm.sendMessage(wsConn, WSMessage{
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

	// Unregister from ArchGuardian
	if archGuardian != nil {
		archGuardian.RemoveDashboardConnection(conn)
	}

	// Unregister the connection locally
	wsm.mutex.Lock()
	delete(wsm.connections, conn)
	wsm.mutex.Unlock()
}

// BroadcastMessage broadcasts a message to all connected clients
// This delegates to ArchGuardian's broadcast system to prevent concurrent writes
func (wsm *WebSocketManager) BroadcastMessage(msgType string, data interface{}) {
	if wsm.archGuardian != nil {
		// Delegate to ArchGuardian's safe broadcast system
		wsm.archGuardian.BroadcastToDashboard(msgType, data)
	} else {
		// Fallback: write directly if ArchGuardian is not available
		// This should rarely happen, but provides a safety net
		wsm.mutex.RLock()
		connections := make([]*wsConnection, 0, len(wsm.connections))
		for _, wsConn := range wsm.connections {
			connections = append(connections, wsConn)
		}
		wsm.mutex.RUnlock()

		message := WSMessage{
			Type:      msgType,
			Timestamp: time.Now(),
			Data:      data,
		}

		for _, wsConn := range connections {
			wsm.sendMessage(wsConn, message)
		}
	}
}

// sendMessage sends a message to a specific connection
func (wsm *WebSocketManager) sendMessage(wsConn *wsConnection, message WSMessage) {
	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal WebSocket message: %v", err)
		return
	}

	if err := wsConn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("Failed to send WebSocket message: %v", err)
		// Remove broken connection
		wsm.mutex.Lock()
		delete(wsm.connections, wsConn.conn)
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
