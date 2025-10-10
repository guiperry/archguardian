package server

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// Allow connections from localhost for development
			return true
		},
	}
)

// WebSocketManager manages WebSocket connections for the dashboard
type WebSocketManager struct {
	connections []*websocket.Conn
	mutex       sync.Mutex
	logBuffer   [][]byte
	bufferMutex sync.Mutex
}

// NewWebSocketManager creates a new WebSocket manager
func NewWebSocketManager() *WebSocketManager {
	return &WebSocketManager{
		connections: make([]*websocket.Conn, 0),
		logBuffer:   make([][]byte, 0, 100),
	}
}

// AddConnection adds a WebSocket connection
func (wsm *WebSocketManager) AddConnection(conn *websocket.Conn) {
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()
	wsm.connections = append(wsm.connections, conn)
	log.Printf("Dashboard client connected. Total clients: %d", len(wsm.connections))
}

// RemoveConnection removes a WebSocket connection
func (wsm *WebSocketManager) RemoveConnection(conn *websocket.Conn) {
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()

	for i, c := range wsm.connections {
		if c == conn {
			wsm.connections = append(wsm.connections[:i], wsm.connections[i+1:]...)
			log.Printf("Dashboard client disconnected. Total clients: %d", len(wsm.connections))
			break
		}
	}
}

// Broadcast sends a message to all connected clients
func (wsm *WebSocketManager) Broadcast(message string) {
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()

	for _, conn := range wsm.connections {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			log.Printf("Failed to send message to dashboard client: %v", err)
			// Remove broken connection asynchronously
			go wsm.RemoveConnection(conn)
		}
	}
}

// FlushInitialLogs sends buffered logs to a newly connected client
func (wsm *WebSocketManager) FlushInitialLogs(conn *websocket.Conn) {
	wsm.bufferMutex.Lock()
	defer wsm.bufferMutex.Unlock()

	for _, logEntry := range wsm.logBuffer {
		if err := conn.WriteMessage(websocket.TextMessage, logEntry); err != nil {
			log.Printf("Failed to flush initial logs: %v", err)
			return
		}
	}
	log.Printf("Flushed %d buffered log entries to new client", len(wsm.logBuffer))
}

// BufferLog adds a log entry to the buffer
func (wsm *WebSocketManager) BufferLog(logEntry []byte) {
	wsm.bufferMutex.Lock()
	defer wsm.bufferMutex.Unlock()

	wsm.logBuffer = append(wsm.logBuffer, logEntry)
	// Keep only the last 100 log entries
	if len(wsm.logBuffer) > 100 {
		wsm.logBuffer = wsm.logBuffer[len(wsm.logBuffer)-100:]
	}
}

// HandleConnection handles WebSocket connections for the dashboard
func (wsm *WebSocketManager) HandleConnection(w http.ResponseWriter, r *http.Request, guardian interface{}) {
	// Log the WebSocket connection attempt
	log.Printf("🔗 WebSocket connection attempt from %s", r.RemoteAddr)

	// Upgrade HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %s\n", err.Error())
		return
	}
	defer conn.Close()

	log.Println("✅ Dashboard WebSocket client connected successfully")

	// Register the connection
	wsm.AddConnection(conn)
	log.Printf("🔗 WebSocket connection registered")

	// Handle client messages
	for {
		// Read message
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %s\n", err.Error())
			}
			break
		}

		// Parse message
		var data map[string]interface{}
		err = json.Unmarshal(message, &data)
		if err != nil {
			log.Printf("Failed to parse message: %s\n", err.Error())
			continue
		}

		// Handle message
		msgType, ok := data["type"].(string)
		if !ok {
			continue
		}

		switch msgType {
		case "client_ready":
			// Client is ready to receive logs
			log.Println("📱 Dashboard WebSocket client ready - flushing initial logs")
			wsm.FlushInitialLogs(conn)
		case "ping":
			// Respond to ping with pong
			pongMsg := map[string]string{"type": "pong"}
			pongJSON, _ := json.Marshal(pongMsg)
			if err := conn.WriteMessage(websocket.TextMessage, pongJSON); err != nil {
				log.Printf("Failed to send pong: %v", err)
			}
		case "subscribe_logs":
			// Client wants to subscribe to log streaming
			log.Println("📋 Client subscribed to log streaming")
		case "unsubscribe_logs":
			// Client wants to unsubscribe from log streaming
			log.Println("📋 Client unsubscribed from log streaming")
		}
	}

	log.Println("❌ Dashboard WebSocket client disconnected")
	// Remove the connection when client disconnects
	wsm.RemoveConnection(conn)
}
