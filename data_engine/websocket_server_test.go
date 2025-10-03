package data_engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketServer(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a WebSocket upgrader
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		}

		// Upgrade HTTP connection to WebSocket
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade connection: %v", err)
			return
		}
		defer conn.Close()

		// Handle messages
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}

			// Parse message
			var data map[string]interface{}
			err = json.Unmarshal(message, &data)
			if err != nil {
				t.Fatalf("Failed to parse message: %v", err)
				return
			}

			// Check message type
			msgType, ok := data["type"].(string)
			if !ok {
				t.Fatalf("Invalid message type")
				return
			}

			// Handle ping message
			if msgType == "ping" {
				// Respond with pong
				err := conn.WriteJSON(map[string]interface{}{
					"type": "pong",
					"time": time.Now().Format(time.RFC3339),
				})
				if err != nil {
					t.Fatalf("Failed to send pong: %v", err)
					return
				}
			}
		}
	}))
	defer server.Close()

	// Create WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	defer conn.Close()

	// Send ping message
	err = conn.WriteJSON(map[string]interface{}{
		"type": "ping",
	})
	if err != nil {
		t.Fatalf("Failed to send ping: %v", err)
	}

	// Read pong message
	var response map[string]interface{}
	err = conn.ReadJSON(&response)
	if err != nil {
		t.Fatalf("Failed to read pong: %v", err)
	}

	// Check response type
	if response["type"] != "pong" {
		t.Fatalf("Expected pong, got %v", response["type"])
	}
}

func TestWebSocketServerWithDataEngine(t *testing.T) {
	// Create a data engine
	dataEngine := NewDataEngine(DataEngineConfig{
		KafkaBrokers:     []string{"localhost:9092"},
		KafkaClientID:    "test-client",
		ChromaDBURL:      "http://localhost:8000",
		ChromaCollection: "test-collection",
		EnableKafka:      false,
		EnableChromaDB:   false,
		EnableWebSocket:  true,
		EnableRESTAPI:    false,
		WebSocketPort:    8080,
		WindowSize:       5 * time.Minute,
		MetricsInterval:  1 * time.Second,
	})

	// Create a WebSocket server
	wsServer := NewWebSocketServer(WebSocketConfig{
		Port:            8080,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     true,
	}, dataEngine)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsServer.HandleWebSocket(w, r)
	}))
	defer server.Close()

	// Create WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	defer conn.Close()

	// Send ping message
	err = conn.WriteJSON(map[string]interface{}{
		"type": "ping",
	})
	if err != nil {
		t.Fatalf("Failed to send ping: %v", err)
	}

	// Set a timeout for reading the response
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a channel for the response
	responseChan := make(chan map[string]interface{}, 1)
	errorChan := make(chan error, 1)

	// Read response in a goroutine
	go func() {
		var response map[string]interface{}
		err := conn.ReadJSON(&response)
		if err != nil {
			errorChan <- err
			return
		}
		responseChan <- response
	}()

	// Wait for response or timeout
	select {
	case <-ctx.Done():
		t.Fatalf("Timeout waiting for response")
	case err := <-errorChan:
		t.Fatalf("Failed to read response: %v", err)
	case response := <-responseChan:
		// Check response type
		if response["type"] != "pong" {
			t.Fatalf("Expected pong, got %v", response["type"])
		}
	}
}
