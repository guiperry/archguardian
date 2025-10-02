package data_engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRESTAPIServer(t *testing.T) {
	// Create a data engine
	dataEngine := NewDataEngine(DataEngineConfig{
		KafkaBrokers:     []string{"localhost:9092"},
		KafkaClientID:    "test-client",
		ChromaDBURL:      "http://localhost:8000",
		ChromaCollection: "test-collection",
		EnableKafka:      false,
		EnableChromaDB:   false,
		EnableWebSocket:  false,
		EnableRESTAPI:    true,
		RESTAPIPort:      7080,
		WindowSize:       5 * time.Minute,
		MetricsInterval:  1 * time.Second,
	})

	// Create a REST API server
	apiServer := NewRESTAPIServer(RESTAPIConfig{
		Port:           8081,
		EnableCORS:     true,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}, dataEngine)

	// Set up routes
	apiServer.setupRoutes()

	// Test health endpoint
	t.Run("TestHealthEndpoint", func(t *testing.T) {
		// Create a request
		req, err := http.NewRequest("GET", "/api/v1/health", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Create a response recorder
		rr := httptest.NewRecorder()

		// Handle the request
		handler := http.HandlerFunc(apiServer.handleHealth)
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Check content type
		contentType := rr.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Handler returned wrong content type: got %v want %v", contentType, "application/json")
		}

		// Parse response
		var response map[string]interface{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		// Check response fields
		if response["status"] != "ok" {
			t.Errorf("Handler returned wrong status: got %v want %v", response["status"], "ok")
		}

		if response["service"] != "rest-api" {
			t.Errorf("Handler returned wrong service: got %v want %v", response["service"], "rest-api")
		}

		if _, ok := response["timestamp"]; !ok {
			t.Errorf("Handler did not return timestamp")
		}
	})

	// Test metrics endpoint
	t.Run("TestMetricsEndpoint", func(t *testing.T) {
		// Create a request
		req, err := http.NewRequest("GET", "/api/v1/metrics", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Create a response recorder
		rr := httptest.NewRecorder()

		// Handle the request
		handler := http.HandlerFunc(apiServer.handleGetMetrics)
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusServiceUnavailable {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusServiceUnavailable)
		}
	})

	// Test alerts endpoint
	t.Run("TestAlertsEndpoint", func(t *testing.T) {
		// Create a request
		req, err := http.NewRequest("GET", "/api/v1/alerts", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Create a response recorder
		rr := httptest.NewRecorder()

		// Handle the request
		handler := http.HandlerFunc(apiServer.handleGetAlerts)
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusServiceUnavailable {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusServiceUnavailable)
		}
	})

	// Test event types endpoint
	t.Run("TestEventTypesEndpoint", func(t *testing.T) {
		// Create a request
		req, err := http.NewRequest("GET", "/api/v1/events/types", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Create a response recorder
		rr := httptest.NewRecorder()

		// Handle the request
		handler := http.HandlerFunc(apiServer.handleGetEventTypes)
		handler.ServeHTTP(rr, req)

		// Check status code
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		// Check content type
		contentType := rr.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Handler returned wrong content type: got %v want %v", contentType, "application/json")
		}

		// Parse response
		var response []string
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		// Check response
		if len(response) == 0 {
			t.Errorf("Handler returned empty event types")
		}
	})
}
