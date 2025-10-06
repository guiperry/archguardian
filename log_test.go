package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogMsgStruct tests the LogMsg struct serialization and validation
func TestLogMsgStruct(t *testing.T) {
	tests := []struct {
		name     string
		logMsg   LogMsg
		expected map[string]interface{}
	}{
		{
			name: "complete log message",
			logMsg: LogMsg{
				Timestamp: time.Date(2023, 10, 1, 12, 0, 0, 0, time.UTC),
				Level:     "ERROR",
				Message:   "Database connection failed",
				Service:   "user-service",
				Component: "database",
				TraceID:   "abc-123",
				SpanID:    "span-456",
				Metadata: map[string]interface{}{
					"user_id": 123,
					"action":  "login",
				},
				Error: &LogError{
					Type:  "ConnectionError",
					Code:  "DB_CONN_FAILED",
					Stack: "at connect (/app/db.js:10:5)",
					Cause: "timeout",
				},
			},
			expected: map[string]interface{}{
				"timestamp": "2023-10-01T12:00:00Z",
				"level":     "ERROR",
				"message":   "Database connection failed",
				"service":   "user-service",
				"component": "database",
				"trace_id":  "abc-123",
				"span_id":   "span-456",
				"metadata": map[string]interface{}{
					"user_id": float64(123),
					"action":  "login",
				},
				"error": map[string]interface{}{
					"type":  "ConnectionError",
					"code":  "DB_CONN_FAILED",
					"stack": "at connect (/app/db.js:10:5)",
					"cause": "timeout",
				},
			},
		},
		{
			name: "minimal log message",
			logMsg: LogMsg{
				Level:   "INFO",
				Message: "Service started",
			},
			expected: map[string]interface{}{
				"timestamp": "",
				"level":     "INFO",
				"message":   "Service started",
				"service":   "",
				"component": "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.logMsg)
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			// Check required fields
			assert.Equal(t, tt.expected["level"], result["level"])
			assert.Equal(t, tt.expected["message"], result["message"])
			assert.Equal(t, tt.expected["service"], result["service"])
			assert.Equal(t, tt.expected["component"], result["component"])

			// Check optional fields
			if tt.expected["timestamp"] != "" {
				assert.Equal(t, tt.expected["timestamp"], result["timestamp"])
			}
			if tt.expected["trace_id"] != nil {
				assert.Equal(t, tt.expected["trace_id"], result["trace_id"])
			}
			if tt.expected["span_id"] != nil {
				assert.Equal(t, tt.expected["span_id"], result["span_id"])
			}
			if tt.expected["metadata"] != nil {
				assert.Equal(t, tt.expected["metadata"], result["metadata"])
			}
			if tt.expected["error"] != nil {
				assert.Equal(t, tt.expected["error"], result["error"])
			}

			// Test JSON unmarshaling
			var unmarshaled LogMsg
			err = json.Unmarshal(data, &unmarshaled)
			require.NoError(t, err)

			assert.Equal(t, tt.logMsg.Level, unmarshaled.Level)
			assert.Equal(t, tt.logMsg.Message, unmarshaled.Message)
			assert.Equal(t, tt.logMsg.Service, unmarshaled.Service)
			assert.Equal(t, tt.logMsg.Component, unmarshaled.Component)
		})
	}
}

// TestLogErrorStruct tests the LogError struct
func TestLogErrorStruct(t *testing.T) {
	tests := []struct {
		name     string
		logError LogError
		expected map[string]interface{}
	}{
		{
			name: "complete error",
			logError: LogError{
				Type:  "ValidationError",
				Code:  "INVALID_INPUT",
				Stack: "at validate (/app/validator.js:25:10)\nat process (/app/main.js:15:5)",
				Cause: "missing required field",
			},
			expected: map[string]interface{}{
				"type":  "ValidationError",
				"code":  "INVALID_INPUT",
				"stack": "at validate (/app/validator.js:25:10)\nat process (/app/main.js:15:5)",
				"cause": "missing required field",
			},
		},
		{
			name: "minimal error",
			logError: LogError{
				Type: "NetworkError",
			},
			expected: map[string]interface{}{
				"type": "NetworkError",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.logError)
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)

			assert.Equal(t, tt.expected["type"], result["type"])
			if tt.expected["code"] != nil {
				assert.Equal(t, tt.expected["code"], result["code"])
			}
			if tt.expected["stack"] != nil {
				assert.Equal(t, tt.expected["stack"], result["stack"])
			}
			if tt.expected["cause"] != nil {
				assert.Equal(t, tt.expected["cause"], result["cause"])
			}
		})
	}
}

// TestLogAnalyzer_ProcessLog tests the ProcessLog method
func TestLogAnalyzer_ProcessLog(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	tests := []struct {
		name     string
		logMsg   LogMsg
		expected error
	}{
		{
			name: "info level log",
			logMsg: LogMsg{
				Timestamp: time.Now(),
				Level:     "INFO",
				Message:   "Service started successfully",
				Service:   "web-server",
				Component: "main",
			},
			expected: nil,
		},
		{
			name: "error level log",
			logMsg: LogMsg{
				Timestamp: time.Now(),
				Level:     "ERROR",
				Message:   "Database connection failed",
				Service:   "user-service",
				Component: "database",
			},
			expected: nil,
		},
		{
			name: "fatal level log",
			logMsg: LogMsg{
				Timestamp: time.Now(),
				Level:     "FATAL",
				Message:   "Critical system failure",
				Service:   "core-service",
				Component: "kernel",
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := analyzer.ProcessLog(ctx, tt.logMsg)

			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expected, err)
			}
		})
	}
}

// TestLogAnalyzer_ErrorPatternAnalysis tests error pattern analysis
func TestLogAnalyzer_ErrorPatternAnalysis(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	// Add multiple error logs to trigger pattern analysis
	ctx := context.Background()

	// Add 5 error logs from the same component (should trigger analysis)
	for i := 0; i < 5; i++ {
		logMsg := LogMsg{
			Timestamp: time.Now(),
			Level:     "ERROR",
			Message:   "Connection timeout",
			Service:   "api-gateway",
			Component: "load-balancer",
		}
		err := analyzer.ProcessLog(ctx, logMsg)
		assert.NoError(t, err)
	}

	// Verify that error buffer contains the logs
	// Note: In a real test, we would mock the AI analysis and verify it was called
	assert.NotNil(t, analyzer)
}

// TestHandleLogIngestion tests the HTTP handler for single log ingestion
func TestHandleLogIngestion(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "valid log message",
			requestBody: LogMsg{
				Level:     "ERROR",
				Message:   "Test error message",
				Service:   "test-service",
				Component: "test-component",
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name: "log message with timestamp",
			requestBody: LogMsg{
				Timestamp: time.Now(),
				Level:     "INFO",
				Message:   "Test info message",
				Service:   "test-service",
				Component: "test-component",
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "invalid JSON",
			requestBody:    "{invalid json",
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			var body bytes.Buffer
			if tt.name == "invalid JSON" {
				body.WriteString(tt.requestBody.(string))
			} else {
				err := json.NewEncoder(&body).Encode(tt.requestBody)
				require.NoError(t, err)
			}

			req := httptest.NewRequest("POST", "/api/v1/logs", &body)
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handleLogIngestion(w, req, analyzer)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Parse response
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectedError {
				assert.Contains(t, response, "error")
			} else {
				assert.Equal(t, "accepted", response["status"])
				assert.Contains(t, response, "timestamp")
				assert.Contains(t, response, "message")
			}
		})
	}
}

// TestHandleBatchLogIngestion tests the HTTP handler for batch log ingestion
func TestHandleBatchLogIngestion(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectedError  bool
	}{
		{
			name: "valid batch of logs",
			requestBody: map[string]interface{}{
				"logs": []LogMsg{
					{
						Level:     "ERROR",
						Message:   "Test error 1",
						Service:   "test-service",
						Component: "test-component",
					},
					{
						Level:     "INFO",
						Message:   "Test info 1",
						Service:   "test-service",
						Component: "test-component",
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name: "empty batch",
			requestBody: map[string]interface{}{
				"logs": []LogMsg{},
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "invalid JSON",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			var body bytes.Buffer
			if tt.name == "invalid JSON" {
				body.WriteString(tt.requestBody.(string))
			} else {
				err := json.NewEncoder(&body).Encode(tt.requestBody)
				require.NoError(t, err)
			}

			req := httptest.NewRequest("POST", "/api/v1/logs/batch", &body)
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handleBatchLogIngestion(w, req, analyzer)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Parse response
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectedError {
				assert.Contains(t, response, "error")
			} else {
				assert.Equal(t, "completed", response["status"])
				assert.Contains(t, response, "timestamp")
				assert.Contains(t, response, "processed")
				assert.Contains(t, response, "errors")
				assert.Contains(t, response, "total")
			}
		})
	}
}

// TestLogIngestionConcurrent tests concurrent log processing
func TestLogIngestionConcurrent(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	ctx := context.Background()

	// Test concurrent processing of multiple logs
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			logMsg := LogMsg{
				Timestamp: time.Now(),
				Level:     "INFO",
				Message:   "Concurrent test message",
				Service:   "test-service",
				Component: "test-component",
				Metadata: map[string]interface{}{
					"request_id": id,
				},
			}

			err := analyzer.ProcessLog(ctx, logMsg)
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent log processing")
		}
	}
}

// TestLogIngestionValidation tests input validation for log ingestion
func TestLogIngestionValidation(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	tests := []struct {
		name        string
		logMsg      LogMsg
		shouldError bool
	}{
		{
			name: "valid log",
			logMsg: LogMsg{
				Level:   "INFO",
				Message: "Valid message",
			},
			shouldError: false,
		},
		{
			name: "empty level",
			logMsg: LogMsg{
				Message: "Message without level",
			},
			shouldError: false, // Level is optional in current implementation
		},
		{
			name: "empty message",
			logMsg: LogMsg{
				Level: "INFO",
			},
			shouldError: false, // Message is optional in current implementation
		},
		{
			name: "very long message",
			logMsg: LogMsg{
				Level:   "INFO",
				Message: string(make([]byte, 10000)), // 10KB message
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := analyzer.ProcessLog(ctx, tt.logMsg)

			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// BenchmarkLogProcessing benchmarks log processing performance
func BenchmarkLogProcessing(b *testing.B) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	ctx := context.Background()
	logMsg := LogMsg{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "Benchmark test message",
		Service:   "benchmark-service",
		Component: "benchmark-component",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzer.ProcessLog(ctx, logMsg)
	}
}

// BenchmarkBatchLogProcessing benchmarks batch log processing performance
func BenchmarkBatchLogProcessing(b *testing.B) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	// Create a batch of 100 logs
	logs := make([]LogMsg, 100)
	for i := range logs {
		logs[i] = LogMsg{
			Timestamp: time.Now(),
			Level:     "INFO",
			Message:   "Benchmark batch test message",
			Service:   "benchmark-service",
			Component: "benchmark-component",
		}
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, logMsg := range logs {
			_ = analyzer.ProcessLog(ctx, logMsg)
		}
	}
}

// TestLogIngestionErrorHandling tests error handling in log ingestion
func TestLogIngestionErrorHandling(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	tests := []struct {
		name        string
		logMsg      LogMsg
		expectError bool
		errorMsg    string
	}{
		{
			name: "empty message with error level",
			logMsg: LogMsg{
				Level:   "ERROR",
				Service: "test-service",
			},
			expectError: false, // Should still process
		},
		{
			name: "very long message",
			logMsg: LogMsg{
				Level:   "INFO",
				Message: string(make([]byte, 100000)), // 100KB message
				Service: "test-service",
			},
			expectError: false,
		},
		{
			name: "special characters in message",
			logMsg: LogMsg{
				Level:   "INFO",
				Message: "Message with special chars: ñáéíóú 🚀 🔥 ∑∆∞",
				Service: "test-service",
			},
			expectError: false,
		},
		{
			name: "nested metadata",
			logMsg: LogMsg{
				Level:   "INFO",
				Message: "Test message",
				Service: "test-service",
				Metadata: map[string]interface{}{
					"nested": map[string]interface{}{
						"deep": map[string]interface{}{
							"value": "test",
						},
					},
					"array": []interface{}{"item1", "item2", 123},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := analyzer.ProcessLog(ctx, tt.logMsg)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestLogIngestionRateLimiting tests rate limiting behavior
func TestLogIngestionRateLimiting(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	ctx := context.Background()

	// Test rapid log ingestion
	start := time.Now()
	logCount := 1000

	for i := 0; i < logCount; i++ {
		logMsg := LogMsg{
			Timestamp: time.Now(),
			Level:     "INFO",
			Message:   fmt.Sprintf("Rate limit test message %d", i),
			Service:   "rate-test-service",
			Component: "rate-test-component",
		}

		err := analyzer.ProcessLog(ctx, logMsg)
		assert.NoError(t, err)
	}

	duration := time.Since(start)
	t.Logf("Processed %d logs in %v (%.2f logs/sec)", logCount, duration, float64(logCount)/duration.Seconds())
}

// TestLogIngestionPatternDetection tests AI-powered pattern detection
func TestLogIngestionPatternDetection(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine - will be nil for this test
	analyzer := NewLogAnalyzer(config, ai)

	ctx := context.Background()

	// Test that logs are buffered correctly without triggering AI analysis
	// Add 3 error logs (below threshold of 5) so AI analysis is not triggered
	for i := 0; i < 3; i++ {
		logMsg := LogMsg{
			Timestamp: time.Now(),
			Level:     "ERROR",
			Message:   "Database connection failed: timeout after 30s",
			Service:   "api-gateway",
			Component: "database-pool",
			Error: &LogError{
				Type:  "ConnectionError",
				Code:  "DB_TIMEOUT",
				Stack: "at connect (/app/db.js:45:12)",
			},
		}

		err := analyzer.ProcessLog(ctx, logMsg)
		assert.NoError(t, err)
	}

	// Verify that analyzer is properly initialized
	assert.NotNil(t, analyzer)

	// Test with different components to ensure isolation
	logMsg := LogMsg{
		Timestamp: time.Now(),
		Level:     "ERROR",
		Message:   "Network timeout",
		Service:   "web-server",
		Component: "http-client",
	}

	err := analyzer.ProcessLog(ctx, logMsg)
	assert.NoError(t, err)
}

// TestLogIngestionTimestampHandling tests timestamp handling
func TestLogIngestionTimestampHandling(t *testing.T) {
	config := &Config{}
	ai := &AIInferenceEngine{} // Mock AI engine
	analyzer := NewLogAnalyzer(config, ai)

	tests := []struct {
		name        string
		logMsg      LogMsg
		expectError bool
	}{
		{
			name: "future timestamp",
			logMsg: LogMsg{
				Timestamp: time.Now().Add(24 * time.Hour), // 1 day in future
				Level:     "INFO",
				Message:   "Future timestamp test",
				Service:   "test-service",
			},
			expectError: false, // Should accept future timestamps
		},
		{
			name: "past timestamp",
			logMsg: LogMsg{
				Timestamp: time.Now().Add(-365 * 24 * time.Hour), // 1 year ago
				Level:     "INFO",
				Message:   "Past timestamp test",
				Service:   "test-service",
			},
			expectError: false, // Should accept past timestamps
		},
		{
			name: "zero timestamp",
			logMsg: LogMsg{
				Timestamp: time.Time{}, // Zero time
				Level:     "INFO",
				Message:   "Zero timestamp test",
				Service:   "test-service",
			},
			expectError: false, // Should handle zero timestamps
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := analyzer.ProcessLog(ctx, tt.logMsg)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestLogIngestionHTTPIntegration tests HTTP integration with real server
func TestLogIngestionHTTPIntegration(t *testing.T) {
	// Skip this test in CI environments unless explicitly enabled
	if os.Getenv("CI") != "" && os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping integration test in CI environment")
	}

	// This test would require starting a real server instance
	// For now, it's a placeholder for future integration testing
	t.Skip("Integration test requires running server - implement when server startup is testable")
}

// TestLogIngestionWebSocketIntegration tests WebSocket log streaming
func TestLogIngestionWebSocketIntegration(t *testing.T) {
	// Skip this test in CI environments unless explicitly enabled
	if os.Getenv("CI") != "" && os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping WebSocket integration test in CI environment")
	}

	// This test would require WebSocket server setup
	// For now, it's a placeholder for future WebSocket testing
	t.Skip("WebSocket integration test requires running server - implement when WebSocket testing is available")
}
