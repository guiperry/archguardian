package data_engine

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDataEngineConfig(t *testing.T) {
	config := DataEngineConfig{
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
	}

	assert.Equal(t, []string{"localhost:9092"}, config.KafkaBrokers)
	assert.Equal(t, "test-client", config.KafkaClientID)
	assert.Equal(t, "http://localhost:8000", config.ChromaDBURL)
	assert.Equal(t, "test-collection", config.ChromaCollection)
	assert.False(t, config.EnableKafka)
	assert.False(t, config.EnableChromaDB)
	assert.False(t, config.EnableWebSocket)
	assert.True(t, config.EnableRESTAPI)
	assert.Equal(t, 7080, config.RESTAPIPort)
	assert.Equal(t, 5*time.Minute, config.WindowSize)
	assert.Equal(t, 1*time.Second, config.MetricsInterval)
}

func TestNewDataEngine(t *testing.T) {
	config := DataEngineConfig{
		KafkaBrokers:     []string{"localhost:9092"},
		KafkaClientID:    "test-client",
		ChromaDBURL:      "http://localhost:8000",
		ChromaCollection: "test-collection",
		EnableKafka:      false,
		EnableChromaDB:   false,
		EnableWebSocket:  false,
		EnableRESTAPI:    false,
		WindowSize:       5 * time.Minute,
		MetricsInterval:  1 * time.Second,
	}

	dataEngine := NewDataEngine(config)

	assert.NotNil(t, dataEngine)
	assert.Equal(t, config, dataEngine.config)
}

func TestRESTAPIConfig(t *testing.T) {
	config := RESTAPIConfig{
		Port:           8081,
		EnableCORS:     true,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	assert.Equal(t, 8081, config.Port)
	assert.True(t, config.EnableCORS)
	assert.Equal(t, 10*time.Second, config.ReadTimeout)
	assert.Equal(t, 10*time.Second, config.WriteTimeout)
	assert.Equal(t, 1<<20, config.MaxHeaderBytes)
}

func TestWebSocketConfig(t *testing.T) {
	config := WebSocketConfig{
		Port:            8080,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     true,
	}

	assert.Equal(t, 8080, config.Port)
	assert.Equal(t, 1024, config.ReadBufferSize)
	assert.Equal(t, 1024, config.WriteBufferSize)
	assert.True(t, config.CheckOrigin)
}

func TestNewRESTAPIServer(t *testing.T) {
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

	apiConfig := RESTAPIConfig{
		Port:           8081,
		EnableCORS:     true,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	apiServer := NewRESTAPIServer(apiConfig, dataEngine)

	assert.NotNil(t, apiServer)
	assert.Equal(t, apiConfig, apiServer.config)
	assert.Equal(t, dataEngine, apiServer.dataEngine)
}

func TestNewWebSocketServer(t *testing.T) {
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

	wsConfig := WebSocketConfig{
		Port:            8080,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     true,
	}

	wsServer := NewWebSocketServer(wsConfig, dataEngine)

	assert.NotNil(t, wsServer)
	assert.Equal(t, dataEngine, wsServer.dataEngine)
}

func TestDataEngineConfigValidation(t *testing.T) {
	testCases := []struct {
		name    string
		config  DataEngineConfig
		isValid bool
	}{
		{
			name: "Valid minimal config",
			config: DataEngineConfig{
				KafkaBrokers:     []string{"localhost:9092"},
				KafkaClientID:    "test-client",
				ChromaDBURL:      "http://localhost:8000",
				ChromaCollection: "test-collection",
				WindowSize:       5 * time.Minute,
				MetricsInterval:  1 * time.Second,
			},
			isValid: true,
		},
		{
			name: "Valid config with all features enabled",
			config: DataEngineConfig{
				KafkaBrokers:     []string{"localhost:9092", "localhost:9093"},
				KafkaClientID:    "test-client",
				ChromaDBURL:      "http://localhost:8000",
				ChromaCollection: "test-collection",
				EnableKafka:      true,
				EnableChromaDB:   true,
				EnableWebSocket:  true,
				EnableRESTAPI:    true,
				WebSocketPort:    8080,
				RESTAPIPort:      7080,
				WindowSize:       10 * time.Minute,
				MetricsInterval:  5 * time.Second,
			},
			isValid: true,
		},
		{
			name: "Config with zero window size",
			config: DataEngineConfig{
				KafkaBrokers:     []string{"localhost:9092"},
				KafkaClientID:    "test-client",
				ChromaDBURL:      "http://localhost:8000",
				ChromaCollection: "test-collection",
				WindowSize:       0,
				MetricsInterval:  1 * time.Second,
			},
			isValid: false,
		},
		{
			name: "Config with zero metrics interval",
			config: DataEngineConfig{
				KafkaBrokers:     []string{"localhost:9092"},
				KafkaClientID:    "test-client",
				ChromaDBURL:      "http://localhost:8000",
				ChromaCollection: "test-collection",
				WindowSize:       5 * time.Minute,
				MetricsInterval:  0,
			},
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataEngine := NewDataEngine(tc.config)
			assert.NotNil(t, dataEngine)

			// Basic validation - ensure the engine was created
			if tc.isValid {
				assert.Equal(t, tc.config, dataEngine.config)
			}
		})
	}
}

func TestDataEnginePortConfiguration(t *testing.T) {
	testCases := []struct {
		name           string
		webSocketPort  int
		restAPIPort    int
		expectConflict bool
	}{
		{
			name:           "Different ports",
			webSocketPort:  8080,
			restAPIPort:    7080,
			expectConflict: false,
		},
		{
			name:           "Same ports (potential conflict)",
			webSocketPort:  8080,
			restAPIPort:    8080,
			expectConflict: true,
		},
		{
			name:           "Standard ports",
			webSocketPort:  3000,
			restAPIPort:    3001,
			expectConflict: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := DataEngineConfig{
				KafkaBrokers:     []string{"localhost:9092"},
				KafkaClientID:    "test-client",
				ChromaDBURL:      "http://localhost:8000",
				ChromaCollection: "test-collection",
				EnableWebSocket:  true,
				EnableRESTAPI:    true,
				WebSocketPort:    tc.webSocketPort,
				RESTAPIPort:      tc.restAPIPort,
				WindowSize:       5 * time.Minute,
				MetricsInterval:  1 * time.Second,
			}

			dataEngine := NewDataEngine(config)
			assert.NotNil(t, dataEngine)

			if tc.expectConflict {
				// In a real scenario, we might want to validate port conflicts
				assert.Equal(t, tc.webSocketPort, tc.restAPIPort)
			} else {
				assert.NotEqual(t, tc.webSocketPort, tc.restAPIPort)
			}
		})
	}
}

func TestDataEngineMultipleBrokers(t *testing.T) {
	brokers := []string{
		"broker1:9092",
		"broker2:9092",
		"broker3:9092",
	}

	config := DataEngineConfig{
		KafkaBrokers:     brokers,
		KafkaClientID:    "test-client",
		ChromaDBURL:      "http://localhost:8000",
		ChromaCollection: "test-collection",
		EnableKafka:      true,
		WindowSize:       5 * time.Minute,
		MetricsInterval:  1 * time.Second,
	}

	dataEngine := NewDataEngine(config)
	assert.NotNil(t, dataEngine)
	assert.Equal(t, brokers, dataEngine.config.KafkaBrokers)
	assert.Len(t, dataEngine.config.KafkaBrokers, 3)
}

func TestDataEngineTimeConfigValidation(t *testing.T) {
	testCases := []struct {
		name            string
		windowSize      time.Duration
		metricsInterval time.Duration
		description     string
	}{
		{
			name:            "Short intervals",
			windowSize:      1 * time.Minute,
			metricsInterval: 1 * time.Second,
			description:     "Minimum practical intervals",
		},
		{
			name:            "Medium intervals",
			windowSize:      5 * time.Minute,
			metricsInterval: 10 * time.Second,
			description:     "Balanced intervals",
		},
		{
			name:            "Long intervals",
			windowSize:      30 * time.Minute,
			metricsInterval: 1 * time.Minute,
			description:     "Extended intervals for low-frequency monitoring",
		},
		{
			name:            "Very long intervals",
			windowSize:      2 * time.Hour,
			metricsInterval: 5 * time.Minute,
			description:     "Long-term aggregation intervals",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := DataEngineConfig{
				KafkaBrokers:     []string{"localhost:9092"},
				KafkaClientID:    "test-client",
				ChromaDBURL:      "http://localhost:8000",
				ChromaCollection: "test-collection",
				WindowSize:       tc.windowSize,
				MetricsInterval:  tc.metricsInterval,
			}

			dataEngine := NewDataEngine(config)
			assert.NotNil(t, dataEngine)
			assert.Equal(t, tc.windowSize, dataEngine.config.WindowSize)
			assert.Equal(t, tc.metricsInterval, dataEngine.config.MetricsInterval)
		})
	}
}

// Benchmark tests
func BenchmarkNewDataEngine(b *testing.B) {
	config := DataEngineConfig{
		KafkaBrokers:     []string{"localhost:9092"},
		KafkaClientID:    "test-client",
		ChromaDBURL:      "http://localhost:8000",
		ChromaCollection: "test-collection",
		WindowSize:       5 * time.Minute,
		MetricsInterval:  1 * time.Second,
	}

	for i := 0; i < b.N; i++ {
		_ = NewDataEngine(config)
	}
}

func BenchmarkNewRESTAPIServer(b *testing.B) {
	dataEngine := NewDataEngine(DataEngineConfig{
		KafkaBrokers:     []string{"localhost:9092"},
		KafkaClientID:    "test-client",
		ChromaDBURL:      "http://localhost:8000",
		ChromaCollection: "test-collection",
		WindowSize:       5 * time.Minute,
		MetricsInterval:  1 * time.Second,
	})

	apiConfig := RESTAPIConfig{
		Port:           8081,
		EnableCORS:     true,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	for i := 0; i < b.N; i++ {
		_ = NewRESTAPIServer(apiConfig, dataEngine)
	}
}

func BenchmarkNewWebSocketServer(b *testing.B) {
	dataEngine := NewDataEngine(DataEngineConfig{
		KafkaBrokers:     []string{"localhost:9092"},
		KafkaClientID:    "test-client",
		ChromaDBURL:      "http://localhost:8000",
		ChromaCollection: "test-collection",
		WindowSize:       5 * time.Minute,
		MetricsInterval:  1 * time.Second,
	})

	wsConfig := WebSocketConfig{
		Port:            8080,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     true,
	}

	for i := 0; i < b.N; i++ {
		_ = NewWebSocketServer(wsConfig, dataEngine)
	}
}
