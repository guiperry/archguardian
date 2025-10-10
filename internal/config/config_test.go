package config

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/philippgille/chromem-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper types that implement required interfaces
type testValidator struct{}

func (tv *testValidator) Validate(settings *Config) error {
	return nil
}

type testListener struct{}

func (tl *testListener) OnSettingsChanged(oldSettings, newSettings *Config) {}

func TestDefaultSettingsValidator_Validate(t *testing.T) {
	validator := &DefaultSettingsValidator{}

	testCases := []struct {
		name        string
		settings    *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid settings",
			settings: &Config{
				ProjectPath:  "/valid/path",
				ScanInterval: time.Hour,
				AIProviders: AIProviderConfig{
					Anthropic: ProviderCredentials{
						APIKey: "test-key",
					},
					CodeRemediationProvider: "anthropic",
				},
			},
			expectError: false,
		},
		{
			name: "Missing project path",
			settings: &Config{
				ScanInterval: time.Hour,
				AIProviders: AIProviderConfig{
					Anthropic: ProviderCredentials{
						APIKey: "test-key",
					},
					CodeRemediationProvider: "anthropic",
				},
			},
			expectError: true,
			errorMsg:    "project_path is required",
		},
		{
			name: "Scan interval too short",
			settings: &Config{
				ProjectPath:  "/valid/path",
				ScanInterval: 30 * time.Second,
				AIProviders: AIProviderConfig{
					Anthropic: ProviderCredentials{
						APIKey: "test-key",
					},
					CodeRemediationProvider: "anthropic",
				},
			},
			expectError: true,
			errorMsg:    "scan_interval must be at least 1 minute",
		},
		{
			name: "Scan interval too long",
			settings: &Config{
				ProjectPath:  "/valid/path",
				ScanInterval: 25 * time.Hour,
				AIProviders: AIProviderConfig{
					Anthropic: ProviderCredentials{
						APIKey: "test-key",
					},
					CodeRemediationProvider: "anthropic",
				},
			},
			expectError: true,
			errorMsg:    "scan_interval cannot exceed 24 hours",
		},
		{
			name: "No AI provider API keys",
			settings: &Config{
				ProjectPath:  "/valid/path",
				ScanInterval: time.Hour,
				AIProviders: AIProviderConfig{
					CodeRemediationProvider: "anthropic",
				},
			},
			expectError: true,
			errorMsg:    "at least one AI provider API key must be configured",
		},
		{
			name: "Invalid code remediation provider",
			settings: &Config{
				ProjectPath:  "/valid/path",
				ScanInterval: time.Hour,
				AIProviders: AIProviderConfig{
					Anthropic: ProviderCredentials{
						APIKey: "test-key",
					},
					CodeRemediationProvider: "invalid-provider",
				},
			},
			expectError: true,
			errorMsg:    "invalid code_remediation_provider: invalid-provider",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.Validate(tc.settings)

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewSettingsManager(t *testing.T) {
	// Create a temporary in-memory ChromaDB instance
	db := chromem.NewDB()

	sm := NewSettingsManager(db)

	assert.NotNil(t, sm)
	assert.NotNil(t, sm.db)
	assert.NotNil(t, sm.settings)
	assert.Len(t, sm.validators, 1) // Should have default validator
	assert.Empty(t, sm.listeners)
}

func TestSettingsManager_AddValidator(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	validator := &testValidator{}
	sm.AddValidator(validator)

	assert.Len(t, sm.validators, 2) // Default + custom
}

func TestSettingsManager_AddChangeListener(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	listener := &testListener{}
	sm.AddChangeListener(listener)

	assert.Len(t, sm.listeners, 1)
}

func TestSettingsManager_GetSettings(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	settings := sm.GetSettings()
	assert.NotNil(t, settings)

	// Verify it's a copy (changing it shouldn't affect the original)
	originalPath := settings.ProjectPath
	settings.ProjectPath = "modified"

	newSettings := sm.GetSettings()
	assert.Equal(t, originalPath, newSettings.ProjectPath)
	assert.NotEqual(t, "modified", newSettings.ProjectPath)
}

func TestSettingsManager_UpdateSettings(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	// Create valid settings
	newSettings := &Config{
		ProjectPath:  "/new/path",
		GitHubToken:  "new-token",
		ScanInterval: 2 * time.Hour,
		AIProviders: AIProviderConfig{
			Anthropic: ProviderCredentials{
				APIKey: "test-key",
			},
			CodeRemediationProvider: "anthropic",
		},
		DataEngine: DataEngineConfig{
			Enable: true,
		},
	}

	err := sm.UpdateSettings(newSettings)
	assert.NoError(t, err)

	// Verify settings were updated
	updated := sm.GetSettings()
	assert.Equal(t, "/new/path", updated.ProjectPath)
	assert.Equal(t, "new-token", updated.GitHubToken)
	assert.Equal(t, 2*time.Hour, updated.ScanInterval)
}

func TestSettingsManager_UpdateSettings_ValidationFailure(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	// Create invalid settings (missing project path)
	invalidSettings := &Config{
		ScanInterval: time.Hour,
		AIProviders: AIProviderConfig{
			Anthropic: ProviderCredentials{
				APIKey: "test-key",
			},
			CodeRemediationProvider: "anthropic",
		},
	}

	err := sm.UpdateSettings(invalidSettings)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
	assert.Contains(t, err.Error(), "project_path is required")
}

func TestSettingsManager_SaveToFile(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "settings_test_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Save settings to file
	err = sm.SaveToFile(tmpFile.Name())
	assert.NoError(t, err)

	// Verify file was created and contains valid JSON
	data, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)

	var settings Config
	err = json.Unmarshal(data, &settings)
	assert.NoError(t, err)
}

func TestSettingsManager_LoadFromFile(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	// Create test settings
	testSettings := &Config{
		ProjectPath:  "/test/path",
		GitHubToken:  "test-token",
		ScanInterval: 3 * time.Hour,
		AIProviders: AIProviderConfig{
			Anthropic: ProviderCredentials{
				APIKey: "test-key",
			},
			CodeRemediationProvider: "anthropic",
		},
		DataEngine: DataEngineConfig{
			Enable: true,
		},
	}

	// Create a temporary file with test settings
	tmpFile, err := os.CreateTemp("", "settings_test_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	data, err := json.MarshalIndent(testSettings, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(tmpFile.Name(), data, 0644)
	require.NoError(t, err)

	// Load settings from file
	err = sm.LoadFromFile(tmpFile.Name())
	assert.NoError(t, err)

	// Verify settings were loaded
	loaded := sm.GetSettings()
	assert.Equal(t, "/test/path", loaded.ProjectPath)
	assert.Equal(t, "test-token", loaded.GitHubToken)
	assert.Equal(t, 3*time.Hour, loaded.ScanInterval)
}

func TestSettingsManager_LoadFromFile_InvalidJSON(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	// Create a temporary file with invalid JSON
	tmpFile, err := os.CreateTemp("", "settings_test_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	invalidJSON := `{"invalid": json content`
	err = os.WriteFile(tmpFile.Name(), []byte(invalidJSON), 0644)
	require.NoError(t, err)

	// Try to load invalid JSON
	err = sm.LoadFromFile(tmpFile.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse settings file")
}

func TestSettingsManager_LoadFromFile_ValidationFailure(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	// Create a file with invalid settings
	invalidSettings := map[string]interface{}{
		"project_path":  "", // Invalid: empty path
		"scan_interval": "1h",
	}

	tmpFile, err := os.CreateTemp("", "settings_test_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	data, err := json.MarshalIndent(invalidSettings, "", "  ")
	require.NoError(t, err)

	err = os.WriteFile(tmpFile.Name(), data, 0644)
	require.NoError(t, err)

	// Try to load invalid settings
	err = sm.LoadFromFile(tmpFile.Name())
	assert.Error(t, err)
}

func TestSettingsManager_GetDefaultSettings(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	defaults := sm.GetDefaultSettings()

	assert.NotNil(t, defaults)
	assert.NotEmpty(t, defaults.ProjectPath)
	assert.True(t, defaults.ScanInterval > 0)
	assert.NotEmpty(t, defaults.RemediationBranch)
	assert.NotNil(t, defaults.AIProviders)
	assert.NotNil(t, defaults.Orchestrator)
	assert.NotNil(t, defaults.DataEngine)
}

func TestAIProviderConfig(t *testing.T) {
	config := AIProviderConfig{
		Cerebras: ProviderCredentials{
			APIKey:   "cerebras-key",
			Endpoint: "https://api.cerebras.ai",
			Model:    "llama3.3-70b",
		},
		Gemini: ProviderCredentials{
			APIKey:   "gemini-key",
			Endpoint: "https://generativelanguage.googleapis.com",
			Model:    "gemini-pro",
		},
		Anthropic: ProviderCredentials{
			APIKey:   "anthropic-key",
			Endpoint: "https://api.anthropic.com",
			Model:    "claude-3-sonnet",
		},
		CodeRemediationProvider: "anthropic",
	}

	// Test serialization
	data, err := json.Marshal(config)
	assert.NoError(t, err)

	var unmarshaled AIProviderConfig
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, config.Cerebras.APIKey, unmarshaled.Cerebras.APIKey)
	assert.Equal(t, config.Gemini.Model, unmarshaled.Gemini.Model)
	assert.Equal(t, config.CodeRemediationProvider, unmarshaled.CodeRemediationProvider)
}

func TestOrchestratorConfig(t *testing.T) {
	config := OrchestratorConfig{
		PlannerModel:   "gemini-pro",
		ExecutorModels: []string{"llama3.3-70b"},
		FinalizerModel: "deepseek-coder",
		VerifierModel:  "gemini-pro",
	}

	// Test serialization
	data, err := json.Marshal(config)
	assert.NoError(t, err)

	var unmarshaled OrchestratorConfig
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, config.PlannerModel, unmarshaled.PlannerModel)
	assert.Equal(t, config.ExecutorModels, unmarshaled.ExecutorModels)
	assert.Equal(t, config.FinalizerModel, unmarshaled.FinalizerModel)
	assert.Equal(t, config.VerifierModel, unmarshaled.VerifierModel)
}

func TestDataEngineConfig(t *testing.T) {
	config := DataEngineConfig{
		Enable:           true,
		EnableKafka:      false,
		EnableChromaDB:   true,
		EnableWebSocket:  true,
		EnableRESTAPI:    true,
		KafkaBrokers:     []string{"localhost:9092", "localhost:9093"},
		ChromaDBURL:      "http://localhost:8000",
		ChromaCollection: "test_collection",
		WebSocketPort:    8080,
		RESTAPIPort:      7080,
	}

	// Test serialization
	data, err := json.Marshal(config)
	assert.NoError(t, err)

	var unmarshaled DataEngineConfig
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, config.Enable, unmarshaled.Enable)
	assert.Equal(t, config.KafkaBrokers, unmarshaled.KafkaBrokers)
	assert.Equal(t, config.ChromaDBURL, unmarshaled.ChromaDBURL)
	assert.Equal(t, config.WebSocketPort, unmarshaled.WebSocketPort)
}

func TestConfig_FullSerialization(t *testing.T) {
	config := &Config{
		ProjectPath:       "/test/project",
		GitHubToken:       "github-token",
		GitHubRepo:        "user/repo",
		ScanInterval:      time.Hour,
		RemediationBranch: "archguardian-fixes",
		AIProviders: AIProviderConfig{
			Cerebras: ProviderCredentials{
				APIKey:   "cerebras-key",
				Endpoint: "https://api.cerebras.ai",
				Model:    "llama3.3-70b",
			},
			CodeRemediationProvider: "anthropic",
		},
		Orchestrator: OrchestratorConfig{
			PlannerModel:   "gemini-pro",
			ExecutorModels: []string{"llama3.3-70b"},
			FinalizerModel: "deepseek-coder",
			VerifierModel:  "gemini-pro",
		},
		DataEngine: DataEngineConfig{
			Enable:         true,
			EnableKafka:    false,
			EnableChromaDB: true,
			WebSocketPort:  8080,
			RESTAPIPort:    7080,
		},
	}

	// Test full serialization/deserialization
	data, err := json.Marshal(config)
	assert.NoError(t, err)

	var unmarshaled Config
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, config.ProjectPath, unmarshaled.ProjectPath)
	assert.Equal(t, config.GitHubToken, unmarshaled.GitHubToken)
	assert.Equal(t, config.ScanInterval, unmarshaled.ScanInterval)
	assert.Equal(t, config.AIProviders.CodeRemediationProvider, unmarshaled.AIProviders.CodeRemediationProvider)
	assert.Equal(t, config.DataEngine.WebSocketPort, unmarshaled.DataEngine.WebSocketPort)
}

// Test concurrent access to settings manager
func TestSettingsManager_ConcurrentAccess(t *testing.T) {
	db := chromem.NewDB()
	sm := NewSettingsManager(db)

	const numGoroutines = 10
	const numOperations = 50

	done := make(chan bool, numGoroutines)

	// Test concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < numOperations; j++ {
				settings := sm.GetSettings()
				assert.NotNil(t, settings)
			}
			done <- true
		}()
	}

	// Wait for all read goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Test concurrent writes (with valid settings)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			newSettings := &Config{
				ProjectPath:  fmt.Sprintf("/test/path/%d", id),
				ScanInterval: time.Hour,
				AIProviders: AIProviderConfig{
					Anthropic: ProviderCredentials{
						APIKey: "test-key",
					},
					CodeRemediationProvider: "anthropic",
				},
			}
			sm.UpdateSettings(newSettings) // May succeed or fail due to concurrency
			done <- true
		}(i)
	}

	// Wait for all write goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}
