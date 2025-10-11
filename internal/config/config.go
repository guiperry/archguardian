package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/philippgille/chromem-go"
)

// Config represents the main application configuration
type Config struct {
	ProjectPath       string             `json:"project_path"`
	GitHubToken       string             `json:"github_token"`
	GitHubRepo        string             `json:"github_repo"`
	AIProviders       AIProviderConfig   `json:"ai_providers"`
	Orchestrator      OrchestratorConfig `json:"orchestrator"`
	DataEngine        DataEngineConfig   `json:"data_engine"`
	ScanInterval      time.Duration      `json:"scan_interval"`
	RemediationBranch string             `json:"remediation_branch"`
	ServerPort        int                `json:"server_port"`
}

// AIProviderConfig defines the configuration for AI providers
type AIProviderConfig struct {
	Cerebras  ProviderCredentials `json:"cerebras"`
	Gemini    ProviderCredentials `json:"gemini"`
	Anthropic ProviderCredentials `json:"anthropic"`
	OpenAI    ProviderCredentials `json:"openai"`
	DeepSeek  ProviderCredentials `json:"deepseek"`
	Embedding ProviderCredentials `json:"embedding"`

	CodeRemediationProvider string `json:"code_remediation_provider"`
}

// OrchestratorConfig defines the models used for each role in the task orchestrator
type OrchestratorConfig struct {
	PlannerModel   string   `json:"planner_model"`
	ExecutorModels []string `json:"executor_models"`
	FinalizerModel string   `json:"finalizer_model"`
	VerifierModel  string   `json:"verifier_model"`
}

// ProviderCredentials represents credentials for an AI provider
type ProviderCredentials struct {
	APIKey   string `json:"api_key"`
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
}

// DataEngineConfig represents configuration for the data engine
type DataEngineConfig struct {
	Enable           bool     `json:"enable"`
	EnableKafka      bool     `json:"enable_kafka"`
	EnableChromaDB   bool     `json:"enable_chromadb"`
	EnableWebSocket  bool     `json:"enable_websocket"`
	EnableRESTAPI    bool     `json:"enable_restapi"`
	KafkaBrokers     []string `json:"kafka_brokers"`
	ChromaDBURL      string   `json:"chromadb_url"`
	ChromaCollection string   `json:"chromadb_collection"`
	WebSocketPort    int      `json:"websocket_port"`
	RESTAPIPort      int      `json:"restapi_port"`
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		ProjectPath:       getEnv("PROJECT_PATH", "."),
		GitHubToken:       getEnv("GITHUB_TOKEN", ""),
		GitHubRepo:        getEnv("GITHUB_REPO", ""),
		ScanInterval:      time.Duration(getEnvInt("SCAN_INTERVAL_HOURS", 24)) * time.Hour,
		RemediationBranch: getEnv("REMEDIATION_BRANCH", "archguardian-fixes"),
		ServerPort:        getEnvInt("SERVER_PORT", 8080),
		AIProviders: AIProviderConfig{
			Cerebras: ProviderCredentials{
				APIKey:   getEnv("CEREBRAS_API_KEY", ""),
				Endpoint: getEnv("CEREBRAS_ENDPOINT", "https://api.cerebras.ai/v1"),
				Model:    getEnv("CEREBRAS_MODEL", "llama3.3-70b"),
			},
			Gemini: ProviderCredentials{
				APIKey:   getEnv("GEMINI_API_KEY", ""),
				Endpoint: getEnv("GEMINI_ENDPOINT", "https://generativelanguage.googleapis.com/v1"),
				Model:    getEnv("GEMINI_MODEL", "gemini-pro"),
			},
			Anthropic: ProviderCredentials{
				APIKey:   getEnv("ANTHROPIC_API_KEY", ""),
				Endpoint: getEnv("ANTHROPIC_ENDPOINT", "https://api.anthropic.com/v1"),
				Model:    getEnv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929"),
			},
			OpenAI: ProviderCredentials{
				APIKey:   getEnv("OPENAI_API_KEY", ""),
				Endpoint: getEnv("OPENAI_ENDPOINT", "https://api.openai.com/v1"),
				Model:    getEnv("OPENAI_MODEL", "gpt-4"),
			},
			DeepSeek: ProviderCredentials{
				APIKey:   getEnv("DEEPSEEK_API_KEY", ""),
				Endpoint: getEnv("DEEPSEEK_ENDPOINT", "https://api.deepseek.com/v1"),
				Model:    getEnv("DEEPSEEK_MODEL", "deepseek-coder"),
			},
			Embedding: ProviderCredentials{
				APIKey:   getEnv("EMBEDDING_API_KEY", ""),
				Endpoint: getEnv("EMBEDDING_ENDPOINT", "https://embeddings.knirv.com"),
			},
			CodeRemediationProvider: getEnv("CODE_REMEDIATION_PROVIDER", "anthropic"),
		},
		Orchestrator: OrchestratorConfig{
			PlannerModel:   getEnv("ORCHESTRATOR_PLANNER_MODEL", "gemini-pro"),
			ExecutorModels: strings.Split(getEnv("ORCHESTRATOR_EXECUTOR_MODELS", "llama3.3-70b"), ","),
			FinalizerModel: getEnv("ORCHESTRATOR_FINALIZER_MODEL", "deepseek-chat"),
			VerifierModel:  getEnv("ORCHESTRATOR_VERIFIER_MODEL", "gemini-pro"),
		},
		DataEngine: DataEngineConfig{
			Enable:           getEnvBool("DATA_ENGINE_ENABLE", true),
			EnableKafka:      getEnvBool("KAFKA_ENABLE", false),
			EnableChromaDB:   getEnvBool("CHROMADB_ENABLE", true),
			EnableWebSocket:  getEnvBool("WEBSOCKET_ENABLE", true),
			EnableRESTAPI:    getEnvBool("RESTAPI_ENABLE", true),
			KafkaBrokers:     strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ","),
			ChromaDBURL:      getEnv("CHROMADB_URL", "http://localhost:8000"),
			ChromaCollection: getEnv("CHROMADB_COLLECTION", "archguardian_events"),
			WebSocketPort:    getEnvInt("WEBSOCKET_PORT", 8080),
			RESTAPIPort:      getEnvInt("RESTAPI_PORT", 7080),
		},
	}
}

// getEnv retrieves environment variable with fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool retrieves boolean environment variable with fallback
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

// getEnvInt retrieves integer environment variable with fallback
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// SettingsValidator defines the interface for validating settings
type SettingsValidator interface {
	Validate(settings *Config) error
}

// SettingsChangeListener defines the interface for listening to settings changes
type SettingsChangeListener interface {
	OnSettingsChanged(oldSettings, newSettings *Config)
}

// SettingsManager manages application settings with validation and persistence
type SettingsManager struct {
	db        *chromem.DB
	settings  *Config
	validators []SettingsValidator
	listeners  []SettingsChangeListener
	mutex     sync.RWMutex
}

// DefaultSettingsValidator provides default validation for settings
type DefaultSettingsValidator struct{}

// Validate validates the configuration settings
func (v *DefaultSettingsValidator) Validate(settings *Config) error {
	if settings.ProjectPath == "" {
		return fmt.Errorf("project_path is required")
	}

	if settings.ScanInterval < time.Minute {
		return fmt.Errorf("scan_interval must be at least 1 minute")
	}

	if settings.ScanInterval > 24*time.Hour {
		return fmt.Errorf("scan_interval cannot exceed 24 hours")
	}

	// Check if at least one AI provider has an API key
	hasAPIKey := settings.AIProviders.Anthropic.APIKey != "" ||
		settings.AIProviders.OpenAI.APIKey != "" ||
		settings.AIProviders.Gemini.APIKey != "" ||
		settings.AIProviders.Cerebras.APIKey != "" ||
		settings.AIProviders.DeepSeek.APIKey != ""

	if !hasAPIKey {
		return fmt.Errorf("at least one AI provider API key must be configured")
	}

	// Validate code remediation provider
	validProviders := map[string]bool{
		"anthropic": true,
		"openai":    true,
		"gemini":    true,
		"cerebras":  true,
		"deepseek":  true,
	}

	if !validProviders[settings.AIProviders.CodeRemediationProvider] {
		return fmt.Errorf("invalid code_remediation_provider: %s", settings.AIProviders.CodeRemediationProvider)
	}

	return nil
}

// NewSettingsManager creates a new settings manager
func NewSettingsManager(db *chromem.DB) *SettingsManager {
	defaultSettings := getDefaultSettings()
	sm := &SettingsManager{
		db:         db,
		settings:   defaultSettings,
		validators: []SettingsValidator{&DefaultSettingsValidator{}},
		listeners:  make([]SettingsChangeListener, 0),
	}

	return sm
}

// GetDefaultSettings returns default configuration settings
func (sm *SettingsManager) GetDefaultSettings() *Config {
	return getDefaultSettings()
}

// getDefaultSettings returns default configuration settings
func getDefaultSettings() *Config {
	return &Config{
		ProjectPath:       ".",
		ScanInterval:      time.Hour,
		RemediationBranch: "archguardian-fixes",
		ServerPort:        8080,
		AIProviders: AIProviderConfig{
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
			EnableChromaDB: true,
			EnableWebSocket: true,
			EnableRESTAPI:  true,
			WebSocketPort:  8080,
			RESTAPIPort:    7080,
		},
	}
}

// GetSettings returns a copy of the current settings
func (sm *SettingsManager) GetSettings() *Config {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Return a deep copy to prevent external modifications
	settingsCopy, _ := json.Marshal(sm.settings)
	var copy Config
	json.Unmarshal(settingsCopy, &copy)

	return &copy
}

// UpdateSettings updates the settings after validation
func (sm *SettingsManager) UpdateSettings(newSettings *Config) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Validate new settings
	for _, validator := range sm.validators {
		if err := validator.Validate(newSettings); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	// Store old settings for listeners
	oldSettings := sm.settings
	sm.settings = newSettings

	// Notify listeners
	for _, listener := range sm.listeners {
		listener.OnSettingsChanged(oldSettings, newSettings)
	}

	return nil
}

// AddValidator adds a settings validator
func (sm *SettingsManager) AddValidator(validator SettingsValidator) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.validators = append(sm.validators, validator)
}

// AddChangeListener adds a settings change listener
func (sm *SettingsManager) AddChangeListener(listener SettingsChangeListener) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.listeners = append(sm.listeners, listener)
}

// SaveToFile saves the current settings to a file
func (sm *SettingsManager) SaveToFile(filename string) error {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	data, err := json.MarshalIndent(sm.settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write settings file: %w", err)
	}

	return nil
}

// LoadFromFile loads settings from a file
func (sm *SettingsManager) LoadFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read settings file: %w", err)
	}

	var newSettings Config
	err = json.Unmarshal(data, &newSettings)
	if err != nil {
		return fmt.Errorf("failed to parse settings file: %w", err)
	}

	// Validate loaded settings
	for _, validator := range sm.validators {
		if err := validator.Validate(&newSettings); err != nil {
			return fmt.Errorf("loaded settings validation failed: %w", err)
		}
	}

	sm.mutex.Lock()
	oldSettings := sm.settings
	sm.settings = &newSettings
	sm.mutex.Unlock()

	// Notify listeners
	for _, listener := range sm.listeners {
		listener.OnSettingsChanged(oldSettings, &newSettings)
	}

	return nil
}
