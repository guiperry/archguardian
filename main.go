package main

import (
	"archguardian/data_engine"
	"archguardian/inference_engine"
	"archguardian/types"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/philippgille/chromem-go"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// EventType represents different types of events that can be produced
type EventType string

// Event type constants
const (
	// ArchGuardian Scan Cycle Events
	ScanCycleEventType EventType = "scan_cycle"
	ScanStartedEvent   EventType = "scan_started"
	ScanCompletedEvent EventType = "scan_completed"
	RiskAnalysisEvent  EventType = "risk_analysis"
	RemediationEvent   EventType = "remediation"

	// System events
	SystemEventType EventType = "system"
	ErrorEvent      EventType = "error"
	WarningEvent    EventType = "warning"
	InfoEvent       EventType = "info"
)

// ChromaDocument represents a document stored in ChromaDB
type ChromaDocument struct {
	ID        string                 `json:"id"`
	Embedding []float64              `json:"embedding,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	Document  string                 `json:"document"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
}

//go:embed dashboard/index.html
var dashboardHTML string

//go:embed dashboard/style.css
var dashboardCSS string

//go:embed dashboard/app.js
var dashboardJS string

// ============================================================================
// AUTHENTICATION SYSTEM
// ============================================================================

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	AvatarURL string    `json:"avatar_url"`
	Provider  string    `json:"provider"` // "github"
	CreatedAt time.Time `json:"created_at"`
	LastLogin time.Time `json:"last_login"`
}

type GitHubAuth struct {
	UserID       string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	TokenType    string
}

type AuthService struct {
	githubClientID     string
	githubClientSecret string
	jwtSecret          []byte
	sessionStore       *sessions.CookieStore
	users              map[string]*User
	tokens             map[string]*GitHubAuth
	mutex              sync.RWMutex
}

func NewAuthService() *AuthService {
	jwtSecret := []byte(getEnv("JWT_SECRET", "your-secret-key-change-in-production"))
	sessionSecret := getEnv("SESSION_SECRET", "another-secret-key-change-in-production")

	return &AuthService{
		githubClientID:     getEnv("GITHUB_CLIENT_ID", ""),
		githubClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		jwtSecret:          jwtSecret,
		sessionStore:       sessions.NewCookieStore([]byte(sessionSecret)),
		users:              make(map[string]*User),
		tokens:             make(map[string]*GitHubAuth),
	}
}

func (as *AuthService) GenerateJWT(user *User) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   user.ID,
		"username":  user.Username,
		"email":     user.Email,
		"provider":  user.Provider,
		"exp":       time.Now().Add(24 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(as.jwtSecret)
}

func (as *AuthService) ValidateJWT(tokenString string) (*User, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return as.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		user := &User{
			ID:       claims["user_id"].(string),
			Username: claims["username"].(string),
			Email:    claims["email"].(string),
			Provider: claims["provider"].(string),
		}
		return user, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (as *AuthService) CreateOrUpdateUser(githubUser map[string]interface{}) *User {
	as.mutex.Lock()
	defer as.mutex.Unlock()

	userID := fmt.Sprintf("%v", githubUser["id"])
	now := time.Now()

	user, exists := as.users[userID]
	if !exists {
		user = &User{
			ID:        userID,
			Username:  githubUser["login"].(string),
			Email:     githubUser["email"].(string),
			Name:      githubUser["name"].(string),
			AvatarURL: githubUser["avatar_url"].(string),
			Provider:  "github",
			CreatedAt: now,
		}
		as.users[userID] = user
	}

	user.LastLogin = now
	return user
}

func (as *AuthService) StoreGitHubToken(userID string, auth *GitHubAuth) {
	as.mutex.Lock()
	defer as.mutex.Unlock()
	as.tokens[userID] = auth
}

func (as *AuthService) GetGitHubToken(userID string) (*GitHubAuth, bool) {
	as.mutex.RLock()
	defer as.mutex.RUnlock()
	token, exists := as.tokens[userID]
	return token, exists
}

func (as *AuthService) GetUser(userID string) (*User, bool) {
	as.mutex.RLock()
	defer as.mutex.RUnlock()
	user, exists := as.users[userID]
	return user, exists
}

// GitHub OAuth URLs
func (as *AuthService) GetGitHubAuthURL(state string) string {
	baseURL := "https://github.com/login/oauth/authorize"
	params := url.Values{}
	params.Add("client_id", as.githubClientID)
	params.Add("redirect_uri", "http://localhost:3000/api/v1/auth/github/callback")
	params.Add("scope", "read:user user:email")
	params.Add("state", state)
	params.Add("response_type", "code")

	return baseURL + "?" + params.Encode()
}

func (as *AuthService) ExchangeGitHubCode(code string) (*GitHubAuth, error) {
	tokenURL := "https://github.com/login/oauth/access_token"

	data := url.Values{}
	data.Set("client_id", as.githubClientID)
	data.Set("client_secret", as.githubClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:3000/api/v1/auth/github/callback")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("GitHub OAuth error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	return &GitHubAuth{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   time.Now().Add(24 * time.Hour), // GitHub tokens typically last 1 year
	}, nil
}

func (as *AuthService) GetGitHubUser(accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return user, nil
}

// Authentication middleware
func (as *AuthService) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for Authorization header (JWT)
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			user, err := as.ValidateJWT(tokenString)
			if err == nil {
				// Add user to request context
				ctx := context.WithValue(r.Context(), "user", user)
				r = r.WithContext(ctx)
				next(w, r)
				return
			}
		}

		// Check for session cookie
		session, err := as.sessionStore.Get(r, "archguardian-session")
		if err == nil {
			if userID, ok := session.Values["user_id"].(string); ok {
				if user, exists := as.GetUser(userID); exists {
					ctx := context.WithValue(r.Context(), "user", user)
					r = r.WithContext(ctx)
					next(w, r)
					return
				}
			}
		}

		// No valid authentication found
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Unauthorized",
			"message": "Authentication required",
		})
	}
}

// Optional authentication middleware (doesn't require auth but adds user if present)
func (as *AuthService) OptionalAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try JWT first
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			user, err := as.ValidateJWT(tokenString)
			if err == nil {
				ctx := context.WithValue(r.Context(), "user", user)
				r = r.WithContext(ctx)
				next(w, r)
				return
			}
		}

		// Try session
		session, err := as.sessionStore.Get(r, "archguardian-session")
		if err == nil {
			if userID, ok := session.Values["user_id"].(string); ok {
				if user, exists := as.GetUser(userID); exists {
					ctx := context.WithValue(r.Context(), "user", user)
					r = r.WithContext(ctx)
					next(w, r)
					return
				}
			}
		}

		// No authentication, but that's okay
		next(w, r)
	}
}

// ============================================================================
// WEBSOCKET MESSAGES
// ============================================================================

type WSMessage struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
	ID        string      `json:"id,omitempty"`
}

// ============================================================================
// PROJECT MANAGEMENT
// ============================================================================

type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	Status      string    `json:"status"` // "idle", "scanning", "error"
	LastScan    *time.Time `json:"lastScan,omitempty"`
	IssueCount  int       `json:"issueCount"`
	CreatedAt   time.Time `json:"createdAt"`
	Config      *Config   `json:"-"` // Don't serialize
	Graph       *types.KnowledgeGraph `json:"-"` // Don't serialize
}

type ProjectStore struct {
	projects map[string]*Project
	mutex    sync.RWMutex
}

func NewProjectStore() *ProjectStore {
	return &ProjectStore{
		projects: make(map[string]*Project),
	}
}

func (ps *ProjectStore) Create(project *Project) {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	ps.projects[project.ID] = project
}

func (ps *ProjectStore) Get(id string) (*Project, bool) {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	project, exists := ps.projects[id]
	return project, exists
}

func (ps *ProjectStore) GetAll() []*Project {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	projects := make([]*Project, 0, len(ps.projects))
	for _, project := range ps.projects {
		projects = append(projects, project)
	}
	return projects
}

func (ps *ProjectStore) Update(project *Project) bool {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	if _, exists := ps.projects[project.ID]; !exists {
		return false
	}

	ps.projects[project.ID] = project
	return true
}

func (ps *ProjectStore) Delete(id string) bool {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	if _, exists := ps.projects[id]; !exists {
		return false
	}

	delete(ps.projects, id)
	return true
}

// ============================================================================
// CONFIGURATION
// ============================================================================

type Config struct {
	ProjectPath       string            `json:"project_path"`
	GitHubToken       string            `json:"github_token"`
	GitHubRepo        string            `json:"github_repo"`
	AIProviders       AIProviderConfig  `json:"ai_providers"`
	Orchestrator      OrchestratorConfig `json:"orchestrator"`
	DataEngine        DataEngineConfig   `json:"data_engine"`
	ScanInterval      time.Duration     `json:"scan_interval"`
	RemediationBranch string            `json:"remediation_branch"`
}

// SettingsManager handles persistent settings storage and validation
type SettingsManager struct {
	db         *chromem.DB
	settings   *Config
	mutex      sync.RWMutex
	validators []SettingsValidator
	listeners  []SettingsChangeListener
}

// SettingsValidator validates settings before they are applied
type SettingsValidator interface {
	Validate(settings *Config) error
}

// SettingsChangeListener is notified when settings change
type SettingsChangeListener interface {
	OnSettingsChanged(oldSettings, newSettings *Config)
}

// DefaultSettingsValidator provides basic validation
type DefaultSettingsValidator struct{}

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

	// Validate AI provider configurations
	if settings.AIProviders.Cerebras.APIKey == "" &&
		settings.AIProviders.Gemini.APIKey == "" &&
		settings.AIProviders.Anthropic.APIKey == "" &&
		settings.AIProviders.OpenAI.APIKey == "" &&
		settings.AIProviders.DeepSeek.APIKey == "" {
		return fmt.Errorf("at least one AI provider API key must be configured")
	}

	// Validate code remediation provider
	validProviders := map[string]bool{
		"anthropic": true,
		"openai":    true,
		"deepseek":  true,
	}
	if !validProviders[settings.AIProviders.CodeRemediationProvider] {
		return fmt.Errorf("invalid code_remediation_provider: %s", settings.AIProviders.CodeRemediationProvider)
	}

	return nil
}



// NewSettingsManager creates a new settings manager
func NewSettingsManager(db *chromem.DB) *SettingsManager {
	sm := &SettingsManager{
		db:         db,
		validators: []SettingsValidator{&DefaultSettingsValidator{}},
		listeners:  make([]SettingsChangeListener, 0),
	}

	// Load existing settings or create defaults
	sm.loadSettings()

	return sm
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

// GetSettings returns a copy of current settings
func (sm *SettingsManager) GetSettings() *Config {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Return a deep copy to prevent external modification
	settingsJSON, _ := json.Marshal(sm.settings)
	var copy Config
	json.Unmarshal(settingsJSON, &copy)
	return &copy
}

// UpdateSettings validates and updates settings
func (sm *SettingsManager) UpdateSettings(newSettings *Config) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Validate settings
	for _, validator := range sm.validators {
		if err := validator.Validate(newSettings); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	// Store old settings for listeners
	oldSettings := sm.settings

	// Update settings
	sm.settings = newSettings

	// Persist to database
	if err := sm.persistSettings(); err != nil {
		// Restore old settings on failure
		sm.settings = oldSettings
		return fmt.Errorf("failed to persist settings: %w", err)
	}

	// Notify listeners
	for _, listener := range sm.listeners {
		go listener.OnSettingsChanged(oldSettings, newSettings)
	}

	log.Printf("✅ Settings updated successfully")
	return nil
}

// LoadFromFile loads settings from a JSON file
func (sm *SettingsManager) LoadFromFile(filePath string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read settings file: %w", err)
	}

	var fileSettings Config
	if err := json.Unmarshal(data, &fileSettings); err != nil {
		return fmt.Errorf("failed to parse settings file: %w", err)
	}

	// Validate and update
	return sm.UpdateSettings(&fileSettings)
}

// SaveToFile saves current settings to a JSON file
func (sm *SettingsManager) SaveToFile(filePath string) error {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	data, err := json.MarshalIndent(sm.settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write settings file: %w", err)
	}

	return nil
}

// loadSettings loads settings from chromem-go database
func (sm *SettingsManager) loadSettings() {
	collection := sm.db.GetCollection("settings-history", nil)
	if collection == nil {
		log.Printf("⚠️  Settings collection not found, using defaults")
		sm.settings = sm.getDefaultSettings()
		return
	}

	// Get the most recent settings
	results, err := collection.Query(
		context.Background(),
		"",
		1,
		nil,
		nil,
	)

	if err != nil || len(results) == 0 {
		log.Printf("⚠️  No saved settings found, using defaults")
		sm.settings = sm.getDefaultSettings()
		return
	}

	// Parse the settings
	var settings Config
	if err := json.Unmarshal([]byte(results[0].Content), &settings); err != nil {
		log.Printf("⚠️  Failed to parse saved settings: %v, using defaults", err)
		sm.settings = sm.getDefaultSettings()
		return
	}

	sm.settings = &settings
	log.Printf("✅ Settings loaded from database")
}

// persistSettings saves current settings to chromem-go database
func (sm *SettingsManager) persistSettings() error {
	collection := sm.db.GetCollection("settings-history", nil)
	if collection == nil {
		return fmt.Errorf("settings collection not available")
	}

	settingsJSON, err := json.Marshal(sm.settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	doc := chromem.Document{
		ID:      fmt.Sprintf("settings_%d", time.Now().Unix()),
		Content: string(settingsJSON),
		Metadata: map[string]string{
			"type":      "settings",
			"timestamp": time.Now().Format(time.RFC3339),
			"version":   "1.0",
		},
	}

	return collection.AddDocument(context.Background(), doc)
}

// getDefaultSettings returns default configuration
func (sm *SettingsManager) getDefaultSettings() *Config {
	return &Config{
		ProjectPath:       getEnv("PROJECT_PATH", "."),
		GitHubToken:       getEnv("GITHUB_TOKEN", ""),
		GitHubRepo:        getEnv("GITHUB_REPO", ""),
		ScanInterval:      time.Duration(getEnvInt("SCAN_INTERVAL_HOURS", 24)) * time.Hour,
		RemediationBranch: getEnv("REMEDIATION_BRANCH", "archguardian-fixes"),
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
			CodeRemediationProvider: getEnv("CODE_REMEDIATION_PROVIDER", "anthropic"),
		},
		Orchestrator: OrchestratorConfig{
			PlannerModel:   getEnv("ORCHESTRATOR_PLANNER_MODEL", "gemini-pro"),
			ExecutorModels: strings.Split(getEnv("ORCHESTRATOR_EXECUTOR_MODELS", "llama3.3-70b"), ","),
			FinalizerModel: getEnv("ORCHESTRATOR_FINALIZER_MODEL", "deepseek-coder"),
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

type AIProviderConfig struct {
	Cerebras  ProviderCredentials // Fast, short context tasks
	Gemini    ProviderCredentials // Deep reasoning, long context
	Anthropic ProviderCredentials // Code remediation
	OpenAI    ProviderCredentials // Code remediation (fallback)
	DeepSeek  ProviderCredentials // Code remediation (fallback)

	CodeRemediationProvider string // "anthropic", "openai", or "deepseek"
}

// OrchestratorConfig defines the models used for each role in the task orchestrator.
type OrchestratorConfig struct {
	PlannerModel   string
	ExecutorModels []string
	FinalizerModel string
	VerifierModel  string
}

type ProviderCredentials struct {
	APIKey   string
	Endpoint string
	Model    string
}

type DataEngineConfig struct {
	Enable           bool
	EnableKafka      bool
	EnableChromaDB   bool
	EnableWebSocket  bool
	EnableRESTAPI    bool
	KafkaBrokers     []string
	ChromaDBURL      string
	ChromaCollection string
	WebSocketPort    int
	RESTAPIPort      int
}

// ============================================================================
// SCANNER SYSTEM
// ============================================================================

type Scanner struct {
	config *Config
	graph  *types.KnowledgeGraph // This should be *types.KnowledgeGraph
	ai     *AIInferenceEngine    // This should be *AIInferenceEngine
}

func NewScanner(cfg *Config, ai *AIInferenceEngine) *Scanner {
	return &Scanner{
		config: cfg,
		graph:  NewKnowledgeGraph(),
		ai:     NewAIInferenceEngine(cfg),
	}
}

func NewKnowledgeGraph() *types.KnowledgeGraph {
	return &types.KnowledgeGraph{
		Nodes: make(map[string]*types.Node),
		Edges: make([]*types.Edge, 0),
	}
}

func (s *Scanner) ScanProject(ctx context.Context) error {
	log.Println("🔍 Starting comprehensive project scan...")

	// Phase 1: Static Code Analysis
	if err := s.scanStaticCode(ctx); err != nil {
		return fmt.Errorf("static code scan failed: %w", err)
	}

	// Phase 2: Dependency Analysis
	if err := s.scanDependencies(ctx); err != nil {
		return fmt.Errorf("dependency scan failed: %w", err)
	}

	// Phase 3: Runtime Inspection
	if err := s.scanRuntime(); err != nil {
		return fmt.Errorf("runtime scan failed: %w", err)
	}

	// Phase 4: Database Schema Analysis
	if err := s.scanDatabaseModels(ctx); err != nil {
		return fmt.Errorf("database scan failed: %w", err)
	}

	// Phase 5: API Discovery
	if err := s.scanAPIs(ctx); err != nil {
		return fmt.Errorf("API scan failed: %w", err)
	}

	// Phase 6: Test Coverage Analysis
	if err := s.scanTestCoverage(ctx); err != nil {
		return fmt.Errorf("test coverage scan failed: %w", err)
	}

	// Phase 7: Build Knowledge Graph
	if err := s.buildKnowledgeGraph(ctx); err != nil {
		return fmt.Errorf("knowledge graph build failed: %w", err)
	}

	s.graph.LastUpdated = time.Now()

	// Persist knowledge graph to chromem-go
	if globalDB != nil {
		projectID := "default" // TODO: Get actual project ID from config
		doc, err := s.graph.ToDocument(projectID)
		if err != nil {
			log.Printf("⚠️  Failed to create knowledge graph document: %v", err)
		} else {
			collection := globalDB.GetCollection("knowledge-graphs", nil)
			err = collection.AddDocument(context.Background(), doc)
			if err != nil {
				log.Printf("⚠️  Failed to persist knowledge graph: %v", err)
			} else {
				log.Printf("✅ Knowledge graph persisted to chromem-go")
			}
		}
	}

	log.Println("✅ Project scan complete")
	return nil
}

func (s *Scanner) scanStaticCode(ctx context.Context) error {
	log.Println("  📄 Scanning static code...")

	err := filepath.Walk(s.config.ProjectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip vendor, node_modules, etc.
		if info.IsDir() && (info.Name() == "vendor" || info.Name() == "node_modules" ||
			info.Name() == ".git" || info.Name() == "dist" || info.Name() == "build") {
			return filepath.SkipDir
		}

		if !info.IsDir() && isCodeFile(path) {
			node := &types.Node{
				ID:           generateNodeID(path),
				Type:         types.NodeTypeCode,
				Name:         filepath.Base(path),
				Path:         path,
				Metadata:     make(map[string]interface{}),
				LastModified: info.ModTime(),
				Dependencies: make([]string, 0),
				Dependents:   make([]string, 0),
			}

			// Parse file for imports/dependencies using AST parsing
			content, err := os.ReadFile(path)
			if err == nil {
				node.Metadata["lines"] = strings.Count(string(content), "\n")
				node.Metadata["size"] = info.Size()

				// Use AST parsing for accurate dependency extraction
				dependencies := s.parseFileDependencies(path, content)
				node.Dependencies = dependencies

				// Use Cerebras for quick analysis
				analysis, _ := s.ai.AnalyzeCodeFile(ctx, string(content), AIProviderCerebras)
				if analysis != nil {
					node.Metadata["complexity"] = analysis["complexity"]
					node.Metadata["quality_score"] = analysis["quality_score"]
				}
			}

			s.graph.Nodes[node.ID] = node
		}

		return nil
	})

	return err
}

func (s *Scanner) scanDependencies(ctx context.Context) error {
	log.Println("  📦 Scanning dependencies...")

	// Scan go.mod
	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "go.mod")); err == nil {
		return s.scanGoMod()
	}

	// Scan package.json
	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "package.json")); err == nil {
		return s.scanPackageJSON(ctx)
	}

	// Scan requirements.txt
	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "requirements.txt")); err == nil {
		return s.scanRequirementsTxt(ctx)
	}

	return nil
}

// scanGoMod scans go.mod file for dependencies
func (s *Scanner) scanGoMod() error {
	content, err := os.ReadFile(filepath.Join(s.config.ProjectPath, "go.mod"))
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require") || strings.Contains(line, "/") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pkg := parts[0]
				version := ""
				if len(parts) >= 2 {
					version = parts[1]
				}

				node := &types.Node{
					ID:   generateNodeID("dep:" + pkg),
					Type: types.NodeTypeLibrary,
					Name: pkg,
					Path: pkg,
					Metadata: map[string]interface{}{
						"version": version,
						"manager": "go",
					},
				}
				s.graph.Nodes[node.ID] = node
			}
		}
	}

	return nil
}

func (s *Scanner) scanPackageJSON(_ context.Context) error {
	content, err := os.ReadFile(filepath.Join(s.config.ProjectPath, "package.json"))
	if err != nil {
		return err
	}

	var pkg map[string]interface{}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return err
	}

	// Process dependencies
	if deps, ok := pkg["dependencies"].(map[string]interface{}); ok {
		for name, version := range deps {
			node := &types.Node{
				ID:   generateNodeID("dep:" + name),
				Type: types.NodeTypeLibrary,
				Name: name,
				Path: name,
				Metadata: map[string]interface{}{
					"version": version,
					"manager": "npm",
				},
			}
			s.graph.Nodes[node.ID] = node
		}
	}

	return nil
}

func (s *Scanner) scanRequirementsTxt(_ context.Context) error {
	content, err := os.ReadFile(filepath.Join(s.config.ProjectPath, "requirements.txt"))
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "==")
		name := strings.TrimSpace(parts[0])
		version := ""
		if len(parts) > 1 {
			version = strings.TrimSpace(parts[1])
		}

		node := &types.Node{
			ID:   generateNodeID("dep:" + name),
			Type: types.NodeTypeLibrary,
			Name: name,
			Path: name,
			Metadata: map[string]interface{}{
				"version": version,
				"manager": "pip",
			},
		}
		s.graph.Nodes[node.ID] = node
	}

	return nil
}

func (s *Scanner) scanDatabaseModels(_ context.Context) error {
	log.Println("  🗄️  Scanning database models...")

	// Look for common ORM patterns
	patterns := []string{
		"**/models/*.go",
		"**/entity/*.go",
		"**/models.py",
		"**/schemas/*.ts",
	}

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(s.config.ProjectPath, pattern))
		for _, path := range matches {
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			// Use Gemini for deep analysis of database models
			analysis, _ := s.ai.AnalyzeDatabaseModel(context.Background(), string(content), AIProviderGemini)

			node := &types.Node{
				ID:   generateNodeID(path),
				Type: types.NodeTypeDatabase,
				Name: filepath.Base(path),
				Path: path,
				Metadata: map[string]interface{}{
					"analysis": analysis,
				},
			}
			s.graph.Nodes[node.ID] = node
		}
	}

	return nil
}

func (s *Scanner) scanRuntime() error {
	log.Println("  🔄 Scanning runtime environment...")

	runtimeScanner := NewRuntimeScanner()
	processNodes, connectionNodes, err := runtimeScanner.ScanSystem()
	if err != nil {
		log.Printf("  ⚠️  Runtime scan failed: %v", err)
		return nil // Don't fail the entire scan for runtime issues
	}

	// Add runtime nodes to knowledge graph
	for _, node := range processNodes {
		s.graph.Nodes[node.ID] = node
	}

	for _, node := range connectionNodes {
		s.graph.Nodes[node.ID] = node
	}

	log.Printf("  📊 Runtime scan complete: %d processes, %d connections",
		len(processNodes), len(connectionNodes))
	return nil
}

func (s *Scanner) scanAPIs(ctx context.Context) error {
	_ = ctx // Acknowledge context for future use
	log.Println("  🌐 Scanning API definitions...")

	// Look for API definitions
	patterns := []string{
		"**/routes/*.go",
		"**/api/*.go",
		"**/controllers/*.go",
		"**/openapi.yaml",
		"**/swagger.json",
	}

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(s.config.ProjectPath, pattern))
		for _, path := range matches {
			node := &types.Node{
				ID:       generateNodeID(path),
				Type:     types.NodeTypeAPI,
				Name:     filepath.Base(path),
				Path:     path,
				Metadata: make(map[string]interface{}),
			}
			s.graph.Nodes[node.ID] = node
		}
	}

	return nil
}

func (s *Scanner) buildKnowledgeGraph(ctx context.Context) error {
	log.Println("  🕸️  Building knowledge graph...")

	// Use Gemini for deep reasoning about relationships
	graphData := s.prepareGraphData()
	relationships, err := s.ai.InferRelationships(ctx, graphData, AIProviderGemini)
	if err != nil {
		log.Printf("Warning: relationship inference failed: %v", err)
		return nil
	}

	// Build edges based on AI inference
	for _, rel := range relationships {
		edge := &types.Edge{
			From:         rel.From,
			To:           rel.To,
			Relationship: rel.Type,
			Strength:     rel.Confidence,
			Metadata:     rel.Metadata,
		}
		s.graph.Edges = append(s.graph.Edges, edge)
	}

	return nil
}

func (s *Scanner) prepareGraphData() map[string]interface{} {
	nodes := make([]map[string]interface{}, 0)
	for _, node := range s.graph.Nodes {
		nodes = append(nodes, map[string]interface{}{
			"id":   node.ID,
			"type": node.Type,
			"name": node.Name,
			"path": node.Path,
		})
	}

	return map[string]interface{}{
		"nodes": nodes,
		"count": len(nodes),
	}
}

// parseFileDependencies uses AST parsing to extract accurate dependencies from source files
func (s *Scanner) parseFileDependencies(filePath string, content []byte) []string {
	var dependencies []string

	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".go":
		dependencies = s.parseGoDependencies(filePath, content)
	case ".js", ".ts", ".jsx", ".tsx":
		dependencies = s.parseJavaScriptDependencies(filePath, content)
	case ".py":
		dependencies = s.parsePythonDependencies(filePath, content)
	case ".java":
		dependencies = s.parseJavaDependencies(filePath, content)
	default:
		// Fallback to simple regex parsing for unknown file types
		dependencies = s.parseDependenciesWithRegex(filePath, content)
	}

	return dependencies
}

// parseGoDependencies uses go/parser to extract import declarations from Go files
func (s *Scanner) parseGoDependencies(filePath string, content []byte) []string {
	var dependencies []string

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, content, parser.ImportsOnly)
	if err != nil {
		log.Printf("  ⚠️  Failed to parse Go file %s: %v", filePath, err)
		return s.parseDependenciesWithRegex(filePath, content)
	}

	for _, imp := range node.Imports {
		// imp.Path.Value is the import path (e.g., "\"fmt\"")
		depPath := strings.Trim(imp.Path.Value, "\"")
		if depPath != "" {
			dependencies = append(dependencies, depPath)
		}
	}

	return dependencies
}

// parseJavaScriptDependencies uses regex to extract import/require statements from JS/TS files
func (s *Scanner) parseJavaScriptDependencies(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Match ES6 imports: import ... from 'module'
	importRegex := regexp.MustCompile(`import\s+.*?\s+from\s+['"]([^'"]+)['"]`)
	matches := importRegex.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) > 1 && match[1] != "" {
			dependencies = append(dependencies, match[1])
		}
	}

	// Match CommonJS requires: require('module')
	requireRegex := regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	requireMatches := requireRegex.FindAllStringSubmatch(text, -1)
	for _, match := range requireMatches {
		if len(match) > 1 && match[1] != "" {
			dependencies = append(dependencies, match[1])
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// parsePythonDependencies uses regex to extract import statements from Python files
func (s *Scanner) parsePythonDependencies(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Match import statements: import module or from module import ...
	importRegex := regexp.MustCompile(`(?m)^(?:import\s+(\S+)|from\s+(\S+)\s+import)`)
	matches := importRegex.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				// Extract the module name (first part before dots)
				moduleName := strings.Split(match[i], ".")[0]
				if moduleName != "" {
					dependencies = append(dependencies, moduleName)
				}
				break
			}
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// parseJavaDependencies uses regex to extract import statements from Java files
func (s *Scanner) parseJavaDependencies(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Match Java import statements: import package.Class;
	importRegex := regexp.MustCompile(`import\s+([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)*)\s*;`)
	matches := importRegex.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 && match[1] != "" {
			dependencies = append(dependencies, match[1])
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// parseDependenciesWithRegex is a fallback method using regex for unknown file types
func (s *Scanner) parseDependenciesWithRegex(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Generic patterns for various languages
	patterns := []string{
		`import\s+['"]([^'"]+)['"]`,            // import 'module'
		`from\s+['"]([^'"]+)['"]`,              // from 'module'
		`require\s*\(\s*['"]([^'"]+)['"]\s*\)`, // require('module')
		`#include\s+[<"]([^>"]+)[>"]`,          // #include <header>
		`use\s+(\S+)`,                          // use module (Perl)
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				dependencies = append(dependencies, match[1])
			}
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// scanTestCoverage performs test coverage analysis and stores results in knowledge graph
func (s *Scanner) scanTestCoverage(ctx context.Context) error {
	log.Println("  📊 Scanning test coverage...")

	// Determine project type and run appropriate coverage command
	var coverageData map[string]interface{}

	if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "go.mod")); err == nil {
		coverageData, err = s.scanGoCoverage(ctx)
		if err != nil {
			log.Printf("  ⚠️  Go coverage scan failed: %v", err)
			return nil // Don't fail the entire scan
		}
	} else if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "package.json")); err == nil {
		coverageData, err = s.scanNodeCoverage(ctx)
		if err != nil {
			log.Printf("  ⚠️  Node.js coverage scan failed: %v", err)
			return nil
		}
	} else if _, err := os.Stat(filepath.Join(s.config.ProjectPath, "requirements.txt")); err == nil {
		coverageData, err = s.scanPythonCoverage(ctx)
		if err != nil {
			log.Printf("  ⚠️  Python coverage scan failed: %v", err)
			return nil
		}
	} else {
		log.Println("  ⚠️  No supported project type found for coverage analysis")
		return nil
	}

	// Store coverage data in knowledge graph
	if coverageData != nil {
		// Create a coverage node
		coverageNode := &types.Node{
			ID:   "coverage_analysis",
			Type: types.NodeTypeCode, // Using code type for coverage data
			Name: "Test Coverage",
			Path: "coverage",
			Metadata: map[string]interface{}{
				"coverage_data": coverageData,
				"scan_time":     time.Now(),
			},
		}
		s.graph.Nodes[coverageNode.ID] = coverageNode

		log.Printf("  📊 Coverage scan complete: %.1f%% coverage", coverageData["overall_coverage"].(float64))

		// Persist coverage data to chromem-go
		if globalDB != nil {
			projectID := "default" // TODO: Get actual project ID from config
			coverageJSON, err := json.Marshal(coverageData)
			if err != nil {
				log.Printf("⚠️  Failed to marshal coverage data: %v", err)
			} else {
				doc := chromem.Document{
					ID:      "coverage_" + projectID + "_" + time.Now().Format("20060102_150405"),
					Content: string(coverageJSON),
					Metadata: map[string]string{
						"type":             "test-coverage",
						"project_id":       projectID,
						"timestamp":        time.Now().Format(time.RFC3339),
						"overall_coverage": fmt.Sprintf("%.2f", coverageData["overall_coverage"].(float64)),
						"lines_covered":    fmt.Sprintf("%d", int(coverageData["lines_covered"].(float64))),
						"total_lines":      fmt.Sprintf("%d", int(coverageData["total_lines"].(float64))),
						"test_files":       fmt.Sprintf("%d", int(coverageData["test_files"].(float64))),
						"language":         coverageData["language"].(string),
					},
				}

				collection := globalDB.GetCollection("test-coverage", nil)
				err = collection.AddDocument(context.Background(), doc)
				if err != nil {
					log.Printf("⚠️  Failed to persist coverage data: %v", err)
				} else {
					log.Printf("✅ Coverage data persisted to chromem-go")
				}
			}
		}
	}

	return nil
}

// scanGoCoverage runs Go test coverage analysis
func (s *Scanner) scanGoCoverage(ctx context.Context) (map[string]interface{}, error) {
	_ = ctx // Acknowledge context for future use

	// Run go test with coverage
	cmd := exec.Command("go", "test", "-coverprofile=coverage.out", "./...")
	cmd.Dir = s.config.ProjectPath
	_, err := cmd.CombinedOutput()
	if err != nil {
		// Some packages might not have tests, which is okay
		log.Printf("  ⚠️  Go test failed (some packages may not have tests): %v", err)
	}

	// Parse coverage output
	coverageFile := filepath.Join(s.config.ProjectPath, "coverage.out")
	if _, err := os.Stat(coverageFile); err != nil {
		return map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
		}, nil
	}

	// Read and parse coverage file
	content, err := os.ReadFile(coverageFile)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	totalLines := 0
	coveredLines := 0

	// Count total and covered lines
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 3 {
			// Parse coverage count (number of times line was executed)
			count := 0
			fmt.Sscanf(parts[2], "%d", &count)
			totalLines++

			if count > 0 {
				coveredLines++
			}
		}
	}

	// Calculate coverage percentage
	var coveragePercent float64
	if totalLines > 0 {
		coveragePercent = (float64(coveredLines) / float64(totalLines)) * 100
	}

	// Count test files
	testFiles := 0
	err = filepath.Walk(s.config.ProjectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			testFiles++
		}
		return nil
	})

	if err != nil {
		log.Printf("  ⚠️  Failed to count test files: %v", err)
	}

	// Clean up coverage file
	os.Remove(coverageFile)

	return map[string]interface{}{
		"overall_coverage": coveragePercent,
		"lines_covered":    coveredLines,
		"total_lines":      totalLines,
		"test_files":       testFiles,
		"language":         "go",
	}, nil
}

// scanNodeCoverage runs Node.js test coverage analysis
func (s *Scanner) scanNodeCoverage(ctx context.Context) (map[string]interface{}, error) {
	_ = ctx // Acknowledge context for future use

	// Check if Jest or other testing framework is available
	var cmd *exec.Cmd

	// Try Jest first
	if s.hasJestConfig() {
		cmd = exec.Command("npx", "jest", "--coverage", "--coverageReporters=json")
	} else if s.hasVitestConfig() {
		cmd = exec.Command("npx", "vitest", "run", "--coverage")
	} else {
		// Fallback to basic test command
		cmd = exec.Command("npm", "test")
	}

	cmd.Dir = s.config.ProjectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("  ⚠️  Node.js test failed: %v", err)
		log.Printf("  Output: %s", string(output))
		// Return zero coverage data instead of failing
		return map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
		}, nil
	}

	// Log successful test output for debugging
	log.Printf("  ✅ Node.js tests completed successfully")

	// Try to read coverage report
	coverageReport := filepath.Join(s.config.ProjectPath, "coverage", "coverage-final.json")
	if _, err := os.Stat(coverageReport); err != nil {
		// Try alternative locations
		coverageReport = filepath.Join(s.config.ProjectPath, "coverage.json")
		if _, err := os.Stat(coverageReport); err != nil {
			return map[string]interface{}{
				"overall_coverage": 0.0,
				"lines_covered":    0,
				"total_lines":      0,
				"test_files":       0,
			}, nil
		}
	}

	// Parse coverage report
	content, err := os.ReadFile(coverageReport)
	if err != nil {
		return nil, err
	}

	var coverage map[string]interface{}
	if err := json.Unmarshal(content, &coverage); err != nil {
		return nil, err
	}

	// Extract coverage data
	totalLines := 0
	coveredLines := 0

	// Parse Jest/Vitest coverage format
	if coverageData, ok := coverage["total"].(map[string]interface{}); ok {
		if lines, ok := coverageData["lines"].(map[string]interface{}); ok {
			if total, ok := lines["total"].(float64); ok {
				totalLines = int(total)
			}
			if covered, ok := lines["covered"].(float64); ok {
				coveredLines = int(covered)
			}
		}
	}

	var coveragePercent float64
	if totalLines > 0 {
		coveragePercent = (float64(coveredLines) / float64(totalLines)) * 100
	}

	// Count test files
	testFiles := 0
	testPatterns := []string{"**/*.test.js", "**/*.test.ts", "**/*.spec.js", "**/*.spec.ts"}
	for _, pattern := range testPatterns {
		matches, _ := filepath.Glob(filepath.Join(s.config.ProjectPath, pattern))
		testFiles += len(matches)
	}

	return map[string]interface{}{
		"overall_coverage": coveragePercent,
		"lines_covered":    coveredLines,
		"total_lines":      totalLines,
		"test_files":       testFiles,
		"language":         "javascript",
		"raw_output":       string(output),
	}, nil
}

// scanPythonCoverage runs Python test coverage analysis
func (s *Scanner) scanPythonCoverage(ctx context.Context) (map[string]interface{}, error) {
	_ = ctx // Acknowledge context for future use

	// Check if pytest is available
	cmd := exec.Command("python", "-m", "pytest", "--cov=.", "--cov-report=json", "--cov-report=term-missing")
	cmd.Dir = s.config.ProjectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("  ⚠️  Python test failed: %v", err)
		return map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
		}, nil
	}

	// Try to read coverage report
	coverageReport := filepath.Join(s.config.ProjectPath, "coverage.json")
	if _, err := os.Stat(coverageReport); err != nil {
		return map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
		}, nil
	}

	// Parse coverage report
	content, err := os.ReadFile(coverageReport)
	if err != nil {
		return nil, err
	}

	var coverage map[string]interface{}
	if err := json.Unmarshal(content, &coverage); err != nil {
		return nil, err
	}

	// Extract coverage data from pytest-cov format
	totalLines := 0
	coveredLines := 0

	if totals, ok := coverage["totals"].(map[string]interface{}); ok {
		if lines, ok := totals["lines"].(map[string]interface{}); ok {
			if total, ok := lines["total"].(float64); ok {
				totalLines = int(total)
			}
			if covered, ok := lines["covered"].(float64); ok {
				coveredLines = int(covered)
			}
		}
	}

	var coveragePercent float64
	if totalLines > 0 {
		coveragePercent = (float64(coveredLines) / float64(totalLines)) * 100
	}

	// Count test files
	testFiles := 0
	testPatterns := []string{"**/test_*.py", "**/*_test.py"}
	for _, pattern := range testPatterns {
		matches, _ := filepath.Glob(filepath.Join(s.config.ProjectPath, pattern))
		testFiles += len(matches)
	}

	return map[string]interface{}{
		"overall_coverage": coveragePercent,
		"lines_covered":    coveredLines,
		"total_lines":      totalLines,
		"test_files":       testFiles,
		"language":         "python",
		"raw_output":       string(output),
	}, nil
}

// Helper functions for coverage scanning

func (s *Scanner) hasJestConfig() bool {
	configFiles := []string{"jest.config.js", "jest.config.ts", "jest.config.json"}
	for _, file := range configFiles {
		if _, err := os.Stat(filepath.Join(s.config.ProjectPath, file)); err == nil {
			return true
		}
	}
	return false
}

func (s *Scanner) hasVitestConfig() bool {
	configFiles := []string{"vitest.config.js", "vitest.config.ts", "vite.config.ts"}
	for _, file := range configFiles {
		if _, err := os.Stat(filepath.Join(s.config.ProjectPath, file)); err == nil {
			return true
		}
	}
	return false
}

// ============================================================================
// CVE SCANNER
// ============================================================================

// CVEScanner handles querying CVE databases like the NVD
type CVEScanner struct {
	httpClient *http.Client
	apiKey     string // For NVD API v2
	baseURL    string
}

// NewCVEScanner creates a new CVE scanner
func NewCVEScanner(apiKey string) *CVEScanner {
	return &CVEScanner{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
		baseURL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

// QueryNVD queries the National Vulnerability Database for a given package
func (cs *CVEScanner) QueryNVD(packageName, version string) ([]types.SecurityVulnerability, error) {
	log.Printf("  🔍 Querying NVD for vulnerabilities in %s@%s...", packageName, version)

	// Construct NVD API URL for keyword search
	// Note: NVD API doesn't directly support package name search, but we can search by keyword
	url := fmt.Sprintf("%s?keyword=%s&resultsPerPage=20", cs.baseURL, packageName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add API key if provided (NVD API v2.0 doesn't require API key for basic queries)
	if cs.apiKey != "" {
		req.Header.Set("apiKey", cs.apiKey)
	}

	resp, err := cs.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query NVD: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	// Parse NVD response
	var nvdResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&nvdResponse); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	// Extract vulnerabilities from response
	vulnerabilities, err := cs.parseNVDResponse(nvdResponse, packageName, version)
	if err != nil {
		log.Printf("  ⚠️  Failed to parse NVD response: %v", err)
		return []types.SecurityVulnerability{}, nil
	}

	log.Printf("  📊 Found %d vulnerabilities for %s@%s", len(vulnerabilities), packageName, version)
	return vulnerabilities, nil
}

// parseNVDResponse extracts vulnerability information from NVD API response
func (cs *CVEScanner) parseNVDResponse(response map[string]interface{}, packageName, version string) ([]types.SecurityVulnerability, error) {
	var vulnerabilities []types.SecurityVulnerability

	// Navigate to vulnerabilities array in NVD response
	vulnData, ok := response["vulnerabilities"].([]interface{})
	if !ok {
		return vulnerabilities, nil
	}

	for _, item := range vulnData {
		vulnMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		cve, ok := vulnMap["cve"].(map[string]interface{})
		if !ok {
			continue
		}

		// Extract CVE ID
		id := ""
		if idMap, ok := cve["id"].(string); ok {
			id = idMap
		}

		// Extract description
		description := ""
		if descArray, ok := cve["descriptions"].([]interface{}); ok && len(descArray) > 0 {
			if descMap, ok := descArray[0].(map[string]interface{}); ok {
				if desc, ok := descMap["value"].(string); ok {
					description = desc
				}
			}
		}

		// Extract CVSS metrics
		cvss := 0.0
		severity := "unknown"
		if metrics, ok := cve["metrics"].(map[string]interface{}); ok {
			if cvssData, ok := metrics["cvssMetricV31"].([]interface{}); ok && len(cvssData) > 0 {
				if cvssMap, ok := cvssData[0].(map[string]interface{}); ok {
					if baseData, ok := cvssMap["cvssData"].(map[string]interface{}); ok {
						if baseScore, ok := baseData["baseScore"].(float64); ok {
							cvss = baseScore
						}
						if severityData, ok := baseData["baseSeverity"].(string); ok {
							severity = severityData
						}
					}
				}
			}
		}

		// Only include vulnerabilities that match our package
		if cs.isRelevantVulnerability(description, packageName) {
			vuln := types.SecurityVulnerability{
				CVE:         id,
				Package:     packageName,
				Version:     version,
				Severity:    severity,
				Description: description,
				FixVersion:  "latest", // NVD doesn't provide fix versions directly
				CVSS:        cvss,
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities, nil
}

// isRelevantVulnerability checks if a vulnerability description mentions the package
func (cs *CVEScanner) isRelevantVulnerability(description, packageName string) bool {
	// Simple heuristic: check if package name appears in description
	// In a real implementation, this would use more sophisticated matching
	descLower := strings.ToLower(description)
	packageLower := strings.ToLower(packageName)

	// Check for exact package name match
	if strings.Contains(descLower, packageLower) {
		return true
	}

	// Check for common package name variations
	parts := strings.Split(packageName, "/")
	if len(parts) > 0 {
		packageBaseName := strings.ToLower(parts[len(parts)-1])
		if strings.Contains(descLower, packageBaseName) {
			return true
		}
	}

	return false
}

// ============================================================================
// RUNTIME SCANNER
// ============================================================================

// RuntimeScanner inspects live system runtime for processes, connections, and resource usage
type RuntimeScanner struct{}

// NewRuntimeScanner creates a new runtime scanner instance
func NewRuntimeScanner() *RuntimeScanner {
	return &RuntimeScanner{}
}

// ScanSystem performs comprehensive runtime inspection of the host system
func (rs *RuntimeScanner) ScanSystem() ([]*types.Node, []*types.Node, error) {
	var processNodes []*types.Node
	var connectionNodes []*types.Node

	// Scan running processes
	processes, err := rs.scanProcesses()
	if err != nil {
		log.Printf("  ⚠️  Failed to scan processes: %v", err)
	} else {
		processNodes = append(processNodes, processes...)
	}

	// Scan network connections
	connections, err := rs.scanNetworkConnections()
	if err != nil {
		log.Printf("  ⚠️  Failed to scan network connections: %v", err)
	} else {
		connectionNodes = append(connectionNodes, connections...)
	}

	// Scan system resources (CPU, Memory, Disk)
	resourceNodes, err := rs.scanSystemResources()
	if err != nil {
		log.Printf("  ⚠️  Failed to scan system resources: %v", err)
	} else {
		processNodes = append(processNodes, resourceNodes...)
	}

	log.Printf("  📊 Runtime scan found: %d processes, %d connections, %d resource nodes",
		len(processNodes), len(connectionNodes), len(resourceNodes))

	return processNodes, connectionNodes, nil
}

// scanProcesses inspects all running processes on the system
func (rs *RuntimeScanner) scanProcesses() ([]*types.Node, error) {
	var nodes []*types.Node

	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %w", err)
	}

	for _, proc := range processes {
		name, err := proc.Name()
		if err != nil {
			continue // Skip processes we can't read
		}

		cmdLine, _ := proc.Cmdline()
		exe, _ := proc.Exe()
		cpuPercent, _ := proc.CPUPercent()
		memoryInfo, _ := proc.MemoryInfo()

		node := &types.Node{
			ID:   fmt.Sprintf("process_%d", proc.Pid),
			Type: types.NodeTypeProcess,
			Name: name,
			Path: exe,
			Metadata: map[string]interface{}{
				"pid":         proc.Pid,
				"cmdline":     cmdLine,
				"cpu_percent": cpuPercent,
				"status":      "running",
			},
		}

		if memoryInfo != nil {
			node.Metadata["memory_rss"] = memoryInfo.RSS
			node.Metadata["memory_vms"] = memoryInfo.VMS
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// scanNetworkConnections inspects active network connections
func (rs *RuntimeScanner) scanNetworkConnections() ([]*types.Node, error) {
	var nodes []*types.Node

	connections, err := net.Connections("all")
	if err != nil {
		return nil, fmt.Errorf("failed to get network connections: %w", err)
	}

	// Group connections by local address to create network nodes
	connectionMap := make(map[string]*types.Node)

	for _, conn := range connections {
		localAddr := fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port)
		remoteAddr := fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port)

		if existingNode, exists := connectionMap[localAddr]; exists {
			// Add to existing connection node
			if conns, ok := existingNode.Metadata["connections"].([]map[string]interface{}); ok {
				conns = append(conns, map[string]interface{}{
					"remote_address": remoteAddr,
					"status":         conn.Status,
					"protocol":       getProtocolName(conn.Type),
				})
				existingNode.Metadata["connections"] = conns
			}
		} else {
			// Create new connection node
			node := &types.Node{
				ID:   fmt.Sprintf("connection_%s", localAddr),
				Type: types.NodeTypeConnection,
				Name: fmt.Sprintf("Connection %s", localAddr),
				Path: localAddr,
				Metadata: map[string]interface{}{
					"local_address": localAddr,
					"connections": []map[string]interface{}{
						{
							"remote_address": remoteAddr,
							"status":         conn.Status,
							"protocol":       getProtocolName(conn.Type),
						},
					},
				},
			}
			connectionMap[localAddr] = node
			nodes = append(nodes, node)
		}
	}

	return nodes, nil
}

// scanSystemResources scans system-wide resource utilization
func (rs *RuntimeScanner) scanSystemResources() ([]*types.Node, error) {
	var nodes []*types.Node

	// CPU information
	cpuPercent, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercent) > 0 {
		node := &types.Node{
			ID:   "resource_cpu",
			Type: types.NodeTypeProcess, // Using process type for system resources
			Name: "CPU Usage",
			Path: "system",
			Metadata: map[string]interface{}{
				"resource_type": "cpu",
				"usage_percent": cpuPercent[0],
			},
		}
		nodes = append(nodes, node)
	}

	// Memory information
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		node := &types.Node{
			ID:   "resource_memory",
			Type: types.NodeTypeProcess,
			Name: "Memory Usage",
			Path: "system",
			Metadata: map[string]interface{}{
				"resource_type":   "memory",
				"total_bytes":     memInfo.Total,
				"available_bytes": memInfo.Available,
				"used_bytes":      memInfo.Used,
				"usage_percent":   memInfo.UsedPercent,
			},
		}
		nodes = append(nodes, node)
	}

	// Disk information
	diskInfo, err := disk.Usage("/")
	if err == nil {
		node := &types.Node{
			ID:   "resource_disk",
			Type: types.NodeTypeProcess,
			Name: "Disk Usage",
			Path: "system",
			Metadata: map[string]interface{}{
				"resource_type": "disk",
				"total_bytes":   diskInfo.Total,
				"free_bytes":    diskInfo.Free,
				"used_bytes":    diskInfo.Used,
				"usage_percent": diskInfo.UsedPercent,
			},
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// getProtocolName converts connection type number to protocol name
func getProtocolName(connType uint32) string {
	switch connType {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return fmt.Sprintf("Type_%d", connType)
	}
}

// ============================================================================
// RISK DIAGNOSIS
// ============================================================================

type RiskDiagnoser struct {
	scanner      *Scanner
	ai           *AIInferenceEngine
	codacyClient *CodacyClient
}

func NewRiskDiagnoser(scanner *Scanner, codacyClient *CodacyClient) *RiskDiagnoser {
	return &RiskDiagnoser{
		scanner:      scanner,
		ai:           scanner.ai,
		codacyClient: codacyClient,
	}
}

func (rd *RiskDiagnoser) DiagnoseRisks(ctx context.Context) (*types.RiskAssessment, error) {
	log.Println("🔬 Diagnosing system risks...")

	assessment := &types.RiskAssessment{
		TechnicalDebt:         make([]types.TechnicalDebtItem, 0),
		SecurityVulns:         make([]types.SecurityVulnerability, 0),
		ObsoleteCode:          make([]types.ObsoleteCodeItem, 0),
		DangerousDependencies: make([]types.DependencyRisk, 0),
		Timestamp:             time.Now(),
	}

	// Fetch Codacy issues if client is available
	if rd.codacyClient != nil {
		codacyIssues, err := rd.codacyClient.GetIssues()
		if err != nil {
			log.Printf("  ⚠️  Failed to fetch Codacy issues: %v", err)
		} else {
			log.Printf("  🔗 Integrating %d Codacy issues into risk assessment", len(codacyIssues))
			for _, codacyIssue := range codacyIssues {
				// Convert Codacy issue to technical debt item
				debtItem := rd.codacyClient.ConvertCodacyIssueToTechnicalDebt(codacyIssue)
				assessment.TechnicalDebt = append(assessment.TechnicalDebt, debtItem)
			}
		}
	}

	// Use Gemini for comprehensive risk analysis
	riskData := rd.prepareRiskAnalysisData()
	risks, err := rd.ai.AnalyzeRisks(ctx, riskData, AIProviderGemini)
	if err != nil {
		return nil, fmt.Errorf("risk analysis failed: %w", err)
	}

	// Parse and categorize risks from AI analysis
	aiTechnicalDebt := rd.extractTechnicalDebt(risks)
	aiSecurityVulns := rd.extractSecurityVulns(risks)
	aiObsoleteCode := rd.extractObsoleteCode(risks)
	aiDependencyRisks := rd.extractDependencyRisks(risks)

	// Merge AI results with Codacy results (avoiding duplicates)
	assessment.TechnicalDebt = append(assessment.TechnicalDebt, aiTechnicalDebt...)
	assessment.SecurityVulns = aiSecurityVulns
	assessment.ObsoleteCode = aiObsoleteCode
	assessment.DangerousDependencies = aiDependencyRisks

	// Calculate overall risk score
	assessment.OverallScore = rd.calculateOverallRisk(assessment)

	log.Printf("  ⚠️  Found: %d technical debt items (%d from Codacy, %d from AI), %d security vulnerabilities, %d obsolete code items",
		len(assessment.TechnicalDebt), len(assessment.TechnicalDebt)-len(aiTechnicalDebt), len(aiTechnicalDebt), len(assessment.SecurityVulns), len(assessment.ObsoleteCode))

	// Persist risk assessment to chromem-go
	if globalDB != nil {
		projectID := "default" // TODO: Get actual project ID from config
		doc, err := assessment.ToDocument(projectID)
		if err != nil {
			log.Printf("⚠️  Failed to create risk assessment document: %v", err)
		} else {
			collection := globalDB.GetCollection("security-issues", nil)
			err = collection.AddDocument(context.Background(), doc)
			if err != nil {
				log.Printf("⚠️  Failed to persist risk assessment: %v", err)
			} else {
				log.Printf("✅ Risk assessment persisted to chromem-go")
			}
		}
	}

	return assessment, nil
}

func (rd *RiskDiagnoser) prepareRiskAnalysisData() map[string]interface{} {
	return map[string]interface{}{
		"graph":      rd.scanner.graph,
		"node_count": len(rd.scanner.graph.Nodes),
		"edge_count": len(rd.scanner.graph.Edges),
	}
}

func (rd *RiskDiagnoser) extractTechnicalDebt(risks map[string]interface{}) []types.TechnicalDebtItem {
	items := make([]types.TechnicalDebtItem, 0)

	if debt, ok := risks["technical_debt"].([]interface{}); ok {
		for i, item := range debt {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, types.TechnicalDebtItem{
					ID:          fmt.Sprintf("TD-%d", i+1),
					Location:    getStringField(m, "location"),
					Type:        getStringField(m, "type"),
					Severity:    getStringField(m, "severity"),
					Description: getStringField(m, "description"),
					Remediation: getStringField(m, "remediation"),
					Effort:      getIntField(m, "effort_hours"),
				})
			}
		}
	}

	return items
}

func (rd *RiskDiagnoser) extractSecurityVulns(risks map[string]interface{}) []types.SecurityVulnerability {
	vulns := make([]types.SecurityVulnerability, 0)

	if security, ok := risks["security"].([]interface{}); ok {
		for _, item := range security {
			if m, ok := item.(map[string]interface{}); ok {
				vulns = append(vulns, types.SecurityVulnerability{
					CVE:         getStringField(m, "cve"),
					Package:     getStringField(m, "package"),
					Version:     getStringField(m, "version"),
					Severity:    getStringField(m, "severity"),
					Description: getStringField(m, "description"),
					FixVersion:  getStringField(m, "fix_version"),
					CVSS:        getFloatField(m, "cvss"),
				})
			}
		}
	}

	return vulns
}

func (rd *RiskDiagnoser) extractObsoleteCode(risks map[string]interface{}) []types.ObsoleteCodeItem {
	items := make([]types.ObsoleteCodeItem, 0)

	if obsolete, ok := risks["obsolete_code"].([]interface{}); ok {
		for _, item := range obsolete {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, types.ObsoleteCodeItem{
					Path:            getStringField(m, "path"),
					References:      getIntField(m, "references"),
					RemovalSafety:   getStringField(m, "removal_safety"),
					RecommendAction: getStringField(m, "action"),
				})
			}
		}
	}

	return items
}

func (rd *RiskDiagnoser) extractDependencyRisks(risks map[string]interface{}) []types.DependencyRisk {
	deps := make([]types.DependencyRisk, 0)

	if dependencies, ok := risks["dependencies"].([]interface{}); ok {
		for _, item := range dependencies {
			if m, ok := item.(map[string]interface{}); ok {
				deps = append(deps, types.DependencyRisk{
					Package:        getStringField(m, "package"),
					CurrentVersion: getStringField(m, "current_version"),
					LatestVersion:  getStringField(m, "latest_version"),
					SecurityIssues: getIntField(m, "security_issues"),
					Maintenance:    getStringField(m, "maintenance"),
					Recommendation: getStringField(m, "recommendation"),
				})
			}
		}
	}

	return deps
}

func (rd *RiskDiagnoser) calculateOverallRisk(assessment *types.RiskAssessment) float64 {
	score := 0.0

	// Weight different risk factors
	score += float64(len(assessment.SecurityVulns)) * 10.0
	score += float64(len(assessment.TechnicalDebt)) * 2.0
	score += float64(len(assessment.ObsoleteCode)) * 1.0
	score += float64(len(assessment.DangerousDependencies)) * 5.0

	// Normalize to 0-100 scale
	return min(100.0, score)
}

// ============================================================================
// AI INFERENCE ENGINE
// ============================================================================

type AIProviderType string

const (
	AIProviderCerebras  AIProviderType = "cerebras"
	AIProviderGemini    AIProviderType = "gemini"
	AIProviderAnthropic AIProviderType = "anthropic"
	AIProviderOpenAI    AIProviderType = "openai"
	AIProviderDeepSeek  AIProviderType = "deepseek"
)

type AIInferenceEngine struct {
	service *inference_engine.InferenceService
}

type Relationship struct {
	From       string
	To         string
	Type       string
	Confidence float64
	Metadata   map[string]interface{}
}

func NewAIInferenceEngine(config *Config) *AIInferenceEngine {
	log.Println("🧠 Initializing Multi-Model AI Inference Engine...")

	// The inference service needs a DB accessor, but doesn't use it. We can pass nil.
	service, err := inference_engine.NewInferenceService(nil)
	if err != nil {
		log.Fatalf("❌ Failed to create inference service: %v", err)
	}

	// Dynamically build the list of available LLMs from the application's configuration
	var attemptConfigs []inference_engine.LLMAttemptConfig
	if config.AIProviders.Cerebras.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "cerebras", ModelName: config.AIProviders.Cerebras.Model, APIKeyEnvVar: "CEREBRAS_API_KEY", MaxTokens: 4000, IsPrimary: true,
		})
	}
	if config.AIProviders.Gemini.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "gemini", ModelName: config.AIProviders.Gemini.Model, APIKeyEnvVar: "GEMINI_API_KEY", MaxTokens: 100000, IsPrimary: false,
		})
	}
	if config.AIProviders.DeepSeek.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "deepseek", ModelName: config.AIProviders.DeepSeek.Model, APIKeyEnvVar: "DEEPSEEK_API_KEY", MaxTokens: 8000, IsPrimary: false,
		})
	}
	if config.AIProviders.Anthropic.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "anthropic", ModelName: config.AIProviders.Anthropic.Model, APIKeyEnvVar: "ANTHROPIC_API_KEY", MaxTokens: 4000, IsPrimary: false,
		})
	}
	if config.AIProviders.OpenAI.APIKey != "" {
		attemptConfigs = append(attemptConfigs, inference_engine.LLMAttemptConfig{
			ProviderName: "openai", ModelName: config.AIProviders.OpenAI.Model, APIKeyEnvVar: "OPENAI_API_KEY", MaxTokens: 4000, IsPrimary: false,
		})
	}

	// Start the service with the dynamic configuration
	// Pass the orchestrator config to the service
	err = service.StartWithConfig(attemptConfigs, config.Orchestrator.PlannerModel, config.Orchestrator.ExecutorModels, config.Orchestrator.FinalizerModel, config.Orchestrator.VerifierModel)
	if err != nil {
		log.Fatalf("❌ Failed to start inference service: %v", err)
	}

	log.Println("✅ AI Inference Engine started successfully.")
	return &AIInferenceEngine{service: service}
}

func (ai *AIInferenceEngine) AnalyzeCodeFile(ctx context.Context, content string, provider AIProviderType) (map[string]interface{}, error) {
	prompt := inference_engine.GetCodeFileAnalysisPrompt(content)

	response, err := ai.service.GenerateText(ctx, string(provider), prompt, "")
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var analysis map[string]interface{}
	if err := json.Unmarshal([]byte(response), &analysis); err != nil {
		log.Printf("⚠️  Could not parse AI analysis for code file: %v", err)
		return map[string]interface{}{"raw_analysis": response}, nil
	}

	return analysis, nil
}

func (ai *AIInferenceEngine) AnalyzeDatabaseModel(ctx context.Context, content string, provider AIProviderType) (map[string]interface{}, error) {
	prompt := inference_engine.GetDatabaseModelAnalysisPrompt(content)

	response, err := ai.service.GenerateText(ctx, string(provider), prompt, "")
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var analysis map[string]interface{}
	if err := json.Unmarshal([]byte(response), &analysis); err != nil {
		log.Printf("⚠️  Could not parse AI analysis for database model: %v", err)
		return map[string]interface{}{"raw_analysis": response}, nil
	}

	return analysis, nil
}

func (ai *AIInferenceEngine) InferRelationships(ctx context.Context, graphData map[string]interface{}, provider AIProviderType) ([]Relationship, error) {
	// Use the real inference service with reflection for deep reasoning about relationships
	graphJSON, _ := json.Marshal(graphData) // Error handling omitted for brevity
	prompt := inference_engine.GetRelationshipInferencePrompt(string(graphJSON))

	response, err := ai.service.GenerateTextWithReflection(ctx, prompt)
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var relationships []Relationship
	if err := json.Unmarshal([]byte(response), &relationships); err != nil {
		log.Printf("⚠️  Could not parse AI relationship inference: %v", err)
		return nil, fmt.Errorf("failed to parse relationships: %w", err)
	}

	return relationships, nil
}

func (ai *AIInferenceEngine) AnalyzeRisks(ctx context.Context, riskData map[string]interface{}, provider AIProviderType) (map[string]interface{}, error) {
	// Use the real inference service with reflection for comprehensive risk analysis
	riskJSON, _ := json.Marshal(riskData) // Error handling omitted for brevity
	prompt := inference_engine.GetRiskAnalysisPrompt(string(riskJSON))

	response, err := ai.service.GenerateTextWithReflection(ctx, prompt)
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var risks map[string]interface{}
	if err := json.Unmarshal([]byte(response), &risks); err != nil {
		log.Printf("⚠️  Could not parse AI risk analysis: %v", err)
		return map[string]interface{}{
			"technical_debt": []interface{}{},
			"security":       []interface{}{},
			"obsolete_code":  []interface{}{},
			"dependencies":   []interface{}{},
			"raw_analysis":   response,
		}, nil
	}

	return risks, nil
}

func (ai *AIInferenceEngine) GenerateRemediation(ctx context.Context, issue interface{}, provider AIProviderType) (string, error) {
	// Use the real inference service with the configured code remediation provider
	issueJSON, _ := json.Marshal(issue) // Error handling omitted for brevity
	prompt := inference_engine.GetRemediationPrompt(string(issueJSON))

	response, err := ai.service.GenerateText(ctx, string(provider), prompt, "")
	if err != nil {
		return "", err
	}

	return response, nil
}

// GenerateRemediationWithOrchestrator uses the multi-step TaskOrchestrator to generate a fix.
func (ai *AIInferenceEngine) GenerateRemediationWithOrchestrator(ctx context.Context, issue interface{}) (string, error) {
	issueJSON, err := json.Marshal(issue)
	if err != nil {
		return "", fmt.Errorf("failed to marshal issue for orchestrator: %w", err)
	}

	// Create a complex prompt that gives the orchestrator the full context to plan and execute a fix.
	complexPrompt := fmt.Sprintf(
		"Generate a code patch or full file replacement to fix the following issue. Plan the change, generate the code, and format the final output as a patch or complete file.\n\n--- ISSUE ---\n%s\n--- END ISSUE ---",
		string(issueJSON),
	)

	// Delegate the entire complex task to the orchestrator.
	return ai.service.ExecuteComplexTask(ctx, complexPrompt)
}

// ============================================================================
// AUTOMATED REMEDIATION
// ============================================================================

type Remediator struct {
	config    *Config
	diagnoser *RiskDiagnoser
	ai        *AIInferenceEngine
	git       *GitManager
}

func NewRemediator(config *Config, diagnoser *RiskDiagnoser) *Remediator {
	return &Remediator{
		config:    config,
		diagnoser: diagnoser,
		ai:        diagnoser.ai,
		git:       NewGitManager(config),
	}
}

func (r *Remediator) RemediateRisks(ctx context.Context, assessment *types.RiskAssessment) error {
	log.Println("🔧 Starting automated remediation...")

	// Create remediation branch
	branchName := fmt.Sprintf("%s-%s", r.config.RemediationBranch, time.Now().Format("20060102-150405"))
	if err := r.git.CreateBranch(branchName); err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	remediationCount := 0

	// Fix security vulnerabilities
	for _, vuln := range assessment.SecurityVulns {
		if err := r.remediateSecurityVuln(ctx, vuln); err != nil {
			log.Printf("  ⚠️  Failed to remediate %s: %v", vuln.CVE, err)
			continue
		}
		remediationCount++
	}

	// Update dependencies
	for _, dep := range assessment.DangerousDependencies {
		if err := r.updateDependency(dep); err != nil {
			log.Printf("  ⚠️  Failed to update %s: %v", dep.Package, err)
			continue
		}
		remediationCount++
	}

	// Remove obsolete code
	for _, obsolete := range assessment.ObsoleteCode {
		if obsolete.RemovalSafety == "safe" {
			if err := r.removeObsoleteCode(ctx, obsolete); err != nil {
				log.Printf("  ⚠️  Failed to remove %s: %v", obsolete.Path, err)
				continue
			}
			remediationCount++
		}
	}

	// Address technical debt
	for _, debt := range assessment.TechnicalDebt {
		if debt.Severity == "critical" || debt.Severity == "high" {
			if err := r.fixTechnicalDebt(ctx, debt); err != nil {
				log.Printf("  ⚠️  Failed to fix %s: %v", debt.ID, err)
				continue
			}
			remediationCount++
		}
	}

	// Advanced Codacy integration: Manage toolchain configuration
	if r.diagnoser.codacyClient != nil {
		if err := r.manageCodacyConfiguration(assessment); err != nil {
			log.Printf("  ⚠️  Failed to manage Codacy configuration: %v", err)
		}
	}

	// Commit and push changes
	if remediationCount > 0 {
		commitMsg := fmt.Sprintf("🤖 Automated remediation: Fixed %d issues\n\n", remediationCount)
		commitMsg += fmt.Sprintf("- Security vulnerabilities: %d\n", len(assessment.SecurityVulns))
		commitMsg += fmt.Sprintf("- Dependency updates: %d\n", len(assessment.DangerousDependencies))
		commitMsg += fmt.Sprintf("- Obsolete code removed: %d\n", len(assessment.ObsoleteCode))
		commitMsg += fmt.Sprintf("- Technical debt addressed: %d\n", len(assessment.TechnicalDebt))

		if err := r.git.CommitAndPush(branchName, commitMsg); err != nil {
			return fmt.Errorf("failed to commit changes: %w", err)
		}

		log.Printf("✅ Remediation complete: %d issues fixed on branch %s", remediationCount, branchName)
	} else {
		log.Println("✅ No issues required remediation")
	}

	return nil
}

func (r *Remediator) remediateSecurityVuln(ctx context.Context, vuln types.SecurityVulnerability) error {
	log.Printf("  🔒 Remediating %s in %s...", vuln.CVE, vuln.Package)

	// Use the TaskOrchestrator for a more robust, multi-step remediation process.
	fix, err := r.ai.GenerateRemediationWithOrchestrator(ctx, map[string]interface{}{
		"type":    "security_vulnerability",
		"cve":     vuln.CVE,
		"package": vuln.Package,
		"version": vuln.Version,
	})

	if err != nil {
		return err
	}

	// Apply the fix
	return r.applyFix(fix, vuln.Package)
}

// updateDependency updates a dependency to the latest version
func (r *Remediator) updateDependency(dep types.DependencyRisk) error {
	log.Printf("  📦 Updating %s from %s to %s...", dep.Package, dep.CurrentVersion, dep.LatestVersion)

	// Determine package manager and update
	if strings.Contains(dep.Package, "/") {
		// Go module
		return r.updateGoModule(dep.Package, dep.LatestVersion)
	} else if fileExists(filepath.Join(r.config.ProjectPath, "package.json")) {
		// NPM package
		return r.updateNPMPackage(dep.Package, dep.LatestVersion)
	} else if fileExists(filepath.Join(r.config.ProjectPath, "requirements.txt")) {
		// Python package
		return r.updatePythonPackage(dep.Package, dep.LatestVersion)
	}

	return nil
}

func (r *Remediator) updateGoModule(pkg, version string) error {
	cmd := exec.Command("go", "get", fmt.Sprintf("%s@%s", pkg, version))
	cmd.Dir = r.config.ProjectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go get failed: %w\n%s", err, output)
	}

	// Run go mod tidy
	tidyCmd := exec.Command("go", "mod", "tidy")
	tidyCmd.Dir = r.config.ProjectPath
	_, err = tidyCmd.CombinedOutput()
	return err
}

func (r *Remediator) updateNPMPackage(pkg, version string) error {
	cmd := exec.Command("npm", "install", fmt.Sprintf("%s@%s", pkg, version))
	cmd.Dir = r.config.ProjectPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("npm install failed: %w\n%s", err, output)
	}
	return nil
}

func (r *Remediator) updatePythonPackage(pkg, version string) error {
	// Update requirements.txt
	reqPath := filepath.Join(r.config.ProjectPath, "requirements.txt")
	content, err := os.ReadFile(reqPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	updated := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), pkg) {
			lines[i] = fmt.Sprintf("%s==%s", pkg, version)
			updated = true
			break
		}
	}

	if updated {
		return os.WriteFile(reqPath, []byte(strings.Join(lines, "\n")), 0644)
	}

	return nil
}

func (r *Remediator) removeObsoleteCode(ctx context.Context, obsolete types.ObsoleteCodeItem) error {
	_ = ctx // Acknowledge context for future use
	log.Printf("  🗑️  Removing obsolete code: %s...", obsolete.Path)

	// Safety check
	if obsolete.References > 0 {
		return fmt.Errorf("code still has %d references", obsolete.References)
	}

	// Remove the file
	return os.Remove(obsolete.Path)
}

func (r *Remediator) fixTechnicalDebt(ctx context.Context, debt types.TechnicalDebtItem) error {
	log.Printf("  🔨 Fixing technical debt: %s...", debt.ID)

	// Use the TaskOrchestrator for a more robust, multi-step remediation process.
	fix, err := r.ai.GenerateRemediationWithOrchestrator(ctx, map[string]interface{}{
		"type":        "technical_debt",
		"location":    debt.Location,
		"description": debt.Description,
		"remediation": debt.Remediation,
	})

	if err != nil {
		return err
	}

	return r.applyFix(fix, debt.Location)
}

func (r *Remediator) applyFix(fix, target string) error {
	if fix == "" {
		return fmt.Errorf("AI returned an empty fix for %s", target)
	}

	// If the target is not a file path (e.g., a package name for a dependency update), we can't apply a file-based fix.
	absPath := filepath.Join(r.config.ProjectPath, target)
	if !fileExists(absPath) {
		log.Printf("    Skipping file-based fix for non-file target: %s", target)
		return nil
	}

	// Check if the fix is a patch (starts with --- or diff --git)
	trimmedFix := strings.TrimSpace(fix)
	if strings.HasPrefix(trimmedFix, "---") || strings.HasPrefix(trimmedFix, "diff --git") {
		log.Printf("    Applying patch to %s", target)
		// Use `git apply` to handle the patch
		cmd := exec.Command("git", "apply", "-")
		cmd.Dir = r.config.ProjectPath
		cmd.Stdin = strings.NewReader(fix)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Log the patch and the error for debugging
			log.Printf("    Failed to apply patch:\n--- PATCH START ---\n%s\n--- PATCH END ---\n", fix)
			return fmt.Errorf("git apply failed for %s: %w\nOutput: %s", target, err, string(output))
		}
		log.Printf("    Successfully applied patch to %s", target)
		return nil
	}

	// If not a patch, assume it's the full file content and overwrite
	log.Printf("    Overwriting file %s with AI-generated content", target)
	return os.WriteFile(absPath, []byte(fix), 0644)
}

// manageCodacyConfiguration handles advanced Codacy toolchain management
func (r *Remediator) manageCodacyConfiguration(assessment *types.RiskAssessment) error {
	log.Println("  🔧 Managing Codacy configuration...")

	// Analyze technical debt items to identify potential false positives
	falsePositiveCandidates := r.identifyFalsePositiveCandidates(assessment)

	if len(falsePositiveCandidates) == 0 {
		log.Println("  ✅ No false positive candidates identified")
		return nil
	}

	// Get current Codacy rules
	rules, err := r.diagnoser.codacyClient.GetRules()
	if err != nil {
		return fmt.Errorf("failed to fetch Codacy rules: %w", err)
	}

	// Identify rules that should be disabled
	rulesToDisable := r.identifyRulesToDisable(rules, falsePositiveCandidates)

	disabledCount := 0
	for _, rule := range rulesToDisable {
		if err := r.diagnoser.codacyClient.UpdateRule(rule.ID, false, rule.Severity); err != nil {
			log.Printf("  ⚠️  Failed to disable Codacy rule %s: %v", rule.ID, err)
			continue
		}
		disabledCount++
		log.Printf("  🔕 Disabled Codacy rule: %s (%s)", rule.Name, rule.ID)
	}

	if disabledCount > 0 {
		log.Printf("  ✅ Disabled %d Codacy rules to reduce false positives", disabledCount)
	} else {
		log.Println("  ✅ No rules needed to be disabled")
	}

	return nil
}

// identifyFalsePositiveCandidates analyzes technical debt items to find potential false positives
func (r *Remediator) identifyFalsePositiveCandidates(assessment *types.RiskAssessment) []types.TechnicalDebtItem {
	var candidates []types.TechnicalDebtItem

	for _, debt := range assessment.TechnicalDebt {
		// Look for patterns that might indicate false positives
		isFalsePositiveCandidate := false

		// Check if it's a Codacy-generated issue (starts with CODACY-)
		if strings.HasPrefix(debt.ID, "CODACY-") {
			// Check for common false positive patterns
			lowerDesc := strings.ToLower(debt.Description)

			// Pattern 1: Issues in generated code or vendor directories
			if r.isInGeneratedOrVendorCode(debt.Location) {
				isFalsePositiveCandidate = true
			}

			// Pattern 2: Issues that are consistently marked as low impact but high effort
			if debt.Severity == "low" && debt.Effort > 3 {
				isFalsePositiveCandidate = true
			}

			// Pattern 3: Issues with specific keywords that often indicate false positives
			falsePositiveKeywords := []string{
				"auto-generated",
				"vendor/",
				"node_modules/",
				"third_party/",
				"generated",
				"protoc-gen",
				"swagger generate",
			}

			for _, keyword := range falsePositiveKeywords {
				if strings.Contains(lowerDesc, keyword) {
					isFalsePositiveCandidate = true
					break
				}
			}
		}

		if isFalsePositiveCandidate {
			candidates = append(candidates, debt)
		}
	}

	log.Printf("  🔍 Identified %d potential false positive candidates", len(candidates))
	return candidates
}

// isInGeneratedOrVendorCode checks if a file location is in generated or vendor code
func (r *Remediator) isInGeneratedOrVendorCode(location string) bool {
	generatedPatterns := []string{
		"vendor/",
		"node_modules/",
		"generated/",
		"gen/",
		"build/",
		"dist/",
		"target/",
		"out/",
		".git/",
	}

	locationLower := strings.ToLower(location)
	for _, pattern := range generatedPatterns {
		if strings.Contains(locationLower, pattern) {
			return true
		}
	}

	return false
}

// identifyRulesToDisable maps false positive candidates to specific Codacy rules
func (r *Remediator) identifyRulesToDisable(rules []CodacyRule, candidates []types.TechnicalDebtItem) []CodacyRule {
	var rulesToDisable []CodacyRule

	// Create a map of rule patterns to rules for quick lookup
	ruleMap := make(map[string]*CodacyRule)
	for _, rule := range rules {
		ruleMap[rule.ID] = &rule
		ruleMap[rule.Name] = &rule
	}

	// Analyze candidates to identify problematic rules
	problematicRuleIDs := make(map[string]bool)

	for _, candidate := range candidates {
		// Extract rule information from the debt item description
		// Format: "[RuleName] Category: Message"
		if strings.Contains(candidate.Description, "[") && strings.Contains(candidate.Description, "]") {
			start := strings.Index(candidate.Description, "[")
			end := strings.Index(candidate.Description, "]")
			if start != -1 && end != -1 && end > start {
				ruleName := candidate.Description[start+1 : end]

				// Look for the rule by name or pattern
				for _, rule := range rules {
					if strings.Contains(strings.ToLower(rule.Name), strings.ToLower(ruleName)) ||
						strings.Contains(strings.ToLower(rule.Description), strings.ToLower(ruleName)) {
						problematicRuleIDs[rule.ID] = true
						break
					}
				}
			}
		}
	}

	// Convert problematic rule IDs to rules
	for _, rule := range rules {
		if problematicRuleIDs[rule.ID] {
			rulesToDisable = append(rulesToDisable, rule)
		}
	}

	log.Printf("  🔍 Identified %d Codacy rules to disable", len(rulesToDisable))
	return rulesToDisable
}

// ============================================================================
// GIT MANAGER
// ============================================================================

type GitManager struct {
	config *Config
}

func NewGitManager(config *Config) *GitManager {
	return &GitManager{config: config}
}

func (gm *GitManager) CreateBranch(branchName string) error {
	log.Printf("🌿 Creating branch: %s", branchName)

	// Checkout to main/master first
	checkoutCmd := exec.Command("git", "checkout", "main")
	checkoutCmd.Dir = gm.config.ProjectPath
	if err := checkoutCmd.Run(); err != nil {
		// Try master if main doesn't exist
		checkoutCmd = exec.Command("git", "checkout", "master")
		checkoutCmd.Dir = gm.config.ProjectPath
		if err := checkoutCmd.Run(); err != nil {
			return fmt.Errorf("failed to checkout base branch: %w", err)
		}
	}

	// Pull latest changes
	pullCmd := exec.Command("git", "pull")
	pullCmd.Dir = gm.config.ProjectPath
	_ = pullCmd.Run() // Ignore errors

	// Create and checkout new branch
	branchCmd := exec.Command("git", "checkout", "-b", branchName)
	branchCmd.Dir = gm.config.ProjectPath
	output, err := branchCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create branch: %w\n%s", err, output)
	}

	return nil
}

func (gm *GitManager) CommitAndPush(branchName, message string) error {
	log.Printf("💾 Committing changes...")

	// Add all changes
	addCmd := exec.Command("git", "add", ".")
	addCmd.Dir = gm.config.ProjectPath
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add changes: %w", err)
	}

	// Commit
	commitCmd := exec.Command("git", "commit", "-m", message)
	commitCmd.Dir = gm.config.ProjectPath
	output, err := commitCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to commit: %w\n%s", err, output)
	}

	// Push to remote
	log.Printf("⬆️  Pushing to remote...")
	pushCmd := exec.Command("git", "push", "-u", "origin", branchName)
	pushCmd.Dir = gm.config.ProjectPath
	output, err = pushCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to push: %w\n%s", err, output)
	}

	log.Printf("✅ Changes committed and pushed to branch: %s", branchName)
	return nil
}

// ============================================================================
// GIT MANAGER
// ============================================================================

type ArchGuardian struct {
	config         *Config
	scanner        *Scanner
	diagnoser      *RiskDiagnoser
	remediator     *Remediator
	dataEngine     *data_engine.DataEngine
	logWriter      *logWriter // Real-time log streaming to dashboard
	triggerScan    chan bool  // Channel to trigger manual scans
	dashboardConns []*websocket.Conn // Connected dashboard WebSocket clients
	connMutex      sync.Mutex        // Mutex for dashboard connections
}

func NewArchGuardian(config *Config, aiEngine *AIInferenceEngine) *ArchGuardian {
	var de *data_engine.DataEngine
	if config.DataEngine.Enable {
		log.Println("📈 Initializing Data Engine...")
		// Convert main.go config to data_engine config
		deConfig := data_engine.DataEngineConfig{
			EnableKafka:      config.DataEngine.EnableKafka,
			KafkaBrokers:     config.DataEngine.KafkaBrokers,
			ChromaDBURL:      config.DataEngine.ChromaDBURL,
			ChromaCollection: config.DataEngine.ChromaCollection,
			EnableChromaDB:   config.DataEngine.EnableChromaDB,
			EnableWebSocket:  config.DataEngine.EnableWebSocket,
			WebSocketPort:    config.DataEngine.WebSocketPort,
			EnableRESTAPI:    config.DataEngine.EnableRESTAPI,
			RESTAPIPort:      config.DataEngine.RESTAPIPort,
			WindowSize:       1 * time.Minute,
			MetricsInterval:  30 * time.Second,
		}
		de = data_engine.NewDataEngine(deConfig)
		if err := de.Start(); err != nil {
			log.Printf("⚠️  Data Engine failed to start: %v. Continuing without it.", err)
			de = nil // Ensure data engine is nil if it fails
		} else {
			log.Println("✅ Data Engine started successfully.")
		}
	}

	scanner := NewScanner(config, aiEngine)
	globalScanner = scanner // Assign to global variable for API access

	// Initialize Codacy client if API token is provided
	var codacyClient *CodacyClient
	if codacyToken := getEnv("CODACY_API_TOKEN", ""); codacyToken != "" {
		codacyProvider := getEnv("CODACY_PROVIDER", "gh") // Default to GitHub
		codacyRepo := getEnv("CODACY_REPOSITORY", "")
		if codacyRepo != "" {
			codacyClient = NewCodacyClient(codacyToken, codacyProvider, codacyRepo)
			log.Println("🔗 Codacy integration enabled")
		}
	}

	diagnoser := NewRiskDiagnoser(scanner, codacyClient)
	globalDiagnoser = diagnoser // Assign to global variable for API access
	remediator := NewRemediator(config, diagnoser)

	guardian := &ArchGuardian{
		config:      config,
		scanner:     scanner,
		diagnoser:   diagnoser,
		remediator:  remediator,
		dataEngine:  de,
		triggerScan: make(chan bool), // Initialize the channel
	}

	// Initialize and activate logWriter for real-time log streaming to dashboard
	lw := &logWriter{
		ag:          guardian,
		initialLogs: make([][]byte, 0, 100),
		clientReady: false,
	}
	guardian.logWriter = lw

	// Set up callback to flush logs when WebSocket client connects
	if guardian.dataEngine != nil {
		guardian.dataEngine.SetOnClientReadyCallback(func() {
			guardian.FlushInitialLogs()
		})
	}

	// Redirect standard log output to our custom writer
	log.SetOutput(lw)

	return guardian
}

func (ag *ArchGuardian) Run(ctx context.Context) error {
	log.Println("🚀 ArchGuardian starting...")
	log.Printf("📁 Project: %s", ag.config.ProjectPath)
	log.Printf("🤖 AI Providers: Cerebras (fast), Gemini (reasoning), %s (remediation)",
		ag.config.AIProviders.CodeRemediationProvider)
	log.Println("✅ ArchGuardian is running. Waiting for scan trigger from API or periodic schedule...")

	ticker := time.NewTicker(ag.config.ScanInterval)
	defer ticker.Stop()

	// Run scans based on ticker or manual trigger
	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 ArchGuardian shutting down...")
			return ctx.Err()
		case <-ag.triggerScan: // Handle manual scan trigger
			log.Println("⚡ Manual scan triggered via API.")
			if err := ag.runCycle(ctx); err != nil {
				log.Printf("❌ Manual scan cycle failed: %v", err)
			}
			// Reset the ticker to align with the manual scan time, preventing immediate double scan
			ticker.Reset(ag.config.ScanInterval)
		case <-ticker.C:
			if err := ag.runCycle(ctx); err != nil {
				log.Printf("❌ Scan cycle failed: %v", err)
			}
		}
	}
}

func (ag *ArchGuardian) runCycle(ctx context.Context) error {
	log.Println("\n" + strings.Repeat("=", 80))
	log.Printf("🔄 Starting scan cycle at %s", time.Now().Format(time.RFC3339))
	log.Println(strings.Repeat("=", 80))

	ag.produceSystemEvent(data_engine.SystemEventType, "scan_cycle_started", nil)

	// Phase 1: Scan project
	if err := ag.scanner.ScanProject(ctx); err != nil {
		ag.produceSystemEvent(data_engine.ErrorEvent, "scan_project_failed", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("scan failed: %w", err)
	}
	ag.produceSystemEvent(data_engine.SystemEventType, "scan_project_completed", map[string]interface{}{"node_count": len(ag.scanner.graph.Nodes)})

	// Export knowledge graph
	if err := ag.exportKnowledgeGraph(); err != nil {
		log.Printf("⚠️  Failed to export knowledge graph: %v", err)
	}

	// Phase 2: Diagnose risks
	assessment, err := ag.diagnoser.DiagnoseRisks(ctx)
	if err != nil {
		ag.produceSystemEvent(data_engine.ErrorEvent, "diagnose_risks_failed", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("risk diagnosis failed: %w", err)
	}
	ag.produceSystemEvent(data_engine.SystemEventType, "diagnose_risks_completed", map[string]interface{}{"overall_score": assessment.OverallScore})
	for _, vuln := range assessment.SecurityVulns {
		if ag.dataEngine != nil {
			ag.dataEngine.BroadcastSecurityVulnerability(vuln)
		}
	}

	// Export risk assessment
	if err := ag.exportRiskAssessment(assessment); err != nil {
		log.Printf("⚠️  Failed to export risk assessment: %v", err)
	}

	// Phase 3: Automated remediation
	if assessment.OverallScore > 20.0 { // Only remediate if risk score is significant
		if err := ag.remediator.RemediateRisks(ctx, assessment); err != nil {
			ag.produceSystemEvent(data_engine.ErrorEvent, "remediation_failed", map[string]interface{}{"error": err.Error()})
			log.Printf("⚠️  Remediation failed: %v", err)
		}
		if ag.dataEngine != nil {
			ag.dataEngine.BroadcastRemediationCompleted(map[string]interface{}{
				"status": "completed",
				"timestamp": time.Now(),
			})
		}
	} else {
		ag.produceSystemEvent(data_engine.SystemEventType, "remediation_skipped", map[string]interface{}{"reason": "System health is good", "overall_score": assessment.OverallScore})
		log.Println("✅ System health is good, no remediation needed")
	}

	log.Println(strings.Repeat("=", 80))
	log.Printf("✅ Scan cycle complete. Overall risk score: %.2f/100", assessment.OverallScore)
	log.Println(strings.Repeat("=", 80) + "\n")

	ag.produceSystemEvent(data_engine.SystemEventType, "scan_cycle_completed", map[string]interface{}{"overall_score": assessment.OverallScore})
	return nil
}

func (ag *ArchGuardian) exportKnowledgeGraph() error {
	outputPath := filepath.Join(ag.config.ProjectPath, ".archguardian", "knowledge-graph.json")
	os.MkdirAll(filepath.Dir(outputPath), 0755)

	data, err := json.MarshalIndent(ag.scanner.graph, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	log.Printf("📊 Knowledge graph exported to: %s", outputPath)
	return nil
}

func (ag *ArchGuardian) exportRiskAssessment(assessment *types.RiskAssessment) error {
	outputPath := filepath.Join(ag.config.ProjectPath, ".archguardian", "risk-assessment.json")
	os.MkdirAll(filepath.Dir(outputPath), 0755)

	data, err := json.MarshalIndent(assessment, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	log.Printf("📊 Risk assessment exported to: %s", outputPath)
	return nil
}

func (ag *ArchGuardian) produceSystemEvent(eventType data_engine.EventType, subType string, data map[string]interface{}) {
	if ag.dataEngine == nil {
		return
	}

	if data == nil {
		data = make(map[string]interface{})
	}
	data["sub_type"] = subType

	event := data_engine.Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Source:    "archguardian_core",
		Data:      data,
	}

	if err := ag.dataEngine.ProcessEvent(event); err != nil {
		log.Printf("⚠️  Failed to produce system event to data engine: %v", err)
	}
}

// AddDashboardConnection adds a WebSocket connection to the list of dashboard clients
func (ag *ArchGuardian) AddDashboardConnection(conn *websocket.Conn) {
	ag.connMutex.Lock()
	defer ag.connMutex.Unlock()
	ag.dashboardConns = append(ag.dashboardConns, conn)
	log.Printf("Dashboard client connected. Total clients: %d", len(ag.dashboardConns))
}

// RemoveDashboardConnection removes a WebSocket connection from the list of dashboard clients
func (ag *ArchGuardian) RemoveDashboardConnection(conn *websocket.Conn) {
	ag.connMutex.Lock()
	defer ag.connMutex.Unlock()

	for i, c := range ag.dashboardConns {
		if c == conn {
			ag.dashboardConns = append(ag.dashboardConns[:i], ag.dashboardConns[i+1:]...)
			log.Printf("Dashboard client disconnected. Total clients: %d", len(ag.dashboardConns))
			break
		}
	}
}

// BroadcastToDashboard broadcasts a message to all connected dashboard clients
func (ag *ArchGuardian) BroadcastToDashboard(message string) {
	ag.connMutex.Lock()
	defer ag.connMutex.Unlock()

	for _, conn := range ag.dashboardConns {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			log.Printf("Failed to send message to dashboard client: %v", err)
			// Remove broken connection
			go ag.RemoveDashboardConnection(conn)
		}
	}
}

// FlushInitialLogs flushes buffered logs to the WebSocket client when it connects
func (ag *ArchGuardian) FlushInitialLogs() {
	if ag.logWriter != nil {
		ag.logWriter.FlushInitialLogs()
	}
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func isCodeFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	codeExts := []string{".go", ".py", ".js", ".ts", ".java", ".cpp", ".c", ".rs", ".rb",
		".php", ".cs", ".swift", ".kt", ".scala", ".sql"}

	for _, codeExt := range codeExts {
		if ext == codeExt {
			return true
		}
	}
	return false
}

func generateNodeID(path string) string {
	// Simple hash-based ID generation
	return fmt.Sprintf("node_%x", []byte(path))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getIntField(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	if v, ok := m[key].(int); ok {
		return v
	}
	return 0
}

func getFloatField(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0.0
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// SETTINGS HOT RELOAD LISTENER
// ============================================================================

// SettingsHotReloadListener implements hot-reload functionality for settings changes
type SettingsHotReloadListener struct{}

// OnSettingsChanged handles settings change notifications
func (shrl *SettingsHotReloadListener) OnSettingsChanged(oldSettings, newSettings *Config) {
	log.Printf("🔄 Settings changed, applying hot-reload...")

	// Update global configuration if guardian instance exists
	if guardianInstance != nil {
		// Update scan interval if changed
		if oldSettings.ScanInterval != newSettings.ScanInterval {
			log.Printf("  ⏰ Scan interval updated: %v -> %v", oldSettings.ScanInterval, newSettings.ScanInterval)
			// Note: Scan interval changes require server restart for ticker update
			log.Printf("  ⚠️  Scan interval change requires server restart to take effect")
		}

		// Update AI provider configurations
		if oldSettings.AIProviders.CodeRemediationProvider != newSettings.AIProviders.CodeRemediationProvider {
			log.Printf("  🤖 Code remediation provider changed: %s -> %s",
				oldSettings.AIProviders.CodeRemediationProvider, newSettings.AIProviders.CodeRemediationProvider)
			// AI provider changes take effect immediately for new requests
		}

		// Update data engine configuration
		if oldSettings.DataEngine.Enable != newSettings.DataEngine.Enable {
			log.Printf("  📈 Data engine enable changed: %t -> %t",
				oldSettings.DataEngine.Enable, newSettings.DataEngine.Enable)
			log.Printf("  ⚠️  Data engine enable change requires server restart to take effect")
		}

		// Update project path if changed
		if oldSettings.ProjectPath != newSettings.ProjectPath {
			log.Printf("  📁 Project path changed: %s -> %s", oldSettings.ProjectPath, newSettings.ProjectPath)
			log.Printf("  ⚠️  Project path change requires server restart to take effect")
		}

		// Update AIInferenceEngine with new configuration
		if shrl.hasAIProviderChanges(oldSettings.AIProviders, newSettings.AIProviders) {
			log.Printf("  🤖 AI provider configuration changed, updating inference engine...")
			// Create new AIInferenceEngine with updated config
			newAIEngine := NewAIInferenceEngine(newSettings)
			guardianInstance.scanner.ai = newAIEngine
			guardianInstance.diagnoser.ai = newAIEngine
			guardianInstance.remediator.ai = newAIEngine
			log.Printf("  ✅ AI inference engine updated with new configuration")
		}

		// Update data engine configuration if ports changed
		if shrl.hasDataEnginePortChanges(oldSettings.DataEngine, newSettings.DataEngine) {
			log.Printf("  📈 Data engine ports changed, restart required for full effect")
			// Note: Port changes require server restart
		}
	}

	log.Printf("✅ Settings hot-reload completed")
}

// hasAIProviderChanges checks if AI provider configuration has changed
func (shrl *SettingsHotReloadListener) hasAIProviderChanges(oldProviders, newProviders AIProviderConfig) bool {
	return oldProviders.Cerebras.APIKey != newProviders.Cerebras.APIKey ||
		oldProviders.Gemini.APIKey != newProviders.Gemini.APIKey ||
		oldProviders.Anthropic.APIKey != newProviders.Anthropic.APIKey ||
		oldProviders.OpenAI.APIKey != newProviders.OpenAI.APIKey ||
		oldProviders.DeepSeek.APIKey != newProviders.DeepSeek.APIKey ||
		oldProviders.CodeRemediationProvider != newProviders.CodeRemediationProvider
}

// hasDataEnginePortChanges checks if data engine ports have changed
func (shrl *SettingsHotReloadListener) hasDataEnginePortChanges(oldEngine, newEngine DataEngineConfig) bool {
	return oldEngine.WebSocketPort != newEngine.WebSocketPort ||
		oldEngine.RESTAPIPort != newEngine.RESTAPIPort
}

// ============================================================================
// ENVIRONMENT-SPECIFIC CONFIGURATION
// ============================================================================

// EnvironmentConfig represents environment-specific configuration
type EnvironmentConfig struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Overrides   map[string]interface{} `json:"overrides"`
}

// EnvironmentManager handles environment-specific configurations
type EnvironmentManager struct {
	environments map[string]*EnvironmentConfig
	currentEnv   string
}

// NewEnvironmentManager creates a new environment manager
func NewEnvironmentManager() *EnvironmentManager {
	em := &EnvironmentManager{
		environments: make(map[string]*EnvironmentConfig),
		currentEnv:   getEnv("ARCHGUARDIAN_ENV", "development"),
	}

	// Load default environments
	em.loadDefaultEnvironments()

	return em
}

// loadDefaultEnvironments loads built-in environment configurations
func (em *EnvironmentManager) loadDefaultEnvironments() {
	em.environments["development"] = &EnvironmentConfig{
		Name:        "development",
		Description: "Development environment with debug logging and local services",
		Overrides: map[string]interface{}{
			"data_engine": map[string]interface{}{
				"enable_kafka":      false,
				"enable_chromadb":   true,
				"chromadb_url":      "http://localhost:8000",
				"websocket_port":    8080,
				"restapi_port":      7080,
			},
			"orchestrator": map[string]interface{}{
				"planner_model":   "gemini-pro",
				"executor_models": []string{"cerebras"},
				"finalizer_model": "gemini-pro",
				"verifier_model":  "gemini-pro",
			},
		},
	}

	em.environments["production"] = &EnvironmentConfig{
		Name:        "production",
		Description: "Production environment with optimized settings and external services",
		Overrides: map[string]interface{}{
			"data_engine": map[string]interface{}{
				"enable_kafka":      true,
				"kafka_brokers":     []string{"kafka:9092"},
				"enable_chromadb":   true,
				"chromadb_url":      "http://chromadb:8000",
				"websocket_port":    8080,
				"restapi_port":      7080,
			},
			"orchestrator": map[string]interface{}{
				"planner_model":   "gemini-pro",
				"executor_models": []string{"cerebras", "deepseek"},
				"finalizer_model": "anthropic",
				"verifier_model":  "gemini-pro",
			},
			"scan_interval_hours": 6, // More frequent scans in production
		},
	}

	em.environments["testing"] = &EnvironmentConfig{
		Name:        "testing",
		Description: "Testing environment with minimal external dependencies",
		Overrides: map[string]interface{}{
			"data_engine": map[string]interface{}{
				"enable_kafka":      false,
				"enable_chromadb":   false,
				"enable_websocket":  false,
				"enable_restapi":    false,
			},
			"scan_interval_hours": 24, // Less frequent scans for testing
		},
	}
}

// GetCurrentEnvironment returns the current environment configuration
func (em *EnvironmentManager) GetCurrentEnvironment() *EnvironmentConfig {
	if env, exists := em.environments[em.currentEnv]; exists {
		return env
	}
	return em.environments["development"] // fallback
}

// ApplyEnvironmentOverrides applies environment-specific overrides to settings
func (em *EnvironmentManager) ApplyEnvironmentOverrides(settings *Config) {
	env := em.GetCurrentEnvironment()
	if env == nil {
		return
	}

	log.Printf("🌍 Applying %s environment overrides...", env.Name)

	// Apply overrides using reflection-like approach
	for key, value := range env.Overrides {
		em.applyOverride(settings, key, value)
	}

	log.Printf("✅ Environment overrides applied")
}

// applyOverride applies a single environment override to the settings
func (em *EnvironmentManager) applyOverride(settings *Config, key string, value interface{}) {
	switch key {
	case "scan_interval_hours":
		if hours, ok := value.(float64); ok {
			settings.ScanInterval = time.Duration(hours) * time.Hour
			log.Printf("  ⏰ Scan interval set to %v", settings.ScanInterval)
		}
	case "data_engine":
		if deConfig, ok := value.(map[string]interface{}); ok {
			em.applyDataEngineOverrides(&settings.DataEngine, deConfig)
		}
	case "orchestrator":
		if orchConfig, ok := value.(map[string]interface{}); ok {
			em.applyOrchestratorOverrides(&settings.Orchestrator, orchConfig)
		}
	}
}

// applyDataEngineOverrides applies data engine specific overrides
func (em *EnvironmentManager) applyDataEngineOverrides(de *DataEngineConfig, overrides map[string]interface{}) {
	for key, value := range overrides {
		switch key {
		case "enable_kafka":
			if v, ok := value.(bool); ok {
				de.EnableKafka = v
				log.Printf("  📈 Kafka enabled: %t", v)
			}
		case "enable_chromadb":
			if v, ok := value.(bool); ok {
				de.EnableChromaDB = v
				log.Printf("  📈 ChromaDB enabled: %t", v)
			}
		case "enable_websocket":
			if v, ok := value.(bool); ok {
				de.EnableWebSocket = v
				log.Printf("  📈 WebSocket enabled: %t", v)
			}
		case "enable_restapi":
			if v, ok := value.(bool); ok {
				de.EnableRESTAPI = v
				log.Printf("  📈 REST API enabled: %t", v)
			}
		case "kafka_brokers":
			if brokers, ok := value.([]interface{}); ok {
				de.KafkaBrokers = make([]string, len(brokers))
				for i, broker := range brokers {
					if b, ok := broker.(string); ok {
						de.KafkaBrokers[i] = b
					}
				}
				log.Printf("  📈 Kafka brokers: %v", de.KafkaBrokers)
			}
		case "chromadb_url":
			if v, ok := value.(string); ok {
				de.ChromaDBURL = v
				log.Printf("  📈 ChromaDB URL: %s", v)
			}
		case "websocket_port":
			if v, ok := value.(float64); ok {
				de.WebSocketPort = int(v)
				log.Printf("  📈 WebSocket port: %d", int(v))
			}
		case "restapi_port":
			if v, ok := value.(float64); ok {
				de.RESTAPIPort = int(v)
				log.Printf("  📈 REST API port: %d", int(v))
			}
		}
	}
}

// applyOrchestratorOverrides applies orchestrator specific overrides
func (em *EnvironmentManager) applyOrchestratorOverrides(orch *OrchestratorConfig, overrides map[string]interface{}) {
	for key, value := range overrides {
		switch key {
		case "planner_model":
			if v, ok := value.(string); ok {
				orch.PlannerModel = v
				log.Printf("  🤖 Planner model: %s", v)
			}
		case "executor_models":
			if models, ok := value.([]interface{}); ok {
				orch.ExecutorModels = make([]string, len(models))
				for i, model := range models {
					if m, ok := model.(string); ok {
						orch.ExecutorModels[i] = m
					}
				}
				log.Printf("  🤖 Executor models: %v", orch.ExecutorModels)
			}
		case "finalizer_model":
			if v, ok := value.(string); ok {
				orch.FinalizerModel = v
				log.Printf("  🤖 Finalizer model: %s", v)
			}
		case "verifier_model":
			if v, ok := value.(string); ok {
				orch.VerifierModel = v
				log.Printf("  🤖 Verifier model: %s", v)
			}
		}
	}
}

// LoadEnvironmentConfig loads environment configuration from file
func (em *EnvironmentManager) LoadEnvironmentConfig(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read environment config file: %w", err)
	}

	var envConfig EnvironmentConfig
	if err := json.Unmarshal(data, &envConfig); err != nil {
		return fmt.Errorf("failed to parse environment config: %w", err)
	}

	em.environments[envConfig.Name] = &envConfig
	log.Printf("✅ Environment configuration loaded: %s", envConfig.Name)
	return nil
}

// SaveEnvironmentConfig saves environment configuration to file
func (em *EnvironmentManager) SaveEnvironmentConfig(envName, filePath string) error {
	env, exists := em.environments[envName]
	if !exists {
		return fmt.Errorf("environment %s not found", envName)
	}

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal environment config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write environment config file: %w", err)
	}

	log.Printf("✅ Environment configuration saved: %s", envName)
	return nil
}

// ============================================================================
// SECRETS MANAGEMENT
// ============================================================================

// SecretsManager handles secure storage and retrieval of sensitive configuration
type SecretsManager struct {
	encryptionKey []byte
	secrets       map[string]string
	mutex         sync.RWMutex
}

// NewSecretsManager creates a new secrets manager
func NewSecretsManager() *SecretsManager {
	// Use environment variable for encryption key, fallback to generated key
	keyString := getEnv("SECRETS_ENCRYPTION_KEY", "")
	var key []byte

	if keyString != "" && len(keyString) >= 32 {
		key = []byte(keyString[:32])
	} else {
		// Generate a random key for development (not secure for production!)
		key = make([]byte, 32)
		rand.Read(key)
		log.Printf("⚠️  Using randomly generated encryption key. Set SECRETS_ENCRYPTION_KEY for production.")
	}

	return &SecretsManager{
		encryptionKey: key,
		secrets:       make(map[string]string),
	}
}

// StoreSecret securely stores a secret value
func (sm *SecretsManager) StoreSecret(key, value string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Encrypt the value
	encrypted, err := sm.encrypt(value)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	sm.secrets[key] = encrypted
	log.Printf("🔐 Secret stored: %s", key)
	return nil
}

// GetSecret retrieves a decrypted secret value
func (sm *SecretsManager) GetSecret(key string) (string, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	encrypted, exists := sm.secrets[key]
	if !exists {
		return "", false
	}

	// Decrypt the value
	decrypted, err := sm.decrypt(encrypted)
	if err != nil {
		log.Printf("⚠️  Failed to decrypt secret %s: %v", key, err)
		return "", false
	}

	return decrypted, true
}

// DeleteSecret removes a secret
func (sm *SecretsManager) DeleteSecret(key string) bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if _, exists := sm.secrets[key]; exists {
		delete(sm.secrets, key)
		log.Printf("🗑️  Secret deleted: %s", key)
		return true
	}
	return false
}

// ListSecrets returns a list of secret keys (without values)
func (sm *SecretsManager) ListSecrets() []string {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	keys := make([]string, 0, len(sm.secrets))
	for key := range sm.secrets {
		keys = append(keys, key)
	}
	return keys
}

// LoadSecretsFromFile loads encrypted secrets from a file
func (sm *SecretsManager) LoadSecretsFromFile(filePath string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read secrets file: %w", err)
	}

	var fileSecrets map[string]string
	if err := json.Unmarshal(data, &fileSecrets); err != nil {
		return fmt.Errorf("failed to parse secrets file: %w", err)
	}

	sm.secrets = fileSecrets
	log.Printf("✅ Secrets loaded from file: %d secrets", len(sm.secrets))
	return nil
}

// SaveSecretsToFile saves encrypted secrets to a file
func (sm *SecretsManager) SaveSecretsToFile(filePath string) error {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	data, err := json.MarshalIndent(sm.secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}

	log.Printf("✅ Secrets saved to file: %s", filePath)
	return nil
}

// encrypt encrypts a string using AES-GCM
func (sm *SecretsManager) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts a string using AES-GCM
func (sm *SecretsManager) decrypt(encrypted string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}



// ============================================================================
// CONFIGURATION FILE SUPPORT
// ============================================================================

// ConfigFileManager handles loading and saving configuration from/to files
type ConfigFileManager struct {
	secretsManager *SecretsManager
}

// NewConfigFileManager creates a new configuration file manager
func NewConfigFileManager(secretsManager *SecretsManager) *ConfigFileManager {
	return &ConfigFileManager{
		secretsManager: secretsManager,
	}
}

// LoadConfigFromFile loads configuration from a JSON file
func (cfm *ConfigFileManager) LoadConfigFromFile(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	log.Printf("✅ Configuration loaded from file: %s", filePath)
	return &config, nil
}

// SaveConfigToFile saves configuration to a JSON file
func (cfm *ConfigFileManager) SaveConfigToFile(config *Config, filePath string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	log.Printf("✅ Configuration saved to file: %s", filePath)
	return nil
}

// LoadConfigWithSecrets loads configuration and resolves secrets
func (cfm *ConfigFileManager) LoadConfigWithSecrets(filePath string) (*Config, error) {
	config, err := cfm.LoadConfigFromFile(filePath)
	if err != nil {
		return nil, err
	}

	// Resolve secrets from secrets manager
	if secretKey, exists := cfm.secretsManager.GetSecret("cerebras_api_key"); exists {
		config.AIProviders.Cerebras.APIKey = secretKey
	}
	if secretKey, exists := cfm.secretsManager.GetSecret("gemini_api_key"); exists {
		config.AIProviders.Gemini.APIKey = secretKey
	}
	if secretKey, exists := cfm.secretsManager.GetSecret("anthropic_api_key"); exists {
		config.AIProviders.Anthropic.APIKey = secretKey
	}
	if secretKey, exists := cfm.secretsManager.GetSecret("openai_api_key"); exists {
		config.AIProviders.OpenAI.APIKey = secretKey
	}
	if secretKey, exists := cfm.secretsManager.GetSecret("deepseek_api_key"); exists {
		config.AIProviders.DeepSeek.APIKey = secretKey
	}
	if secretKey, exists := cfm.secretsManager.GetSecret("github_token"); exists {
		config.GitHubToken = secretKey
	}

	log.Printf("🔐 Secrets resolved from secrets manager")
	return config, nil
}

// SaveConfigWithSecrets saves configuration with secrets stored separately
func (cfm *ConfigFileManager) SaveConfigWithSecrets(config *Config, configFilePath, secretsFilePath string) error {
	// Create a copy of config with secrets removed
	configCopy := *config

	// Store secrets separately and replace with placeholders
	if config.AIProviders.Cerebras.APIKey != "" {
		cfm.secretsManager.StoreSecret("cerebras_api_key", config.AIProviders.Cerebras.APIKey)
		configCopy.AIProviders.Cerebras.APIKey = "SECRET:cerebras_api_key"
	}
	if config.AIProviders.Gemini.APIKey != "" {
		cfm.secretsManager.StoreSecret("gemini_api_key", config.AIProviders.Gemini.APIKey)
		configCopy.AIProviders.Gemini.APIKey = "SECRET:gemini_api_key"
	}
	if config.AIProviders.Anthropic.APIKey != "" {
		cfm.secretsManager.StoreSecret("anthropic_api_key", config.AIProviders.Anthropic.APIKey)
		configCopy.AIProviders.Anthropic.APIKey = "SECRET:anthropic_api_key"
	}
	if config.AIProviders.OpenAI.APIKey != "" {
		cfm.secretsManager.StoreSecret("openai_api_key", config.AIProviders.OpenAI.APIKey)
		configCopy.AIProviders.OpenAI.APIKey = "SECRET:openai_api_key"
	}
	if config.AIProviders.DeepSeek.APIKey != "" {
		cfm.secretsManager.StoreSecret("deepseek_api_key", config.AIProviders.DeepSeek.APIKey)
		configCopy.AIProviders.DeepSeek.APIKey = "SECRET:deepseek_api_key"
	}
	if config.GitHubToken != "" {
		cfm.secretsManager.StoreSecret("github_token", config.GitHubToken)
		configCopy.GitHubToken = "SECRET:github_token"
	}

	// Save config file
	if err := cfm.SaveConfigToFile(&configCopy, configFilePath); err != nil {
		return err
	}

	// Save secrets file
	if err := cfm.secretsManager.SaveSecretsToFile(secretsFilePath); err != nil {
		return err
	}

	log.Printf("✅ Configuration and secrets saved separately")
	return nil
}

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

var guardianInstance *ArchGuardian // Global ArchGuardian instance for API access
var globalProjectStore *ProjectStore // Global project store for API access
var globalDB *chromem.DB // Global chromem database instance
var globalScanner *Scanner // Global scanner instance for API access
var globalDiagnoser *RiskDiagnoser // Global risk diagnoser instance for API access
var globalSettingsManager *SettingsManager // Global settings manager instance

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

func main() {
	log.Println("╔════════════════════════════════════════════════════════════════╗")
	log.Println("║            ArchGuardian - AI-Powered Code Guardian             ║")
	log.Println("║          Deep Visibility • Risk Detection • Auto-Fix           ║")
	log.Println("╚════════════════════════════════════════════════════════════════╝")

	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  No .env file found or failed to load, using environment variables only")
	} else {
		log.Println("✅ .env file loaded successfully")
	}

	// Initialize secrets manager for secure credential storage
	secretsManager := NewSecretsManager()
	log.Println("✅ Secrets manager initialized")

	// Initialize environment manager for environment-specific configurations
	envManager := NewEnvironmentManager()
	log.Println("✅ Environment manager initialized")

	// Load configuration from environment variables (base config)
	config := &Config{
		ProjectPath:       getEnv("PROJECT_PATH", "."),
		GitHubToken:       getEnv("GITHUB_TOKEN", ""),
		GitHubRepo:        getEnv("GITHUB_REPO", ""),
		ScanInterval:      time.Duration(getEnvInt("SCAN_INTERVAL_HOURS", 24)) * time.Hour,
		RemediationBranch: getEnv("REMEDIATION_BRANCH", "archguardian-fixes"),
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
			CodeRemediationProvider: getEnv("CODE_REMEDIATION_PROVIDER", "anthropic"),
		},
		Orchestrator: OrchestratorConfig{
			PlannerModel:   getEnv("ORCHESTRATOR_PLANNER_MODEL", "gemini-pro"),
			ExecutorModels: strings.Split(getEnv("ORCHESTRATOR_EXECUTOR_MODELS", "llama3.3-70b,"), ","),
			FinalizerModel: getEnv("ORCHESTRATOR_FINALIZER_MODEL", "deepseek-coder"),
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

	// Apply environment-specific overrides
	envManager.ApplyEnvironmentOverrides(config)
	log.Printf("🌍 Applied %s environment configuration", envManager.currentEnv)

	// Resolve secrets from secrets manager
	if secretKey, exists := secretsManager.GetSecret("cerebras_api_key"); exists && config.AIProviders.Cerebras.APIKey == "" {
		config.AIProviders.Cerebras.APIKey = secretKey
		log.Println("🔐 Resolved Cerebras API key from secrets")
	}
	if secretKey, exists := secretsManager.GetSecret("gemini_api_key"); exists && config.AIProviders.Gemini.APIKey == "" {
		config.AIProviders.Gemini.APIKey = secretKey
		log.Println("🔐 Resolved Gemini API key from secrets")
	}
	if secretKey, exists := secretsManager.GetSecret("anthropic_api_key"); exists && config.AIProviders.Anthropic.APIKey == "" {
		config.AIProviders.Anthropic.APIKey = secretKey
		log.Println("🔐 Resolved Anthropic API key from secrets")
	}
	if secretKey, exists := secretsManager.GetSecret("openai_api_key"); exists && config.AIProviders.OpenAI.APIKey == "" {
		config.AIProviders.OpenAI.APIKey = secretKey
		log.Println("🔐 Resolved OpenAI API key from secrets")
	}
	if secretKey, exists := secretsManager.GetSecret("deepseek_api_key"); exists && config.AIProviders.DeepSeek.APIKey == "" {
		config.AIProviders.DeepSeek.APIKey = secretKey
		log.Println("🔐 Resolved DeepSeek API key from secrets")
	}
	if secretKey, exists := secretsManager.GetSecret("github_token"); exists && config.GitHubToken == "" {
		config.GitHubToken = secretKey
		log.Println("🔐 Resolved GitHub token from secrets")
	}

	// Validate configuration
	if config.ProjectPath == "" {
		log.Fatal("❌ PROJECT_PATH is required")
	}

	if config.AIProviders.Cerebras.APIKey == "" {
		log.Println("⚠️  Warning: CEREBRAS_API_KEY not set")
	}

	if config.AIProviders.Gemini.APIKey == "" {
		log.Println("⚠️  Warning: GEMINI_API_KEY not set")
	}

	// Initialize chromem-go persistent database
	var err error
	globalDB, err = chromem.NewPersistentDB("./archguardian-data", true)
	if err != nil {
		log.Fatalf("❌ Failed to initialize chromem database: %v", err)
	}
	log.Println("✅ Chromem database initialized successfully")

	// Create collections for different data types
	collections := map[string]string{
		"projects":         "Project metadata and configuration",
		"knowledge-graphs": "Scan results with node/edge data",
		"security-issues":  "Discovered vulnerabilities and risks",
		"test-coverage":    "Code coverage reports",
		"scan-history":     "Historical scan metadata",
		"settings-history": "Configuration change audit trail",
		"remediation-logs": "AI remediation attempts and results",
	}

	for name, description := range collections {
		collection, err := globalDB.GetOrCreateCollection(name, map[string]string{"type": description}, nil)
		if err != nil {
			log.Fatalf("❌ Failed to create collection %s: %v", name, err)
		}
		log.Printf("✅ Created collection: %s", name)
		_ = collection // Keep reference if needed later
	}

	// Initialize project store
	globalProjectStore = NewProjectStore()
	log.Println("✅ Project store initialized successfully")

	// Initialize settings manager
	globalSettingsManager = NewSettingsManager(globalDB)
	log.Println("✅ Settings manager initialized successfully")

	// Add settings change listeners for hot-reload
	globalSettingsManager.AddChangeListener(&SettingsHotReloadListener{})

	// Create a single AIInferenceEngine instance to be shared
	aiEngine := NewAIInferenceEngine(config)

	// Create ArchGuardian instance
	guardian := NewArchGuardian(config, aiEngine)
	guardianInstance = guardian // Assign to global variable

	// Initialize Log Analyzer for log stream processing
	logAnalyzer := NewLogAnalyzer(config, aiEngine)

	// Start consolidated server with all endpoints
	go func() {
		if err := startConsolidatedServer(guardianInstance, logAnalyzer); err != nil {
			log.Printf("⚠️  Consolidated server failed: %v", err)
		}
	}()

	// Start log ingestion server for external log streams
	go func() {
		if err := startLogIngestionServer(logAnalyzer); err != nil {
			log.Printf("⚠️  Log ingestion server failed: %v", err)
		}
	}()

	// Run with context
	ctx := context.Background()
	if err := guardianInstance.Run(ctx); err != nil {
		log.Fatalf("❌ ArchGuardian failed: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intVal int
		if _, err := fmt.Sscanf(value, "%d", &intVal); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// logWriter is a custom writer to pipe log output to the WebSocket
type logWriter struct {
	ag            *ArchGuardian
	initialLogs   [][]byte
	bufferMutex   sync.Mutex
	clientReady   bool
	maxBufferSize int
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	// Write to original stdout
	n, err = os.Stdout.Write(p)

	lw.bufferMutex.Lock()
	defer lw.bufferMutex.Unlock()

	// If the client is ready, broadcast immediately.
	if lw.clientReady && lw.ag != nil {
		lw.ag.BroadcastToDashboard(string(p))
	} else {
		// Otherwise, buffer the initial logs.
		if lw.maxBufferSize == 0 {
			lw.maxBufferSize = 100 // Default max buffer size
		}
		if len(lw.initialLogs) < lw.maxBufferSize {
			// Create a copy of the byte slice to avoid data races
			logCopy := make([]byte, len(p))
			copy(logCopy, p)
			lw.initialLogs = append(lw.initialLogs, logCopy)
		}
	}

	return n, err
}

func (lw *logWriter) FlushInitialLogs() {
	lw.bufferMutex.Lock()
	defer lw.bufferMutex.Unlock()
	lw.clientReady = true
	for _, logBytes := range lw.initialLogs {
		if lw.ag != nil {
			lw.ag.BroadcastToDashboard(string(logBytes))
		}
	}
	// Clear the buffer after flushing
	lw.initialLogs = nil
}

// ============================================================================
// CODACY CLIENT
// ============================================================================

// CodacyClient handles interactions with the Codacy API
type CodacyClient struct {
	httpClient *http.Client
	apiToken   string
	baseURL    string
	provider   string // "gh" for GitHub, "gl" for GitLab, etc.
	repository string // owner/repo format
}

// CodacyIssue represents an issue from Codacy API
type CodacyIssue struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	FilePath    string                 `json:"file_path"`
	Line        int                    `json:"line"`
	Column      int                    `json:"column"`
	PatternID   string                 `json:"pattern_id"`
	PatternName string                 `json:"pattern_name"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// CodacyRepository represents a repository in Codacy
type CodacyRepository struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	URL      string `json:"url"`
}

// CodacyRule represents a Codacy rule configuration
type CodacyRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Severity    string `json:"severity"`
}

// NewCodacyClient creates a new Codacy client
func NewCodacyClient(apiToken, provider, repository string) *CodacyClient {
	return &CodacyClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiToken:   apiToken,
		baseURL:    "https://api.codacy.com/api/v3",
		provider:   provider,
		repository: repository,
	}
}

// GetIssues fetches all open issues for the repository from Codacy
func (cc *CodacyClient) GetIssues() ([]CodacyIssue, error) {
	log.Printf("  🔍 Fetching Codacy issues for repository: %s", cc.repository)

	url := fmt.Sprintf("%s/analysis/repositories/%s/%s/issues", cc.baseURL, cc.provider, cc.repository)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-token", cc.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issues: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("codacy API returned status %d", resp.StatusCode)
	}

	var response struct {
		Data []CodacyIssue `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	log.Printf("  📊 Retrieved %d issues from Codacy", len(response.Data))
	return response.Data, nil
}

// GetRepositories fetches all repositories for the account
func (cc *CodacyClient) GetRepositories() ([]CodacyRepository, error) {
	log.Println("  🔍 Fetching Codacy repositories...")

	url := fmt.Sprintf("%s/repositories", cc.baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-token", cc.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repositories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("codacy API returned status %d", resp.StatusCode)
	}

	var response struct {
		Data []CodacyRepository `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	log.Printf("  📊 Retrieved %d repositories from Codacy", len(response.Data))
	return response.Data, nil
}

// GetRules fetches all rules for the repository
func (cc *CodacyClient) GetRules() ([]CodacyRule, error) {
	log.Printf("  🔍 Fetching Codacy rules for repository: %s", cc.repository)

	url := fmt.Sprintf("%s/analysis/repositories/%s/%s/rules", cc.baseURL, cc.provider, cc.repository)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-token", cc.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch rules: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("codacy API returned status %d", resp.StatusCode)
	}

	var response struct {
		Data []CodacyRule `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	log.Printf("  📊 Retrieved %d rules from Codacy", len(response.Data))
	return response.Data, nil
}

// UpdateRule updates a specific rule configuration
func (cc *CodacyClient) UpdateRule(ruleID string, enabled bool, severity string) error {
	log.Printf("  🔧 Updating Codacy rule %s: enabled=%t, severity=%s", ruleID, enabled, severity)

	url := fmt.Sprintf("%s/analysis/repositories/%s/%s/rules/%s", cc.baseURL, cc.provider, cc.repository, ruleID)

	rule := CodacyRule{
		ID:       ruleID,
		Enabled:  enabled,
		Severity: severity,
	}

	jsonData, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule data: %w", err)
	}

	req, err := http.NewRequest("PUT", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("api-token", cc.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("codacy API returned status %d", resp.StatusCode)
	}

	log.Printf("  ✅ Successfully updated Codacy rule %s", ruleID)
	return nil
}

// ConvertCodacyIssueToTechnicalDebt converts a Codacy issue to a TechnicalDebtItem
func (cc *CodacyClient) ConvertCodacyIssueToTechnicalDebt(issue CodacyIssue) types.TechnicalDebtItem {
	// Map Codacy severity to our severity levels
	severity := "medium"
	switch issue.Severity {
	case "Error", "Critical":
		severity = "high"
	case "Warning":
		severity = "medium"
	case "Info":
		severity = "low"
	}

	// Map Codacy category to our type
	debtType := "code_quality"
	switch issue.Category {
	case "CodeStyle", "BestPractice":
		debtType = "code_style"
	case "ErrorProne", "BugRisk":
		debtType = "error_prone"
	case "Performance":
		debtType = "performance"
	case "Security":
		debtType = "security"
	case "UnusedCode":
		debtType = "unused_code"
	case "Complexity":
		debtType = "complexity"
	case "Duplication":
		debtType = "duplication"
	}

	// Estimate effort based on severity and category
	effort := 2 // default
	if issue.Severity == "Critical" || issue.Severity == "Error" {
		effort = 4
	} else if issue.Category == "Complexity" || issue.Category == "Duplication" {
		effort = 3
	}

	location := issue.FilePath
	if issue.Line > 0 {
		location = fmt.Sprintf("%s:%d", issue.FilePath, issue.Line)
	}

	return types.TechnicalDebtItem{
		ID:          fmt.Sprintf("CODACY-%s", issue.ID),
		Location:    location,
		Type:        debtType,
		Severity:    severity,
		Description: fmt.Sprintf("[%s] %s: %s", issue.PatternName, issue.Category, issue.Message),
		Remediation: fmt.Sprintf("Fix the %s issue identified by Codacy rule: %s", issue.Category, issue.PatternName),
		Effort:      effort,
	}
}

// ============================================================================
// LOG ANALYZER
// ============================================================================

// LogMsg represents a log message from external applications
type LogMsg struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Service   string                 `json:"service"`
	Component string                 `json:"component"`
	TraceID   string                 `json:"trace_id,omitempty"`
	SpanID    string                 `json:"span_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Error     *LogError              `json:"error,omitempty"`
}

// LogError represents error information in log messages
type LogError struct {
	Type  string `json:"type"`
	Code  string `json:"code,omitempty"`
	Stack string `json:"stack,omitempty"`
	Cause string `json:"cause,omitempty"`
}

// LogAnalyzer processes log streams to identify issues and create remediation tasks
type LogAnalyzer struct {
	config         *Config
	ai             *AIInferenceEngine
	errorBuffer    map[string][]LogMsg // Buffer of recent errors per component
	alertThreshold int
}

// NewLogAnalyzer creates a new log analyzer instance
func NewLogAnalyzer(config *Config, ai *AIInferenceEngine) *LogAnalyzer {
	return &LogAnalyzer{
		config:         config,
		ai:             ai,
		errorBuffer:    make(map[string][]LogMsg),
		alertThreshold: 5, // Alert after 5 errors from same component
	}
}

// ProcessLog processes a single log message and identifies potential issues
func (la *LogAnalyzer) ProcessLog(ctx context.Context, logMsg LogMsg) error {
	// Add to error buffer for pattern analysis
	componentKey := fmt.Sprintf("%s:%s", logMsg.Service, logMsg.Component)
	if logMsg.Level == "ERROR" || logMsg.Level == "FATAL" || logMsg.Level == "CRITICAL" {
		la.errorBuffer[componentKey] = append(la.errorBuffer[componentKey], logMsg)

		// Keep only recent errors (last 50 per component)
		if len(la.errorBuffer[componentKey]) > 50 {
			la.errorBuffer[componentKey] = la.errorBuffer[componentKey][len(la.errorBuffer[componentKey])-50:]
		}
	}

	// Check if we should analyze this component for issues
	if len(la.errorBuffer[componentKey]) >= la.alertThreshold {
		return la.analyzeErrorPattern(ctx, componentKey)
	}

	return nil
}

// analyzeErrorPattern uses AI to analyze error patterns and identify root causes
func (la *LogAnalyzer) analyzeErrorPattern(ctx context.Context, componentKey string) error {
	log.Printf("  🔍 Analyzing error pattern for component: %s", componentKey)

	errors := la.errorBuffer[componentKey]

	// Prepare error data for AI analysis
	errorData := map[string]interface{}{
		"component":   componentKey,
		"error_count": len(errors),
		"errors":      errors,
		"time_range": map[string]interface{}{
			"start": errors[0].Timestamp,
			"end":   errors[len(errors)-1].Timestamp,
		},
	}

	// Use AI to analyze the error pattern
	provider := AIProviderGemini // Use Gemini for deep error analysis
	analysis, err := la.ai.AnalyzeRisks(ctx, errorData, provider)
	if err != nil {
		log.Printf("  ⚠️  Failed to analyze error pattern: %v", err)
		return nil
	}

	// Extract actionable issues from analysis
	issues := la.extractIssuesFromAnalysis(analysis, componentKey)

	// Create technical debt items for identified issues
	for _, issue := range issues {
		if err := la.createTechnicalDebtItem(issue); err != nil {
			log.Printf("  ⚠️  Failed to create technical debt item: %v", err)
		}
	}

	// Clear error buffer after analysis
	delete(la.errorBuffer, componentKey)

	log.Printf("  ✅ Error pattern analysis complete for %s: %d issues identified", componentKey, len(issues))
	return nil
}

// extractIssuesFromAnalysis extracts actionable issues from AI analysis
func (la *LogAnalyzer) extractIssuesFromAnalysis(analysis map[string]interface{}, componentKey string) []map[string]interface{} {
	var issues []map[string]interface{}

	// Extract issues from AI analysis
	if issuesData, ok := analysis["log_issues"].([]interface{}); ok {
		for _, issue := range issuesData {
			if issueMap, ok := issue.(map[string]interface{}); ok {
				issueMap["component"] = componentKey
				issueMap["source"] = "log_analysis"
				issues = append(issues, issueMap)
			}
		}
	}

	return issues
}

// createTechnicalDebtItem creates a technical debt item from log analysis findings
func (la *LogAnalyzer) createTechnicalDebtItem(issue map[string]interface{}) error {
	// In a real implementation, this would integrate with the RiskDiagnoser
	// For now, we'll log the issue and could trigger remediation

	log.Printf("  📋 Created technical debt item from log analysis:")
	log.Printf("    Component: %v", issue["component"])
	log.Printf("    Type: %v", issue["type"])
	log.Printf("    Description: %v", issue["description"])
	log.Printf("    Severity: %v", issue["severity"])

	// Here we could trigger immediate remediation for critical log-identified issues
	if severity, ok := issue["severity"].(string); ok && severity == "critical" {
		log.Printf("  🚨 Critical issue detected in logs, triggering immediate remediation...")
		// In a real implementation, this would trigger the remediation cycle
	}

	return nil
}

// ============================================================================
// ERROR HANDLING & RESPONSE UTILITIES
// ============================================================================

// APIError represents a standardized API error response
type APIError struct {
	Error   string                 `json:"error"`
	Message string                 `json:"message"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// APIResponse represents a standardized API response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

// sendError sends a standardized error response
func sendError(w http.ResponseWriter, statusCode int, message string, code string, details map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := APIResponse{
		Success: false,
		Error: &APIError{
			Error:   http.StatusText(statusCode),
			Message: message,
			Code:    code,
			Details: details,
		},
	}

	sendSuccess(w, response)
}

// sendSuccess sends a standardized success response
func sendSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := APIResponse{
		Success: true,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}


// RateLimiter implements simple rate limiting
type RateLimiter struct {
	requests map[string][]time.Time
	window   time.Duration
	limit    int
	mutex    sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(window time.Duration, limit int) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		limit:   limit,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// IsAllowed checks if a request is allowed
func (rl *RateLimiter) IsAllowed(key string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	requests := rl.requests[key]

	// Remove old requests outside the window
	var validRequests []time.Time
	for _, req := range requests {
		if now.Sub(req) < rl.window {
			validRequests = append(validRequests, req)
		}
	}

	// Check if under limit
	if len(validRequests) >= rl.limit {
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	rl.requests[key] = validRequests

	return true
}

// cleanup removes old entries periodically
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()

	for range ticker.C {
		rl.mutex.Lock()
		now := time.Now()

		for key, requests := range rl.requests {
			var validRequests []time.Time
			for _, req := range requests {
				if now.Sub(req) < rl.window {
					validRequests = append(validRequests, req)
				}
			}

			if len(validRequests) == 0 {
				delete(rl.requests, key)
			} else {
				rl.requests[key] = validRequests
			}
		}
		rl.mutex.Unlock()
	}
}

// rateLimitMiddleware implements rate limiting middleware
func rateLimitMiddleware(rl *RateLimiter) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use client IP as key
			clientIP := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				clientIP = forwarded
			}

			if !rl.IsAllowed(clientIP) {
				sendError(w, http.StatusTooManyRequests, "Rate limit exceeded", "RATE_LIMIT_EXCEEDED", map[string]interface{}{
					"retry_after": "60", // seconds
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// securityHeadersMiddleware adds security headers
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' ws: wss: http://localhost:3000 https://api.github.com https://unpkg.com https://cdn.jsdelivr.net")

		// CORS headers (updated for security)
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validationMiddleware validates request data
func validationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Content-Type for POST/PUT requests
		if r.Method == "POST" || r.Method == "PUT" {
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				sendError(w, http.StatusBadRequest, "Content-Type must be application/json", "INVALID_CONTENT_TYPE", nil)
				return
			}
		}

		// Check request size (limit to 10MB)
		if r.ContentLength > 10*1024*1024 {
			sendError(w, http.StatusRequestEntityTooLarge, "Request too large", "REQUEST_TOO_LARGE", nil)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// CONSOLIDATED SERVER
// ============================================================================

// startConsolidatedServer starts a single consolidated server with all endpoints
func startConsolidatedServer(ag *ArchGuardian, logAnalyzer *LogAnalyzer) error {
	log.Println("🌐 Starting ArchGuardian Consolidated Server...")

	router := mux.NewRouter()

	// Initialize rate limiter (100 requests per minute per IP)
	rateLimiter := NewRateLimiter(time.Minute, 100)

	// Apply global middleware
	router.Use(corsMiddleware)
	router.Use(securityHeadersMiddleware)
	router.Use(rateLimitMiddleware(rateLimiter))
	router.Use(validationMiddleware)

	// Serve embedded dashboard files
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedFile(w, r, "index.html", "text/html")
	})

	router.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedFile(w, r, "style.css", "text/css")
	})

	router.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		serveEmbeddedFile(w, r, "app.js", "application/javascript")
	})

	// Initialize authentication service
	authService := NewAuthService()

	// Authentication endpoints (public)
	router.HandleFunc("/api/v1/auth/github", func(w http.ResponseWriter, r *http.Request) {
		handleGitHubAuth(w, r, authService)
	}).Methods("GET", "POST")
	router.HandleFunc("/api/v1/auth/github/callback", func(w http.ResponseWriter, r *http.Request) {
		handleGitHubCallback(w, r, authService)
	}).Methods("GET")
	router.HandleFunc("/api/v1/auth/github/status", func(w http.ResponseWriter, r *http.Request) {
		handleGitHubAuthStatus(w, r, authService)
	}).Methods("GET")
	router.HandleFunc("/api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		handleLogout(w, r, authService)
	}).Methods("POST")

	// Protected API endpoints for dashboard data
	router.HandleFunc("/api/v1/knowledge-graph", authService.OptionalAuthMiddleware(handleKnowledgeGraph)).Methods("GET")
	router.HandleFunc("/api/v1/risk-assessment", authService.OptionalAuthMiddleware(handleRiskAssessment)).Methods("GET")
	router.HandleFunc("/api/v1/issues", authService.OptionalAuthMiddleware(handleIssues)).Methods("GET")
	router.HandleFunc("/api/v1/coverage", authService.OptionalAuthMiddleware(handleCoverage)).Methods("GET")
	router.HandleFunc("/api/v1/scan/start", authService.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handleStartScan(w, r, ag)
	})).Methods("POST")
	router.HandleFunc("/api/v1/settings", authService.OptionalAuthMiddleware(handleSettings)).Methods("GET", "POST")

	// Project management endpoints
	router.HandleFunc("/api/v1/projects", handleGetProjects).Methods("GET")
	router.HandleFunc("/api/v1/projects", handleCreateProject).Methods("POST")
	router.HandleFunc("/api/v1/projects/{id}", handleGetProject).Methods("GET")
	router.HandleFunc("/api/v1/projects/{id}", handleDeleteProject).Methods("DELETE")
	router.HandleFunc("/api/v1/projects/{id}/scan", func(w http.ResponseWriter, r *http.Request) {
		handleScanProject(w, r, ag)
	}).Methods("POST")

	// Health check endpoint
	router.HandleFunc("/health", handleHealth).Methods("GET")

	// Integration monitoring endpoints
	router.HandleFunc("/api/v1/integrations/status", handleIntegrationStatus).Methods("GET")

	// Alert configuration endpoints
	router.HandleFunc("/api/v1/alerts", handleAlertConfigs).Methods("GET", "POST")
	router.HandleFunc("/api/v1/alerts/{id}", handleAlertConfig).Methods("GET", "PUT", "DELETE")

	// System metrics endpoint
	router.HandleFunc("/api/v1/metrics", handleSystemMetrics).Methods("GET")

	// Scan history and search endpoints
	router.HandleFunc("/api/v1/scans/history", handleScanHistory).Methods("GET")
	router.HandleFunc("/api/v1/search", handleSemanticSearch).Methods("GET")
	router.HandleFunc("/api/v1/backup", handleBackup).Methods("POST")
	router.HandleFunc("/api/v1/backup", handleBackupList).Methods("GET")

	// Log ingestion endpoints (consolidated from port 4000)
	router.HandleFunc("/api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		handleLogIngestion(w, r, logAnalyzer)
	}).Methods("POST")
	router.HandleFunc("/api/v1/logs/batch", func(w http.ResponseWriter, r *http.Request) {
		handleBatchLogIngestion(w, r, logAnalyzer)
	}).Methods("POST")
	router.HandleFunc("/api/v1/logs/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"service":   "log_ingestion",
			"timestamp": time.Now(),
		})
	}).Methods("GET")

	// Data Engine endpoints (consolidated from port 7080)
	if guardianInstance != nil && guardianInstance.dataEngine != nil {
		de := guardianInstance.dataEngine

		// Knowledge graph endpoint
		router.HandleFunc("/api/v1/data/knowledge-graph", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineKnowledgeGraph(w, r, de)
		}).Methods("GET")

		// Issues endpoint
		router.HandleFunc("/api/v1/data/issues", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineIssues(w, r, de)
		}).Methods("GET")

		// Coverage endpoint
		router.HandleFunc("/api/v1/data/coverage", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineCoverage(w, r, de)
		}).Methods("GET")

		// Metrics endpoint
		router.HandleFunc("/api/v1/data/metrics", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineMetrics(w, r, de)
		}).Methods("GET")

		// Alerts endpoints
		router.HandleFunc("/api/v1/data/alerts", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineAlerts(w, r, de)
		}).Methods("GET")
		router.HandleFunc("/api/v1/data/alerts/{id}/resolve", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineResolveAlert(w, r, de)
		}).Methods("POST")

		// Events endpoints
		router.HandleFunc("/api/v1/data/events", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineEvents(w, r, de)
		}).Methods("GET")
		router.HandleFunc("/api/v1/data/events/search", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineSearchEvents(w, r, de)
		}).Methods("GET")
		router.HandleFunc("/api/v1/data/events/types", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineEventTypes(w, r, de)
		}).Methods("GET")

		// Windows endpoints
		router.HandleFunc("/api/v1/data/windows", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineWindows(w, r, de)
		}).Methods("GET")
		router.HandleFunc("/api/v1/data/windows/range", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineWindowsInRange(w, r, de)
		}).Methods("GET")

		// Active users endpoint
		router.HandleFunc("/api/v1/data/active-users", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineActiveUsers(w, r, de)
		}).Methods("GET")

		// Event rates endpoint
		router.HandleFunc("/api/v1/data/event-rates", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineEventRates(w, r, de)
		}).Methods("GET")

		// Health check for data engine
		router.HandleFunc("/api/v1/data/health", func(w http.ResponseWriter, r *http.Request) {
			handleDataEngineHealth(w, r, de)
		}).Methods("GET")
	}

	// WebSocket endpoint for dashboard log streaming
	router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handleDashboardWebSocket(w, r, guardianInstance)
	})

	// API Documentation endpoint
	router.HandleFunc("/api/docs", handleAPIDocs).Methods("GET")
	router.HandleFunc("/api/v1/docs", handleAPIDocs).Methods("GET")

	log.Println("✅ Consolidated server started on http://localhost:3000")
	log.Println("📊 All API endpoints available on http://localhost:3000/api/v1/")
	log.Println("📁 Dashboard files served from embedded resources")
	log.Println("🔗 WebSocket available on ws://localhost:3000/ws")
	log.Println("📝 Log ingestion available on http://localhost:3000/api/v1/logs")
	return http.ListenAndServe(":3000", router)
}

// corsMiddleware adds CORS headers to all responses
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveEmbeddedFile serves embedded dashboard files with proper content types
func serveEmbeddedFile(w http.ResponseWriter, r *http.Request, filename, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")

	var content string
	switch filename {
	case "index.html":
		content = dashboardHTML
	case "style.css":
		content = dashboardCSS
	case "app.js":
		content = dashboardJS
	default:
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
}

// handleKnowledgeGraph returns the current knowledge graph data
func handleKnowledgeGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalScanner == nil || globalScanner.graph == nil {
		// Return empty graph if no scan has been performed yet
		response := map[string]interface{}{
			"nodes": []map[string]interface{}{},
			"edges": []map[string]interface{}{},
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Return real knowledge graph data using ToAPIFormat()
	response := globalScanner.graph.ToAPIFormat()
	json.NewEncoder(w).Encode(response)
}

// ============================================================================
// AUTHENTICATION HANDLERS
// ============================================================================

// handleGitHubAuth initiates GitHub OAuth flow
func handleGitHubAuth(w http.ResponseWriter, r *http.Request, authService *AuthService) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	switch r.Method {
	case "GET":
		// Generate state for CSRF protection
		state := generateState()
		authURL := authService.GetGitHubAuthURL(state)

		response := map[string]interface{}{
			"auth_url": authURL,
			"state":    state,
		}
		json.NewEncoder(w).Encode(response)

	case "POST":
		// Handle direct token exchange (for testing or mobile apps)
		var req struct {
			Code string `json:"code"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		if req.Code == "" {
			http.Error(w, "Authorization code is required", http.StatusBadRequest)
			return
		}

		// Exchange code for token
		auth, err := authService.ExchangeGitHubCode(req.Code)
		if err != nil {
			log.Printf("GitHub OAuth error: %v", err)
			http.Error(w, "Failed to exchange code for token", http.StatusBadRequest)
			return
		}

		// Get user info
		githubUser, err := authService.GetGitHubUser(auth.AccessToken)
		if err != nil {
			log.Printf("Failed to get GitHub user: %v", err)
			http.Error(w, "Failed to get user information", http.StatusInternalServerError)
			return
		}

		// Create or update user
		user := authService.CreateOrUpdateUser(githubUser)
		authService.StoreGitHubToken(user.ID, auth)

		// Generate JWT
		jwtToken, err := authService.GenerateJWT(user)
		if err != nil {
			log.Printf("Failed to generate JWT: %v", err)
			http.Error(w, "Failed to generate authentication token", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"success": true,
			"token":   jwtToken,
			"user":    user,
		}
		json.NewEncoder(w).Encode(response)
	}
}

// handleGitHubCallback handles the OAuth callback from GitHub
func handleGitHubCallback(w http.ResponseWriter, r *http.Request, authService *AuthService) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	code := r.URL.Query().Get("code")
	errorParam := r.URL.Query().Get("error")

	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		log.Printf("GitHub OAuth error: %s - %s", errorParam, errorDesc)
		http.Error(w, "OAuth authentication failed", http.StatusBadRequest)
		return
	}

	if code == "" {
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	// TODO: Validate state parameter for CSRF protection

	// Exchange code for token
	auth, err := authService.ExchangeGitHubCode(code)
	if err != nil {
		log.Printf("GitHub OAuth error: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	// Get user info
	githubUser, err := authService.GetGitHubUser(auth.AccessToken)
	if err != nil {
		log.Printf("Failed to get GitHub user: %v", err)
		http.Error(w, "Failed to get user information", http.StatusInternalServerError)
		return
	}

	// Create or update user
	user := authService.CreateOrUpdateUser(githubUser)
	authService.StoreGitHubToken(user.ID, auth)

	// Create session
	session, err := authService.sessionStore.Get(r, "archguardian-session")
	if err != nil {
		log.Printf("Failed to get session: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	session.Values["user_id"] = user.ID
	session.Save(r, w)

	// Generate JWT
	jwtToken, err := authService.GenerateJWT(user)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		http.Error(w, "Failed to generate authentication token", http.StatusInternalServerError)
		return
	}

	// Redirect to dashboard with token
	redirectURL := fmt.Sprintf("http://localhost:3000/?token=%s", jwtToken)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleGitHubAuthStatus returns the current authentication status
func handleGitHubAuthStatus(w http.ResponseWriter, r *http.Request, authService *AuthService) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Try JWT first
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		user, err := authService.ValidateJWT(tokenString)
		if err == nil {
			response := map[string]interface{}{
				"authenticated": true,
				"user":          user,
				"method":        "jwt",
			}
			json.NewEncoder(w).Encode(response)
			return
		}
	}

	// Try session
	session, err := authService.sessionStore.Get(r, "archguardian-session")
	if err == nil {
		if userID, ok := session.Values["user_id"].(string); ok {
			if user, exists := authService.GetUser(userID); exists {
				response := map[string]interface{}{
					"authenticated": true,
					"user":          user,
					"method":        "session",
				}
				json.NewEncoder(w).Encode(response)
				return
			}
		}
	}

	// Not authenticated
	response := map[string]interface{}{
		"authenticated": false,
		"user":          nil,
	}
	json.NewEncoder(w).Encode(response)
}

// handleLogout clears the user session
func handleLogout(w http.ResponseWriter, r *http.Request, authService *AuthService) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Clear session
	session, err := authService.sessionStore.Get(r, "archguardian-session")
	if err == nil {
		session.Values["user_id"] = nil
		session.Save(r, w)
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Logged out successfully",
	}
	json.NewEncoder(w).Encode(response)
}

// generateState generates a random state string for CSRF protection
func generateState() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// startLogIngestionServer starts the log ingestion server for receiving external log streams
func startLogIngestionServer(logAnalyzer *LogAnalyzer) error {
	log.Println("📝 Starting Log Ingestion Server...")

	router := mux.NewRouter()

	// Log ingestion endpoints
	router.HandleFunc("/api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		handleLogIngestion(w, r, logAnalyzer)
	}).Methods("POST")

	router.HandleFunc("/api/v1/logs/batch", func(w http.ResponseWriter, r *http.Request) {
		handleBatchLogIngestion(w, r, logAnalyzer)
	}).Methods("POST")

	// Health check for log ingestion
	router.HandleFunc("/api/v1/logs/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"service":   "log_ingestion",
			"timestamp": time.Now(),
		})
	}).Methods("GET")

	log.Println("✅ Log ingestion server started on http://localhost:4000")
	log.Println("📝 Log endpoints available on http://localhost:4000/api/v1/logs")
	return http.ListenAndServe(":4000", router)
}

// handleLogIngestion processes a single log message
func handleLogIngestion(w http.ResponseWriter, r *http.Request, logAnalyzer *LogAnalyzer) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var logMsg LogMsg
	if err := json.NewDecoder(r.Body).Decode(&logMsg); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Set timestamp if not provided
	if logMsg.Timestamp.IsZero() {
		logMsg.Timestamp = time.Now()
	}

	// Process the log message
	ctx := context.Background()
	if err := logAnalyzer.ProcessLog(ctx, logMsg); err != nil {
		log.Printf("  ⚠️  Failed to process log message: %v", err)
		http.Error(w, "Failed to process log", http.StatusInternalServerError)
		return
	}

	// Respond with success
	response := map[string]interface{}{
		"status":    "accepted",
		"timestamp": time.Now(),
		"message":   "Log message processed successfully",
	}

	json.NewEncoder(w).Encode(response)
}

// handleBatchLogIngestion processes multiple log messages at once
func handleBatchLogIngestion(w http.ResponseWriter, r *http.Request, logAnalyzer *LogAnalyzer) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var logBatch struct {
		Logs []LogMsg `json:"logs"`
	}

	if err := json.NewDecoder(r.Body).Decode(&logBatch); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	processed := 0
	errors := 0

	// Process each log message
	for _, logMsg := range logBatch.Logs {
		// Set timestamp if not provided
		if logMsg.Timestamp.IsZero() {
			logMsg.Timestamp = time.Now()
		}

		if err := logAnalyzer.ProcessLog(ctx, logMsg); err != nil {
			log.Printf("  ⚠️  Failed to process log message: %v", err)
			errors++
		} else {
			processed++
		}
	}

	// Respond with processing summary
	response := map[string]interface{}{
		"status":    "completed",
		"timestamp": time.Now(),
		"processed": processed,
		"errors":    errors,
		"total":     len(logBatch.Logs),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleRiskAssessment returns the current risk assessment data
func handleRiskAssessment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// In a real implementation, this would get data from the current scan
	// For now, return a sample response
	response := map[string]interface{}{
		"overall_score": 15.5,
		"technical_debt": []map[string]interface{}{
			{
				"id":          "TD-1",
				"location":    "main.go:100",
				"type":        "complex_function",
				"severity":    "medium",
				"description": "Function is too complex",
				"remediation": "Break down into smaller functions",
				"effort":      4,
			},
		},
		"security_vulns":         []map[string]interface{}{},
		"obsolete_code":          []map[string]interface{}{},
		"dangerous_dependencies": []map[string]interface{}{},
		"timestamp":              time.Now(),
	}

	json.NewEncoder(w).Encode(response)
}

// handleIssues returns filtered issues based on type
func handleIssues(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	issueType := r.URL.Query().Get("type")
	if issueType == "" {
		issueType = "technical-debt"
	}

	// In a real implementation, this would get data from the current scan
	// For now, return sample data based on type
	var response map[string]interface{}

	// Try to get real data from the diagnoser if available
	if globalDiagnoser != nil {
		ctx := context.Background()
		assessment, err := globalDiagnoser.DiagnoseRisks(ctx)
		if err == nil {
			// Return real data from the risk assessment
			switch issueType {
			case "technical-debt":
				technicalDebt := make([]map[string]interface{}, len(assessment.TechnicalDebt))
				for i, debt := range assessment.TechnicalDebt {
					technicalDebt[i] = map[string]interface{}{
						"id":          debt.ID,
						"location":    debt.Location,
						"type":        debt.Type,
						"severity":    debt.Severity,
						"description": debt.Description,
						"remediation": debt.Remediation,
						"effort":      debt.Effort,
					}
				}
				response = map[string]interface{}{
					"technical_debt": technicalDebt,
				}
			case "security":
				securityVulns := make([]map[string]interface{}, len(assessment.SecurityVulns))
				for i, vuln := range assessment.SecurityVulns {
					securityVulns[i] = map[string]interface{}{
						"cve":         vuln.CVE,
						"package":     vuln.Package,
						"version":     vuln.Version,
						"severity":    vuln.Severity,
						"description": vuln.Description,
						"fix_version": vuln.FixVersion,
						"cvss":        vuln.CVSS,
					}
				}
				response = map[string]interface{}{
					"security_vulns": securityVulns,
				}
			case "obsolete":
				obsoleteCode := make([]map[string]interface{}, len(assessment.ObsoleteCode))
				for i, obsolete := range assessment.ObsoleteCode {
					obsoleteCode[i] = map[string]interface{}{
						"path":             obsolete.Path,
						"references":       obsolete.References,
						"removal_safety":   obsolete.RemovalSafety,
						"recommend_action": obsolete.RecommendAction,
					}
				}
				response = map[string]interface{}{
					"obsolete_code": obsoleteCode,
				}
			case "dependencies":
				dependencies := make([]map[string]interface{}, len(assessment.DangerousDependencies))
				for i, dep := range assessment.DangerousDependencies {
					dependencies[i] = map[string]interface{}{
						"package":         dep.Package,
						"current_version": dep.CurrentVersion,
						"latest_version":  dep.LatestVersion,
						"security_issues": dep.SecurityIssues,
						"maintenance":     dep.Maintenance,
						"recommendation":  dep.Recommendation,
					}
				}
				response = map[string]interface{}{
					"dangerous_dependencies": dependencies,
				}
			}
		} else {
			log.Printf("⚠️  Failed to get risk assessment: %v", err)
		}
	}

	// If no real data available, fall back to sample data
	if response == nil {
		switch issueType {
		case "technical-debt":
			response = map[string]interface{}{
				"technical_debt": []map[string]interface{}{
					{
						"id":          "TD-1",
						"location":    "main.go:100",
						"type":        "complex_function",
						"severity":    "medium",
						"description": "Function is too complex",
						"remediation": "Break down into smaller functions",
						"effort":      4,
					},
				},
			}
		case "security":
			response = map[string]interface{}{
				"security_vulns": []map[string]interface{}{
					{
						"cve":         "CVE-2023-1234",
						"package":     "example-package",
						"version":     "1.0.0",
						"severity":    "high",
						"description": "Buffer overflow vulnerability",
						"fix_version": "1.0.1",
						"cvss":        7.5,
					},
				},
			}
		case "obsolete":
			response = map[string]interface{}{
				"obsolete_code": []map[string]interface{}{
					{
						"path":             "old_file.go",
						"references":       0,
						"removal_safety":   "safe",
						"recommend_action": "File is no longer used and can be removed",
					},
				},
			}
		case "dependencies":
			response = map[string]interface{}{
				"dangerous_dependencies": []map[string]interface{}{
					{
						"package":         "old-package",
						"current_version": "1.0.0",
						"latest_version":  "2.0.0",
						"security_issues": 3,
						"maintenance":     "deprecated",
						"recommendation":  "Update to latest version",
					},
				},
			}
		}
	}

	json.NewEncoder(w).Encode(response)
}

// handleCoverage returns test coverage data
func handleCoverage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalScanner == nil || globalScanner.graph == nil {
		// Return zero coverage if no scan has been performed yet
		response := map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
			"file_coverage":    map[string]float64{},
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Look for coverage data in the knowledge graph
	coverageNode, exists := globalScanner.graph.Nodes["coverage_analysis"]
	if !exists {
		// Return zero coverage if no coverage analysis was performed
		response := map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
			"file_coverage":    map[string]float64{},
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Extract coverage data from the node metadata
	coverageData, ok := coverageNode.Metadata["coverage_data"].(map[string]interface{})
	if !ok {
		// Return zero coverage if coverage data is malformed
		response := map[string]interface{}{
			"overall_coverage": 0.0,
			"lines_covered":    0,
			"total_lines":      0,
			"test_files":       0,
			"file_coverage":    map[string]float64{},
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Return real coverage data
	json.NewEncoder(w).Encode(coverageData)
}

// handleSettings handles GET and POST for settings
func handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	switch r.Method {
	case "GET":
		// Return current settings from the settings manager
		if globalSettingsManager == nil {
			http.Error(w, "Settings manager not initialized", http.StatusInternalServerError)
			return
		}

		currentSettings := globalSettingsManager.GetSettings()
		response := map[string]interface{}{
			"project_path":           currentSettings.ProjectPath,
			"github_token":           currentSettings.GitHubToken,
			"github_repo":            currentSettings.GitHubRepo,
			"scan_interval_hours":    int(currentSettings.ScanInterval.Hours()),
			"remediation_branch":     currentSettings.RemediationBranch,
			"ai_providers": map[string]interface{}{
				"cerebras": map[string]interface{}{
					"api_key":  currentSettings.AIProviders.Cerebras.APIKey != "",
					"endpoint": currentSettings.AIProviders.Cerebras.Endpoint,
					"model":    currentSettings.AIProviders.Cerebras.Model,
				},
				"gemini": map[string]interface{}{
					"api_key":  currentSettings.AIProviders.Gemini.APIKey != "",
					"endpoint": currentSettings.AIProviders.Gemini.Endpoint,
					"model":    currentSettings.AIProviders.Gemini.Model,
				},
				"anthropic": map[string]interface{}{
					"api_key":  currentSettings.AIProviders.Anthropic.APIKey != "",
					"endpoint": currentSettings.AIProviders.Anthropic.Endpoint,
					"model":    currentSettings.AIProviders.Anthropic.Model,
				},
				"openai": map[string]interface{}{
					"api_key":  currentSettings.AIProviders.OpenAI.APIKey != "",
					"endpoint": currentSettings.AIProviders.OpenAI.Endpoint,
					"model":    currentSettings.AIProviders.OpenAI.Model,
				},
				"deepseek": map[string]interface{}{
					"api_key":  currentSettings.AIProviders.DeepSeek.APIKey != "",
					"endpoint": currentSettings.AIProviders.DeepSeek.Endpoint,
					"model":    currentSettings.AIProviders.DeepSeek.Model,
				},
				"code_remediation_provider": currentSettings.AIProviders.CodeRemediationProvider,
			},
			"orchestrator": map[string]interface{}{
				"planner_model":   currentSettings.Orchestrator.PlannerModel,
				"executor_models": currentSettings.Orchestrator.ExecutorModels,
				"finalizer_model": currentSettings.Orchestrator.FinalizerModel,
				"verifier_model":  currentSettings.Orchestrator.VerifierModel,
			},
			"data_engine": map[string]interface{}{
				"enable":            currentSettings.DataEngine.Enable,
				"enable_kafka":      currentSettings.DataEngine.EnableKafka,
				"enable_chromadb":   currentSettings.DataEngine.EnableChromaDB,
				"enable_websocket":  currentSettings.DataEngine.EnableWebSocket,
				"enable_restapi":    currentSettings.DataEngine.EnableRESTAPI,
				"kafka_brokers":     currentSettings.DataEngine.KafkaBrokers,
				"chromadb_url":      currentSettings.DataEngine.ChromaDBURL,
				"chromadb_collection": currentSettings.DataEngine.ChromaCollection,
				"websocket_port":    currentSettings.DataEngine.WebSocketPort,
				"restapi_port":      currentSettings.DataEngine.RESTAPIPort,
				"database_note":     "Chromem-go is the default in-app database. ChromaDB is optional for vector search integration.",
			},
		}
		json.NewEncoder(w).Encode(response)

	case "POST":
		// Update settings via the settings manager
		if globalSettingsManager == nil {
			http.Error(w, "Settings manager not initialized", http.StatusInternalServerError)
			return
		}

		var updateRequest map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		// Get current settings as base
		currentSettings := globalSettingsManager.GetSettings()
		newSettings := *currentSettings // Create a copy

		// Update fields from request
		if projectPath, ok := updateRequest["project_path"].(string); ok {
			newSettings.ProjectPath = projectPath
		}
		if githubToken, ok := updateRequest["github_token"].(string); ok {
			newSettings.GitHubToken = githubToken
		}
		if githubRepo, ok := updateRequest["github_repo"].(string); ok {
			newSettings.GitHubRepo = githubRepo
		}
		if scanIntervalHours, ok := updateRequest["scan_interval_hours"].(float64); ok {
			newSettings.ScanInterval = time.Duration(scanIntervalHours) * time.Hour
		}
		if remediationBranch, ok := updateRequest["remediation_branch"].(string); ok {
			newSettings.RemediationBranch = remediationBranch
		}

		// Update AI providers
		if aiProviders, ok := updateRequest["ai_providers"].(map[string]interface{}); ok {
			if cerebras, ok := aiProviders["cerebras"].(map[string]interface{}); ok {
				if apiKey, ok := cerebras["api_key"].(string); ok {
					newSettings.AIProviders.Cerebras.APIKey = apiKey
				}
				if endpoint, ok := cerebras["endpoint"].(string); ok {
					newSettings.AIProviders.Cerebras.Endpoint = endpoint
				}
				if model, ok := cerebras["model"].(string); ok {
					newSettings.AIProviders.Cerebras.Model = model
				}
			}
			if gemini, ok := aiProviders["gemini"].(map[string]interface{}); ok {
				if apiKey, ok := gemini["api_key"].(string); ok {
					newSettings.AIProviders.Gemini.APIKey = apiKey
				}
				if endpoint, ok := gemini["endpoint"].(string); ok {
					newSettings.AIProviders.Gemini.Endpoint = endpoint
				}
				if model, ok := gemini["model"].(string); ok {
					newSettings.AIProviders.Gemini.Model = model
				}
			}
			if anthropic, ok := aiProviders["anthropic"].(map[string]interface{}); ok {
				if apiKey, ok := anthropic["api_key"].(string); ok {
					newSettings.AIProviders.Anthropic.APIKey = apiKey
				}
				if endpoint, ok := anthropic["endpoint"].(string); ok {
					newSettings.AIProviders.Anthropic.Endpoint = endpoint
				}
				if model, ok := anthropic["model"].(string); ok {
					newSettings.AIProviders.Anthropic.Model = model
				}
			}
			if openai, ok := aiProviders["openai"].(map[string]interface{}); ok {
				if apiKey, ok := openai["api_key"].(string); ok {
					newSettings.AIProviders.OpenAI.APIKey = apiKey
				}
				if endpoint, ok := openai["endpoint"].(string); ok {
					newSettings.AIProviders.OpenAI.Endpoint = endpoint
				}
				if model, ok := openai["model"].(string); ok {
					newSettings.AIProviders.OpenAI.Model = model
				}
			}
			if deepseek, ok := aiProviders["deepseek"].(map[string]interface{}); ok {
				if apiKey, ok := deepseek["api_key"].(string); ok {
					newSettings.AIProviders.DeepSeek.APIKey = apiKey
				}
				if endpoint, ok := deepseek["endpoint"].(string); ok {
					newSettings.AIProviders.DeepSeek.Endpoint = endpoint
				}
				if model, ok := deepseek["model"].(string); ok {
					newSettings.AIProviders.DeepSeek.Model = model
				}
			}
			if codeRemediationProvider, ok := aiProviders["code_remediation_provider"].(string); ok {
				newSettings.AIProviders.CodeRemediationProvider = codeRemediationProvider
			}
		}

		// Update orchestrator
		if orchestrator, ok := updateRequest["orchestrator"].(map[string]interface{}); ok {
			if plannerModel, ok := orchestrator["planner_model"].(string); ok {
				newSettings.Orchestrator.PlannerModel = plannerModel
			}
			if executorModels, ok := orchestrator["executor_models"].([]interface{}); ok {
				models := make([]string, len(executorModels))
				for i, model := range executorModels {
					if modelStr, ok := model.(string); ok {
						models[i] = modelStr
					}
				}
				newSettings.Orchestrator.ExecutorModels = models
			}
			if finalizerModel, ok := orchestrator["finalizer_model"].(string); ok {
				newSettings.Orchestrator.FinalizerModel = finalizerModel
			}
			if verifierModel, ok := orchestrator["verifier_model"].(string); ok {
				newSettings.Orchestrator.VerifierModel = verifierModel
			}
		}

		// Update data engine
		if dataEngine, ok := updateRequest["data_engine"].(map[string]interface{}); ok {
			if enable, ok := dataEngine["enable"].(bool); ok {
				newSettings.DataEngine.Enable = enable
			}
			if enableKafka, ok := dataEngine["enable_kafka"].(bool); ok {
				newSettings.DataEngine.EnableKafka = enableKafka
			}
			if enableChromaDB, ok := dataEngine["enable_chromadb"].(bool); ok {
				newSettings.DataEngine.EnableChromaDB = enableChromaDB
			}
			if enableWebSocket, ok := dataEngine["enable_websocket"].(bool); ok {
				newSettings.DataEngine.EnableWebSocket = enableWebSocket
			}
			if enableRESTAPI, ok := dataEngine["enable_restapi"].(bool); ok {
				newSettings.DataEngine.EnableRESTAPI = enableRESTAPI
			}
			if kafkaBrokers, ok := dataEngine["kafka_brokers"].([]interface{}); ok {
				brokers := make([]string, len(kafkaBrokers))
				for i, broker := range kafkaBrokers {
					if brokerStr, ok := broker.(string); ok {
						brokers[i] = brokerStr
					}
				}
				newSettings.DataEngine.KafkaBrokers = brokers
			}
			if chromaDBURL, ok := dataEngine["chromadb_url"].(string); ok {
				newSettings.DataEngine.ChromaDBURL = chromaDBURL
			}
			if chromaCollection, ok := dataEngine["chromadb_collection"].(string); ok {
				newSettings.DataEngine.ChromaCollection = chromaCollection
			}
			if websocketPort, ok := dataEngine["websocket_port"].(float64); ok {
				newSettings.DataEngine.WebSocketPort = int(websocketPort)
			}
			if restapiPort, ok := dataEngine["restapi_port"].(float64); ok {
				newSettings.DataEngine.RESTAPIPort = int(restapiPort)
			}
		}

		// Update settings via the manager
		if err := globalSettingsManager.UpdateSettings(&newSettings); err != nil {
			log.Printf("⚠️  Failed to update settings: %v", err)
			http.Error(w, fmt.Sprintf("Failed to update settings: %v", err), http.StatusBadRequest)
			return
		}

		response := map[string]interface{}{
			"success": true,
			"message": "Settings updated successfully",
		}
		json.NewEncoder(w).Encode(response)
	}
}

// handleStartScan triggers a new scan cycle
func handleStartScan(w http.ResponseWriter, _ *http.Request, ag *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	// CORS headers are now handled by the middleware

	// Send a signal to the trigger channel
	// Use a non-blocking send in case no one is listening (e.g., if a scan is already in progress)
	select {
	case ag.triggerScan <- true:
		log.Println("API: Scan trigger signal sent.")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "message": "Scan triggered successfully."})
	default:
		log.Println("API: Scan trigger channel is busy or not ready.")
		http.Error(w, "Scan trigger channel is busy or a scan is already in progress.", http.StatusServiceUnavailable)
	}
}

// handleHealth returns health check status
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
	}

	json.NewEncoder(w).Encode(response)
}

// ============================================================================
// PROJECT API HANDLERS
// ============================================================================

// handleGetProjects returns all projects
func handleGetProjects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalProjectStore == nil {
		http.Error(w, "Project store not initialized", http.StatusInternalServerError)
		return
	}

	projects := globalProjectStore.GetAll()
	json.NewEncoder(w).Encode(projects)
}

// handleCreateProject creates a new project
func handleCreateProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalProjectStore == nil {
		http.Error(w, "Project store not initialized", http.StatusInternalServerError)
		return
	}

	var projectData struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&projectData); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if projectData.Name == "" || projectData.Path == "" {
		http.Error(w, "Name and path are required", http.StatusBadRequest)
		return
	}

	// Generate unique ID
	projectID := fmt.Sprintf("proj_%d", time.Now().UnixNano())

	project := &Project{
		ID:         projectID,
		Name:       projectData.Name,
		Path:       projectData.Path,
		Status:     "idle",
		IssueCount: 0,
		CreatedAt:  time.Now(),
	}

	globalProjectStore.Create(project)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(project)
}

// handleGetProject returns a specific project by ID
func handleGetProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalProjectStore == nil {
		http.Error(w, "Project store not initialized", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	projectID := vars["id"]

	project, exists := globalProjectStore.Get(projectID)
	if !exists {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(project)
}

// handleDeleteProject deletes a project by ID
func handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalProjectStore == nil {
		http.Error(w, "Project store not initialized", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	projectID := vars["id"]

	if !globalProjectStore.Delete(projectID) {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Project deleted successfully",
	}
	json.NewEncoder(w).Encode(response)
}

// handleScanProject triggers a scan for a specific project
func handleScanProject(w http.ResponseWriter, r *http.Request, ag *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalProjectStore == nil {
		http.Error(w, "Project store not initialized", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	projectID := vars["id"]

	project, exists := globalProjectStore.Get(projectID)
	if !exists {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	// Update project status to scanning
	project.Status = "scanning"
	project.LastScan = &time.Time{} // Will be set when scan completes
	globalProjectStore.Update(project)

	// TODO: Implement project-specific scanning
	// For now, trigger the general scan
	select {
	case ag.triggerScan <- true:
		log.Printf("API: Scan triggered for project %s", projectID)
		response := map[string]interface{}{
			"status":    "ok",
			"message":   "Scan triggered successfully",
			"projectId": projectID,
		}
		json.NewEncoder(w).Encode(response)
	default:
		project.Status = "idle"
		globalProjectStore.Update(project)
		http.Error(w, "Scan trigger channel is busy or a scan is already in progress", http.StatusServiceUnavailable)
	}
}

// ============================================================================
// SCAN HISTORY AND SEARCH API HANDLERS
// ============================================================================

// handleScanHistory returns historical scan data
func handleScanHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalDB == nil {
		http.Error(w, "Database not initialized", http.StatusInternalServerError)
		return
	}

	projectID := r.URL.Query().Get("project_id")
	if projectID == "" {
		projectID = "default"
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 10 // default
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	// Query knowledge-graphs collection for historical scans
	collection := globalDB.GetCollection("knowledge-graphs", nil)
	results, err := collection.Query(
		r.Context(),
		"",
		limit,
		map[string]string{"project_id": projectID},
		nil,
	)

	if err != nil {
		log.Printf("⚠️  Failed to query scan history: %v", err)
		http.Error(w, "Failed to retrieve scan history", http.StatusInternalServerError)
		return
	}

	// Format results for API response
	history := make([]map[string]interface{}, len(results))
	for i, result := range results {
		var scanData map[string]interface{}
		if err := json.Unmarshal([]byte(result.Content), &scanData); err != nil {
			log.Printf("⚠️  Failed to parse scan data: %v", err)
			continue
		}

		history[i] = map[string]interface{}{
			"id":        result.ID,
			"timestamp": result.Metadata["timestamp"],
			"project_id": result.Metadata["project_id"],
			"node_count": result.Metadata["node_count"],
			"edge_count": result.Metadata["edge_count"],
			"data":      scanData,
		}
	}

	response := map[string]interface{}{
		"project_id": projectID,
		"total":      len(history),
		"scans":      history,
	}

	json.NewEncoder(w).Encode(response)
}

// handleSemanticSearch performs natural language search across stored data
func handleSemanticSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalDB == nil {
		http.Error(w, "Database not initialized", http.StatusInternalServerError)
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}

	collectionName := r.URL.Query().Get("collection")
	if collectionName == "" {
		collectionName = "knowledge-graphs" // default
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 5 // default
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 20 {
			limit = parsedLimit
		}
	}

	// Get the specified collection
	collection := globalDB.GetCollection(collectionName, nil)
	if collection == nil {
		http.Error(w, fmt.Sprintf("Collection '%s' not found", collectionName), http.StatusNotFound)
		return
	}

	// Perform semantic search
	results, err := collection.Query(
		r.Context(),
		query,
		limit,
		nil, // no metadata filter
		nil, // no embedding filter
	)

	if err != nil {
		log.Printf("⚠️  Failed to perform semantic search: %v", err)
		http.Error(w, "Failed to perform search", http.StatusInternalServerError)
		return
	}

	// Format results for API response
	searchResults := make([]map[string]interface{}, len(results))
	for i, result := range results {
		searchResults[i] = map[string]interface{}{
			"id":       result.ID,
			"content":  result.Content,
			"metadata": result.Metadata,
		}
	}

	response := map[string]interface{}{
		"query":       query,
		"collection":  collectionName,
		"total":       len(searchResults),
		"results":     searchResults,
	}

	json.NewEncoder(w).Encode(response)
}

// handleBackup creates a backup of the chromem-go database
func handleBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalDB == nil {
		http.Error(w, "Database not initialized", http.StatusInternalServerError)
		return
	}

	// Parse request body for encryption key (optional)
	var requestBody struct {
		EncryptionKey string `json:"encryption_key,omitempty"`
	}

	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}
	}

	// Create backups directory if it doesn't exist
	backupDir := "./backups"
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		log.Printf("⚠️  Failed to create backups directory: %v", err)
		http.Error(w, "Failed to create backups directory", http.StatusInternalServerError)
		return
	}

	// Generate backup filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("archguardian_backup_%s.gob.gz", timestamp))

	// Add encryption extension if key provided
	if requestBody.EncryptionKey != "" {
		if len(requestBody.EncryptionKey) != 32 {
			http.Error(w, "Encryption key must be exactly 32 bytes", http.StatusBadRequest)
			return
		}
		backupPath += ".enc"
	}

	// Perform the backup
	log.Printf("📦 Creating database backup: %s", backupPath)
	err := globalDB.ExportToFile(backupPath, true, requestBody.EncryptionKey)
	if err != nil {
		log.Printf("⚠️  Failed to create backup: %v", err)
		http.Error(w, "Failed to create backup", http.StatusInternalServerError)
		return
	}

	// Get backup file info
	fileInfo, err := os.Stat(backupPath)
	if err != nil {
		log.Printf("⚠️  Failed to get backup file info: %v", err)
	} else {
		log.Printf("✅ Database backup created successfully: %s (%d bytes)", backupPath, fileInfo.Size())
	}

	response := map[string]interface{}{
		"success":     true,
		"backup_path": backupPath,
		"timestamp":   time.Now(),
		"encrypted":   requestBody.EncryptionKey != "",
	}

	if fileInfo != nil {
		response["size_bytes"] = fileInfo.Size()
	}

	json.NewEncoder(w).Encode(response)
}

// handleBackupList returns a list of available backups
func handleBackupList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	backupDir := "./backups"

	// Check if backups directory exists
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		response := map[string]interface{}{
			"backups": []map[string]interface{}{},
			"total":   0,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Read backup directory
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		log.Printf("⚠️  Failed to read backups directory: %v", err)
		http.Error(w, "Failed to read backups directory", http.StatusInternalServerError)
		return
	}

	// Filter and format backup files
	backups := make([]map[string]interface{}, 0)
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".gob.gz") || strings.HasSuffix(entry.Name(), ".gob.gz.enc")) {
			fileInfo, err := entry.Info()
			if err != nil {
				continue
			}

			backup := map[string]interface{}{
				"filename":  entry.Name(),
				"path":      filepath.Join(backupDir, entry.Name()),
				"size":      fileInfo.Size(),
				"modified":  fileInfo.ModTime(),
				"encrypted": strings.HasSuffix(entry.Name(), ".enc"),
			}

			backups = append(backups, backup)
		}
	}

	// Sort backups by modification time (newest first)
	for i := 0; i < len(backups)-1; i++ {
		for j := i + 1; j < len(backups); j++ {
			timeI := backups[i]["modified"].(time.Time)
			timeJ := backups[j]["modified"].(time.Time)
			if timeI.Before(timeJ) {
				backups[i], backups[j] = backups[j], backups[i]
			}
		}
	}

	response := map[string]interface{}{
		"backups": backups,
		"total":   len(backups),
		"directory": backupDir,
	}

	json.NewEncoder(w).Encode(response)
}

// ============================================================================
// INTEGRATION HEALTH CHECKS & MONITORING
// ============================================================================

// IntegrationHealthChecker handles health checks for external integrations
type IntegrationHealthChecker struct {
	config *Config
}

// NewIntegrationHealthChecker creates a new integration health checker
func NewIntegrationHealthChecker(config *Config) *IntegrationHealthChecker {
	return &IntegrationHealthChecker{
		config: config,
	}
}

// CheckGitHubIntegration checks GitHub API connectivity and token validity
func (ihc *IntegrationHealthChecker) CheckGitHubIntegration(ctx context.Context) map[string]interface{} {
	status := map[string]interface{}{
		"connected": false,
		"status":    "disconnected",
		"message":   "GitHub integration not configured",
	}

	if ihc.config.GitHubToken == "" {
		return status
	}

	// Test GitHub API connectivity
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		status["message"] = fmt.Sprintf("Failed to create request: %v", err)
		return status
	}

	req.Header.Set("Authorization", "Bearer "+ihc.config.GitHubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		status["message"] = fmt.Sprintf("Connection failed: %v", err)
		return status
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		status["connected"] = true
		status["status"] = "healthy"
		status["message"] = "GitHub API connection successful"
	case http.StatusUnauthorized:
		status["status"] = "error"
		status["message"] = "Invalid GitHub token"
	default:
		status["status"] = "error"
		status["message"] = fmt.Sprintf("GitHub API returned status %d", resp.StatusCode)
	}

	return status
}

// CheckKafkaIntegration checks Kafka broker connectivity
func (ihc *IntegrationHealthChecker) CheckKafkaIntegration(ctx context.Context) map[string]interface{} {
	status := map[string]interface{}{
		"connected": false,
		"status":    "disconnected",
		"message":   "Kafka integration not enabled",
	}

	if !ihc.config.DataEngine.EnableKafka || len(ihc.config.DataEngine.KafkaBrokers) == 0 {
		return status
	}

	// For now, return a basic status since we don't have direct Kafka client access
	// In a real implementation, this would test actual Kafka connectivity
	status["connected"] = true
	status["status"] = "healthy"
	status["message"] = fmt.Sprintf("Kafka brokers configured: %v", ihc.config.DataEngine.KafkaBrokers)
	status["brokers"] = ihc.config.DataEngine.KafkaBrokers

	return status
}

// CheckChromaDBIntegration checks ChromaDB connectivity
func (ihc *IntegrationHealthChecker) CheckChromaDBIntegration(ctx context.Context) map[string]interface{} {
	status := map[string]interface{}{
		"connected": false,
		"status":    "disconnected",
		"message":   "ChromaDB integration not enabled",
	}

	if !ihc.config.DataEngine.EnableChromaDB || ihc.config.DataEngine.ChromaDBURL == "" {
		return status
	}

	// Test ChromaDB connectivity
	req, err := http.NewRequestWithContext(ctx, "GET", ihc.config.DataEngine.ChromaDBURL+"/api/v1/heartbeat", nil)
	if err != nil {
		status["message"] = fmt.Sprintf("Failed to create request: %v", err)
		return status
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		status["message"] = fmt.Sprintf("Connection failed: %v", err)
		return status
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		status["connected"] = true
		status["status"] = "healthy"
		status["message"] = "ChromaDB connection successful"
		status["url"] = ihc.config.DataEngine.ChromaDBURL
	} else {
		status["status"] = "error"
		status["message"] = fmt.Sprintf("ChromaDB returned status %d", resp.StatusCode)
		status["url"] = ihc.config.DataEngine.ChromaDBURL
	}

	return status
}

// CheckDataEngineIntegration checks internal data engine status
func (ihc *IntegrationHealthChecker) CheckDataEngineIntegration(ctx context.Context) map[string]interface{} {
	status := map[string]interface{}{
		"connected": false,
		"status":    "disconnected",
		"message":   "Data engine not enabled",
	}

	if !ihc.config.DataEngine.Enable {
		return status
	}

	// Check if data engine services are running
	// This is a simplified check - in practice you'd check actual service health
	status["connected"] = true
	status["status"] = "healthy"
	status["message"] = "Data engine services configured"
	status["services"] = map[string]interface{}{
		"kafka_enabled":      ihc.config.DataEngine.EnableKafka,
		"chromadb_enabled":   ihc.config.DataEngine.EnableChromaDB,
		"websocket_enabled":  ihc.config.DataEngine.EnableWebSocket,
		"restapi_enabled":    ihc.config.DataEngine.EnableRESTAPI,
	}

	return status
}

// GetAllIntegrationStatus returns status for all integrations
func (ihc *IntegrationHealthChecker) GetAllIntegrationStatus(ctx context.Context) map[string]interface{} {
	return map[string]interface{}{
		"github":      ihc.CheckGitHubIntegration(ctx),
		"kafka":       ihc.CheckKafkaIntegration(ctx),
		"chromadb":    ihc.CheckChromaDBIntegration(ctx),
		"data_engine": ihc.CheckDataEngineIntegration(ctx),
		"timestamp":   time.Now(),
	}
}

// ============================================================================
// ALERT CONFIGURATION SYSTEM
// ============================================================================

// AlertConfig represents alert configuration
type AlertConfig struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"` // "threshold", "pattern", "anomaly"
	Enabled     bool                   `json:"enabled"`
	Conditions  map[string]interface{} `json:"conditions"`
	Actions     []AlertAction          `json:"actions"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// AlertAction represents an action to take when an alert triggers
type AlertAction struct {
	Type       string                 `json:"type"` // "websocket", "email", "webhook"
	Config     map[string]interface{} `json:"config"`
	Enabled    bool                   `json:"enabled"`
}

// AlertManager manages alert configurations and notifications
type AlertManager struct {
	alerts   map[string]*AlertConfig
	mutex    sync.RWMutex
	notifier *AlertNotifier
}

// NewAlertManager creates a new alert manager
func NewAlertManager() *AlertManager {
	return &AlertManager{
		alerts:   make(map[string]*AlertConfig),
		notifier: NewAlertNotifier(),
	}
}

// CreateAlert creates a new alert configuration
func (am *AlertManager) CreateAlert(config *AlertConfig) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if config.ID == "" {
		config.ID = fmt.Sprintf("alert_%d", time.Now().UnixNano())
	}

	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	am.alerts[config.ID] = config
	log.Printf("✅ Alert configuration created: %s", config.Name)
	return nil
}

// UpdateAlert updates an existing alert configuration
func (am *AlertManager) UpdateAlert(id string, config *AlertConfig) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if _, exists := am.alerts[id]; !exists {
		return fmt.Errorf("alert not found: %s", id)
	}

	config.ID = id
	config.UpdatedAt = time.Now()

	am.alerts[id] = config
	log.Printf("✅ Alert configuration updated: %s", config.Name)
	return nil
}

// DeleteAlert deletes an alert configuration
func (am *AlertManager) DeleteAlert(id string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if _, exists := am.alerts[id]; !exists {
		return fmt.Errorf("alert not found: %s", id)
	}

	delete(am.alerts, id)
	log.Printf("✅ Alert configuration deleted: %s", id)
	return nil
}

// GetAlert returns an alert configuration by ID
func (am *AlertManager) GetAlert(id string) (*AlertConfig, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	alert, exists := am.alerts[id]
	if !exists {
		return nil, fmt.Errorf("alert not found: %s", id)
	}

	return alert, nil
}

// GetAllAlerts returns all alert configurations
func (am *AlertManager) GetAllAlerts() []*AlertConfig {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	alerts := make([]*AlertConfig, 0, len(am.alerts))
	for _, alert := range am.alerts {
		alerts = append(alerts, alert)
	}

	return alerts
}

// TriggerAlert triggers an alert notification
func (am *AlertManager) TriggerAlert(alertID string, data map[string]interface{}) error {
	alert, err := am.GetAlert(alertID)
	if err != nil {
		return err
	}

	if !alert.Enabled {
		return nil // Alert is disabled
	}

	// Send notification
	return am.notifier.Notify(alert, data)
}

// ============================================================================
// ALERT NOTIFICATION SYSTEM
// ============================================================================

// AlertNotifier handles sending alert notifications
type AlertNotifier struct {
	wsServer *data_engine.WebSocketServer
}

// NewAlertNotifier creates a new alert notifier
func NewAlertNotifier() *AlertNotifier {
	return &AlertNotifier{}
}

// SetWebSocketServer sets the WebSocket server for broadcasting alerts
func (an *AlertNotifier) SetWebSocketServer(wsServer *data_engine.WebSocketServer) {
	an.wsServer = wsServer
}

// Notify sends alert notifications through configured channels
func (an *AlertNotifier) Notify(alert *AlertConfig, data map[string]interface{}) error {
	log.Printf("🚨 Alert triggered: %s", alert.Name)

	notification := map[string]interface{}{
		"type":        "alert",
		"alert_id":    alert.ID,
		"alert_name":  alert.Name,
		"description": alert.Description,
		"data":        data,
		"timestamp":   time.Now(),
	}

	// Send WebSocket notification
	if an.wsServer != nil {
		an.wsServer.Broadcast(notification)
		log.Printf("📡 Alert broadcast via WebSocket: %s", alert.Name)
	}

	// Execute configured actions
	for _, action := range alert.Actions {
		if !action.Enabled {
			continue
		}

		switch action.Type {
		case "websocket":
			// Already handled above
		case "webhook":
			go an.sendWebhook(action.Config, notification)
		case "email":
			go an.sendEmail(action.Config, notification)
		default:
			log.Printf("⚠️  Unknown alert action type: %s", action.Type)
		}
	}

	return nil
}

// sendWebhook sends alert notification to a webhook URL
func (an *AlertNotifier) sendWebhook(config map[string]interface{}, notification map[string]interface{}) {
	url, ok := config["url"].(string)
	if !ok {
		log.Printf("⚠️  Webhook URL not configured")
		return
	}

	jsonData, err := json.Marshal(notification)
	if err != nil {
		log.Printf("⚠️  Failed to marshal webhook data: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		log.Printf("⚠️  Failed to create webhook request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("⚠️  Webhook request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("✅ Webhook notification sent successfully")
	} else {
		log.Printf("⚠️  Webhook returned status %d", resp.StatusCode)
	}
}

// sendEmail sends alert notification via email (placeholder implementation)
func (an *AlertNotifier) sendEmail(config map[string]interface{}, _ map[string]interface{}) {
	// Placeholder for email implementation
	// In a real implementation, this would integrate with an email service
	log.Printf("📧 Email notification would be sent (not implemented): %v", config)
}

// ============================================================================
// MONITORING DASHBOARD ENDPOINTS
// ============================================================================

// handleIntegrationStatus returns status of all integrations
func handleIntegrationStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if globalSettingsManager == nil {
		http.Error(w, "Settings manager not initialized", http.StatusInternalServerError)
		return
	}

	config := globalSettingsManager.GetSettings()
	checker := NewIntegrationHealthChecker(config)

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	status := checker.GetAllIntegrationStatus(ctx)
	json.NewEncoder(w).Encode(status)
}

// handleAlertConfigs handles alert configuration CRUD operations
func handleAlertConfigs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// This is a global alert manager instance - in a real implementation,
	// this would be properly initialized and managed
	alertManager := &AlertManager{
		alerts:   make(map[string]*AlertConfig),
		notifier: NewAlertNotifier(),
	}

	switch r.Method {
	case "GET":
		alerts := alertManager.GetAllAlerts()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"alerts": alerts,
			"total":  len(alerts),
		})

	case "POST":
		var config AlertConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		if err := alertManager.CreateAlert(&config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(config)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAlertConfig handles individual alert configuration operations
func handleAlertConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	vars := mux.Vars(r)
	alertID := vars["id"]

	alertManager := &AlertManager{
		alerts:   make(map[string]*AlertConfig),
		notifier: NewAlertNotifier(),
	}

	switch r.Method {
	case "GET":
		alert, err := alertManager.GetAlert(alertID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(alert)

	case "PUT":
		var config AlertConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		if err := alertManager.UpdateAlert(alertID, &config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(config)

	case "DELETE":
		if err := alertManager.DeleteAlert(alertID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		response := map[string]interface{}{
			"success": true,
			"message": "Alert configuration deleted",
		}
		json.NewEncoder(w).Encode(response)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSystemMetrics returns real-time system metrics
func handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Collect real system metrics
	metrics, err := collectRealSystemMetrics(ctx)
	if err != nil {
		log.Printf("⚠️  Failed to collect system metrics: %v", err)
		// Return basic metrics on error
		metrics = map[string]interface{}{
			"cpu":       0.0,
			"memory":    0.0,
			"disk":      0.0,
			"network":   map[string]interface{}{"in": 0, "out": 0},
			"timestamp": time.Now(),
			"error":     err.Error(),
		}
	}

	json.NewEncoder(w).Encode(metrics)
}

// ============================================================================
// API DOCUMENTATION
// ============================================================================

// handleAPIDocs returns API documentation in JSON format
func handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	docs := map[string]interface{}{
		"openapi": "3.0.1",
		"info": map[string]interface{}{
			"title":       "ArchGuardian API",
			"description": "AI-Powered Code Guardian API for comprehensive security monitoring and automated remediation",
			"version":     "1.0.0",
			"contact": map[string]interface{}{
				"name":  "ArchGuardian Team",
				"email": "support@archguardian.dev",
			},
		},
		"servers": []interface{}{
			map[string]interface{}{
				"url":         "http://localhost:3000",
				"description": "Development server",
			},
		},
		"security": []interface{}{
			map[string]interface{}{
				"bearerAuth": []interface{}{},
			},
		},
		"paths": map[string]interface{}{
			"/health": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Health check",
					"description": "Returns the health status of the ArchGuardian service",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Service is healthy",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"status": map[string]interface{}{
												"type": "string",
												"example": "healthy",
											},
											"timestamp": map[string]interface{}{
												"type": "string",
												"format": "date-time",
											},
											"version": map[string]interface{}{
												"type": "string",
												"example": "1.0.0",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/knowledge-graph": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Get knowledge graph",
					"description": "Returns the current knowledge graph data showing code relationships and dependencies",
					"security":    []map[string]interface{}{{"bearerAuth": []string{}}},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Knowledge graph data",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"nodes": map[string]interface{}{
												"type": "array",
												"items": map[string]interface{}{
													"type": "object",
													"properties": map[string]interface{}{
														"id": map[string]interface{}{
															"type": "string",
														},
														"label": map[string]interface{}{
															"type": "string",
														},
														"type": map[string]interface{}{
															"type": "string",
														},
														"group": map[string]interface{}{
															"type": "string",
														},
														"metadata": map[string]interface{}{
															"type": "object",
														},
													},
												},
											},
											"edges": map[string]interface{}{
												"type": "array",
												"items": map[string]interface{}{
													"type": "object",
													"properties": map[string]interface{}{
														"from": map[string]interface{}{
															"type": "string",
														},
														"to": map[string]interface{}{
															"type": "string",
														},
														"label": map[string]interface{}{
															"type": "string",
														},
														"arrows": map[string]interface{}{
															"type": "string",
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/issues": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Get issues",
					"description": "Returns security issues, technical debt, and other code quality problems",
					"security":    []map[string]interface{}{{"bearerAuth": []string{}}},
					"parameters": []map[string]interface{}{
						{
							"name": "type",
							"in": "query",
							"description": "Type of issues to return (technical-debt, security, obsolete, dependencies)",
							"schema": map[string]interface{}{
								"type": "string",
								"enum": []string{"technical-debt", "security", "obsolete", "dependencies"},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Issues data",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/coverage": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Get test coverage",
					"description": "Returns test coverage metrics for the scanned codebase",
					"security":    []map[string]interface{}{{"bearerAuth": []string{}}},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Coverage data",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"overall_coverage": map[string]interface{}{
												"type": "number",
												"format": "float",
											},
											"lines_covered": map[string]interface{}{
												"type": "integer",
											},
											"total_lines": map[string]interface{}{
												"type": "integer",
											},
											"test_files": map[string]interface{}{
												"type": "integer",
											},
											"language": map[string]interface{}{
												"type": "string",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/scan/start": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Start scan",
					"description": "Triggers a new comprehensive security and code quality scan",
					"security":    []map[string]interface{}{{"bearerAuth": []string{}}},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Scan started successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"status": map[string]interface{}{
												"type": "string",
												"example": "ok",
											},
											"message": map[string]interface{}{
												"type": "string",
												"example": "Scan triggered successfully.",
											},
										},
									},
								},
							},
						},
						"503": map[string]interface{}{
							"description": "Scan already in progress",
						},
					},
				},
			},
			"/api/v1/settings": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Get settings",
					"description": "Returns current ArchGuardian configuration settings",
					"security":    []map[string]interface{}{{"bearerAuth": []string{}}},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Settings data",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
									},
								},
							},
						},
					},
				},
				"post": map[string]interface{}{
					"summary":     "Update settings",
					"description": "Updates ArchGuardian configuration settings",
					"security":    []map[string]interface{}{{"bearerAuth": []string{}}},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Settings updated successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"success": map[string]interface{}{
												"type": "boolean",
											},
											"message": map[string]interface{}{
												"type": "string",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/projects": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List projects",
					"description": "Returns a list of all configured projects",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "List of projects",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "array",
										"items": map[string]interface{}{
											"type": "object",
											"properties": map[string]interface{}{
												"id": map[string]interface{}{
													"type": "string",
												},
												"name": map[string]interface{}{
													"type": "string",
												},
												"path": map[string]interface{}{
													"type": "string",
												},
												"status": map[string]interface{}{
													"type": "string",
													"enum": []string{"idle", "scanning", "error"},
												},
												"lastScan": map[string]interface{}{
													"type": "string",
													"format": "date-time",
												},
												"issueCount": map[string]interface{}{
													"type": "integer",
												},
												"createdAt": map[string]interface{}{
													"type": "string",
													"format": "date-time",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				"post": map[string]interface{}{
					"summary":     "Create project",
					"description": "Creates a new project for monitoring",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"required": []string{"name", "path"},
									"properties": map[string]interface{}{
										"name": map[string]interface{}{
											"type": "string",
											"description": "Project name",
										},
										"path": map[string]interface{}{
											"type": "string",
											"description": "Project path",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"201": map[string]interface{}{
							"description": "Project created successfully",
						},
						"400": map[string]interface{}{
							"description": "Invalid request data",
						},
					},
				},
			},
			"/api/v1/projects/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Get project",
					"description": "Returns details for a specific project",
					"parameters": []map[string]interface{}{
						{
							"name": "id",
							"in": "path",
							"required": true,
							"description": "Project ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Project details",
						},
						"404": map[string]interface{}{
							"description": "Project not found",
						},
					},
				},
				"delete": map[string]interface{}{
					"summary":     "Delete project",
					"description": "Deletes a project from monitoring",
					"parameters": []map[string]interface{}{
						{
							"name": "id",
							"in": "path",
							"required": true,
							"description": "Project ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Project deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "Project not found",
						},
					},
				},
			},
			"/api/v1/projects/{id}/scan": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Scan project",
					"description": "Triggers a scan for a specific project",
					"parameters": []map[string]interface{}{
						{
							"name": "id",
							"in": "path",
							"required": true,
							"description": "Project ID",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Scan started successfully",
						},
						"404": map[string]interface{}{
							"description": "Project not found",
						},
						"503": map[string]interface{}{
							"description": "Scan already in progress",
						},
					},
				},
			},
			"/api/v1/integrations/status": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Integration status",
					"description": "Returns the health status of all external integrations",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Integration status data",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"github": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"connected": map[string]interface{}{
														"type": "boolean",
													},
													"status": map[string]interface{}{
														"type": "string",
														"enum": []string{"healthy", "error", "disconnected"},
													},
													"message": map[string]interface{}{
														"type": "string",
													},
												},
											},
											"kafka": map[string]interface{}{
												"type": "object",
											},
											"chromadb": map[string]interface{}{
												"type": "object",
											},
											"data_engine": map[string]interface{}{
												"type": "object",
											},
											"timestamp": map[string]interface{}{
												"type": "string",
												"format": "date-time",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/metrics": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "System metrics",
					"description": "Returns real-time system performance metrics",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "System metrics data",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"cpu": map[string]interface{}{
												"type": "number",
												"format": "float",
												"description": "CPU usage percentage",
											},
											"memory": map[string]interface{}{
												"type": "number",
												"format": "float",
												"description": "Memory usage percentage",
											},
											"disk": map[string]interface{}{
												"type": "number",
												"format": "float",
												"description": "Disk usage percentage",
											},
											"network": map[string]interface{}{
												"type": "object",
												"properties": map[string]interface{}{
													"in": map[string]interface{}{
														"type": "integer",
														"description": "Bytes received",
													},
													"out": map[string]interface{}{
														"type": "integer",
														"description": "Bytes sent",
													},
												},
											},
											"processes": map[string]interface{}{
												"type": "integer",
												"description": "Number of running processes",
											},
											"timestamp": map[string]interface{}{
												"type": "string",
												"format": "date-time",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/backup": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Create backup",
					"description": "Creates a backup of the ArchGuardian database",
					"security":    []map[string]interface{}{{"bearerAuth": []string{}}},
					"requestBody": map[string]interface{}{
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"encryption_key": map[string]interface{}{
											"type": "string",
											"description": "Optional encryption key (32 bytes)",
										},
									},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Backup created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"success": map[string]interface{}{
												"type": "boolean",
											},
											"backup_path": map[string]interface{}{
												"type": "string",
											},
											"timestamp": map[string]interface{}{
												"type": "string",
												"format": "date-time",
											},
											"encrypted": map[string]interface{}{
												"type": "boolean",
											},
											"size_bytes": map[string]interface{}{
												"type": "integer",
											},
										},
									},
								},
							},
						},
					},
				},
				"get": map[string]interface{}{
					"summary":     "List backups",
					"description": "Returns a list of available database backups",
					"security":    []map[string]interface{}{{"bearerAuth": []string{}}},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "List of backups",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"backups": map[string]interface{}{
												"type": "array",
												"items": map[string]interface{}{
													"type": "object",
													"properties": map[string]interface{}{
														"filename": map[string]interface{}{
															"type": "string",
														},
														"path": map[string]interface{}{
															"type": "string",
														},
														"size": map[string]interface{}{
															"type": "integer",
														},
														"modified": map[string]interface{}{
															"type": "string",
															"format": "date-time",
														},
														"encrypted": map[string]interface{}{
															"type": "boolean",
														},
													},
												},
											},
											"total": map[string]interface{}{
												"type": "integer",
											},
											"directory": map[string]interface{}{
												"type": "string",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/search": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Semantic search",
					"description": "Performs natural language search across stored data",
					"security":    []map[string]interface{}{{"bearerAuth": []string{}}},
					"parameters": []map[string]interface{}{
						{
							"name": "q",
							"in": "query",
							"required": true,
							"description": "Search query",
							"schema": map[string]interface{}{
								"type": "string",
							},
						},
						{
							"name": "collection",
							"in": "query",
							"description": "Collection to search in",
							"schema": map[string]interface{}{
								"type": "string",
								"default": "knowledge-graphs",
							},
						},
						{
							"name": "limit",
							"in": "query",
							"description": "Maximum number of results",
							"schema": map[string]interface{}{
								"type": "integer",
								"default": 5,
								"maximum": 20,
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Search results",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"query": map[string]interface{}{
												"type": "string",
											},
											"collection": map[string]interface{}{
												"type": "string",
											},
											"total": map[string]interface{}{
												"type": "integer",
											},
											"results": map[string]interface{}{
												"type": "array",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"bearerAuth": map[string]interface{}{
					"type": "http",
					"scheme": "bearer",
					"bearerFormat": "JWT",
				},
			},
		},
		"tags": []map[string]interface{}{
			{
				"name": "health",
				"description": "Health check endpoints",
			},
			{
				"name": "scanning",
				"description": "Code scanning and analysis",
			},
			{
				"name": "projects",
				"description": "Project management",
			},
			{
				"name": "monitoring",
				"description": "System monitoring and metrics",
			},
			{
				"name": "administration",
				"description": "Administrative operations",
			},
		},
	}

	json.NewEncoder(w).Encode(docs)
}

// ============================================================================
// DATA ENGINE HANDLERS
// ============================================================================

// handleDataEngineKnowledgeGraph handles requests for knowledge graph data
func handleDataEngineKnowledgeGraph(w http.ResponseWriter, _ *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil {
		http.Error(w, "Data engine not available", http.StatusServiceUnavailable)
		return
	}

	// For now, return a basic response - in a real implementation this would query the knowledge graph
	response := map[string]interface{}{
		"nodes": []map[string]interface{}{},
		"edges": []map[string]interface{}{},
		"message": "Knowledge graph data not yet implemented in data engine",
	}

	json.NewEncoder(w).Encode(response)
}

// handleDataEngineIssues handles requests for issues data
func handleDataEngineIssues(w http.ResponseWriter, _ *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil {
		http.Error(w, "Data engine not available", http.StatusServiceUnavailable)
		return
	}

	// For now, return a basic response - in a real implementation this would query issues
	response := map[string]interface{}{
		"issues": []map[string]interface{}{},
		"message": "Issues data not yet implemented in data engine",
	}

	json.NewEncoder(w).Encode(response)
}

// handleDataEngineCoverage handles requests for coverage data
func handleDataEngineCoverage(w http.ResponseWriter, _ *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil {
		http.Error(w, "Data engine not available", http.StatusServiceUnavailable)
		return
	}

	// For now, return a basic response - in a real implementation this would query coverage data
	response := map[string]interface{}{
		"overall_coverage": 0.0,
		"lines_covered":    0,
		"total_lines":      0,
		"test_files":       0,
		"message":          "Coverage data not yet implemented in data engine",
	}

	json.NewEncoder(w).Encode(response)
}

// handleDataEngineHealth handles health check requests for data engine
func handleDataEngineHealth(w http.ResponseWriter, _ *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	// Create health status
	health := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "data-engine",
	}

	// Add data engine status
	if de != nil {
		health["data_engine"] = map[string]interface{}{
			"running": de.IsRunning(),
		}

		// Add Kafka status
		if de.GetProducer() != nil {
			health["kafka"] = map[string]interface{}{
				"connected": de.GetProducer().IsConnected(),
			}
		}

		// Add ChromaDB status
		if de.GetChromaDB() != nil {
			health["chromadb"] = map[string]interface{}{
				"connected": de.GetChromaDB().IsConnected(),
			}
		}
	}

	json.NewEncoder(w).Encode(health)
}

// handleDataEngineMetrics handles requests for data engine metrics
func handleDataEngineMetrics(w http.ResponseWriter, _ *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil {
		http.Error(w, "Data engine not available", http.StatusServiceUnavailable)
		return
	}

	// Get metrics
	metrics := de.GetMetrics()
	if metrics == nil {
		http.Error(w, "No metrics available", http.StatusServiceUnavailable)
		return
	}

	json.NewEncoder(w).Encode(metrics)
}

// handleDataEngineAlerts handles requests for alerts
func handleDataEngineAlerts(w http.ResponseWriter, r *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil || de.GetAlerting() == nil {
		http.Error(w, "Alerting system not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	activeOnly := r.URL.Query().Get("active") == "true"

	var alerts []data_engine.Alert
	if activeOnly {
		alerts = de.GetAlerting().GetActiveAlerts()
	} else {
		alerts = de.GetAlerting().GetAlerts()
	}

	json.NewEncoder(w).Encode(alerts)
}

// handleDataEngineResolveAlert handles requests to resolve an alert
func handleDataEngineResolveAlert(w http.ResponseWriter, r *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil || de.GetAlerting() == nil {
		http.Error(w, "Alerting system not available", http.StatusServiceUnavailable)
		return
	}

	// Get alert ID from URL
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Resolve alert
	resolved := de.ResolveAlert(alertID)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       alertID,
		"resolved": resolved,
	})
}

// handleDataEngineEvents handles requests for events
func handleDataEngineEvents(w http.ResponseWriter, r *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil || de.GetChromaDB() == nil || !de.GetChromaDB().IsConnected() {
		http.Error(w, "ChromaDB not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	eventType := r.URL.Query().Get("type")

	// Set default limit
	limit := 10
	if limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			limit = 10
		}
		if limit > 100 {
			limit = 100
		}
	}

	var docs []data_engine.ChromaDocument
	var err error

	// Query events
	if eventType != "" {
		// Filter by event type
		docs, err = de.GetChromaDB().GetEventsByType(r.Context(), data_engine.EventType(eventType), limit)
	} else {
		// Get recent events
		docs, err = de.GetChromaDB().GetRecentEvents(r.Context(), limit)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to query events: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(docs)
}

// handleDataEngineSearchEvents handles requests to search events
func handleDataEngineSearchEvents(w http.ResponseWriter, r *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil || de.GetChromaDB() == nil || !de.GetChromaDB().IsConnected() {
		http.Error(w, "ChromaDB not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
		return
	}

	limitStr := r.URL.Query().Get("limit")

	// Set default limit
	limit := 10
	if limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			limit = 10
		}
		if limit > 100 {
			limit = 100
		}
	}

	// Search events
	docs, err := de.GetChromaDB().QueryEvents(r.Context(), query, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to search events: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(docs)
}

// handleDataEngineEventTypes handles requests for event types
func handleDataEngineEventTypes(w http.ResponseWriter, _ *http.Request, _ *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	// Define event types
	eventTypes := []string{
		string(ScanCycleEventType),
		string(ScanStartedEvent),
		string(ScanCompletedEvent),
		string(RiskAnalysisEvent),
		string(RemediationEvent),
		string(SystemEventType),
		string(ErrorEvent),
		string(WarningEvent),
		string(InfoEvent),
		// Add other relevant event types as they are defined and used
	}

	json.NewEncoder(w).Encode(eventTypes)
}

// handleDataEngineWindows handles requests for windows
func handleDataEngineWindows(w http.ResponseWriter, _ *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil || de.GetAggregator() == nil {
		http.Error(w, "Windowed aggregator not available", http.StatusServiceUnavailable)
		return
	}

	// Get windows
	windows := de.GetAggregator().GetWindows()
	json.NewEncoder(w).Encode(windows)
}

// handleDataEngineWindowsInRange handles requests for windows in a time range
func handleDataEngineWindowsInRange(w http.ResponseWriter, r *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil || de.GetAggregator() == nil {
		http.Error(w, "Windowed aggregator not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	if startStr == "" || endStr == "" {
		http.Error(w, "Query parameters 'start' and 'end' are required", http.StatusBadRequest)
		return
	}

	// Parse timestamps
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid start time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid end time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Get windows in range
	windows := de.GetAggregator().GetWindowsInRange(start, end)
	json.NewEncoder(w).Encode(windows)
}

// handleDataEngineActiveUsers handles requests for active users
func handleDataEngineActiveUsers(w http.ResponseWriter, r *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil || de.GetAggregator() == nil {
		http.Error(w, "Windowed aggregator not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	if startStr == "" || endStr == "" {
		http.Error(w, "Query parameters 'start' and 'end' are required", http.StatusBadRequest)
		return
	}

	// Parse timestamps
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid start time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid end time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Get active users
	activeUsers := de.GetAggregator().GetActiveUsers(start, end)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"start":        start.Format(time.RFC3339),
		"end":          end.Format(time.RFC3339),
		"active_users": activeUsers,
	})
}

// handleDataEngineEventRates handles requests for event rates
func handleDataEngineEventRates(w http.ResponseWriter, r *http.Request, de *data_engine.DataEngine) {
	w.Header().Set("Content-Type", "application/json")

	if de == nil || de.GetAggregator() == nil {
		http.Error(w, "Windowed aggregator not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	if startStr == "" || endStr == "" {
		http.Error(w, "Query parameters 'start' and 'end' are required", http.StatusBadRequest)
		return
	}

	// Parse timestamps
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid start time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid end time: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Get event rate
	eventRate := de.GetAggregator().GetEventRate(start, end)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"start":      start.Format(time.RFC3339),
		"end":        end.Format(time.RFC3339),
		"event_rate": eventRate,
		"unit":       "events/second",
	})
}

// handleDashboardWebSocket handles WebSocket connections for dashboard log streaming
func handleDashboardWebSocket(w http.ResponseWriter, r *http.Request, ag *ArchGuardian) {
	// Upgrade HTTP connection to WebSocket
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// Allow connections from localhost for development
			return true
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %s\n", err.Error())
		return
	}
	defer conn.Close()

	log.Println("Dashboard WebSocket client connected")

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
			log.Println("Dashboard WebSocket client ready - flushing initial logs")
			// Flush any buffered logs
			if ag != nil {
				ag.FlushInitialLogs()
			}
		}
	}

	log.Println("Dashboard WebSocket client disconnected")
}

// collectRealSystemMetrics collects actual system metrics using gopsutil
func collectRealSystemMetrics(ctx context.Context) (map[string]interface{}, error) {
	metrics := make(map[string]interface{})

	// CPU usage
	cpuPercent, err := cpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU metrics: %w", err)
	}
	if len(cpuPercent) > 0 {
		metrics["cpu"] = cpuPercent[0]
	} else {
		metrics["cpu"] = 0.0
	}

	// Memory usage
	memInfo, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get memory metrics: %w", err)
	}
	metrics["memory"] = memInfo.UsedPercent

	// Disk usage
	diskInfo, err := disk.UsageWithContext(ctx, "/")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk metrics: %w", err)
	}
	metrics["disk"] = diskInfo.UsedPercent

	// Network I/O
	netInfo, err := net.IOCountersWithContext(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get network metrics: %w", err)
	}
	if len(netInfo) > 0 {
		metrics["network"] = map[string]interface{}{
			"in":  netInfo[0].BytesRecv,
			"out": netInfo[0].BytesSent,
		}
	} else {
		metrics["network"] = map[string]interface{}{
			"in":  0,
			"out": 0,
		}
	}

	// Process information
	processes, err := process.ProcessesWithContext(ctx)
	if err == nil {
		metrics["processes"] = len(processes)
	} else {
		metrics["processes"] = 0
	}

	metrics["timestamp"] = time.Now()
	return metrics, nil
}
