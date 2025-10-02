// /home/gperry/Documents/GitHub/Inc-Line/Wordpress-Inference-Engine/inference/inference_service.go
package inference_engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	gollm "github.com/guiperry/gollm_cerebras"
	"github.com/guiperry/gollm_cerebras/config"
	"github.com/guiperry/gollm_cerebras/llm"
)

// LLMAttemptConfig defines the configuration for a single LLM attempt.
type LLMAttemptConfig struct {
	ProviderName string
	ModelName    string
	APIKeyEnvVar string // Environment variable name for the API key
	MaxTokens    int
	IsPrimary    bool // True if part of initial attempts, false for fallback
	// Add EndpointOverride string if needed
}

// LLMAttempt holds an initialized LLM instance and its config.
type LLMAttempt struct {
	Instance llm.LLM
	Config   LLMAttemptConfig
	Opts     []config.ConfigOption // ADDED: Store the options used to create this instance
}

// InferenceService manages the interaction with the gollm library and its providers.
type InferenceService struct {
	// Store lists of attempts instead of single instances
	primaryAttempts  []LLMAttempt
	fallbackAttempts []LLMAttempt
	delegator        *DelegatorService
	db               DatabaseAccessor // ADDED: Use the DatabaseAccessor interface
	contextManager   *ContextManager  // ADDED: Context Manager instance
	isRunning        bool
	mutex            sync.Mutex
	moa              *gollm.MOA
	// Store names/config options for MOA defaults, separate from execution attempts
	moaPrimaryModelName  string
	moaFallbackModelName string
	moaPrimaryOpts       []config.ConfigOption
	moaFallbackOpts      []config.ConfigOption
}

// NewInferenceService creates a new instance of InferenceService.
func NewInferenceService(db DatabaseAccessor) (*InferenceService, error) {
	return &InferenceService{
		// Initialize slices
		primaryAttempts:  make([]LLMAttempt, 0),
		fallbackAttempts: make([]LLMAttempt, 0),
		// Initialize ContextManager with default strategy
		contextManager: NewContextManager(
			ChunkByTokenCount,                        // Use token count for better splitting
			WithProcessingMode(SequentialProcessing), // Default to sequential
		),
		db: db, // Store the provided database accessor
	}, nil
}

// StartWithConfig configures the service with dynamic LLM configurations and starts it.
func (s *InferenceService) StartWithConfig(attemptConfigs []LLMAttemptConfig) error {
	log.Println("InferenceService: Starting with dynamic configuration...")
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.primaryAttempts = make([]LLMAttempt, 0)
	s.fallbackAttempts = make([]LLMAttempt, 0)
	var primaryOptsList [][]config.ConfigOption
	var fallbackOptsList [][]config.ConfigOption

	// Initialize LLM instances based on provided config
	for _, attemptConf := range attemptConfigs {
		log.Printf("InferenceService: Configuring LLM attempt: Provider=%s, Model=%s, Primary=%t", attemptConf.ProviderName, attemptConf.ModelName, attemptConf.IsPrimary)
		apiKey := os.Getenv(attemptConf.APIKeyEnvVar)
		if apiKey == "" {
			log.Printf("[WARN] InferenceService: API Key from env var '%s' not found for model '%s'. Skipping this attempt.", attemptConf.APIKeyEnvVar, attemptConf.ModelName)
			continue
		}

		opts := []config.ConfigOption{
			config.SetProvider(attemptConf.ProviderName),
			config.SetAPIKey(apiKey),
			config.SetModel(attemptConf.ModelName),
			config.SetMaxTokens(attemptConf.MaxTokens),
		}

		llmInstance, err := gollm.NewLLM(opts...)
		if err != nil {
			log.Printf("[ERROR] InferenceService: Failed to create LLM instance for model '%s': %v. Skipping this attempt.", attemptConf.ModelName, err)
			continue
		}

		if initializedLLM, ok := llmInstance.(llm.LLM); ok {
			attempt := LLMAttempt{
				Instance: initializedLLM,
				Config:   attemptConf,
				Opts:     opts,
			}
			if attemptConf.IsPrimary {
				s.primaryAttempts = append(s.primaryAttempts, attempt)
				primaryOptsList = append(primaryOptsList, opts)
			} else {
				s.fallbackAttempts = append(s.fallbackAttempts, attempt)
				fallbackOptsList = append(fallbackOptsList, opts)
			}
			log.Printf("InferenceService: Successfully configured LLM instance for model '%s'", attemptConf.ModelName)
		} else {
			log.Printf("[ERROR] InferenceService: Initialized instance for model '%s' is not of type llm.LLM. Skipping.", attemptConf.ModelName)
		}
	}

	// Validate that we have at least one primary and one fallback
	if len(s.primaryAttempts) == 0 {
		return fmt.Errorf("inference service configuration error: no primary LLM attempts were successfully initialized")
	}
	if len(s.fallbackAttempts) == 0 {
		return fmt.Errorf("inference service configuration error: no fallback LLM attempts were successfully initialized")
	}

	// Set initial MOA defaults based on the first primary and last fallback attempt
	s.moaPrimaryModelName = s.primaryAttempts[0].Config.ModelName
	s.moaFallbackModelName = s.fallbackAttempts[len(s.fallbackAttempts)-1].Config.ModelName
	s.moaPrimaryOpts = primaryOptsList[0]
	s.moaFallbackOpts = fallbackOptsList[len(fallbackOptsList)-1]

	// Create the initial MOA instance
	if err := s.reconfigureMOAInternal(); err != nil {
		log.Printf("[WARN] InferenceService: Initial MOA configuration failed: %v. MOA features disabled.", err)
	}

	// Create the Delegator Service
	delegatorTokenLimit := s.primaryAttempts[0].Config.MaxTokens
	delegatorTokenModel := s.primaryAttempts[0].Config.ModelName
	s.delegator = NewDelegatorService(s.primaryAttempts, s.fallbackAttempts, delegatorTokenLimit, delegatorTokenModel, s.moa, s.contextManager)
	if s.delegator == nil {
		log.Println("[ERROR] InferenceService: Failed to create DelegatorService.")
		s.isRunning = false
		s.moa = nil
		return fmt.Errorf("failed to create delegator service")
	}
	log.Println("InferenceService: DelegatorService created.")

	s.isRunning = true
	log.Println("InferenceService: Started successfully with dynamic configuration.")
	return nil
}

// Start configures the service with both proxy and base providers and the delegator.
func (s *InferenceService) Start() error {
	log.Println("InferenceService: Starting...")
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// --- Define the desired attempts ---
	// Example: Try Cerebras model A, then Cerebras model B, then fallback to Gemini Flash, then Gemini Pro
	attemptConfigs := []LLMAttemptConfig{
		{ProviderName: "cerebras", ModelName: "llama-4-scout-17b-16e-instruct", APIKeyEnvVar: "CEREBRAS_API_KEY", MaxTokens: 4000, IsPrimary: true},
		// {ProviderName: "cerebras", ModelName: "some-other-cerebras-model", APIKeyEnvVar: "CEREBRAS_API_KEY", MaxTokens: 8000, IsPrimary: true}, // Example: another primary
		// {ProviderName: "cerebras", ModelName: "llama-4-scout-17b-16e-instruct", APIKeyEnvVar: "CEREBRAS_API_KEY_2", MaxTokens: 4000, IsPrimary: true}, // Example: different key
		{ProviderName: "gemini", ModelName: "gemini-1.5-flash-latest", APIKeyEnvVar: "GEMINI_API_KEY", MaxTokens: 100000, IsPrimary: false}, // Fallback 1 (Use working model name)
		{ProviderName: "deepseek", ModelName: "deepseek-chat", APIKeyEnvVar: "DEEPSEEK_API_KEY", MaxTokens: 8000, IsPrimary: false},         // Fallback 2 (Target for final chunking)
		// {ProviderName: "gemini", ModelName: "gemini-1.5-pro-latest", APIKeyEnvVar: "GEMINI_API_KEY", MaxTokens: 1000000, IsPrimary: false}, // Fallback 3 (Example: Use Pro if needed)
	}

	s.primaryAttempts = make([]LLMAttempt, 0)
	s.fallbackAttempts = make([]LLMAttempt, 0)
	var primaryOptsList [][]config.ConfigOption  // For MOA
	var fallbackOptsList [][]config.ConfigOption // For MOA (aggregator might use last fallback)

	// --- Initialize LLM instances based on config ---
	for _, attemptConf := range attemptConfigs {
		log.Printf("InferenceService: Configuring LLM attempt: Provider=%s, Model=%s, Primary=%t", attemptConf.ProviderName, attemptConf.ModelName, attemptConf.IsPrimary)
		apiKey := os.Getenv(attemptConf.APIKeyEnvVar)
		if apiKey == "" {
			log.Printf("[WARN] InferenceService: API Key from env var '%s' not found for model '%s'. Skipping this attempt.", attemptConf.APIKeyEnvVar, attemptConf.ModelName)
			continue // Skip this attempt if key is missing
		}

		opts := []config.ConfigOption{
			config.SetProvider(attemptConf.ProviderName),
			config.SetAPIKey(apiKey),
			config.SetModel(attemptConf.ModelName),
			config.SetMaxTokens(attemptConf.MaxTokens),
			// Add config.SetEndpoint(attemptConf.EndpointOverride) if needed
		}

		llmInstance, err := gollm.NewLLM(opts...)
		if err != nil {
			log.Printf("[ERROR] InferenceService: Failed to create LLM instance for model '%s': %v. Skipping this attempt.", attemptConf.ModelName, err)
			continue // Skip this attempt on error
		}

		if initializedLLM, ok := llmInstance.(llm.LLM); ok {
			attempt := LLMAttempt{
				Instance: initializedLLM,
				Config:   attemptConf,
				Opts:     opts, // STORE THE OPTS
			}
			if attemptConf.IsPrimary {
				s.primaryAttempts = append(s.primaryAttempts, attempt)
				primaryOptsList = append(primaryOptsList, opts)
			} else {
				s.fallbackAttempts = append(s.fallbackAttempts, attempt)
				fallbackOptsList = append(fallbackOptsList, opts)
			}
			log.Printf("InferenceService: Successfully configured LLM instance for model '%s'", attemptConf.ModelName)
		} else {
			log.Printf("[ERROR] InferenceService: Initialized instance for model '%s' is not of type llm.LLM. Skipping.", attemptConf.ModelName)
		}
	}

	// --- Validate that we have at least one primary and one fallback ---
	if len(s.primaryAttempts) == 0 {
		return fmt.Errorf("inference service configuration error: no primary LLM attempts were successfully initialized")
	}
	if len(s.fallbackAttempts) == 0 {
		return fmt.Errorf("inference service configuration error: no fallback LLM attempts were successfully initialized")
	}

	// --- Initial MOA Configuration ---
	// Set initial MOA defaults based on the first primary and last fallback attempt
	s.moaPrimaryModelName = s.primaryAttempts[0].Config.ModelName
	s.moaFallbackModelName = s.fallbackAttempts[len(s.fallbackAttempts)-1].Config.ModelName
	s.moaPrimaryOpts = primaryOptsList[0]
	s.moaFallbackOpts = fallbackOptsList[len(fallbackOptsList)-1]

	// Attempt to create the initial MOA instance
	if err := s.reconfigureMOAInternal(); err != nil {
		log.Printf("[WARN] InferenceService: Initial MOA configuration failed: %v. MOA features disabled.", err)
	} // Removed incorrect 'else' block that was setting s.moa = nil on success
	// --- End MOA Creation ---

	// --- Create the Delegator Service ---
	// Pass the lists of attempts and the MOA instance
	// The first primary attempt's config determines the initial token limit check
	delegatorTokenLimit := s.primaryAttempts[0].Config.MaxTokens
	delegatorTokenModel := s.primaryAttempts[0].Config.ModelName // Model used for token estimation
	// Pass contextManager to DelegatorService
	s.delegator = NewDelegatorService(s.primaryAttempts, s.fallbackAttempts, delegatorTokenLimit, delegatorTokenModel, s.moa, s.contextManager)
	if s.delegator == nil {
		log.Println("[ERROR] InferenceService: Failed to create DelegatorService.") // Corrected log message
		s.isRunning = false
		// Clear attempts?
		s.moa = nil
		return fmt.Errorf("failed to create delegator service")
	}
	log.Println("InferenceService: DelegatorService created.")

	s.isRunning = true
	log.Println("InferenceService: Started successfully.")
	return nil
}

// Stop cleans up the clients and delegator
func (s *InferenceService) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if !s.isRunning {
		return nil
	}
	s.isRunning = false
	s.primaryAttempts = nil // Clear attempts
	s.fallbackAttempts = nil
	s.moa = nil // Clear MOA instance
	s.moaPrimaryOpts = nil
	s.moaFallbackOpts = nil
	s.delegator = nil // Clear delegator
	// s.contextManager = nil // Keep context manager? Or re-init on Start? Let's keep it.
	log.Println("InferenceService stopped.")
	return nil
}

// GenerateText delegates to the DelegatorService.
func (s *InferenceService) GenerateText(ctx context.Context, modelName string, promptText string, instructionText string) (string, error) {
	s.mutex.Lock() // Lock at the beginning
	if !s.isRunning || s.delegator == nil {
		s.mutex.Unlock()
		return "", errors.New("inference service is not running or delegator not configured")
	}
	delegatorInstance := s.delegator // Capture instance under lock
	s.mutex.Unlock()

	log.Printf("InferenceService: Delegating generation request to DelegatorService. Model: '%s', Instruction: '%s'", modelName, instructionText)
	// --- Adapt GenerateText to potentially use ContextManager ---
	// The delegator will now handle the potential call to ContextManager internally
	// Pass modelName and instructionText to the delegator
	response, err := delegatorInstance.GenerateSimple(ctx, modelName, promptText, instructionText)
	// --- End Adapt ---
	if err != nil {
		return "", err
	}
	log.Println("InferenceService: Generation successful via DelegatorService.")
	return response, nil
}

// --- ADDED: GenerateTextWithProvider ---
// GenerateTextWithProvider sends a prompt directly to the first configured instance of a specific provider.
func (s *InferenceService) GenerateTextWithProvider(providerName string, promptText string) (string, error) {
	s.mutex.Lock()
	if !s.isRunning {
		s.mutex.Unlock()
		return "", errors.New("inference service is not running")
	}
	// Find the specific LLM instance
	llmInstance := s.findLLMInstance(providerName)
	if llmInstance == nil {
		s.mutex.Unlock()
		return "", fmt.Errorf("provider '%s' not found or not configured", providerName)
	}
	s.mutex.Unlock() // Unlock before making the potentially long call

	ctx := context.Background() // Consider allowing context passing
	log.Printf("InferenceService: Delegating direct generation request to provider '%s'...", providerName)

	// Use the llm.NewPrompt helper from the gollm library
	prompt := llm.NewPrompt(promptText)

	return llmInstance.Generate(ctx, prompt)
}

// --- ADDED: GenerateTextWithMOA ---
// GenerateTextWithMOA directly delegates to the MOA instance.
func (s *InferenceService) GenerateTextWithMOA(promptText string, instructionText string) (string, error) {
	s.mutex.Lock()
	if !s.isRunning {
		s.mutex.Unlock()
		return "", errors.New("inference service is not running")
	}
	if s.moa == nil {
		s.mutex.Unlock()
		return "", errors.New("MOA (Mixture of Agents) is not configured or failed to initialize")
	}
	moaInstance := s.moa // Capture instance under lock
	s.mutex.Unlock()

	ctx := context.Background() // Consider allowing context passing
	log.Printf("InferenceService: Delegating generation request to MOA. Instruction: '%s'", instructionText)

	combinedPrompt := promptText
	if instructionText != "" {
		combinedPrompt = "Instructions:\n" + instructionText + "\n\n---\n\n" + promptText
	}

	// Note: MOA's Generate might have its own internal timeouts based on AgentTimeout
	response, err := moaInstance.Generate(ctx, combinedPrompt)
	if err != nil {
		log.Printf("InferenceService: Direct MOA generation failed: %v", err)
		return "", fmt.Errorf("MOA generation failed: %w", err)
	}
	log.Println("InferenceService: Direct generation successful via MOA.")
	return response, nil
}

// --- ADDED: GenerateTextWithContextManager ---
// Explicitly trigger context manager processing (useful for testing or specific UI actions)
func (s *InferenceService) GenerateTextWithContextManager(promptText, instruction string, llmProviderName string) (string, error) {
	s.mutex.Lock()
	if !s.isRunning || s.contextManager == nil {
		s.mutex.Unlock()
		return "", errors.New("service not running or context manager not configured")
	}
	// Find the LLM instance to use (e.g., Deepseek) - simplified lookup
	llmInstance := s.findLLMInstance(llmProviderName) // Need to implement findLLMInstance
	if llmInstance == nil {
		s.mutex.Unlock()
		return "", fmt.Errorf("LLM provider '%s' not found or configured", llmProviderName)
	}
	ctxMgr := s.contextManager
	s.mutex.Unlock()

	ctx := context.Background()
	log.Printf("InferenceService: Explicitly calling ContextManager with provider %s", llmProviderName)
	// Adapt llmInstance to TextGenerator interface if needed
	// Wrap the LLM in our adapter to implement TextGenerator
	wrappedLLM := &LLMAdapter{LLM: llmInstance, ProviderName: llmProviderName} // Pass ProviderName
	return ctxMgr.ProcessLargePrompt(ctx, wrappedLLM, promptText, instruction)
}

// --- Update other generation methods to use DelegatorService ---

func (s *InferenceService) GenerateTextWithCoT(ctx context.Context, promptText string) (string, error) {
	s.mutex.Lock()
	if !s.isRunning || s.delegator == nil {
		s.mutex.Unlock()
		return "", errors.New("service not running")
	}
	delegatorInstance := s.delegator
	s.mutex.Unlock()
	log.Println("InferenceService: Delegating CoT generation to DelegatorService...")
	return delegatorInstance.GenerateWithCoT(ctx, promptText) // Call delegator
}

func (s *InferenceService) GenerateTextWithReflection(ctx context.Context, promptText string) (string, error) {
	s.mutex.Lock()
	if !s.isRunning || s.delegator == nil {
		s.mutex.Unlock()
		return "", errors.New("service not running")
	}
	delegatorInstance := s.delegator
	s.mutex.Unlock()
	log.Println("InferenceService: Delegating Reflection generation to DelegatorService...")
	return delegatorInstance.GenerateWithReflection(ctx, promptText) // Call delegator
}

func (s *InferenceService) GenerateStructuredOutput(content string, schema string) (string, error) {
	s.mutex.Lock()
	if !s.isRunning || s.delegator == nil {
		s.mutex.Unlock()
		return "", errors.New("service not running")
	}
	delegatorInstance := s.delegator
	s.mutex.Unlock()
	ctx := context.Background()
	log.Println("InferenceService: Delegating structured output generation to DelegatorService...")
	return delegatorInstance.GenerateStructuredOutput(ctx, content, schema) // Call delegator
}

// --- Model Setting Methods ---
// SetMOAPrimaryModel sets the default primary model used for MOA configuration.
// This does NOT change the primary execution/fallback list.
func (s *InferenceService) SetMOAPrimaryModel(modelName string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isRunning {
		return errors.New("service is not running")
	}

	// Find the config options for the requested model from the loaded primary attempts
	var foundOpts []config.ConfigOption
	for _, attempt := range s.primaryAttempts {
		if attempt.Config.ModelName == modelName {
			foundOpts = attempt.Opts // Use stored opts
			break
		}
	}

	if foundOpts == nil {
		return fmt.Errorf("model '%s' not found in the configured primary attempts", modelName)
	}

	s.moaPrimaryModelName = modelName
	s.moaPrimaryOpts = foundOpts
	log.Printf("InferenceService: MOA primary model default set to '%s'. Reconfiguring MOA...", modelName)

	// Reconfigure MOA
	if err := s.reconfigureMOAInternal(); err != nil {
		log.Printf("[ERROR] Failed to reconfigure MOA after setting primary model: %v", err)
		return fmt.Errorf("failed to reconfigure MOA: %w", err)
	}

	log.Println("InferenceService: MOA reconfigured successfully.")
	return nil
}

// SetMOAFallbackModel sets the default fallback model used for MOA configuration (including aggregator).
// This does NOT change the primary execution/fallback list.
func (s *InferenceService) SetMOAFallbackModel(modelName string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isRunning {
		return errors.New("service is not running")
	}

	// Find the config options for the requested model from the loaded fallback attempts
	var foundOpts []config.ConfigOption
	for _, attempt := range s.fallbackAttempts {
		if attempt.Config.ModelName == modelName {
			foundOpts = attempt.Opts // Use stored opts
			break
		}
	}

	if foundOpts == nil {
		return fmt.Errorf("model '%s' not found in the configured fallback attempts", modelName)
	}

	s.moaFallbackModelName = modelName
	s.moaFallbackOpts = foundOpts
	log.Printf("InferenceService: MOA fallback model default set to '%s'. Reconfiguring MOA...", modelName)

	// Reconfigure MOA
	if err := s.reconfigureMOAInternal(); err != nil {
		log.Printf("[ERROR] Failed to reconfigure MOA after setting fallback model: %v", err)
		return fmt.Errorf("failed to reconfigure MOA: %w", err)
	}

	log.Println("InferenceService: MOA reconfigured successfully.")
	return nil
}

// GetPrimaryModels returns the names of the configured primary models.
func (s *InferenceService) GetPrimaryModels() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	models := make([]string, 0, len(s.primaryAttempts))
	for _, attempt := range s.primaryAttempts {
		models = append(models, attempt.Config.ModelName)
	}
	return models
}

// GetFallbackModels returns the names of the configured fallback models.
func (s *InferenceService) GetFallbackModels() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	models := make([]string, 0, len(s.fallbackAttempts))
	for _, attempt := range s.fallbackAttempts {
		models = append(models, attempt.Config.ModelName)
	}
	return models
}

// GetProxyModel returns the name of the proxy model.
// Returns the currently selected default model for MOA's primary role.
func (s *InferenceService) GetProxyModel() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.moaPrimaryModelName
}

// GetBaseModel returns the name of the base model.
// Returns the currently selected default model for MOA's fallback/aggregator role.
func (s *InferenceService) GetBaseModel() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.moaFallbackModelName
}

// IsRunning checks the client status
func (s *InferenceService) IsRunning() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.isRunning
}

// GetName identifies the service structure
func (s *InferenceService) GetName() string {
	return "InferenceService(Delegator+MOA)" // Updated name
}

// ClearConversationHistory clears the memory in the delegator.
func (s *InferenceService) ClearConversationHistory() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isRunning || s.delegator == nil {
		return errors.New("inference service is not running or delegator not configured")
	}

	s.delegator.memory.Clear()
	return nil
}

// reconfigureMOAInternal handles the creation or recreation of the MOA instance.
// Assumes lock is already held.
func (s *InferenceService) reconfigureMOAInternal() error {
	log.Println("InferenceService: Reconfiguring MOA...")

	// Check if required opts are set
	if s.moaPrimaryOpts == nil || s.moaFallbackOpts == nil {
		s.moa = nil // Ensure MOA is nil if config is incomplete
		return fmt.Errorf("cannot configure MOA, primary or fallback options missing")
	}

	// --- END DEBUG ---
	// --- Create the MOA Service ---
	moaCfg := gollm.MOAConfig{
		Iterations: 2, // Or make configurable
		Models: []config.ConfigOption{
			// Use the currently selected MOA primary options
			func(cfg *config.Config) {
				for _, opt := range s.moaPrimaryOpts {
					opt(cfg)
				}
			},
			// Use the currently selected MOA fallback options
			func(cfg *config.Config) {
				for _, opt := range s.moaFallbackOpts {
					opt(cfg)
				}
			},
		},
		MaxParallel:  2,                // Or make configurable
		AgentTimeout: 60 * time.Second, // Or make configurable
	}
	// Aggregator uses the options of the currently selected MOA fallback model
	aggregatorOpts := s.moaFallbackOpts
	moaInstance, moaErr := gollm.NewMOA(moaCfg, aggregatorOpts...)
	if moaErr != nil {
		log.Printf("[ERROR] InferenceService: Failed to create/recreate MOA instance: %v", moaErr)
		s.moa = nil // Ensure it's nil on error
		return moaErr
	}

	s.moa = moaInstance // Store the new MOA instance
	log.Printf("InferenceService: MOA instance created/recreated successfully (Primary: %s, Fallback: %s).", s.moaPrimaryModelName, s.moaFallbackModelName)

	// Update the delegator with the new MOA instance
	if s.delegator != nil {
		s.delegator.UpdateMOA(s.moa)
	}
	return nil
}

// findLLMInstance searches primary and fallback attempts for a provider name.
// NOTE: This is a simplified lookup, might need refinement if multiple models
// from the same provider exist. Returns the first match.
func (s *InferenceService) findLLMInstance(providerName string) llm.LLM {
	for _, attempt := range s.primaryAttempts {
		if attempt.Config.ProviderName == providerName {
			return attempt.Instance
		}
	}
	for _, attempt := range s.fallbackAttempts {
		if attempt.Config.ProviderName == providerName {
			return attempt.Instance
		}
	}
	return nil
}
