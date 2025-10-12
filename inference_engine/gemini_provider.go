// /home/gperry/Documents/GitHub/Inc-Line/Wordpress-Inference-Engine/inference/gemini_provider.go
package inference_engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json" // Import json package
	"fmt"
	"io"
	"log"
	"net/http" // Import net/http package
	"strings"
	"sync"
	"time"

	// Import Google's Gemini client library
	// "github.com/google/generative-ai-go/genai" // REMOVE genai client import
	// "google.golang.org/api/option" // REMOVE unused import

	"os" // Import os package
	"github.com/guiperry/gollm_cerebras/config"
	"github.com/guiperry/gollm_cerebras/providers"
	"github.com/guiperry/gollm_cerebras/types"
	"github.com/guiperry/gollm_cerebras/utils"
)

// GeminiProvider implements the provider interface for Google Gemini.
type GeminiProvider struct {
	apiKey      string
	model       string
	maxTokens   int
	temperature *float32
	topP        *float32
	topK        *int32
	// geminiClient *genai.Client // REMOVE genai client
	client       *http.Client // ADD standard http client
	baseEndpoint string       // ADD base endpoint storage
	extraHeaders map[string]string
	logger       utils.Logger
	mutex        sync.Mutex
}

// --- Gemini API Request/Response Structs (Manual HTTP) ---
type GeminiRequest struct {
	Contents         []GeminiContent         `json:"contents"`
	GenerationConfig *GeminiGenerationConfig `json:"generationConfig,omitempty"`
	Stream           bool                     `json:"stream,omitempty"`
	// SafetySettings, Tools, etc. can be added here if needed
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"` // "user" or "model"
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
	// InlineData, FunctionCall, etc. can be added here
}

// init registers the Gemini provider with the gollm registry.
// This function runs automatically when the package is imported.
func init() {
	log.Println("Registering Gemini provider constructor with gollm registry")
	providers.GetDefaultRegistry().Register("gemini", NewGeminiProvider)
}

type GeminiGenerationConfig struct {
	Temperature     *float32 `json:"temperature,omitempty"`
	TopP            *float32 `json:"topP,omitempty"`
	TopK            *int32   `json:"topK,omitempty"`
	MaxOutputTokens *int32   `json:"maxOutputTokens,omitempty"`
	// StopSequences []string `json:"stopSequences,omitempty"`
}

type GeminiResponse struct {
	Candidates []struct {
		Content      *GeminiContent `json:"content"`
		FinishReason string         `json:"finishReason,omitempty"`
		// SafetyRatings, etc. can be added here if needed
	} `json:"candidates"`
	PromptFeedback *struct {
		BlockReason string `json:"blockReason,omitempty"`
		// SafetyRatings, etc. can be added here if needed
	} `json:"promptFeedback,omitempty"`
}

// Error structure (example, might need adjustment based on actual API errors)
type GeminiErrorResponse struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// NewGeminiProvider creates an instance of the Gemini provider.
// It's called by gollm when gollm.NewLLM is used with provider "gemini".
func NewGeminiProvider(apiKey, model string, extraHeaders map[string]string) providers.Provider {
	log.Printf("[DEBUG] NewGeminiProvider called! apiKey: %t, model: %s", apiKey != "", model)

	// Initialize with arguments and defaults
	provider := &GeminiProvider{
		apiKey:       apiKey,
		model:        model,
		maxTokens:    1024,
		extraHeaders: make(map[string]string),
		client: &http.Client{
			Timeout: 120 * time.Second, // Set timeout (e.g., 120 seconds)
		}, // Initialize standard HTTP client
		logger: utils.NewLogger(utils.LogLevelInfo),
	}

	// Set default model if provided one is empty
	if provider.model == "" {
		provider.model = "gemini-1.5-flash-latest" // Use the known working model name
		log.Printf("Gemini model defaulting to %s", provider.model)
	}

	// Copy provided extraHeaders
	for k, v := range extraHeaders {
		provider.extraHeaders[k] = v
	}

	// --- Read Endpoint from Environment Variable ---
	apiEndpoint := os.Getenv("GEMINI_API_ENDPOINT")
	if apiEndpoint == "" {
		// Default to the v1beta base path as it's commonly needed
		apiEndpoint = "https://generativelanguage.googleapis.com/v1beta/"
		log.Println("GeminiProvider: GEMINI_API_ENDPOINT not set, using default:", apiEndpoint)
	} else {
		log.Println("GeminiProvider: Using endpoint from GEMINI_API_ENDPOINT:", apiEndpoint)
	}
	provider.baseEndpoint = apiEndpoint // Store the base endpoint

	log.Printf("NewGeminiProvider created: model=%s", provider.model)
	return provider
}

// --- Implement the providers.Provider interface methods ---

// Name returns the name of the provider.
func (p *GeminiProvider) Name() string {
	return "gemini"
}

// Endpoint returns the API endpoint URL.
func (p *GeminiProvider) Endpoint() string {
	// Construct the full URL path required by the API for generateContent
	// Gollm likely uses this directly for the request.
	p.mutex.Lock()
	base := p.baseEndpoint
	model := p.model
	apiKey := p.apiKey // Get API key
	p.mutex.Unlock()

	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	// Append the API key as a query parameter
	if apiKey == "" {
		p.logger.Error("Gemini API key is missing when constructing endpoint URL") // Log error if key missing
	}
	return fmt.Sprintf("%smodels/%s:generateContent?key=%s", base, model, apiKey)
}

// Headers returns the necessary HTTP headers.
func (p *GeminiProvider) Headers() map[string]string {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	headers := map[string]string{
		"Content-Type": "application/json", // Key is now in the URL
		"User-Agent":   "Wordpress-Inference-Engine/1.0",
	}
	// --- REMOVED Authorization Header ---
	// The API key is passed via the URL parameter, not this header.

	// Add any extra headers
	for k, v := range p.extraHeaders {
		headers[k] = v
	}

	return headers
}

// PrepareRequest creates the request body for a standard API call.
func (p *GeminiProvider) PrepareRequest(prompt string, options map[string]interface{}) ([]byte, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	log.Printf("GeminiProvider: Preparing request for model %s", p.model)

	// Construct the request body manually
	reqBody := GeminiRequest{
		Contents: []GeminiContent{
			{
				Role: "user", // Assume simple prompt is from user
				Parts: []GeminiPart{
					{Text: prompt},
				},
			},
		},
		GenerationConfig: &GeminiGenerationConfig{},
	}

	// Apply options from the 'options' map to reqBody.GenerationConfig
	if options != nil {
		if tempVal, ok := options["temperature"].(float64); ok {
			tempFloat32 := float32(tempVal)
			reqBody.GenerationConfig.Temperature = &tempFloat32
		}
		if topPVal, ok := options["top_p"].(float64); ok {
			topPFloat32 := float32(topPVal)
			reqBody.GenerationConfig.TopP = &topPFloat32
		}
		if topKVal, ok := options["top_k"].(float64); ok {
			topKInt32 := int32(topKVal)
			reqBody.GenerationConfig.TopK = &topKInt32
		}
		if maxTokensVal, ok := options["max_tokens"].(float64); ok {
			maxTokensInt32 := int32(maxTokensVal)
			reqBody.GenerationConfig.MaxOutputTokens = &maxTokensInt32
		}
		if streamVal, ok := options["stream"].(bool); ok {
			reqBody.Stream = streamVal
		}
	}

	// Marshal the request body
	jsonBytes, err := json.Marshal(reqBody)
	return jsonBytes, err
}

// PrepareRequestWithSchema creates a request with JSON schema validation.
func (p *GeminiProvider) PrepareRequestWithSchema(prompt string, options map[string]interface{}, schema interface{}) ([]byte, error) {
	// Gemini supports structured output, but we'll implement this in a basic way for now
	return p.PrepareRequest(prompt, options)
}

// PrepareRequestWithMessages handles messages for conversation.
func (p *GeminiProvider) PrepareRequestWithMessages(messages []types.MemoryMessage, options map[string]interface{}) ([]byte, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	log.Printf("GeminiProvider: Preparing request with messages for model %s", p.model)

	// Convert messages to Gemini format
	geminiContents := make([]GeminiContent, 0, len(messages))
	for _, msg := range messages {
		role := "user" // Default role
		if strings.ToLower(msg.Role) == "assistant" || strings.ToLower(msg.Role) == "ai" || strings.ToLower(msg.Role) == "model" {
			role = "model"
		}
		geminiContents = append(geminiContents, GeminiContent{
			Role:  role,
			Parts: []GeminiPart{{Text: msg.Content}},
		})
	}

	reqBody := GeminiRequest{
		Contents:         geminiContents,
		GenerationConfig: &GeminiGenerationConfig{},
	}

	// Apply GenerationConfig from options map
	if options != nil {
		if tempVal, ok := options["temperature"].(float64); ok {
			tempFloat32 := float32(tempVal)
			reqBody.GenerationConfig.Temperature = &tempFloat32
		}
		if topPVal, ok := options["top_p"].(float64); ok {
			topPFloat32 := float32(topPVal)
			reqBody.GenerationConfig.TopP = &topPFloat32
		}
		if topKVal, ok := options["top_k"].(float64); ok {
			topKInt32 := int32(topKVal)
			reqBody.GenerationConfig.TopK = &topKInt32
		}
		if maxTokensVal, ok := options["max_tokens"].(float64); ok {
			maxTokensInt32 := int32(maxTokensVal)
			reqBody.GenerationConfig.MaxOutputTokens = &maxTokensInt32
		}
		if streamVal, ok := options["stream"].(bool); ok {
			reqBody.Stream = streamVal
		}
	}
	jsonBytes, err := json.Marshal(reqBody)
	return jsonBytes, err
}

// ParseResponse extracts the generated text from the API response.
func (p *GeminiProvider) ParseResponse(body []byte) (string, error) {
	// This method won't be used directly since we're using the client library
	// But we need to implement it to satisfy the interface
	// Parse the manually constructed response
	var resp GeminiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		// Try parsing as error
		var errResp GeminiErrorResponse
		if errParseErr := json.Unmarshal(body, &errResp); errParseErr == nil && errResp.Error.Message != "" {
			return "", fmt.Errorf("gemini API error: %s", errResp.Error.Message)
		}
		return "", fmt.Errorf("failed to unmarshal Gemini response: %w", err)
	}

	if len(resp.Candidates) > 0 {
		candidate := resp.Candidates[0]

		// Check if content exists and has parts
		if candidate.Content != nil && len(candidate.Content.Parts) > 0 {
			// Assuming the first part of the first candidate is the text response
			return candidate.Content.Parts[0].Text, nil
		}

		// Handle finish reasons that indicate no content
		switch candidate.FinishReason {
		case "SAFETY":
			p.logger.Warn("Gemini response blocked due to safety filters", "finishReason", candidate.FinishReason)
			return "", fmt.Errorf("response blocked by Gemini safety filters")
		case "RECITATION":
			p.logger.Warn("Gemini response blocked due to recitation filters", "finishReason", candidate.FinishReason)
			return "", fmt.Errorf("response blocked by Gemini recitation filters")
		case "MAX_TOKENS":
			p.logger.Warn("Gemini response stopped due to max tokens limit", "finishReason", candidate.FinishReason)
			return "", fmt.Errorf("response truncated due to max tokens limit")
		case "OTHER":
			p.logger.Warn("Gemini response finished for other reasons", "finishReason", candidate.FinishReason)
			return "", fmt.Errorf("response finished for unspecified reasons")
		default:
			p.logger.Warn("Gemini response has no content but valid finish reason", "finishReason", candidate.FinishReason)
			return "", fmt.Errorf("no content in response (finish reason: %s)", candidate.FinishReason)
		}
	}

	// Check PromptFeedback for blocked prompts
	if resp.PromptFeedback != nil && resp.PromptFeedback.BlockReason != "" {
		p.logger.Warn("Gemini prompt was blocked", "blockReason", resp.PromptFeedback.BlockReason)
		return "", fmt.Errorf("prompt blocked by Gemini: %s", resp.PromptFeedback.BlockReason)
	}

	// Handle cases with no candidates at all
	p.logger.Warn("Gemini response parsed but no candidates found", "body", string(body))
	return "", fmt.Errorf("no response candidates found in Gemini response")
}

// SetExtraHeaders configures additional HTTP headers.
func (p *GeminiProvider) SetExtraHeaders(extraHeaders map[string]string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Replace existing headers
	p.extraHeaders = make(map[string]string)
	for k, v := range extraHeaders {
		p.extraHeaders[k] = v
	}
}

// HandleFunctionCalls processes function calling capabilities.
func (p *GeminiProvider) HandleFunctionCalls(body []byte) ([]byte, error) {
	// Gemini supports function calling, but we'll implement this in a basic way for now
	return body, nil
}

// SupportsJSONSchema indicates whether the provider supports native JSON schema validation.
func (p *GeminiProvider) SupportsJSONSchema() bool {
	// Gemini's function calling is the way to get structured output, not direct JSON schema in response_format yet.
	return false // Set to false for now, can be true if function calling is implemented
}

// SetDefaultOptions configures provider-specific defaults.
func (p *GeminiProvider) SetDefaultOptions(cfg *config.Config) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// --- Use cfg directly ---
	if cfg == nil {
		p.logger.Warn("SetDefaultOptions called with nil config")
		return
	}

	// Get Gemini provider-specific API key if available
	providerAPIKey := ""
	if cfg.APIKeys != nil {
		if apiKey, ok := cfg.APIKeys[p.Name()]; ok { // Use p.Name() which is "gemini"
			providerAPIKey = apiKey
			p.logger.Debug("Found provider-specific API key for Gemini")
		}
	}

	// Get provider-specific model if available (assuming gollm config supports this structure)
	// Note: gollm's base config might only have a single cfg.Model.
	// If provider-specific models aren't directly in cfg, we might need to adjust.
	// For now, let's prioritize the provider key and then the global model.
	providerModel := ""
	// if cfg.ProviderModels != nil { // Assuming a hypothetical structure
	// 	if model, ok := cfg.ProviderModels[p.Name()]; ok {
	// 		providerModel = model
	// 	}
	// }

	// --- Apply settings ---

	// Set API key if provided and not already set
	if providerAPIKey != "" && p.apiKey == "" {
		p.apiKey = providerAPIKey
		p.logger.Info("Applied default API key for Gemini")
		// No client re-initialization needed for http.Client
	} else if p.apiKey == "" {
		p.logger.Warn("No default or specific API key found/set for Gemini")
	}

	// Set model: Prioritize provider-specific, then global, then keep existing default
	if providerModel != "" && (p.model == "" || p.model == "gemini-1.5-flash-latest") { // Updated default check
		p.model = providerModel
		p.logger.Info("Applied provider-specific default model", "model", p.model)
	} else if cfg.Model != "" && (p.model == "" || p.model == "gemini-1.5-flash-latest") { // Updated default check
		p.model = cfg.Model // Fallback to global default model
		p.logger.Info("Applied global default model", "model", p.model)
	}

	// Set max tokens: Prioritize global, then keep existing default
	if cfg.MaxTokens > 0 && (p.maxTokens == 0 || p.maxTokens == 1024) {
		p.maxTokens = cfg.MaxTokens
		p.logger.Info("Applied global default max tokens", "maxTokens", p.maxTokens)
	}

	// Set temperature if not already set
	if p.temperature == nil && cfg.Temperature > 0 {
		tempFloat32 := float32(cfg.Temperature)
		p.temperature = &tempFloat32
		p.logger.Info("Applied global default temperature", "temperature", *p.temperature)
	}

	// Set TopP if not already set
	if p.topP == nil && cfg.TopP > 0 {
		topPFloat32 := float32(cfg.TopP)
		p.topP = &topPFloat32
		p.logger.Info("Applied global default TopP", "topP", *p.topP)
	}

	// Set TopK if not already set (assuming cfg has TopK)
	// if p.topK == nil && cfg.TopK > 0 {
	// 	topKInt32 := int32(cfg.TopK)
	// 	p.topK = &topKInt32
	// 	p.logger.Info("Applied global default TopK", "topK", *p.topK)
	// }

	p.logger.Info("Default options processing complete for Gemini", "final_model", p.model, "final_maxTokens", p.maxTokens)
}

// validateGeminiConfig validates Gemini API configuration parameters
func validateGeminiConfig(key string, value interface{}) error {
	switch key {
	case "temperature":
		var temp float64
		switch v := value.(type) {
		case float64:
			temp = v
		case float32:
			temp = float64(v)
		default:
			return fmt.Errorf("temperature must be a number")
		}
		if temp < 0.0 || temp > 2.0 {
			return fmt.Errorf("temperature must be between 0.0 and 2.0, got %f", temp)
		}
	case "top_p":
		var topP float64
		switch v := value.(type) {
		case float64:
			topP = v
		case float32:
			topP = float64(v)
		default:
			return fmt.Errorf("top_p must be a number")
		}
		if topP < 0.0 || topP > 1.0 {
			return fmt.Errorf("top_p must be between 0.0 and 1.0, got %f", topP)
		}
	case "top_k":
		var topK int
		switch v := value.(type) {
		case int:
			topK = v
		case int32:
			topK = int(v)
		case float64:
			if v != float64(int(v)) {
				return fmt.Errorf("top_k must be an integer")
			}
			topK = int(v)
		default:
			return fmt.Errorf("top_k must be an integer")
		}
		if topK < 1 {
			return fmt.Errorf("top_k must be at least 1, got %d", topK)
		}
	case "max_tokens":
		var maxTokens int
		switch v := value.(type) {
		case int:
			maxTokens = v
		case float64:
			if v != float64(int(v)) {
				return fmt.Errorf("max_tokens must be an integer")
			}
			maxTokens = int(v)
		default:
			return fmt.Errorf("max_tokens must be an integer")
		}
		if maxTokens < 1 {
			return fmt.Errorf("max_tokens must be at least 1, got %d", maxTokens)
		}
	}
	return nil
}

// SetOption sets a specific option for the provider.
func (p *GeminiProvider) SetOption(key string, value interface{}) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Validate the configuration
	if err := validateGeminiConfig(key, value); err != nil {
		p.logger.Warn("Invalid configuration value", "key", key, "error", err)
		return // Don't set invalid values
	}

	switch key {
	case "model":
		if modelStr, ok := value.(string); ok {
			p.model = modelStr
		}
	case "max_tokens":
		if maxTokens, ok := value.(int); ok {
			p.maxTokens = maxTokens
		}
	case "temperature":
		if temp, ok := value.(float64); ok {
			tempFloat32 := float32(temp)
			p.temperature = &tempFloat32
		} else if temp, ok := value.(float32); ok {
			p.temperature = &temp
		}
	case "top_p":
		if topP, ok := value.(float64); ok {
			topPFloat32 := float32(topP)
			p.topP = &topPFloat32
		} else if topP, ok := value.(float32); ok {
			p.topP = &topP
		}
	case "top_k":
		if topK, ok := value.(int); ok {
			topKInt32 := int32(topK)
			p.topK = &topKInt32
		} else if topK, ok := value.(int32); ok {
			p.topK = &topK
		}
	}
}

// SetLogger configures the logger for the provider.
func (p *GeminiProvider) SetLogger(logger utils.Logger) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.logger = logger
}

// SupportsStreaming indicates if the provider supports streaming responses.
func (p *GeminiProvider) SupportsStreaming() bool {
	return true // Gemini supports streaming
}

// PrepareStreamRequest creates a request body for streaming API calls.
func (p *GeminiProvider) PrepareStreamRequest(prompt string, options map[string]interface{}) ([]byte, error) {
	// Ensure stream is set to true for streaming requests
	if options == nil {
		options = make(map[string]interface{})
	}
	options["stream"] = true
	return p.PrepareRequest(prompt, options)
}

// ParseStreamResponse processes a single chunk from a streaming response.
func (p *GeminiProvider) ParseStreamResponse(chunk []byte) (string, error) {
	// Parse the JSON response chunk
	var streamResp GeminiResponse
	if err := json.Unmarshal(chunk, &streamResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal streaming response chunk: %w", err)
	}

	// Extract text from candidates
	if len(streamResp.Candidates) > 0 {
		candidate := streamResp.Candidates[0]

		// Check for finish reasons that indicate completion or errors
		if candidate.FinishReason != "" {
			switch candidate.FinishReason {
			case "STOP":
				// Normal completion - return empty string to indicate end
				return "", nil
			case "SAFETY":
				return "", fmt.Errorf("response blocked by Gemini safety filters")
			case "MAX_TOKENS":
				return "", fmt.Errorf("response truncated due to max tokens limit")
			default:
				return "", fmt.Errorf("streaming finished with reason: %s", candidate.FinishReason)
			}
		}

		// Return text content
		if candidate.Content != nil && len(candidate.Content.Parts) > 0 {
			return candidate.Content.Parts[0].Text, nil
		}
	}

	// Check for prompt feedback (blocked prompts)
	if streamResp.PromptFeedback != nil && streamResp.PromptFeedback.BlockReason != "" {
		return "", fmt.Errorf("prompt blocked by Gemini: %s", streamResp.PromptFeedback.BlockReason)
	}

	// No content in this chunk
	return "", nil
}

// --- Helper methods for actual implementation ---

// GenerateContent sends a request to the Gemini API and returns the response.
func (p *GeminiProvider) GenerateContent(ctx context.Context, prompt string) (string, error) {
	// This method might not be directly called by gollm's standard Generate flow,
	// which uses PrepareRequest, Endpoint, Headers, and ParseResponse.
	// Keep it simple or log a warning if it's unexpectedly called.
	p.logger.Warn("GenerateContent called directly - this might bypass gollm's standard flow.")

	// Prepare request body using the provider method
	_, err := p.PrepareRequest(prompt, nil) // Pass nil options for now
	if err != nil {
		return "", fmt.Errorf("failed to prepare Gemini request: %w", err)
	}

	p.mutex.Lock()
	model := p.model
	apiKey := p.apiKey
	baseEndpoint := p.baseEndpoint
	httpClient := p.client
	p.mutex.Unlock()

	if apiKey == "" {
		return "", fmt.Errorf("gemini API key not set")
	}
	if httpClient == nil {
		return "", fmt.Errorf("http client not initialized")
	}

	// Construct the full URL manually
	// Ensure baseEndpoint ends with a slash
	if !strings.HasSuffix(baseEndpoint, "/") {
		baseEndpoint += "/"
	}
	_ = fmt.Sprintf("%smodels/%s:generateContent?key=%s", baseEndpoint, model, apiKey)
	// --- REMOVED: Manual HTTP Request Logic ---
	// The gollm library should handle the actual HTTP call using Endpoint(), Headers(), PrepareRequest(), ParseResponse().
	// If this method IS called, it means something is using it directly.
	// For now, return an error or a placeholder.
	//return "", fmt.Errorf("direct call to GeminiProvider.GenerateContent is not the standard gollm flow")
	/*

		log.Printf("GeminiProvider (GenerateContent): Constructed URL: %s", fullURL)

		p.logger.Debug("GeminiProvider: Sending HTTP request", "url", fullURL, "body_len", len(reqBytes))

		// Create HTTP request
		httpReq, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBuffer(reqBytes))
		if err != nil {
			return "", fmt.Errorf("failed to create Gemini HTTP request: %w", err)
		}

		// Set headers (minimal, Content-Type is important)
		httpReq.Header.Set("Content-Type", "application/json")

		/* // Generation config is now part of the request body
		if p.temperature != nil {
			genModel.SetTemperature(*p.temperature)
		}
		if p.topP != nil {
			genModel.SetTopP(*p.topP)
		}
		if p.topK != nil {
			genModel.SetTopK(*p.topK)
		}
		genModel.SetMaxOutputTokens(int32(p.maxTokens))
	*/

	// --- Add Debug Logging ---
	p.logger.Debug("GeminiProvider: Attempting GenerateContent", "model", model, "prompt_length", len(prompt))
	if len(prompt) > 100 {
		p.logger.Debug("GeminiProvider: Prompt prefix", "prefix", prompt[:100]+"...")
	} else {
		p.logger.Debug("GeminiProvider: Prompt", "prompt", prompt)
	}
	// --- End Debug Logging ---

	// HTTP request logic removed - handled by gollm
	return "", fmt.Errorf("direct call to GeminiProvider.GenerateContent is not the standard gollm flow")

}

// GenerateContentFromMessages sends a conversation to the Gemini API and returns the response.

func (p *GeminiProvider) GenerateContentFromMessages(ctx context.Context, messages []types.MemoryMessage) (string, error) {
	p.logger.Warn("GenerateContentFromMessages called directly - this might bypass gollm's standard flow.")
	// Prepare request body using the provider method
	_, err := p.PrepareRequestWithMessages(messages, nil) // Pass nil options for now
	if err != nil {
		return "", fmt.Errorf("failed to prepare Gemini messages request: %w", err)
	}

	p.mutex.Lock()
	model := p.model
	apiKey := p.apiKey
	baseEndpoint := p.baseEndpoint
	httpClient := p.client
	p.mutex.Unlock()

	if apiKey == "" {
		return "", fmt.Errorf("gemini API key not set")
	}
	if httpClient == nil {
		return "", fmt.Errorf("http client not initialized")
	}

	// Construct the full URL manually
	if !strings.HasSuffix(baseEndpoint, "/") {
		baseEndpoint += "/"
	}
	fullURL := fmt.Sprintf("%smodels/%s:generateContent?key=%s", baseEndpoint, model, apiKey)
	log.Printf("GeminiProvider (GenerateContentFromMessages): Constructed URL: %s", fullURL)

	// --- REMOVED: Manual HTTP Request Logic ---
	// Keep chat slice building for API contract even though unused in this implementation
	/*
		p.logger.Debug("GeminiProvider: Sending HTTP request (messages)", "url", fullURL, "body_len", len(reqBytes))

		// Create HTTP request
		httpReq, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewBuffer(reqBytes))
		if err != nil {
			return "", fmt.Errorf("failed to create Gemini HTTP request (messages): %w", err)
		}

		// Set headers
		httpReq.Header.Set("Content-Type", "application/json")
		p.mutex.Lock()
		for k, v := range p.extraHeaders {
			httpReq.Header.Set(k, v)
		}
		/* // Generation config is now part of the request body
		if p.temperature != nil {
			genModel.SetTemperature(*p.temperature)
		}
		if p.topP != nil {
			genModel.SetTopP(*p.topP)
		}
		if p.topK != nil {
			genModel.SetTopK(*p.topK)
		}
		genModel.SetMaxOutputTokens(int32(p.maxTokens))
	*/
	//p.mutex.Unlock()

	// HTTP request logic removed - handled by gollm
	return "", fmt.Errorf("direct call to GeminiProvider.GenerateContentFromMessages is not the standard gollm flow")

}

// StreamContent streams a response from the Gemini API.
func (p *GeminiProvider) StreamContent(ctx context.Context, prompt string) (chan string, chan error) {
	textChan := make(chan string)
	errChan := make(chan error, 1)

	go func() {
		defer close(textChan)
		defer close(errChan)

		// Prepare streaming request
		reqBody, err := p.PrepareStreamRequest(prompt, nil)
		if err != nil {
			errChan <- fmt.Errorf("failed to prepare streaming request: %w", err)
			return
		}

		// Get endpoint and headers
		endpoint := p.Endpoint()
		headers := p.Headers()

		// Create HTTP request
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(reqBody))
		if err != nil {
			errChan <- fmt.Errorf("failed to create HTTP request: %w", err)
			return
		}

		// Set headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		p.logger.Debug("Sending streaming request to Gemini API", "endpoint", endpoint)

		// Send request
		resp, err := p.client.Do(req)
		if err != nil {
			errChan <- fmt.Errorf("failed to send streaming request: %w", err)
			return
		}
		defer resp.Body.Close()

		// Check status code
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			errChan <- fmt.Errorf("gemini API returned status %d: %s", resp.StatusCode, string(body))
			return
		}

		// Read streaming response line by line
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// Parse the JSON response
			var streamResp GeminiResponse
			if err := json.Unmarshal([]byte(line), &streamResp); err != nil {
				p.logger.Warn("Failed to parse streaming response line", "line", line, "error", err)
				continue
			}

			// Extract text from candidates
			if len(streamResp.Candidates) > 0 {
				candidate := streamResp.Candidates[0]

				// Check for finish reasons that indicate completion or errors
				if candidate.FinishReason != "" {
					switch candidate.FinishReason {
					case "STOP":
						// Normal completion
						p.logger.Debug("Streaming completed normally")
						return
					case "SAFETY":
						errChan <- fmt.Errorf("response blocked by Gemini safety filters")
						return
					case "MAX_TOKENS":
						errChan <- fmt.Errorf("response truncated due to max tokens limit")
						return
					default:
						p.logger.Warn("Streaming finished with reason", "finishReason", candidate.FinishReason)
						return
					}
				}

				// Send text content
				if candidate.Content != nil && len(candidate.Content.Parts) > 0 {
					text := candidate.Content.Parts[0].Text
					if text != "" {
						select {
						case textChan <- text:
						case <-ctx.Done():
							errChan <- ctx.Err()
							return
						}
					}
				}
			}

			// Check for prompt feedback (blocked prompts)
			if streamResp.PromptFeedback != nil && streamResp.PromptFeedback.BlockReason != "" {
				errChan <- fmt.Errorf("prompt blocked by Gemini: %s", streamResp.PromptFeedback.BlockReason)
				return
			}
		}

		// Check for scanner errors
		if err := scanner.Err(); err != nil {
			errChan <- fmt.Errorf("error reading streaming response: %w", err)
			return
		}
	}()

	return textChan, errChan
}
