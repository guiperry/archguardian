// /home/gperry/Documents/GitHub/Inc-Line/Wordpress-Inference-Engine/inference/gemini_provider.go
package inference_engine

import (
	"context"
	"encoding/json" // Import json package
	"fmt"
	"log"
	"net/http" // Import net/http package
	"strings"
	"sync"
	"time"

	// Import Google's Gemini client library
	// "github.com/google/generative-ai-go/genai" // REMOVE genai client import
	// "google.golang.org/api/option" // REMOVE unused import

	"os" // Import os package

	"github.com/google/generative-ai-go/genai"
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
		Content *GeminiContent `json:"content"`
		// FinishReason, SafetyRatings, etc.
	} `json:"candidates"`
	// PromptFeedback
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
		GenerationConfig: &GeminiGenerationConfig{
			// Apply options if needed, similar to how it was done for Cerebras/Deepseek
			// Temperature: p.temperature,
			// TopP: p.topP,
			// TopK: p.topK,
			// MaxOutputTokens: &maxTokensInt32,
		},
	}
	// TODO: Apply options from the 'options' map to reqBody.GenerationConfig

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
		Contents: geminiContents,
		// TODO: Apply GenerationConfig from options map
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

	if len(resp.Candidates) > 0 && resp.Candidates[0].Content != nil && len(resp.Candidates[0].Content.Parts) > 0 {
		// Assuming the first part of the first candidate is the text response
		return resp.Candidates[0].Content.Parts[0].Text, nil
	}

	// Handle cases with no valid content (e.g., safety blocks, empty response)
	// TODO: Inspect resp.Candidates[0].FinishReason or PromptFeedback if needed
	p.logger.Warn("Gemini response parsed but no valid content found", "body", string(body))
	return "", fmt.Errorf("no valid content found in Gemini response")
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

// SetOption sets a specific option for the provider.
func (p *GeminiProvider) SetOption(key string, value interface{}) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

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
	// Similar to PrepareRequest, but for streaming
	return p.PrepareRequest(prompt, options)
}

// ParseStreamResponse processes a single chunk from a streaming response.
func (p *GeminiProvider) ParseStreamResponse(chunk []byte) (string, error) {
	// This method won't be used directly since we're using the client library
	// But we need to implement it to satisfy the interface
	return string(chunk), nil
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

	// Convert messages to Gemini format
	var chat []*genai.Content // Use pointer slice
	for _, msg := range messages {
		role := msg.Role
		if role == "assistant" {
			role = "model"
		}
		// Ensure role is either "user" or "model"
		if role != "user" && role != "model" {
			p.logger.Warn("Invalid role for Gemini, skipping message", "role", role)
			continue
		}

		content := &genai.Content{ // Create pointer
			Role:  role,
			Parts: []genai.Part{genai.Text(msg.Content)},
		}
		chat = append(chat, content)
		p.logger.Debug("Added message to chat", "role", content.Role, "content_length", len(msg.Content), "chat_length", len(chat))
	}

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

		// TODO: Implement streaming using manual HTTP request
		// This involves setting "stream":true in the request body,
		// sending the request, and then reading the response body line by line,
		// parsing each Server-Sent Event (SSE) chunk.
		// For now, return an error indicating it's not implemented.
		errChan <- fmt.Errorf("streaming not yet implemented for manual Gemini HTTP provider")
		//return
		//p.mutex.Lock()
		// if p.temperature != nil {
		// 	genModel.SetTemperature(*p.temperature) // undefined: genModel
		// }
		// if p.topP != nil {
		// 	genModel.SetTopP(*p.topP) // undefined: genModel
		// }
		// if p.topK != nil {
		// 	genModel.SetTopK(*p.topK) // undefined: genModel
		// }
		// genModel.SetMaxOutputTokens(int32(p.maxTokens)) // undefined: genModel
		//p.mutex.Unlock()

	}()

	return textChan, errChan
}
