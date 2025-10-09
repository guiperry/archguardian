// /home/gperry/Documents/GitHub/Inc-Line/Wordpress-Inference-Engine/inference/deepseek_provider.go
package inference_engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	// Use official gollm imports
	"github.com/guiperry/gollm_cerebras/config"
	"github.com/guiperry/gollm_cerebras/providers"
	gollm_types "github.com/guiperry/gollm_cerebras/types"
	"github.com/guiperry/gollm_cerebras/utils"

	// Import jsonschema for tool parameters and response format
	"github.com/invopop/jsonschema"
)

// --- Deepseek API Specific Structs (Assuming OpenAI Compatibility) ---
// We can reuse the Cerebras structs as they are based on the OpenAI format.
// Renaming them slightly for clarity might be good practice, but for simplicity,
// we'll reuse CerebrasMessage, CerebrasTool, etc. If Deepseek has specific deviations,
// these structs would need adjustment.

// DeepseekMessage uses the same structure as CerebrasMessage (OpenAI compatible)
type DeepseekMessage = CerebrasMessage

// DeepseekTool uses the same structure as CerebrasTool (OpenAI compatible)
type DeepseekTool = CerebrasTool

// DeepseekToolCall uses the same structure as CerebrasToolCall (OpenAI compatible)
type DeepseekToolCall = CerebrasToolCall

// DeepseekChatCompletionRequest uses the same structure as ChatCompletionRequest (OpenAI compatible)
type DeepseekChatCompletionRequest = ChatCompletionRequest

// DeepseekChatCompletionResponse uses the same structure as ChatCompletionResponse (OpenAI compatible)
type DeepseekChatCompletionResponse = ChatCompletionResponse

// DeepseekStreamChoiceDelta uses the same structure as streamChoiceDelta (OpenAI compatible)
type DeepseekStreamChoiceDelta = streamChoiceDelta

// DeepseekStreamChoice uses the same structure as streamChoice (OpenAI compatible)
type DeepseekStreamChoice = streamChoice

// DeepseekStreamChunk uses the same structure as streamChunk (OpenAI compatible)
type DeepseekStreamChunk = streamChunk

// --- DeepseekProvider Implementation ---

// DeepseekProvider implements providers.Provider for the Deepseek API
type DeepseekProvider struct {
	apiKey       string
	model        string
	maxTokens    int
	temperature  *float64
	topP         *float64
	seed         *int64 // Deepseek might support seed
	extraHeaders map[string]string
	logger       utils.Logger
	client       *http.Client // Standard HTTP client

	mutex sync.Mutex
}

// --- Registration ---
func init() {
	registry := providers.GetDefaultRegistry()
	registry.Register("deepseek", NewDeepseekProvider)
	log.Println("Registered Deepseek provider constructor with gollm registry")
}

// NewDeepseekProvider creates a new Deepseek provider instance.
func NewDeepseekProvider(apiKey, model string, extraHeaders map[string]string) providers.Provider {
	log.Printf("[DEBUG] NewDeepseekProvider called! apiKey present: %t, model: %s", apiKey != "", model)
	provider := &DeepseekProvider{
		apiKey:       apiKey,
		model:        model,
		maxTokens:    2048, // Default max tokens for Deepseek (adjust if needed)
		extraHeaders: make(map[string]string),
		logger:       utils.NewLogger(utils.LogLevelInfo),
		client:       &http.Client{},
	}
	// Set default model if provided one is empty
	if provider.model == "" {
		provider.model = "deepseek-chat" // Default Deepseek model
		log.Printf("Deepseek model defaulting to %s", provider.model)
	}
	// Copy provided extraHeaders
	for k, v := range extraHeaders {
		provider.extraHeaders[k] = v
	}
	log.Printf("NewDeepseekProvider created: model=%s", provider.model)
	return provider
}

// Name returns the provider's identifier.
func (p *DeepseekProvider) Name() string {
	return "deepseek"
}

// Endpoint returns the API endpoint URL.
func (p *DeepseekProvider) Endpoint() string {
	// Official Deepseek API endpoint
	return "https://api.deepseek.com/v1/chat/completions"
}

// Headers returns the necessary HTTP headers.
func (p *DeepseekProvider) Headers() map[string]string {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
		"User-Agent":   "Wordpress-Inference-Engine/1.0 (via Gollm Provider)",
	}
	if p.apiKey != "" {
		headers["Authorization"] = "Bearer " + p.apiKey
	} else {
		p.logger.Warn("Deepseek API key is missing when generating headers")
	}
	for k, v := range p.extraHeaders {
		headers[k] = v
	}
	return headers
}

// Helper to convert gollm messages to Deepseek messages (reusing Cerebras logic)
func convertMessagesToDeepseek(messages []gollm_types.MemoryMessage) []DeepseekMessage {
	// Since Deepseek is OpenAI compatible, reuse the Cerebras conversion logic
	return convertMessagesToCerebras(messages)
}

// Helper to convert gollm tools to Deepseek tools (reusing Cerebras logic)
func convertToolsToDeepseek(gollmTools []utils.Tool) ([]DeepseekTool, error) {
	// Since Deepseek is OpenAI compatible, reuse the Cerebras conversion logic
	return convertToolsToCerebras(gollmTools)
}

// Helper to determine Deepseek tool choice string/object (reusing Cerebras logic)
func getDeepseekToolChoice(gollmChoice interface{}) interface{} {
	// Since Deepseek is OpenAI compatible, reuse the Cerebras conversion logic
	return getCerebrasToolChoice(gollmChoice)
}

// PrepareRequest creates the request body for a standard API call.
func (p *DeepseekProvider) PrepareRequest(prompt string, options map[string]interface{}) ([]byte, error) {
	p.mutex.Lock()
	model := p.model
	maxTokens := p.maxTokens
	apiKey := p.apiKey // Needed for logging/checks
	temp := p.temperature
	topP := p.topP
	seed := p.seed
	p.mutex.Unlock()

	req := DeepseekChatCompletionRequest{
		Model: model,
		Messages: []DeepseekMessage{
			{Role: "user", Content: prompt},
		},
		MaxTokens:   maxTokens,
		Temperature: temp,
		TopP:        topP,
		Seed:        seed,
	}

	// Apply Options (similar to Cerebras)
	if m, ok := options["model"].(string); ok && m != "" {
		req.Model = m
	}
	if mtVal, ok := options["max_tokens"]; ok {
		switch mt := mtVal.(type) {
		case int:
			if mt > 0 {
				req.MaxTokens = mt
			}
		case float64: // Handle potential float from config
			if mt > 0 {
				req.MaxTokens = int(mt)
			}
		}
	}
	if tVal, ok := options["temperature"].(float64); ok {
		req.Temperature = &tVal
	}
	if pVal, ok := options["top_p"].(float64); ok {
		req.TopP = &pVal
	}
	if sVal, ok := options["seed"]; ok {
		switch s := sVal.(type) {
		case int:
			seed64 := int64(s)
			req.Seed = &seed64
		case int64:
			req.Seed = &s
		case float64:
			seed64 := int64(s)
			req.Seed = &seed64
		}
	}
	if stopVal, ok := options["stop"].([]string); ok {
		req.Stop = stopVal
	}

	// Handle Tools & ToolChoice (reusing Cerebras logic)
	if toolsVal, ok := options["tools"].([]utils.Tool); ok {
		apiTools, err := convertToolsToDeepseek(toolsVal)
		if err != nil {
			p.logger.Error("Failed to convert tools for Deepseek", "error", err)
		}
		req.Tools = apiTools
	}
	if toolChoiceVal, ok := options["tool_choice"]; ok {
		choice := getDeepseekToolChoice(toolChoiceVal)
		if choiceStr, ok := choice.(string); ok {
			req.ToolChoice = choiceStr
		} else {
			log.Printf("Warning: Unsupported tool_choice map provided for Deepseek, assigning 'auto'.")
			req.ToolChoice = "auto"
		}
	}

	// Handle Streaming flag
	if stream, ok := options["stream"].(bool); ok && stream {
		req.Stream = true
	}

	// Handle Response Format (JSON Schema) - Assuming Deepseek supports it like OpenAI
	if schemaPtr, ok := options["_schema_internal"].(*jsonschema.Schema); ok {
		req.ResponseFormat = &struct {
			Type       string `json:"type"`
			JSONSchema *struct {
				Name   string             `json:"name"`
				Schema *jsonschema.Schema `json:"schema"`
				Strict bool               `json:"strict,omitempty"`
			} `json:"json_schema,omitempty"`
		}{
			Type: "json_object", // OpenAI uses json_object, assume Deepseek does too
			// Deepseek might not use the nested json_schema structure, adjust if needed
			// For now, assume it does for compatibility testing
			JSONSchema: &struct {
				Name   string             `json:"name"`
				Schema *jsonschema.Schema `json:"schema"`
				Strict bool               `json:"strict,omitempty"`
			}{
				Name:   "structured_output",
				Schema: schemaPtr,
			},
		}
	} else if _, ok := options["_schema_internal"]; ok {
		p.logger.Error("Schema provided in options is not *jsonschema.Schema")
	}

	p.logger.Debug("Preparing Deepseek request", "provider", p.Name(), "model", req.Model, "streaming", req.Stream)
	if apiKey == "" {
		p.logger.Warn("API key is not set for Deepseek provider")
	}

	return json.Marshal(req)
}

// PrepareRequestWithSchema uses the ResponseFormat field.
func (p *DeepseekProvider) PrepareRequestWithSchema(prompt string, options map[string]interface{}, schema interface{}) ([]byte, error) {
	if !p.SupportsJSONSchema() {
		return nil, errors.New("internal error: PrepareRequestWithSchema called but SupportsJSONSchema is false")
	}

	var schemaPtr *jsonschema.Schema
	if s, ok := schema.(*jsonschema.Schema); ok {
		schemaPtr = s
	} else {
		reflector := jsonschema.Reflector{}
		schemaPtr = reflector.Reflect(schema)
		if schemaPtr == nil {
			return nil, fmt.Errorf("failed to reflect jsonschema from provided schema type: %T", schema)
		}
	}

	if options == nil {
		options = make(map[string]interface{})
	}
	options["_schema_internal"] = schemaPtr

	return p.PrepareRequest(prompt, options)
}

// PrepareRequestWithMessages handles messages and tools.
func (p *DeepseekProvider) PrepareRequestWithMessages(messages []gollm_types.MemoryMessage, options map[string]interface{}) ([]byte, error) {
	p.mutex.Lock()
	model := p.model
	maxTokens := p.maxTokens
	apiKey := p.apiKey
	temp := p.temperature
	topP := p.topP
	seed := p.seed
	p.mutex.Unlock()

	req := DeepseekChatCompletionRequest{
		Model:       model,
		Messages:    convertMessagesToDeepseek(messages), // Use helper
		MaxTokens:   maxTokens,
		Temperature: temp,
		TopP:        topP,
		Seed:        seed,
	}

	// Apply Options (same logic as PrepareRequest)
	// ... (copy option application logic from PrepareRequest) ...
	if m, ok := options["model"].(string); ok && m != "" {
		req.Model = m
	}
	if mtVal, ok := options["max_tokens"]; ok {
		switch mt := mtVal.(type) {
		case int:
			if mt > 0 {
				req.MaxTokens = mt
			}
		case float64:
			if mt > 0 {
				req.MaxTokens = int(mt)
			}
		}
	}
	if tVal, ok := options["temperature"].(float64); ok {
		req.Temperature = &tVal
	}
	if pVal, ok := options["top_p"].(float64); ok {
		req.TopP = &pVal
	}
	if sVal, ok := options["seed"]; ok {
		switch s := sVal.(type) {
		case int:
			seed64 := int64(s)
			req.Seed = &seed64
		case int64:
			req.Seed = &s
		case float64:
			seed64 := int64(s)
			req.Seed = &seed64
		}
	}
	if stopVal, ok := options["stop"].([]string); ok {
		req.Stop = stopVal
	}
	if toolsVal, ok := options["tools"].([]utils.Tool); ok {
		apiTools, err := convertToolsToDeepseek(toolsVal)
		if err == nil {
			req.Tools = apiTools
		}
	}
	if toolChoiceVal, ok := options["tool_choice"]; ok {
		choice := getDeepseekToolChoice(toolChoiceVal)
		if choiceStr, ok := choice.(string); ok {
			req.ToolChoice = choiceStr
		} else {
			req.ToolChoice = "auto"
		}
	}
	if stream, ok := options["stream"].(bool); ok && stream {
		req.Stream = true
	}
	if schemaPtr, ok := options["_schema_internal"].(*jsonschema.Schema); ok {
		req.ResponseFormat = &struct {
			Type       string `json:"type"`
			JSONSchema *struct {
				Name   string             `json:"name"`
				Schema *jsonschema.Schema `json:"schema"`
				Strict bool               `json:"strict,omitempty"`
			} `json:"json_schema,omitempty"`
		}{
			Type: "json_object",
			JSONSchema: &struct {
				Name   string             `json:"name"`
				Schema *jsonschema.Schema `json:"schema"`
				Strict bool               `json:"strict,omitempty"`
			}{
				Name:   "structured_output",
				Schema: schemaPtr,
			},
		}
	} else if _, ok := options["_schema_internal"]; ok {
		p.logger.Error("Schema provided in options is not *jsonschema.Schema")
	}

	p.logger.Debug("Preparing Deepseek request with messages", "provider", p.Name(), "model", req.Model, "num_msgs", len(req.Messages))
	if apiKey == "" {
		p.logger.Warn("API key is not set for Deepseek provider")
	}

	return json.Marshal(req)
}

// ParseResponse extracts the generated text or handles tool calls (reusing Cerebras logic).
func (p *DeepseekProvider) ParseResponse(body []byte) (string, error) {
	// Since Deepseek is OpenAI compatible, reuse the Cerebras parsing logic
	return (&CerebrasProvider{logger: p.logger}).ParseResponse(body)
}

// SetExtraHeaders configures additional HTTP headers.
func (p *DeepseekProvider) SetExtraHeaders(extraHeaders map[string]string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.extraHeaders == nil {
		p.extraHeaders = make(map[string]string)
	}
	for k, v := range extraHeaders {
		p.extraHeaders[k] = v
	}
	p.logger.Debug("Deepseek extra headers set", "headers", p.extraHeaders)
}

// HandleFunctionCalls processes tool calls (reusing Cerebras logic).
func (p *DeepseekProvider) HandleFunctionCalls(body []byte) ([]byte, error) {
	// Since Deepseek is OpenAI compatible, reuse the Cerebras logic
	return (&CerebrasProvider{logger: p.logger}).HandleFunctionCalls(body)
}

// SupportsJSONSchema indicates support via ResponseFormat (assuming OpenAI compatibility).
func (p *DeepseekProvider) SupportsJSONSchema() bool {
	return true
}

// SetDefaultOptions applies global configuration defaults.
func (p *DeepseekProvider) SetDefaultOptions(cfg *config.Config) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if cfg == nil {
		return
	}

	// Get provider-specific API key
	providerAPIKey := ""
	if cfg.APIKeys != nil {
		if apiKey, ok := cfg.APIKeys[p.Name()]; ok { // p.Name() is "deepseek"
			providerAPIKey = apiKey
		}
	}

	// Apply API key if not already set
	if providerAPIKey != "" && p.apiKey == "" {
		p.apiKey = providerAPIKey
	}

	// Apply global defaults if provider-specific ones weren't set or are defaults
	if (p.model == "" || p.model == "deepseek-chat") && cfg.Model != "" {
		p.model = cfg.Model
	}
	if (p.maxTokens == 0 || p.maxTokens == 2048) && cfg.MaxTokens > 0 {
		p.maxTokens = cfg.MaxTokens
	}
	if p.temperature == nil && cfg.Temperature > 0 {
		p.setOptionInternal("temperature", cfg.Temperature)
	}
	if p.topP == nil && cfg.TopP > 0 {
		p.setOptionInternal("top_p", cfg.TopP)
	}
	if p.seed == nil && cfg.Seed != nil {
		p.setOptionInternal("seed", *cfg.Seed)
	}

	p.logger.Info("Deepseek default options applied", "model", p.model, "maxTokens", p.maxTokens)
}

// setOptionInternal is called by SetDefaultOptions/SetOption without locking
func (p *DeepseekProvider) setOptionInternal(key string, value interface{}) {
	// Reuse Cerebras logic, adjusting defaults if necessary
	switch key {
	case "api_key":
		if v, ok := value.(string); ok {
			p.apiKey = v
		}
	case "model":
		if v, ok := value.(string); ok {
			p.model = v
		}
	case "max_tokens":
		switch v := value.(type) {
		case int:
			if v > 0 {
				p.maxTokens = v
			}
		case float64:
			if v > 0 {
				p.maxTokens = int(v)
			}
		}
	case "temperature":
		if v, ok := value.(float64); ok {
			p.temperature = &v
		}
	case "top_p":
		if v, ok := value.(float64); ok {
			p.topP = &v
		}
	case "seed":
		switch v := value.(type) {
		case int:
			seedVal := int64(v)
			p.seed = &seedVal
		case int64:
			p.seed = &v
		case float64:
			seedVal := int64(v)
			p.seed = &seedVal
		}
	default:
		p.logger.Warn("Attempted to set unknown option for DeepseekProvider", "key", key)
	}
}

// SetOption sets a specific configuration option.
func (p *DeepseekProvider) SetOption(key string, value interface{}) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.logger.Debug("Deepseek setting option", "key", key)
	p.setOptionInternal(key, value)
}

// SetLogger configures the logger for the provider.
func (p *DeepseekProvider) SetLogger(logger utils.Logger) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if logger != nil {
		p.logger = logger
		p.logger.Debug("Logger configured for Deepseek provider")
	}
}

// SupportsStreaming indicates whether the provider supports streaming.
func (p *DeepseekProvider) SupportsStreaming() bool {
	return true // Assuming Deepseek supports streaming like OpenAI
}

// PrepareStreamRequest creates a request body for streaming API calls.
func (p *DeepseekProvider) PrepareStreamRequest(prompt string, options map[string]interface{}) ([]byte, error) {
	if options == nil {
		options = make(map[string]interface{})
	}
	options["stream"] = true
	return p.PrepareRequest(prompt, options)
}

// ParseStreamResponse processes a single chunk from a streaming response (reusing Cerebras logic).
func (p *DeepseekProvider) ParseStreamResponse(chunk []byte) (string, error) {
	// Since Deepseek is OpenAI compatible, reuse the Cerebras parsing logic
	return (&CerebrasProvider{logger: p.logger}).ParseStreamResponse(chunk)
}

// --- Compile-time Interface Check ---
var _ providers.Provider = (*DeepseekProvider)(nil)
