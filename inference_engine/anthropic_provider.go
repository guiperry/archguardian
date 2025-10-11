package inference_engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/guiperry/gollm_cerebras/config"
	"github.com/guiperry/gollm_cerebras/providers"
	gollm_types "github.com/guiperry/gollm_cerebras/types"
	"github.com/guiperry/gollm_cerebras/utils"
)

// --- Anthropic API Specific Structs ---

type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type AnthropicRequest struct {
	Model     string             `json:"model"`
	Messages  []AnthropicMessage `json:"messages"`
	MaxTokens int                `json:"max_tokens"`
	Stream    bool               `json:"stream,omitempty"`
	System    string             `json:"system,omitempty"`
}

type AnthropicResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
}

// --- AnthropicProvider Implementation ---

type AnthropicProvider struct {
	apiKey       string
	model        string
	maxTokens    int
	extraHeaders map[string]string
	logger       utils.Logger
	client       *http.Client
	mutex        sync.Mutex
}

// --- Registration ---
func init() {
	registry := providers.GetDefaultRegistry()
	registry.Register("anthropic", NewAnthropicProvider)
	log.Println("Registered Anthropic provider constructor with gollm registry")
}

func NewAnthropicProvider(apiKey, model string, extraHeaders map[string]string) providers.Provider {
	log.Printf("[DEBUG] NewAnthropicProvider called! apiKey present: %t, model: %s", apiKey != "", model)
	provider := &AnthropicProvider{
		apiKey:       apiKey,
		model:        model,
		maxTokens:    4096, // Default for Claude
		extraHeaders: make(map[string]string),
		logger:       utils.NewLogger(utils.LogLevelInfo),
		client:       &http.Client{},
	}
	if provider.model == "" {
		provider.model = "claude-3-sonnet-20240229"
	}
	for k, v := range extraHeaders {
		provider.extraHeaders[k] = v
	}
	log.Printf("NewAnthropicProvider created: model=%s", provider.model)
	return provider
}

func (p *AnthropicProvider) Name() string {
	return "anthropic"
}

func (p *AnthropicProvider) Endpoint() string {
	return "https://api.anthropic.com/v1/messages"
}

func (p *AnthropicProvider) Headers() map[string]string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	headers := map[string]string{
		"Content-Type":      "application/json",
		"x-api-key":         p.apiKey,
		"anthropic-version": "2023-06-01",
		"User-Agent":        "ArchGuardian/1.0",
	}
	for k, v := range p.extraHeaders {
		headers[k] = v
	}
	return headers
}

func (p *AnthropicProvider) PrepareRequest(prompt string, options map[string]interface{}) ([]byte, error) {
	return p.PrepareRequestWithMessages([]gollm_types.MemoryMessage{{Role: "user", Content: prompt}}, options)
}

func (p *AnthropicProvider) PrepareRequestWithMessages(messages []gollm_types.MemoryMessage, options map[string]interface{}) ([]byte, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	apiMessages := make([]AnthropicMessage, 0, len(messages))
	var systemPrompt string
	for _, msg := range messages {
		role := "user"
		if strings.ToLower(msg.Role) == "assistant" || strings.ToLower(msg.Role) == "ai" {
			role = "assistant"
		} else if strings.ToLower(msg.Role) == "system" {
			systemPrompt = msg.Content // Anthropic has a dedicated system prompt field
			continue
		}
		apiMessages = append(apiMessages, AnthropicMessage{Role: role, Content: msg.Content})
	}

	req := AnthropicRequest{
		Model:     p.model,
		Messages:  apiMessages,
		MaxTokens: p.maxTokens,
		System:    systemPrompt,
	}

	if m, ok := options["model"].(string); ok && m != "" {
		req.Model = m
	}
	if mt, ok := options["max_tokens"].(int); ok && mt > 0 {
		req.MaxTokens = mt
	}
	if stream, ok := options["stream"].(bool); ok {
		req.Stream = stream
	}

	return json.Marshal(req)
}

func (p *AnthropicProvider) ParseResponse(body []byte) (string, error) {
	var response AnthropicResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal Anthropic response: %w", err)
	}

	if len(response.Content) > 0 && response.Content[0].Type == "text" {
		return response.Content[0].Text, nil
	}

	return "", errors.New("no text content found in Anthropic response")
}

func (p *AnthropicProvider) SetDefaultOptions(cfg *config.Config) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if cfg == nil {
		return
	}
	if apiKey, ok := cfg.APIKeys[p.Name()]; ok && p.apiKey == "" {
		p.apiKey = apiKey
	}
	if (p.model == "" || p.model == "claude-3-sonnet-20240229") && cfg.Model != "" {
		p.model = cfg.Model
	}
	if p.maxTokens == 4096 && cfg.MaxTokens > 0 {
		p.maxTokens = cfg.MaxTokens
	}
}

func (p *AnthropicProvider) SetOption(key string, value interface{}) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	switch key {
	case "model":
		if v, ok := value.(string); ok {
			p.model = v
		}
	case "max_tokens":
		if v, ok := value.(int); ok {
			p.maxTokens = v
		}
	}
}

// --- Stubbed/Unsupported Methods ---

func (p *AnthropicProvider) PrepareRequestWithSchema(prompt string, options map[string]interface{}, schema interface{}) ([]byte, error) {
	return nil, errors.New("anthropic provider does not support JSON schema validation via response_format")
}
func (p *AnthropicProvider) SupportsJSONSchema() bool                        { return false }
func (p *AnthropicProvider) HandleFunctionCalls(body []byte) ([]byte, error) { return body, nil }
func (p *AnthropicProvider) SetExtraHeaders(headers map[string]string)       {}
func (p *AnthropicProvider) SetLogger(logger utils.Logger)                   { p.logger = logger }
func (p *AnthropicProvider) SupportsStreaming() bool                         { return false } // Can be implemented later
func (p *AnthropicProvider) PrepareStreamRequest(prompt string, options map[string]interface{}) ([]byte, error) {
	return nil, errors.New("streaming not implemented for Anthropic provider")
}
func (p *AnthropicProvider) ParseStreamResponse(chunk []byte) (string, error) {
	return "", errors.New("streaming not implemented for Anthropic provider")
}

var _ providers.Provider = (*AnthropicProvider)(nil)
