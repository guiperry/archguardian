package inference_engine

import (
	"github.com/guiperry/gollm_cerebras/config"
	"github.com/guiperry/gollm_cerebras/providers"
)

// ProviderType defines the type of provider (e.g., "openai", "anthropic")
type ProviderType string

// ProviderConstructor defines a function type for creating new provider instances.
// Each provider implementation must provide a constructor function of this type.
type ProviderConstructor func(apiKey, model string, extraHeaders map[string]string) providers.Provider

// ProviderConfig holds the configuration for a provider
type ProviderConfig struct {
	// Name is the provider identifier
	Name string

	// Type is the API format this provider uses (e.g., "openai", "anthropic")
	Type ProviderType

	// Model is the default model to use
	Model string

	// APIKey is the authentication key
	APIKey string

	// MaxTokens is the default maximum tokens
	MaxTokens int

	// Endpoint is the API endpoint URL
	Endpoint string

	// AuthHeader is the header key used for authentication
	AuthHeader string

	// AuthPrefix is the prefix to use before the API key (e.g., "Bearer ")
	AuthPrefix string

	// RequiredHeaders are additional headers always needed
	RequiredHeaders map[string]string

	// EndpointParams are URL parameters to add to the endpoint
	EndpointParams map[string]string

	// ResponseFormat defines how to parse the response
	// If empty, uses the default parser for the provider type
	ResponseFormat string

	// SupportsSchema indicates if JSON schema validation is supported
	SupportsSchema bool

	// SupportsStreaming indicates if streaming is supported
	SupportsStreaming bool
}

// LocalConfig wraps the gollm Config with typed Providers
type LocalConfig struct {
	*config.Config // Embed the original config

	// Providers maps provider names to their configuration
	Providers map[string]ProviderConfig

	// ProviderDefaults contains default settings for each provider
	ProviderDefaults map[string]map[string]interface{} `json:"provider_defaults"`
}
