package inference_engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/guiperry/gollm_cerebras/llm"
	"github.com/guiperry/gollm_cerebras/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockTokenStream implements llm.TokenStream interface for testing
type MockTokenStream struct {
	response string
	done     bool
}

func (m *MockTokenStream) Next(ctx context.Context) (*llm.StreamToken, error) {
	if m.done {
		return nil, nil
	}
	m.done = true
	return &llm.StreamToken{
		Text: m.response,
	}, nil
}

func (m *MockTokenStream) Close() error {
	return nil
}

// MockLLM implements llm.LLM interface for testing
type MockLLM struct {
	generateFunc func(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error)
}

func (m *MockLLM) Generate(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error) {
	if m.generateFunc != nil {
		return m.generateFunc(ctx, prompt, opts...)
	}
	return "mock response", nil
}

func (m *MockLLM) GenerateWithSchema(ctx context.Context, prompt *llm.Prompt, schema interface{}, opts ...llm.GenerateOption) (string, error) {
	// For testing purposes, just call the regular Generate method
	return m.Generate(ctx, prompt, opts...)
}

func (m *MockLLM) GetLogger() utils.Logger {
	// Return a mock logger for testing purposes
	return utils.NewLogger(utils.LogLevelInfo)
}

func (m *MockLLM) NewPrompt(content string) *llm.Prompt {
	// Return a new prompt for testing purposes
	return llm.NewPrompt(content)
}

func (m *MockLLM) SetEndpoint(endpoint string) {
	// Mock implementation - no-op for testing
}

func (m *MockLLM) SetLogLevel(level utils.LogLevel) {
	// Mock implementation - no-op for testing
}

func (m *MockLLM) SetOption(key string, value interface{}) {
	// Mock implementation - no-op for testing
}

func (m *MockLLM) Stream(ctx context.Context, prompt *llm.Prompt, opts ...llm.StreamOption) (llm.TokenStream, error) {
	// Mock implementation - return a TokenStream for testing
	return &MockTokenStream{
		response: "mock streaming response",
	}, nil
}

func (m *MockLLM) SupportsJSONSchema() bool {
	// Mock implementation - return true for testing
	return true
}

func (m *MockLLM) SupportsStreaming() bool {
	// Mock implementation - return true for testing
	return true
}

func TestNewLLMAdapter(t *testing.T) {
	mockLLM := &MockLLM{}
	adapter := NewLLMAdapter(mockLLM, "test-provider")

	assert.NotNil(t, adapter)
	assert.Equal(t, mockLLM, adapter.LLM)
	assert.Equal(t, "test-provider", adapter.ProviderName)
}

func TestLLMAdapter_GenerateText(t *testing.T) {
	mockLLM := &MockLLM{
		generateFunc: func(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error) {
			return "Generated response", nil
		},
	}

	adapter := NewLLMAdapter(mockLLM, "test-provider")

	response, err := adapter.GenerateText("test prompt")

	require.NoError(t, err)
	assert.Equal(t, "Generated response", response)
}

func TestLLMAdapter_GenerateText_Error(t *testing.T) {
	expectedErr := errors.New("generation failed")
	mockLLM := &MockLLM{
		generateFunc: func(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error) {
			return "", expectedErr
		},
	}

	adapter := NewLLMAdapter(mockLLM, "test-provider")

	response, err := adapter.GenerateText("test prompt")

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Empty(t, response)
}

func TestLLMAdapter_GenerateText_WithTimeout(t *testing.T) {
	// Test that the adapter properly handles context timeout
	mockLLM := &MockLLM{
		generateFunc: func(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error) {
			// Check if context is already canceled
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			default:
				// Simulate slow generation
				time.Sleep(100 * time.Millisecond)
				return "response", nil
			}
		},
	}

	adapter := NewLLMAdapter(mockLLM, "test-provider")

	// This test verifies the adapter works with the LLM's context handling
	response, err := adapter.GenerateText("test prompt")

	require.NoError(t, err)
	assert.Equal(t, "response", response)
}

func TestLLMAdapter_MultipleProviders(t *testing.T) {
	testCases := []struct {
		name         string
		providerName string
		response     string
	}{
		{
			name:         "OpenAI Provider",
			providerName: "openai",
			response:     "OpenAI response",
		},
		{
			name:         "Cerebras Provider",
			providerName: "cerebras",
			response:     "Cerebras response",
		},
		{
			name:         "Custom Provider",
			providerName: "custom",
			response:     "Custom response",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockLLM := &MockLLM{
				generateFunc: func(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error) {
					return tc.response, nil
				},
			}

			adapter := NewLLMAdapter(mockLLM, tc.providerName)

			response, err := adapter.GenerateText("test prompt")

			require.NoError(t, err)
			assert.Equal(t, tc.response, response)
			assert.Equal(t, tc.providerName, adapter.ProviderName)
		})
	}
}

func TestLLMAdapter_EmptyPrompt(t *testing.T) {
	mockLLM := &MockLLM{
		generateFunc: func(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error) {
			return "response to empty prompt", nil
		},
	}

	adapter := NewLLMAdapter(mockLLM, "test-provider")

	response, err := adapter.GenerateText("")

	require.NoError(t, err)
	assert.Equal(t, "response to empty prompt", response)
}

func TestLLMAdapter_LongPrompt(t *testing.T) {
	longPrompt := "This is a very long prompt " +
		"that contains a lot of text and should be handled properly by the adapter. " +
		"It tests the adapter's ability to handle large inputs without issues."

	mockLLM := &MockLLM{
		generateFunc: func(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error) {
			return "response to long prompt", nil
		},
	}

	adapter := NewLLMAdapter(mockLLM, "test-provider")

	response, err := adapter.GenerateText(longPrompt)

	require.NoError(t, err)
	assert.Equal(t, "response to long prompt", response)
}

// Benchmark test for LLMAdapter performance
func BenchmarkLLMAdapter_GenerateText(b *testing.B) {
	mockLLM := &MockLLM{
		generateFunc: func(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error) {
			return "benchmark response", nil
		},
	}

	adapter := NewLLMAdapter(mockLLM, "benchmark-provider")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := adapter.GenerateText("benchmark prompt")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestLLMAdapter_ConcurrentAccess(t *testing.T) {
	mockLLM := &MockLLM{
		generateFunc: func(ctx context.Context, prompt *llm.Prompt, opts ...llm.GenerateOption) (string, error) {
			// Simulate some processing time
			time.Sleep(10 * time.Millisecond)
			return "concurrent response", nil
		},
	}

	adapter := NewLLMAdapter(mockLLM, "concurrent-provider")

	const numGoroutines = 10
	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			response, err := adapter.GenerateText("concurrent prompt")
			if err != nil {
				results <- err
				return
			}
			if response != "concurrent response" {
				results <- errors.New("unexpected response")
				return
			}
			results <- nil
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		err := <-results
		assert.NoError(t, err)
	}
}
