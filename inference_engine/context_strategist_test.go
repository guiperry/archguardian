package inference_engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTextGenerator is a mock implementation of the TextGenerator interface for testing.
type mockTextGenerator struct {
	GenerateTextFunc func(prompt string) (string, error)
}

func (m *mockTextGenerator) GenerateText(prompt string) (string, error) {
	if m.GenerateTextFunc != nil {
		return m.GenerateTextFunc(prompt)
	}
	// Default behavior
	if strings.Contains(prompt, "CONCISE SUMMARY") {
		return "mock summary", nil
	}
	if strings.Contains(prompt, "REASSEMBLE") {
		return "mock reassembled result", nil
	}
	return "mock generation result", nil
}

// mockTaskOrchestrator is a mock implementation for testing.
type mockTaskOrchestrator struct {
	ExecuteComplexTaskFunc                 func(ctx context.Context, complexPrompt string) (string, error)
	AnalyzeRecurringErrorFunc              func(ctx context.Context, codeWithError string) (string, error)
	AnalyzeSystemicErrorsFunc              func(ctx context.Context, knowledgeGraph string) (string, error)
	ExecuteComplexTaskWithDeepAnalysisFunc func(ctx context.Context, complexPrompt string, errorContext interface{}) (string, error)
	wasCalled                              bool
	promptReceived                         string
	mu                                     sync.Mutex
}

func (m *mockTaskOrchestrator) ExecuteComplexTask(ctx context.Context, complexPrompt string) (string, error) {
	m.mu.Lock()
	m.wasCalled = true
	m.promptReceived = complexPrompt
	m.mu.Unlock()

	if m.ExecuteComplexTaskFunc != nil {
		return m.ExecuteComplexTaskFunc(ctx, complexPrompt)
	}
	return "orchestrator result", nil
}

func (m *mockTaskOrchestrator) AnalyzeRecurringError(ctx context.Context, codeWithError string) (string, error) {
	if m.AnalyzeRecurringErrorFunc != nil {
		return m.AnalyzeRecurringErrorFunc(ctx, codeWithError)
	}
	return "recurring error analysis result", nil
}

func (m *mockTaskOrchestrator) AnalyzeSystemicErrors(ctx context.Context, knowledgeGraph string) (string, error) {
	if m.AnalyzeSystemicErrorsFunc != nil {
		return m.AnalyzeSystemicErrorsFunc(ctx, knowledgeGraph)
	}
	return "systemic error analysis result", nil
}

func (m *mockTaskOrchestrator) ExecuteComplexTaskWithDeepAnalysis(ctx context.Context, complexPrompt string, errorContext interface{}) (string, error) {
	if m.ExecuteComplexTaskWithDeepAnalysisFunc != nil {
		return m.ExecuteComplexTaskWithDeepAnalysisFunc(ctx, complexPrompt, errorContext)
	}
	return "complex task with deep analysis result", nil
}

func (m *mockTaskOrchestrator) WasCalledWith(prompt string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.wasCalled && m.promptReceived == prompt
}

func TestNewContextStrategist(t *testing.T) {
	orchestrator := &mockTaskOrchestrator{}
	strategist := NewContextStrategist(orchestrator, ChunkByParagraph)

	assert.NotNil(t, strategist)
	assert.Equal(t, orchestrator, strategist.orchestrator)
	assert.Equal(t, ChunkByParagraph, strategist.strategy)
	assert.Equal(t, ParallelProcessing, strategist.processingMode) // Check default
	assert.Equal(t, 1000, strategist.maxChunkSize)                 // Check default

	// Test with options
	strategistWithOptions := NewContextStrategist(
		orchestrator,
		ChunkByTokenCount,
		WithProcessingMode(SequentialProcessing),
		WithMaxChunkSize(2048),
	)
	assert.Equal(t, SequentialProcessing, strategistWithOptions.processingMode)
	assert.Equal(t, 2048, strategistWithOptions.maxChunkSize)
}

func TestDecideStrategy_Orchestration(t *testing.T) {
	tests := []struct {
		name          string
		prompt        string
		expectedError error
	}{
		{
			name:   "with 'plan' keyword",
			prompt: "Create a step-by-step plan to refactor my service.",
		},
		{
			name:   "with 'implement' keyword",
			prompt: "Please implement the following feature based on this spec.",
		},
		{
			name:   "with 'refactor' keyword",
			prompt: "refactor this large Go file.",
		},
		{
			name:   "with 'generate a patch' keyword",
			prompt: "Given the bug report, generate a patch to fix it.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			mockOrchestrator := &mockTaskOrchestrator{}
			strategist := NewContextStrategist(mockOrchestrator, ChunkByTokenCount)
			mockLLM := &mockTextGenerator{}
			ctx := context.Background()

			// Act
			result, err := strategist.DecideStrategy(ctx, mockLLM, tt.prompt, "instruction")

			// Assert
			require.NoError(t, err)
			assert.True(t, mockOrchestrator.WasCalledWith(tt.prompt), "Expected orchestrator to be called")
			assert.Equal(t, "orchestrator result", result)
		})
	}
}

func TestDecideStrategy_Compaction(t *testing.T) {
	// Arrange
	mockOrchestrator := &mockTaskOrchestrator{}
	strategist := NewContextStrategist(mockOrchestrator, ChunkByTokenCount, WithProcessingMode(ParallelProcessing)) // Use parallel for simpler test
	mockLLM := &mockTextGenerator{
		GenerateTextFunc: func(prompt string) (string, error) {
			return fmt.Sprintf("compacted: %s", prompt), nil
		},
	}
	ctx := context.Background()
	prompt := "This is a long text that needs summarization but does not contain any orchestration keywords."

	// Act
	result, err := strategist.DecideStrategy(ctx, mockLLM, prompt, "Summarize this:")

	// Assert
	require.NoError(t, err)
	assert.False(t, mockOrchestrator.wasCalled, "Expected orchestrator NOT to be called")
	assert.Contains(t, result, "compacted: Summarize this:")
	assert.Contains(t, result, prompt)
}

func TestExecuteOrchestration_NilOrchestrator(t *testing.T) {
	// Arrange
	strategist := NewContextStrategist(nil, ChunkByTokenCount) // No orchestrator
	ctx := context.Background()

	// Act
	_, err := strategist.executeOrchestration(ctx, "some prompt")

	// Assert
	require.Error(t, err)
	assert.Equal(t, "orchestrator is not available in ContextStrategist to execute complex task", err.Error())
}

func TestExecuteCompaction_NilLLM(t *testing.T) {
	// Arrange
	strategist := NewContextStrategist(nil, ChunkByTokenCount)
	ctx := context.Background()

	// Act
	_, err := strategist.executeCompaction(ctx, nil, "some prompt", "instruction")

	// Assert
	require.Error(t, err)
	assert.Equal(t, "context strategist cannot process: TextGenerator (LLM) is nil", err.Error())
}

func TestExecuteNoteTaking_Fallback(t *testing.T) {
	// Arrange
	strategist := NewContextStrategist(nil, ChunkByTokenCount, WithProcessingMode(ParallelProcessing))
	mockLLM := &mockTextGenerator{}
	ctx := context.Background()
	prompt := "This is a prompt for note taking."

	// Act
	result, err := strategist.executeNoteTaking(ctx, mockLLM, prompt)

	// Assert
	require.NoError(t, err)
	// Check that it fell back to compaction
	assert.Equal(t, "mock generation result", result)
}
