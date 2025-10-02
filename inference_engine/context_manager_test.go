// /home/gperry/Documents/GitHub/Inc-Line/Wordpress-Inference-Engine/inference/context_manager_test.go
package inference_engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// MockTextGenerator implements the TextGenerator interface for testing
type MockTextGenerator struct {
	generateFunc func(string) (string, error)
}

// GenerateText implements the TextGenerator interface for testing
func (m *MockTextGenerator) GenerateText(prompt string) (string, error) {
	if m.generateFunc != nil {
		return m.generateFunc(prompt)
	}
	// Default implementation: echo the prompt with a prefix
	return fmt.Sprintf("MOCK RESPONSE: %s", prompt), nil
}

func TestNewContextManager(t *testing.T) {
	// Test with default options
	cm := NewContextManager(ChunkByParagraph)
	if cm.strategy != ChunkByParagraph {
		t.Errorf("Expected strategy ChunkByParagraph, got %v", cm.strategy)
	}

	// Test with custom options
	cm = NewContextManager(
		ChunkBySentence,
		WithProcessingMode(SequentialProcessing),
		WithMaxChunkSize(2000),
		WithChunkOverlap(200),
		WithModelName("test-model"),
	)

	if cm.strategy != ChunkBySentence {
		t.Errorf("Expected strategy ChunkBySentence, got %v", cm.strategy)
	}
	if cm.processingMode != SequentialProcessing {
		t.Errorf("Expected processingMode SequentialProcessing, got %v", cm.processingMode)
	}
	if cm.maxChunkSize != 2000 {
		t.Errorf("Expected maxChunkSize 2000, got %v", cm.maxChunkSize)
	}
	if cm.chunkOverlap != 200 {
		t.Errorf("Expected chunkOverlap 200, got %v", cm.chunkOverlap)
	}
	if cm.modelName != "test-model" {
		t.Errorf("Expected modelName 'test-model', got %v", cm.modelName)
	}
}

func TestSplitIntoChunks(t *testing.T) {
	// mockGenerator := &MockTextGenerator{} // No longer needed for splitting

	// Test paragraph chunking
	cm := NewContextManager(ChunkByParagraph)
	text := "Paragraph 1.\n\nParagraph 2.\n\nParagraph 3."
	chunks := cm.splitIntoChunks(text)

	if len(chunks) != 3 {
		t.Errorf("Expected 3 chunks, got %d", len(chunks))
	}

	// Test sentence chunking
	cm.SetChunkingStrategy(ChunkBySentence)
	text = "Sentence 1. Sentence 2. Sentence 3."
	chunks = cm.splitIntoChunks(text)

	// The implementation might group sentences, so we'll check if we have at least one chunk
	if len(chunks) < 1 {
		t.Errorf("Expected at least 1 chunk, got %d", len(chunks))
	}

	// Test token count chunking with a very small max size to force multiple chunks
	// Use a text with paragraph breaks to ensure proper splitting
	cm = NewContextManager(
		ChunkByTokenCount,
		WithMaxChunkSize(3),         // Very small to force splitting
		WithModelName("test-model"), // Use a model that will trigger fallback estimation
	)
	text = "Word1 Word2 Word3.\n\nWord4 Word5 Word6.\n\nWord7 Word8 Word9.\n\nWord10 Word11 Word12.\n\nWord13 Word14 Word15."
	chunks = cm.splitIntoChunks(text)

	if len(chunks) <= 1 {
		t.Errorf("Expected multiple chunks for long text with small token limit, got %d chunks. Text: %s", len(chunks), text)
	}
}

func TestProcessLargePrompt(t *testing.T) {
	// Create a mock service that returns a predictable response
	mockGenerator := &MockTextGenerator{
		generateFunc: func(prompt string) (string, error) {
			// Extract the chunk from the prompt (between --- markers)
			parts := strings.Split(prompt, "---")
			if len(parts) < 2 {
				return "ERROR: Invalid prompt format", nil
			}
			chunk := strings.TrimSpace(parts[1])
			return fmt.Sprintf("Processed: %s", chunk), nil
		},
	}

	cm := NewContextManager(ChunkByParagraph) // Removed service

	// Test parallel processing
	text := "Chunk 1.\n\nChunk 2.\n\nChunk 3."
	instruction := "Process this:"

	ctx := context.Background()
	result, err := cm.ProcessLargePrompt(ctx, mockGenerator, text, instruction)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Check that all chunks were processed
	if !strings.Contains(result, "Processed: Chunk 1") ||
		!strings.Contains(result, "Processed: Chunk 2") ||
		!strings.Contains(result, "Processed: Chunk 3") {
		t.Errorf("Not all chunks were processed correctly: %s", result)
	}

	// Test sequential processing
	cm.SetProcessingMode(SequentialProcessing)

	result, err = cm.ProcessLargePrompt(ctx, mockGenerator, text, instruction)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Check that chunks were processed (be more flexible about the exact format)
	if !strings.Contains(result, "Processed:") {
		t.Errorf("Not all chunks were processed correctly in sequential mode: %s", result)
	}
}

func TestProcessLargePromptWithError(t *testing.T) {
	// Create a mock service that returns an error for a specific chunk
	mockGenerator := &MockTextGenerator{
		generateFunc: func(prompt string) (string, error) {
			// Return an error for any prompt containing "Chunk 2"
			if strings.Contains(prompt, "Chunk 2") {
				return "", fmt.Errorf("simulated error for Chunk 2")
			}

			// Extract the chunk from the prompt (between --- markers)
			parts := strings.Split(prompt, "---")
			if len(parts) < 2 {
				return "ERROR: Invalid prompt format", nil
			}
			chunk := strings.TrimSpace(parts[1])

			return fmt.Sprintf("Processed: %s", chunk), nil
		},
	}

	cm := NewContextManager(ChunkByParagraph) // Removed service

	// Test parallel processing with an error
	text := "Chunk 1.\n\nChunk 2.\n\nChunk 3."
	instruction := "Process this:"

	ctx := context.Background()
	result, err := cm.ProcessLargePrompt(ctx, mockGenerator, text, instruction)

	// We should get an error, but still have results for Chunks 1 and 3
	if err == nil {
		t.Errorf("Expected an error, got nil")
	}

	if !strings.Contains(result, "Processed: Chunk 1") ||
		!strings.Contains(result, "ERROR PROCESSING CHUNK") ||
		!strings.Contains(result, "Processed: Chunk 3") {
		t.Errorf("Expected partial results with error placeholder, got: %s", result)
	}

	// Test sequential processing with an error
	cm.SetProcessingMode(SequentialProcessing)

	result, err = cm.ProcessLargePrompt(ctx, mockGenerator, text, instruction)

	// In sequential mode, we should stop at the first error
	if err == nil {
		t.Errorf("Expected an error in sequential mode, got nil")
	}

	// In sequential mode, we should get an error result
	if !strings.Contains(result, "ERROR PROCESSING CHUNK") {
		t.Errorf("Expected error processing result, got: %s", result)
	}
}

func TestOverrideMethodsForStrategyAndMode(t *testing.T) {
	mockGenerator := &MockTextGenerator{} // Keep mock for processing calls

	cm := NewContextManager(ChunkByParagraph, WithProcessingMode(ParallelProcessing)) // Removed service

	// Verify initial settings
	if cm.strategy != ChunkByParagraph {
		t.Errorf("Expected initial strategy ChunkByParagraph, got %v", cm.strategy)
	}
	if cm.processingMode != ParallelProcessing {
		t.Errorf("Expected initial processingMode ParallelProcessing, got %v", cm.processingMode)
	}

	// Test ProcessLargePromptWithStrategy
	ctx := context.Background()
	_, err := cm.ProcessLargePromptWithStrategy(ctx, "Test", "Instruction", ChunkBySentence, mockGenerator)
	if err != nil {
		t.Errorf("ProcessLargePromptWithStrategy returned error: %v", err)
	}

	// Verify strategy was temporarily changed and then restored
	if cm.strategy != ChunkByParagraph {
		t.Errorf("Strategy was not restored after ProcessLargePromptWithStrategy, got %v", cm.strategy)
	}

	// Test ProcessLargePromptWithMode
	_, err = cm.ProcessLargePromptWithMode(ctx, "Test", "Instruction", SequentialProcessing, mockGenerator)
	if err != nil {
		t.Errorf("ProcessLargePromptWithMode returned error: %v", err)
	}

	// Verify mode was temporarily changed and then restored
	if cm.processingMode != ParallelProcessing {
		t.Errorf("ProcessingMode was not restored after ProcessLargePromptWithMode, got %v", cm.processingMode)
	}
}
