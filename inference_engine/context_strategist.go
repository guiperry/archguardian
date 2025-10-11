// /home/gperry/Documents/GitHub/Inc-Line/Wordpress-Inference-Engine/inference/context_manager.go
package inference_engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	// Import time package
)

// ChunkingStrategy defines how to split the text.
type ChunkingStrategy int

const (
	// ChunkByParagraph splits text based on double newlines.
	ChunkByParagraph ChunkingStrategy = iota
	// ChunkBySentence splits text based on sentence boundaries.
	ChunkBySentence
	// ChunkByTokenCount splits text based on estimated token count.
	ChunkByTokenCount
)

// ContextStrategy defines the high-level approach for handling large contexts.
type ContextStrategy string

const (
	CompactionStrategy    ContextStrategy = "compaction"
	OrchestrationStrategy ContextStrategy = "orchestration"
)

// ProcessingMode defines how chunks should be processed.
type ProcessingMode int

const (
	// ParallelProcessing processes chunks in parallel (faster but no context sharing).
	ParallelProcessing ProcessingMode = iota
	// SequentialProcessing processes chunks in sequence, passing context between them.
	SequentialProcessing
)

// TaskOrchestratorInterface defines the interface for task orchestrators
type TaskOrchestratorInterface interface {
	ExecuteComplexTask(ctx context.Context, complexPrompt string) (string, error)
	AnalyzeRecurringError(ctx context.Context, codeWithError string) (string, error)
	AnalyzeSystemicErrors(ctx context.Context, knowledgeGraph string) (string, error)
	ExecuteComplexTaskWithDeepAnalysis(ctx context.Context, complexPrompt string, errorContext interface{}) (string, error)
}

// ContextStrategist decides on and executes a strategy for handling large text inputs.
type ContextStrategist struct {
	orchestrator TaskOrchestratorInterface // ADDED: Reference to the orchestrator for the sub-agent strategy
	// inferenceService TextGenerator // REMOVED: LLM will be passed to ProcessLargePrompt
	strategy           ChunkingStrategy // How to split the text
	processingMode     ProcessingMode   // How to process chunks
	maxChunkSize       int              // Maximum tokens per chunk (for ChunkByTokenCount)
	chunkOverlap       int              // Number of tokens to overlap between chunks
	modelName          string           // Model name for token estimation
	contextTokenBudget int              // Max tokens for summary context in sequential mode
}

// ContextStrategistOption defines a functional option for configuring ContextStrategist.
type ContextStrategistOption func(*ContextStrategist)

// WithProcessingMode sets the processing mode.
func WithProcessingMode(mode ProcessingMode) ContextStrategistOption {
	return func(cm *ContextStrategist) {
		cm.processingMode = mode
	}
}

// WithMaxChunkSize sets the maximum chunk size in tokens.
func WithMaxChunkSize(size int) ContextStrategistOption {
	return func(cm *ContextStrategist) {
		cm.maxChunkSize = size
	}
}

// WithChunkOverlap sets the overlap between chunks in tokens.
func WithChunkOverlap(overlap int) ContextStrategistOption {
	return func(cm *ContextStrategist) {
		cm.chunkOverlap = overlap
	}
}

// WithModelName sets the model name for token estimation.
func WithModelName(modelName string) ContextStrategistOption {
	return func(cm *ContextStrategist) {
		cm.modelName = modelName
	}
}

// WithContextTokenBudget sets the maximum tokens for the summary context in sequential mode.
func WithContextTokenBudget(budget int) ContextStrategistOption {
	return func(cm *ContextStrategist) {
		cm.contextTokenBudget = budget
	}
}

// TextGenerator defines the minimal interface needed for generating text
// This allows passing different LLM instances (like those from gollm).
type TextGenerator interface {
	GenerateText(prompt string) (string, error)
	// Add other methods if needed by the context manager, e.g., Generate(ctx, prompt)
}

// NewContextStrategist creates a new ContextStrategist with the given options.
// The TextGenerator (LLM) is now passed during processing, not creation.
func NewContextStrategist(orchestrator TaskOrchestratorInterface, strategy ChunkingStrategy, opts ...ContextStrategistOption) *ContextStrategist {
	// Create with default values
	cm := &ContextStrategist{
		orchestrator: orchestrator,
		// inferenceService: service, // REMOVED
		strategy:           strategy,
		processingMode:     ParallelProcessing, // Default to parallel
		maxChunkSize:       1000,               // Default max chunk size
		chunkOverlap:       100,                // Default overlap
		modelName:          "gpt-4",            // Default model for token estimation
		contextTokenBudget: 250,                // Default token budget for context summary
	}

	// Apply options
	for _, opt := range opts {
		opt(cm)
	}

	return cm
}

// DecideStrategy analyzes the prompt and determines the best strategy to use.
func (cm *ContextStrategist) DecideStrategy(ctx context.Context, llm TextGenerator, largePrompt string, instructionPerChunk string) (string, error) {
	// For now, we will use a simplified logic. A more advanced implementation
	// would use an LLM call to make this decision.
	// Let's check for keywords that suggest a multi-step plan is needed.
	keywords := []string{"plan", "step-by-step", "implement", "refactor", "fix the following issue", "generate a patch"}
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(largePrompt), keyword) {
			log.Println("ContextStrategist: Detected keywords for orchestration. Choosing OrchestrationStrategy.")
			return cm.executeOrchestration(ctx, largePrompt)
		}
	}

	// Default to Compaction
	log.Println("ContextStrategist: Defaulting to CompactionStrategy.")
	return cm.executeCompaction(ctx, llm, largePrompt, instructionPerChunk)
}

// executeOrchestration handles the sub-agent task strategy by delegating to the TaskOrchestrator.
func (cm *ContextStrategist) executeOrchestration(ctx context.Context, complexPrompt string) (string, error) {
	if cm.orchestrator == nil {
		return "", errors.New("orchestrator is not available in ContextStrategist to execute complex task")
	}
	log.Println("ContextStrategist: Executing complex task via TaskOrchestrator.")
	return cm.orchestrator.ExecuteComplexTask(ctx, complexPrompt)
}

// executeNoteTaking is a placeholder for the structured note-taking strategy.
func (cm *ContextStrategist) executeNoteTaking(ctx context.Context, llm TextGenerator, largePrompt string) (string, error) {
	// TODO: Implement structured note-taking.
	// 1. Give the LLM tools to `save_note(key, content)` and `retrieve_note(key)`.
	// 2. The LLM would first analyze the prompt and decide if it needs to retrieve notes.
	// 3. It would then process the prompt, potentially saving new notes.
	// 4. This requires a persistent key-value store accessible by the inference service.
	log.Println("ContextStrategist: Structured Note-Taking strategy is not yet implemented.")
	// Fallback to compaction for now.
	return cm.executeCompaction(ctx, llm, largePrompt, "Process the following text:")
}

// executeCompaction chunks the input, processes each chunk, and reassembles the results.
// This is the refactored version of the original ProcessLargePrompt.
func (cm *ContextStrategist) executeCompaction(ctx context.Context, llm TextGenerator, largePrompt string, instructionPerChunk string) (string, error) {
	if llm == nil {
		return "", fmt.Errorf("context strategist cannot process: TextGenerator (LLM) is nil")
	}

	chunks := cm.splitIntoChunks(largePrompt)
	if len(chunks) == 0 {
		return "", fmt.Errorf("prompt resulted in zero chunks")
	}

	log.Printf("ContextStrategist: Executing Compaction strategy with %d chunks using %s mode...", len(chunks), func() string {
		if cm.processingMode == ParallelProcessing {
			return "parallel"
		}
		return "sequential"
	}())

	// Choose processing method based on mode
	if cm.processingMode == SequentialProcessing {
		return cm.processSequentially(ctx, llm, chunks, instructionPerChunk, largePrompt)
	}

	// Default to parallel processing
	return cm.processInParallel(ctx, llm, chunks, instructionPerChunk)
}

// splitIntoChunks splits text based on the configured strategy.
func (cm *ContextStrategist) splitIntoChunks(text string) []string {
	switch cm.strategy {
	case ChunkByParagraph:
		// Simple split by double newline
		chunks := strings.Split(text, "\n\n")
		var nonEmptyChunks []string
		for _, chunk := range chunks {
			trimmed := strings.TrimSpace(chunk)
			if trimmed != "" {
				nonEmptyChunks = append(nonEmptyChunks, trimmed)
			}
		}
		return nonEmptyChunks

	case ChunkBySentence:
		// Split by sentence boundaries using a simple regex
		// This is a basic implementation - a more sophisticated NLP approach could be used
		sentenceRegex := regexp.MustCompile(`[.!?]\s+`)
		sentences := sentenceRegex.Split(text, -1)

		var nonEmptySentences []string
		for _, sentence := range sentences {
			trimmed := strings.TrimSpace(sentence)
			if trimmed != "" {
				// Add back punctuation for context, unless it's the last sentence part
				if len(trimmed) > 0 && len(text) > len(trimmed) {
					originalIndex := strings.Index(text, trimmed)
					if originalIndex != -1 && originalIndex+len(trimmed) < len(text) {
						punctuation := text[originalIndex+len(trimmed)]
						if punctuation == '.' || punctuation == '!' || punctuation == '?' {
							trimmed += string(punctuation)
						}
					}
				}
				nonEmptySentences = append(nonEmptySentences, trimmed)
			}
		}

		// Group sentences into chunks to avoid too many small chunks
		return cm.groupSentencesIntoChunks(nonEmptySentences)

	case ChunkByTokenCount:
		// Split based on estimated token count
		return cm.splitByTokenCount(text)

	default:
		log.Printf("[WARN] Unknown chunking strategy: %d. Falling back to paragraph.", cm.strategy)
		// Set to ChunkByParagraph and retry
		cm.strategy = ChunkByParagraph
		return cm.splitIntoChunks(text) // Recursive call with default strategy
	}
}

// groupSentencesIntoChunks groups sentences into larger chunks to avoid too many small chunks.
func (cm *ContextStrategist) groupSentencesIntoChunks(sentences []string) []string {
	if len(sentences) == 0 {
		return []string{}
	}

	var chunks []string
	var currentChunk strings.Builder
	currentTokens := 0

	for _, sentence := range sentences {
		sentenceTokens := estimateTokens(sentence, cm.modelName)

		// If adding this sentence would exceed the max chunk size, start a new chunk
		if currentTokens > 0 && currentTokens+sentenceTokens > cm.maxChunkSize {
			chunks = append(chunks, currentChunk.String())
			currentChunk.Reset()
			currentTokens = 0
		}

		// Add the sentence to the current chunk
		if currentTokens > 0 {
			currentChunk.WriteString(" ") // Add space between sentences
		}
		currentChunk.WriteString(sentence)
		currentTokens += sentenceTokens
	}

	// Add the last chunk if it's not empty
	if currentChunk.Len() > 0 {
		chunks = append(chunks, currentChunk.String())
	}

	return chunks
}

// splitByTokenCount splits text into chunks based on token count.
func (cm *ContextStrategist) splitByTokenCount(text string) []string {
	// First split by paragraphs to preserve natural boundaries
	paragraphs := strings.Split(text, "\n\n")

	var chunks []string
	var currentChunk strings.Builder
	currentTokens := 0

	for _, paragraph := range paragraphs {
		trimmed := strings.TrimSpace(paragraph)
		if trimmed == "" {
			continue
		}

		paragraphTokens := estimateTokens(trimmed, cm.modelName)

		// If this paragraph alone exceeds the max chunk size, split it further
		if paragraphTokens > cm.maxChunkSize {
			// Add the current chunk if it's not empty
			if currentChunk.Len() > 0 {
				chunks = append(chunks, currentChunk.String())
				currentChunk.Reset()
				currentTokens = 0
			}

			// Split the large paragraph by sentences
			sentences := regexp.MustCompile(`[.!?]\s+`).Split(trimmed, -1)
			var currentSentenceChunk strings.Builder
			currentSentenceTokens := 0

			for _, sentence := range sentences {
				sentenceTrimmed := strings.TrimSpace(sentence)
				if sentenceTrimmed == "" {
					continue
				}
				// Add back punctuation
				if len(sentenceTrimmed) > 0 && len(trimmed) > len(sentenceTrimmed) {
					originalIndex := strings.Index(trimmed, sentenceTrimmed)
					if originalIndex != -1 && originalIndex+len(sentenceTrimmed) < len(trimmed) {
						punctuation := trimmed[originalIndex+len(sentenceTrimmed)]
						if punctuation == '.' || punctuation == '!' || punctuation == '?' {
							sentenceTrimmed += string(punctuation)
						}
					}
				}

				sentenceTokens := estimateTokens(sentenceTrimmed, cm.modelName)

				// If adding this sentence would exceed the max chunk size, start a new chunk
				if currentSentenceTokens > 0 && currentSentenceTokens+sentenceTokens > cm.maxChunkSize {
					chunks = append(chunks, currentSentenceChunk.String())
					currentSentenceChunk.Reset()
					currentSentenceTokens = 0
				}

				// Add the sentence to the current chunk
				if currentSentenceTokens > 0 {
					currentSentenceChunk.WriteString(" ")
				}
				currentSentenceChunk.WriteString(sentenceTrimmed)
				currentSentenceTokens += sentenceTokens
			}

			// Add the last sentence chunk if it's not empty
			if currentSentenceChunk.Len() > 0 {
				chunks = append(chunks, currentSentenceChunk.String())
			}
		} else if currentTokens+paragraphTokens > cm.maxChunkSize {
			// If adding this paragraph would exceed the max chunk size, start a new chunk
			chunks = append(chunks, currentChunk.String())
			currentChunk.Reset()
			currentChunk.WriteString(trimmed)
			currentTokens = paragraphTokens
		} else {
			// Add the paragraph to the current chunk
			if currentTokens > 0 {
				currentChunk.WriteString("\n\n") // Preserve paragraph break
			}
			currentChunk.WriteString(trimmed)
			currentTokens += paragraphTokens
		}
	}

	// Add the last chunk if it's not empty
	if currentChunk.Len() > 0 {
		chunks = append(chunks, currentChunk.String())
	}

	// TODO: Implement overlap logic if needed. This would involve adding the end
	// of the previous chunk to the start of the next chunk during processing,
	// or adjusting the splitting logic to create overlapping chunks directly.

	return chunks
}

// processInParallel processes chunks in parallel for speed.
// Accepts the TextGenerator (LLM instance).
func (cm *ContextStrategist) processInParallel(_ context.Context, llm TextGenerator, chunks []string, instructionPerChunk string) (string, error) {
	var wg sync.WaitGroup
	var lastError error
	var errMutex sync.Mutex                     // To safely write to lastError from goroutines
	resultsArray := make([]string, len(chunks)) // Store results in order

	for i, chunk := range chunks {
		wg.Add(1)
		go func(index int, chunkText string) {
			defer wg.Done() // Corrected from cm.wg.Done()
			log.Printf("ContextStrategist: Processing chunk %d/%d in parallel...", index+1, len(chunks))

			// Construct prompt for this chunk
			chunkPrompt := fmt.Sprintf("%s\n\n---\n%s\n---", instructionPerChunk, chunkText)

			result, err := llm.GenerateText(chunkPrompt) // Use the passed LLM
			if err != nil {
				errMutex.Lock()
				lastError = fmt.Errorf("error processing chunk %d: %w", index+1, err)
				errMutex.Unlock()
				log.Printf("ContextStrategist: Error on chunk %d: %v", index+1, err)
				resultsArray[index] = fmt.Sprintf("[ERROR PROCESSING CHUNK %d]", index+1) // Placeholder
				return
			}
			resultsArray[index] = result
			log.Printf("ContextStrategist: Chunk %d processed.", index+1)
		}(i, chunk)
	}

	wg.Wait() // Wait for all goroutines to finish

	// Reassemble results in order
	finalResult := strings.Join(resultsArray, "\n\n---\n\n") // Join with a separator

	log.Println("ContextStrategist: Finished processing all chunks in parallel.")
	return finalResult, lastError
}

// processSequentially processes chunks in sequence, passing context between them.
// Accepts the TextGenerator (LLM instance).
func (cm *ContextStrategist) processSequentially(ctx context.Context, llm TextGenerator, chunks []string, instructionPerChunk, originalPrompt string) (string, error) {
	remainingText := strings.Join(chunks, "\n\n") // Reconstruct (or pass original text)

	var results []string
	var previousOutputSummary string // Store summary of previous output

	chunkIndex := 0

	for remainingText != "" {
		chunkIndex++
		// Estimate tokens for the base instruction and current summary
		instructionTokens := estimateTokens(instructionPerChunk, cm.modelName)
		summaryTokens := estimateTokens(previousOutputSummary, cm.modelName)
		var (
			chunkPrompt   string
			currentChunk  string
			contextTokens int
		)

		// Calculate tokens used by instruction and summary
		contextTokens = instructionTokens + summaryTokens + estimateTokens(instructionPerChunk, cm.modelName)

		// Log token distribution for debugging
		log.Printf("ContextStrategist: Chunk %d token budget - Instruction: %d, Summary: %d, Context: %d, Content budget: %d",
			chunkIndex,
			instructionTokens,
			summaryTokens,
			contextTokens,
			cm.maxChunkSize-contextTokens-50)

		contentBudget := cm.maxChunkSize - contextTokens - 50 // Add buffer
		if contentBudget <= 0 {
			log.Printf("ContextStrategist: Warning - No token budget left for chunk %d content after context/instruction. Context Tokens: %d", chunkIndex, contextTokens)
			// Handle this case - maybe skip chunk, return error, or try with minimal content?
			// For now, let's try to take a very small chunk.
			contentBudget = 50 // Arbitrary small budget
		}

		// Extract the next chunk based on the budget
		// Find the best split point (e.g., end of sentence or paragraph) within the budget
		chunkEndIndex := findSplitIndex(remainingText, contentBudget, cm.modelName)
		if chunkEndIndex <= 0 {
			// If no good split point found within budget, or budget is too small, take the whole remaining text or up to budget limit
			chunkEndIndex = min(len(remainingText), contentBudget*5) // Use a multiplier as budget is tokens, not chars
			if chunkEndIndex == 0 && len(remainingText) > 0 {
				// Force taking at least some characters if budget was effectively zero
				chunkEndIndex = min(len(remainingText), 100)
			}
			log.Printf("ContextStrategist: Using fallback split index %d for chunk %d", chunkEndIndex, chunkIndex)
		}

		currentChunk = strings.TrimSpace(remainingText[:chunkEndIndex])
		remainingText = strings.TrimSpace(remainingText[chunkEndIndex:])

		if currentChunk == "" && remainingText != "" {
			log.Printf("ContextStrategist: Warning - Could not extract next chunk within budget for chunk %d.", chunkIndex)
			results = append(results, fmt.Sprintf("[ERROR SKIPPING REST OF TEXT - CHUNK %d TOO SMALL FOR BUDGET]", chunkIndex))
			break
		}

		log.Printf("ContextStrategist: Processing chunk %d sequentially (Content Budget: %d tokens)...", chunkIndex, contentBudget)

		// Construct the prompt for the current chunk
		promptBuilder := strings.Builder{}
		promptBuilder.WriteString(instructionPerChunk)
		if previousOutputSummary != "" {
			promptBuilder.WriteString("\n\nContext from previous section:\n")
			promptBuilder.WriteString(previousOutputSummary)
		}
		promptBuilder.WriteString("\n\n---\nCurrent Section:\n")
		promptBuilder.WriteString(currentChunk)
		promptBuilder.WriteString("\n---")
		chunkPrompt = promptBuilder.String()
		// --- Add logging for the prompt being sent ---

		log.Printf("ContextStrategist: Sequential Prompt for Chunk %d:\n%s\n", chunkIndex, chunkPrompt)
		// --- End logging ---

		result, err := llm.GenerateText(chunkPrompt) // Use the passed LLM
		if err != nil {
			// If an error occurs, return the results obtained so far and the error

			log.Printf("ContextStrategist: Error on chunk %d: %v", chunkIndex, err)
			results = append(results, fmt.Sprintf("[ERROR PROCESSING CHUNK %d]", chunkIndex))
			return strings.Join(results, "\n\n---\n\n"),

				fmt.Errorf("error processing chunk %d: %w", chunkIndex, err)
		}

		results = append(results, result)
		log.Printf("ContextStrategist: Chunk %d processed.", chunkIndex)

		// Generate a high-quality summary using an AI call
		summary, err := cm.aiSummarizeForContext(ctx, llm, currentChunk, result)
		if err != nil {
			log.Printf("ContextStrategist: Warning - failed to generate AI summary for chunk %d: %v. Proceeding without summary.", chunkIndex, err)
			previousOutputSummary = "" // Reset summary on failure
		} else {
			previousOutputSummary = summary
			log.Printf("ContextStrategist: Generated AI summary for next chunk context: %s", previousOutputSummary)
		}
	} // End of loop through remainingText

	// === FINAL STEP: Reassemble and clean the results ===
	finalResult, err := cm.reassembleAndClean(ctx, llm, originalPrompt, results)
	if err != nil {
		log.Printf("ContextStrategist: Final reassembly failed: %v. Returning raw joined results.", err)
		return strings.Join(results, "\n\n---\n\n"), nil // Return raw results as a fallback
	}

	return finalResult, nil
}

// aiSummarizeForContext uses an LLM to create a high-quality summary of the last processed chunk and its result.
func (cm *ContextStrategist) aiSummarizeForContext(_ context.Context, llm TextGenerator, previousChunk, previousResult string) (string, error) {
	if previousResult == "" {
		return "", nil
	}

	summaryPrompt := fmt.Sprintf(`
You are a summarization AI. Your task is to create a concise summary that bridges the gap between a processed text chunk and the next one.
Focus on the key information and context from the "PREVIOUS CHUNK" and its "GENERATED RESULT" that will be essential for understanding and continuing the task on the next chunk of text.

PREVIOUS CHUNK:
---
%s
---

GENERATED RESULT:
---
%s
---

CONCISE SUMMARY FOR NEXT CHUNK:
`, previousChunk, previousResult)

	return llm.GenerateText(summaryPrompt)
}

// reassembleAndClean takes the individual chunk results and uses an LLM to create a final, clean, coherent document.
func (cm *ContextStrategist) reassembleAndClean(_ context.Context, llm TextGenerator, originalPrompt string, chunkResults []string) (string, error) {
	log.Println("ContextStrategist: Starting final reassembly and cleanup step...")

	if len(chunkResults) == 0 {
		return "", errors.New("no chunk results to reassemble")
	}

	joinedResults := strings.Join(chunkResults, "\n\n--- (New Chunk Result) ---\n\n")

	reassemblyPrompt := fmt.Sprintf(`
You are a document reassembly AI. Your task is to combine the following processed text chunks into a single, coherent, and clean final document.
The final document must fully address the "ORIGINAL PROMPT".

CRITICAL INSTRUCTIONS:
1.  Merge the chunk results seamlessly.
2.  Remove any repetitive headers, footers, or instructions that the AI may have included for itself (e.g., "Context from previous section:", "Current Section:", "---").
3.  Ensure the final output is a clean, complete, and well-formatted response. Do not include any of your own commentary.

ORIGINAL PROMPT: "%s"

PROCESSED CHUNKS TO REASSEMBLE:
%s
`, originalPrompt, joinedResults)

	return llm.GenerateText(reassemblyPrompt)
}

// findSplitIndex finds a suitable index to split the text within the token budget.
// It prioritizes paragraph breaks, then sentence breaks.
func findSplitIndex(text string, tokenBudget int, modelName string) int {
	if estimateTokens(text, modelName) <= tokenBudget {
		return len(text) // Whole text fits
	}

	bestSplit := -1
	currentTokens := 0

	// Iterate through characters, estimating tokens and looking for good split points
	// This is approximate; a more robust method would use actual tokenization.
	for i := 0; i < len(text); i++ {
		// Estimate tokens incrementally (very rough)
		if i%4 == 0 { // Estimate 1 token every 4 chars
			currentTokens++
		}

		if currentTokens > tokenBudget {
			// We've exceeded the budget, return the last good split point found
			if bestSplit > 0 {
				return bestSplit
			}
			// If no good split found, return the index just before exceeding budget
			return max(0, i-1) // Ensure non-negative index
		}

		// Check for preferred split points (double newline, then sentence end)
		if i > 0 && text[i] == '\n' && text[i-1] == '\n' {
			bestSplit = i + 1 // Split after double newline
		} else if bestSplit == -1 && (text[i] == '.' || text[i] == '!' || text[i] == '?') {
			// If no paragraph break found yet, consider sentence end
			if i+1 < len(text) && (text[i+1] == ' ' || text[i+1] == '\n') {
				bestSplit = i + 1 // Split after punctuation and space/newline
			}
		}
	}

	// If loop finishes, the whole text fits (should have been caught earlier)
	return len(text)
}

// GetChunkingStrategy returns the current chunking strategy.
func (cm *ContextStrategist) GetChunkingStrategy() ChunkingStrategy {
	return cm.strategy
}

// SetChunkingStrategy sets a new chunking strategy.
func (cm *ContextStrategist) SetChunkingStrategy(strategy ChunkingStrategy) {
	cm.strategy = strategy
	log.Printf("ContextManager: Chunking strategy set to %d", strategy)
}

// GetProcessingMode returns the current processing mode.
func (cm *ContextStrategist) GetProcessingMode() ProcessingMode {
	return cm.processingMode
}

// SetProcessingMode sets a new processing mode.
func (cm *ContextStrategist) SetProcessingMode(mode ProcessingMode) {
	cm.processingMode = mode
	log.Printf("ContextManager: Processing mode set to %d", mode)
}

// SetMaxChunkSize sets the maximum chunk size in tokens.
func (cm *ContextStrategist) SetMaxChunkSize(size int) {
	cm.maxChunkSize = size
	log.Printf("ContextManager: Max chunk size set to %d tokens", size)
}

// SetChunkOverlap sets the overlap between chunks in tokens.
func (cm *ContextStrategist) SetChunkOverlap(overlap int) {
	cm.chunkOverlap = overlap
	log.Printf("ContextManager: Chunk overlap set to %d tokens", overlap)
}

// Deprecated: LLM is now passed during processing.
// func (cm *ContextManager) GetInferenceService() TextGenerator {
// 	return cm.inferenceService
// }

// Helper min function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper max function
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
