// /home/gperry/Documents/GitHub/Inc-Line/Wordpress-Inference-Engine/inference/delegator_service.go
package inference_engine

import (
	"context"
	"errors" // Import the errors package
	"fmt"
	"log"
	"strings"

	gollm "github.com/guiperry/gollm_cerebras"
	"github.com/pkoukk/tiktoken-go"

	// Import gollm for MOA type
	"github.com/guiperry/gollm_cerebras/llm"
	gollm_types "github.com/guiperry/gollm_cerebras/types" // Renamed import
	// Add other necessary imports if message conversion or specific types are moved here
)

// DelegatorService handles request delegation between a primary (proxy)
// and a secondary (base) LLM, including fallback logic and MOA orchestration.
type DelegatorService struct {
	primaryAttempts   []LLMAttempt       // Ordered list of primary LLMs to try
	fallbackAttempts  []LLMAttempt       // Ordered list of fallback LLMs to try
	memory            ConversationMemory // Manages conversation history
	contextStrategist *ContextStrategist // ADDED: Reference to context manager

	// Configuration for delegation logic
	tokenLimitThreshold  int        // Token limit to decide initial routing
	tokenLimitCheckModel string     // Model name used for token estimation against the limit
	moa                  *gollm.MOA // MOA instance
}

// NewDelegatorService creates a new delegator instance.
// It requires lists of initialized LLM attempts, an optional MOA instance, and a ContextStrategist.
func NewDelegatorService(primaryAttempts []LLMAttempt, fallbackAttempts []LLMAttempt, tokenLimit int, tokenModel string, moaInstance *gollm.MOA, ctxStrategist *ContextStrategist) *DelegatorService {
	if len(primaryAttempts) == 0 || len(fallbackAttempts) == 0 {
		log.Println("CRITICAL: NewDelegatorService called with empty primary or fallback attempts")
		return nil
	}
	if moaInstance == nil {
		log.Println("[WARN] NewDelegatorService: MOA instance is nil. MOA features will be disabled.")
	}
	if ctxStrategist == nil {
		log.Println("[WARN] NewDelegatorService: ContextStrategist instance is nil. Large context handling will be disabled.")
	}
	return &DelegatorService{
		primaryAttempts:      primaryAttempts,
		fallbackAttempts:     fallbackAttempts,
		moa:                  moaInstance,
		contextStrategist:    ctxStrategist,                     // Store context manager
		memory:               NewSimpleWindowMemory(tokenModel), // Use tokenModel here
		tokenLimitThreshold:  tokenLimit,                        // Use correct field name and passed value
		tokenLimitCheckModel: tokenModel,                        // ADDED: Store the model name for token checking
	}
}

// --- Helper Functions (Moved from OptimizingProxy) ---

// modelToEncoding is a map of model prefixes to their corresponding tiktoken encoding.
// This provides a centralized and extensible way to manage tokenization rules.
var modelToEncoding = map[string]string{
	"gpt-4":      "cl100k_base",
	"gpt-3.5":    "cl100k_base",
	"cerebras":   "cl100k_base", // Cerebras models are compatible with cl100k_base
	"gemini":     "cl100k_base", // Gemini models are compatible with cl100k_base
	"claude":     "cl100k_base", // Anthropic's Claude models are compatible with cl100k_base
	"deepseek":   "cl100k_base", // Deepseek models are compatible with cl100k_base
	"mistral":    "cl100k_base", // Mistral models are compatible with cl100k_base
	"llama":      "cl100k_base", // Llama models are compatible with cl100k_base
	"command-r":  "cl100k_base", // Cohere's Command R models are compatible with cl100k_base
	"openrouter": "cl100k_base", // OpenRouter uses various models, cl100k_base is a safe default
	"groq":       "cl100k_base", // Groq uses models like Llama/Mistral, so cl100k_base is appropriate
}

// getEncodingForModel returns the appropriate tiktoken encoding for a given model
func getEncodingForModel(model string) (*tiktoken.Tiktoken, error) {
	lowerModel := strings.ToLower(model)

	// Check for an exact model name match first (e.g., "gpt-4")
	if encodingName, ok := tiktoken.MODEL_TO_ENCODING[lowerModel]; ok {
		return tiktoken.GetEncoding(encodingName)
	}

	// Check for prefixes from our custom map
	for prefix, encodingName := range modelToEncoding {
		if strings.Contains(lowerModel, prefix) {
			return tiktoken.GetEncoding(encodingName)
		}
	}

	// Fallback for truly unknown models
	log.Printf("Warning: Unsupported model '%s' for token estimation, using cl100k_base as a fallback.", model)
	return tiktoken.GetEncoding("cl100k_base")
}

// estimateTokens provides accurate token estimation based on model
func estimateTokens(content string, model string) int {
	// Try to get proper encoding first
	enc, err := getEncodingForModel(model)
	if err == nil {
		tokens := enc.Encode(content, nil, nil)
		return len(tokens)
	}

	// Fallback for unknown models: rough estimate (1 token ~ 4 chars)
	log.Printf("Warning: Using character-based fallback for token estimation (model: %s)", model)
	return (len(content) / 4) + 5
}

// estimateTotalTokens estimates tokens for a slice of messages.
func estimateTotalTokens(messages []gollm_types.MemoryMessage, model string) int {
	total := 0
	for _, msg := range messages {
		total += estimateTokens(msg.Content, model)
	}
	// Add overhead for message formatting (3 tokens per message)
	return total + (len(messages) * 3)
}

// formatMessagesToPrompt converts a slice of messages into a single string prompt.
// This is a basic implementation; specific models might prefer different formats.
func formatMessagesToPrompt(messages []gollm_types.MemoryMessage) string {
	var builder strings.Builder
	for _, msg := range messages {
		// Simple format: "[Role]: Content\n"
		// Adjust this format if Cerebras/Gemini expect something different
		// when receiving history in a single prompt.
		builder.WriteString(fmt.Sprintf("[%s]: %s\n", msg.Role, msg.Content))
	}
	// Remove trailing newline if present
	return strings.TrimSuffix(builder.String(), "\n")
}

// shouldRetryWithError determines if the given error warrants a fallback attempt to the base LLM.
// Customize this logic based on the errors observed from the primary LLM (Cerebras).
func (d *DelegatorService) shouldFallbackOnError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	log.Printf("DelegatorService: Evaluating error for fallback: %s", errStr)

	// Allow Fallback on context length exceeded
	if strings.Contains(errStr, "context_length_exceeded") || strings.Contains(errStr, "token limit") {
		log.Println("DelegatorService: Decision: Allowing Fallback (Context Length Exceeded)")
		return true
	}

	// Add other conditions where fallback is desired (e.g., specific server errors, timeouts)
	// if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "status code 5") {
	// 	   log.Println("DelegatorService: Decision: Allowing Fallback (Transient Error)")
	//     return true
	// }

	// Allow fallback for common transient errors (e.g., 5xx status codes, timeouts)
	if strings.Contains(errStr, "status code 5") || strings.Contains(errStr, "timeout") || strings.Contains(errStr, "connection refused") {
		log.Println("DelegatorService: Decision: Allowing Fallback (Transient Error)")
		return true
	}

	// TODO: Refine - Should we fallback on API key errors? Probably not to the *same* provider.
	// if strings.Contains(errStr, "invalid API key") { return false }

	// Default: Allow fallback for now, can be made stricter
	log.Println("DelegatorService: Decision: Allowing Fallback (Default Error)")
	return true
}

// executeGenerationInternal is the core generation logic without the proactive context strategist check.
// This is intended for internal use by components like the TaskOrchestrator that are already
// part of a higher-level strategy and need to make direct LLM calls.
func (d *DelegatorService) executeGenerationInternal(ctx context.Context, modelName string, messages []gollm_types.MemoryMessage, instructionText string, operationName string) (string, error) {
	if len(d.primaryAttempts) == 0 || len(d.fallbackAttempts) == 0 {
		return "", fmt.Errorf("delegator service (%s): not properly configured", operationName)
	}
	if len(messages) == 0 {
		return "", fmt.Errorf("delegator service (%s): cannot generate with empty messages", operationName)
	}

	var attemptsToTry []LLMAttempt
	specificModelRequested := modelName != "" && modelName != "No models available" && modelName != "Service unavailable"

	if specificModelRequested {
		log.Printf("DelegatorService (%s): Specific model '%s' requested. Attempting to find and use it.", operationName, modelName)
		found := false
		for _, attempt := range append(d.primaryAttempts, d.fallbackAttempts...) {
			if attempt.Config.ModelName == modelName {
				attemptsToTry = []LLMAttempt{attempt}
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("delegator service (%s): requested model '%s' not found in configured attempts", operationName, modelName)
		}
	} else {
		// If no specific model is requested, the default behavior is to try the primary list first,
		// and then the fallback list if the primary fails. This is handled by the main loop below.
		// We initialize attemptsToTry here to start with the primary list.
		attemptsToTry = d.primaryAttempts
	}

	promptString := formatMessagesToPrompt(messages)
	var lastError error
	currentAttemptList := attemptsToTry

	for listNum := 0; listNum < 2; listNum++ { // Max 2 lists: primary then fallback
		if specificModelRequested && listNum > 0 {
			break
		}

		listName := "Primary/Specified"
		if !specificModelRequested {
			if listNum == 0 {
				listName = "Primary"
				currentAttemptList = d.primaryAttempts
			} else if listNum == 1 && lastError != nil && d.shouldFallbackOnError(lastError) {
				listName = "Fallback"
				log.Printf("DelegatorService (%s): Primary attempts failed with fallback-allowed error: %v. Switching to fallback attempts.", operationName, lastError)
				currentAttemptList = d.fallbackAttempts
			} else if listNum == 1 && lastError != nil {
				log.Printf("DelegatorService (%s): Primary attempts failed but error doesn't warrant fallback: %v", operationName, lastError)
				break
			}
		}

		for i, attempt := range currentAttemptList {
			targetName := fmt.Sprintf("%s Attempt %d/%d (Model: %s)", listName, i+1, len(currentAttemptList), attempt.Config.ModelName)
			log.Printf("DelegatorService (%s): Trying %s", operationName, targetName)

			finalPromptStringForLLM := "Instructions:\n" + instructionText + "\n\n---\n\n" + promptString
			finalPromptForLLM := llm.NewPrompt(finalPromptStringForLLM)
			responseContent, err := attempt.Instance.Generate(ctx, finalPromptForLLM)

			if err == nil {
				log.Printf("DelegatorService (%s): Generation successful with %s.", operationName, targetName)
				// Note: We don't add to memory here, as the caller (orchestrator) manages state.
				return responseContent, nil
			}

			lastError = err
			log.Printf("DelegatorService (%s): Attempt with %s failed: %v", operationName, targetName, err)
		}
	}

	return "", fmt.Errorf("%s failed after all attempts, last error: %w", operationName, lastError)
}

// executeGenerationWithRetry attempts generation using a sequence of LLMs, handling retries and fallbacks.
func (d *DelegatorService) executeGenerationWithRetry(ctx context.Context, modelName string, messages []gollm_types.MemoryMessage, instructionText string, operationName string) (string, error) {
	if len(d.primaryAttempts) == 0 || len(d.fallbackAttempts) == 0 {
		return "", fmt.Errorf("delegator service (%s): not properly configured", operationName)
	}
	if len(messages) == 0 {
		return "", fmt.Errorf("delegator service (%s): cannot generate with empty messages", operationName)
	}

	// Estimate tokens using the designated model for limit checking
	estimatedTokens := estimateTotalTokens(messages, d.tokenLimitCheckModel)
	log.Printf("DelegatorService (%s): Estimated tokens for request: %d (Limit: %d, Check Model: %s)",
		operationName, estimatedTokens, d.tokenLimitThreshold, d.tokenLimitCheckModel) // Log estimation, but don't bypass primary based on it.

	// --- ADDED: Proactive Chunking Check ---
	if estimatedTokens > d.tokenLimitThreshold && d.contextStrategist != nil {
		log.Printf("DelegatorService (%s): Estimated tokens exceed limit. Delegating to ContextStrategist...", operationName)
		// Find a suitable LLM for chunking (e.g., the first primary or a designated one)
		// Using the first primary attempt for proactive chunking
		chunkingLLM := d.primaryAttempts[0].Instance
		chunkingModelName := d.primaryAttempts[0].Config.ModelName
		log.Printf("DelegatorService (%s): Using LLM '%s' for context strategy execution.", operationName, chunkingModelName)

		// Check context to see if this is a scan-initiated request
		source, _ := ctx.Value("source").(string)
		if source == "scan_worker" {
			log.Println("DelegatorService: Scan worker source detected, forcing OrchestrationStrategy.")
			// Directly execute orchestration, bypassing intent classification
			chunkedResponse, chunkErr := d.contextStrategist.executeOrchestration(ctx, formatMessagesToPrompt(messages))
			if chunkErr == nil {
				d.memory.AddMessage(gollm_types.MemoryMessage{Role: "assistant", Content: chunkedResponse})
				return chunkedResponse, nil
			}
			log.Printf("DelegatorService: Forced orchestration failed: %v. Proceeding to standard logic.", chunkErr)
		}

		fullPromptForChunking := formatMessagesToPrompt(messages)
		chunkInstruction := instructionText                                          // Pass along the original instruction
		wrappedLLM := &LLMAdapter{LLM: chunkingLLM, ProviderName: chunkingModelName} // Pass ProviderName

		chunkedResponse, chunkErr := d.contextStrategist.DecideStrategy(ctx, wrappedLLM, fullPromptForChunking, chunkInstruction)
		if chunkErr == nil {
			log.Printf("DelegatorService (%s): ContextStrategist processing successful.", operationName)
			d.memory.AddMessage(gollm_types.MemoryMessage{Role: "assistant", Content: chunkedResponse})
			return chunkedResponse, nil // Return successful chunked response
		}
		log.Printf("DelegatorService (%s): ContextStrategist processing failed: %v. Proceeding to standard attempt logic.", operationName, chunkErr)
		// If proactive chunking fails, let the standard loop proceed, it might hit the reactive chunking later.
	}
	// --- END Proactive Chunking Check ---

	var attemptsToTry []LLMAttempt
	specificModelRequested := modelName != "" && modelName != "No models available" && modelName != "Service unavailable"

	if specificModelRequested {
		log.Printf("DelegatorService (%s): Specific model '%s' requested. Attempting to find and use it.", operationName, modelName)
		found := false
		for _, attempt := range append(d.primaryAttempts, d.fallbackAttempts...) {
			if attempt.Config.ModelName == modelName {
				attemptsToTry = []LLMAttempt{attempt}
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("delegator service (%s): requested model '%s' not found in configured attempts", operationName, modelName)
		}
	} else {
		attemptsToTry = d.primaryAttempts // Default to primary list if no specific model
	}

	// Convert messages to a single prompt string
	promptString := formatMessagesToPrompt(messages)
	_ = llm.NewPrompt(promptString) // gollm expects a Prompt object, assign to blank identifier if not used directly

	var lastError error
	currentAttemptList := attemptsToTry

	for listNum := 0; listNum < 2; listNum++ { // Max 2 lists: primary then fallback (or just fallback)
		if specificModelRequested && listNum > 0 { // If specific model was requested, only try that list (which is `attemptsToTry`)
			break
		}

		listName := "Primary/Specified"
		if !specificModelRequested { // Only consider switching to fallback if no specific model was requested
			if listNum == 0 {
				listName = "Primary"
				currentAttemptList = d.primaryAttempts
			} else if listNum == 1 && lastError != nil && d.shouldFallbackOnError(lastError) { // Only switch to fallback if primary failed and error warrants it
				listName = "Fallback"
				log.Printf("DelegatorService (%s): Primary attempts failed with fallback-allowed error: %v. Switching to fallback attempts.", operationName, lastError)
				currentAttemptList = d.fallbackAttempts
			} else if listNum == 1 && lastError != nil {
				log.Printf("DelegatorService (%s): Primary attempts failed but error doesn't warrant fallback: %v", operationName, lastError)
				break // Don't try fallback for this type of error
			}
		} else if listNum == 1 { // This case should not be hit if specificModelRequested is true due to the break above
			break // Already tried fallback, don't try primary
		}

		for i, attempt := range currentAttemptList {
			targetName := fmt.Sprintf("%s Attempt %d/%d (Model: %s)", listName, i+1, len(currentAttemptList), attempt.Config.ModelName)
			log.Printf("DelegatorService (%s): Trying %s", operationName, targetName)

			// --- Incorporate Instruction Text ---
			finalPromptStringForLLM := promptString
			if instructionText != "" {
				finalPromptStringForLLM = "Instructions:\n" + instructionText + "\n\n---\n\n" + promptString
			}
			finalPromptForLLM := llm.NewPrompt(finalPromptStringForLLM)
			responseContent, err := attempt.Instance.Generate(ctx, finalPromptForLLM)

			if err == nil {
				log.Printf("DelegatorService (%s): Generation successful with %s.", operationName, targetName)
				d.memory.AddMessage(gollm_types.MemoryMessage{Role: "assistant", Content: responseContent})
				return responseContent, nil // Success!
			}

			// Attempt failed
			log.Printf("DelegatorService (%s): Attempt with %s failed: %v", operationName, targetName, err)
			lastError = err // Store the error

			// Decide if we should continue to the next attempt in *this* list
			// --- REMOVED: Reactive Chunking on Context Error ---
			// The proactive check at the beginning of the function should handle this.
			// If a context length error still occurs, it's a sign that token estimation is off
			// or the LLM has a stricter limit than advertised. We will let it fall through to the
			// next attempt or fail, rather than re-running the strategist.

			log.Printf("DelegatorService (%s): Error is retryable. Continuing to next attempt...", operationName)
		}

		// If we finished a list and haven't succeeded, decide if we should try the *next* list
		if listNum == 0 && !specificModelRequested && lastError != nil {
			// Primary list failed, continue to fallback list (outer loop handles this)
			continue
		} else {
			// Fallback list failed, or we started with fallback and it failed, or primary succeeded (handled above)
			break // Exit outer loop
		}
	}

	// If we exit the loops, all attempts failed
	log.Printf("DelegatorService (%s): All generation attempts failed.", operationName)
	if lastError == nil { // Should not happen if we reach here, but defensive check
		lastError = errors.New("all attempts failed for unknown reasons")
	}

	// If not a context error, or no context manager, or chunking LLM not found, return the last error from regular attempts
	return "", fmt.Errorf("%s failed after all attempts, last error: %w", operationName, lastError)
}

// --- Generation Methods ---

// GenerateSimple uses standard delegation/fallback ONLY.
// It now uses the conversation memory.
func (d *DelegatorService) GenerateSimple(ctx context.Context, modelName string, promptText string, instructionText string) (string, error) {
	userMessage := gollm_types.MemoryMessage{Role: "user", Content: promptText} // Instruction is handled separately

	// Add user prompt to memory
	d.memory.AddMessage(userMessage)

	var messagesForContext []gollm_types.MemoryMessage

	// Estimate tokens for the *current* message only
	// Token estimation for context should consider the model being targeted if specific, else the default check model.
	tokenCheckModelForContext := d.tokenLimitCheckModel
	if modelName != "" {
		tokenCheckModelForContext = modelName
	}
	currentMessageTokens := estimateTokens(userMessage.Content, tokenCheckModelForContext)

	if currentMessageTokens > d.tokenLimitThreshold {
		// If the current message ALONE exceeds the limit, send only it to the fallback logic
		log.Printf("DelegatorService (Simple): Current prompt (%d tokens) exceeds limit (%d). Sending only current prompt.", currentMessageTokens, d.tokenLimitThreshold)
		messagesForContext = []gollm_types.MemoryMessage{userMessage}
	} else {
		// Otherwise, try to get history including the current message, respecting the limit
		messagesForContext = d.memory.GetMessagesForContext(d.tokenLimitThreshold, tokenCheckModelForContext)
		if len(messagesForContext) == 0 {
			// This should ideally not happen if currentMessageTokens <= proxyTokenLimit, but handle defensively
			log.Printf("DelegatorService (Simple): Warning - GetMessagesForContext returned empty despite current prompt fitting. Sending only current prompt.")
			messagesForContext = []gollm_types.MemoryMessage{userMessage}
			// Alternative: return fmt.Errorf("GenerateSimple: No messages fit within the context window limit (%d tokens)", d.proxyTokenLimit)
		}
	}

	// MOA is NOT used for simple generation in this design
	return d.executeGenerationWithRetry(ctx, modelName, messagesForContext, instructionText, "Simple")
}

// GenerateWithCoT uses MOA if available, otherwise standard fallback.
// It now uses the conversation memory for the fallback path.
func (d *DelegatorService) GenerateWithCoT(ctx context.Context, promptText string) (string, error) {
	// Construct CoT prompt
	cotPromptText := fmt.Sprintf("Think step-by-step to answer the following question:\n%s\n\nReasoning steps:", promptText)

	// --- Add user prompt to memory (even if MOA is used first) ---
	// We add the *original* prompt, not the CoT-enhanced one, to keep history clean.
	// The CoT enhancement is specific to this generation attempt.
	d.memory.AddMessage(gollm_types.MemoryMessage{Role: "user", Content: promptText})

	// --- Use MOA if available ---
	if d.moa != nil {
		log.Println("DelegatorService (CoT): Using MOA for generation...")
		response, err := d.moa.Generate(ctx, cotPromptText)
		if err != nil {
			log.Printf("DelegatorService (CoT): MOA generation failed: %v", err)
			// Optionally, could fall back AGAIN to executeGenerationWithFallback here?
			// return "", fmt.Errorf("CoT generation failed via MOA: %w", err)
			log.Println("DelegatorService (CoT): MOA failed, falling back to standard generation...")
			// Fall through to standard execution if MOA fails
		} else {
			// Add successful MOA response to memory
			d.memory.AddMessage(gollm_types.MemoryMessage{
				Role:    "assistant",
				Content: response,
			})
			log.Println("DelegatorService (CoT): MOA generation successful.")
			// TODO: Optional parsing if needed for CoT
			return response, nil
		}
	}

	// --- Standard Fallback if MOA is nil or failed ---
	log.Println("DelegatorService (CoT): Using standard generation with fallback...")
	// For fallback, we need messages. We'll create a temporary message list
	// containing the CoT prompt, but ideally, memory should handle this better.
	// For now, let's get context and append the CoT prompt as the last user message.
	// NOTE: This might exceed token limits if history is large. A better approach
	// would be to integrate the CoT logic *within* the memory retrieval or
	// pass the specific CoT prompt directly to executeGenerationWithFallback
	// which would then use *that* as the final message instead of pulling from memory.

	// Let's modify executeGenerationWithFallback slightly: if the last message is user, use it.
	// Here, we create a specific message for the CoT request.
	cotMessage := gollm_types.MemoryMessage{Role: "user", Content: cotPromptText}
	// We pass only this message for the CoT attempt, ignoring history for this specific fallback.
	// This assumes CoT doesn't need prior context from memory for this step.
	fullResponse, err := d.executeGenerationWithRetry(ctx, "", []gollm_types.MemoryMessage{cotMessage}, "", "CoT-Fallback") // No specific model, no instruction for this internal step
	if err != nil {
		return "", err // Error already includes context from helper
	}
	// TODO: Optional parsing if needed for CoT
	// Note: The successful response is added to memory inside executeGenerationWithFallback
	return fullResponse, nil
}

// GenerateWithReflection uses MOA if available for each step, otherwise standard fallback.
// It now uses the conversation memory for the fallback paths.
func (d *DelegatorService) GenerateWithReflection(ctx context.Context, promptText string) (string, error) {
	log.Println("DelegatorService: GenerateWithReflection - Starting initial generation step")

	// --- Step 1: Initial Response Generation (Use MOA if available) ---
	var initialResponse string
	var err error
	if d.moa != nil {
		// Add user prompt to memory before MOA attempt
		// We add the original prompt here.
		d.memory.AddMessage(gollm_types.MemoryMessage{Role: "user", Content: promptText})

		log.Println("DelegatorService (Reflection-Initial): Using MOA...")
		initialResponse, err = d.moa.Generate(ctx, promptText)
		if err != nil {
			log.Printf("DelegatorService (Reflection-Initial): MOA failed: %v. Falling back...", err)
			// Fall through to standard execution if MOA fails
		}
	}

	// If MOA not used or failed, use standard fallback
	if initialResponse == "" {
		// If MOA wasn't used, add user prompt to memory now
		if d.moa == nil {
			d.memory.AddMessage(gollm_types.MemoryMessage{Role: "user", Content: promptText})
		}

		log.Println("DelegatorService (Reflection-Initial): Using standard generation...")
		// Get messages for context
		messagesForContext := d.memory.GetMessagesForContext(d.tokenLimitThreshold, d.tokenLimitCheckModel) // Use default check model
		if len(messagesForContext) == 0 {
			return "", fmt.Errorf("reflection initial generation: No messages fit context window")
		}
		initialResponse, err = d.executeGenerationWithRetry(ctx, "", messagesForContext, "", "Reflection-Initial") // No specific model, no instruction
	}

	// Handle final error from Step 1
	if err != nil {
		return "", fmt.Errorf("reflection initial generation failed: %w", err)
	} else if d.moa != nil && initialResponse != "" { // If MOA succeeded
		d.memory.AddMessage(gollm_types.MemoryMessage{Role: "assistant", Content: initialResponse})
	}
	log.Println("DelegatorService: GenerateWithReflection - Initial generation successful")

	// --- Step 2: Reflection Prompt Construction ---
	reflectionPromptText := fmt.Sprintf("Original prompt: %s\n\nInitial response: %s\n\nPlease review the initial response for accuracy, completeness, and clarity. Provide a revised and improved response based on your review.", promptText, initialResponse)
	log.Println("DelegatorService: GenerateWithReflection - Starting reflection generation step")

	// --- Step 3: Reflection Response Generation (Use MOA if available) ---
	var finalResponse string
	if d.moa != nil {
		// Add the reflection prompt "user" message to memory before MOA attempt
		// This makes the reflection step part of the history.
		d.memory.AddMessage(gollm_types.MemoryMessage{Role: "user", Content: reflectionPromptText})

		log.Println("DelegatorService (Reflection-Reflect): Using MOA...")
		finalResponse, err = d.moa.Generate(ctx, reflectionPromptText)
		if err != nil {
			log.Printf("DelegatorService (Reflection-Reflect): MOA failed: %v. Falling back...", err)
			// Fall through to standard execution if MOA fails
		}
	}

	// If MOA not used or failed, use standard fallback
	if finalResponse == "" {
		// If MOA wasn't used, add reflection prompt to memory now
		if d.moa == nil {
			d.memory.AddMessage(gollm_types.MemoryMessage{Role: "user", Content: reflectionPromptText})
		}

		log.Println("DelegatorService (Reflection-Reflect): Using standard generation...")
		// Get messages for context (including the reflection prompt)
		messagesForContext := d.memory.GetMessagesForContext(d.tokenLimitThreshold, d.tokenLimitCheckModel) // Use default check model
		if len(messagesForContext) == 0 {
			return "", fmt.Errorf("reflection refinement generation: No messages fit context window")
		}
		finalResponse, err = d.executeGenerationWithRetry(ctx, "", messagesForContext, "", "Reflection-Reflect") // No specific model, no instruction
	}

	// Handle final error from Step 3
	if err != nil {
		return "", fmt.Errorf("reflection refinement generation failed: %w", err)
	} else if d.moa != nil && finalResponse != "" { // If MOA succeeded
		d.memory.AddMessage(gollm_types.MemoryMessage{Role: "assistant", Content: finalResponse})
	}
	log.Println("DelegatorService: GenerateWithReflection - Reflection generation successful")

	return finalResponse, nil
}

// GenerateStructuredOutput uses MOA if available, otherwise standard fallback.
// It now uses the conversation memory for the fallback path.
func (d *DelegatorService) GenerateStructuredOutput(ctx context.Context, content string, schema string) (string, error) {
	log.Println("DelegatorService: GenerateStructuredOutput - Starting generation")

	// --- Step 1: Construct Structured Prompt ---
	structuredPromptText := fmt.Sprintf("Analyze the following content:\n\n---\n%s\n---\n\nPlease extract the relevant information and respond ONLY with a valid JSON object strictly adhering to the following JSON schema:\n```json\n%s\n```", content, schema)

	// --- Add user prompt to memory ---
	// We add the structured prompt text itself as the user message.
	// Alternatively, could store original content/schema and reconstruct if needed.
	d.memory.AddMessage(gollm_types.MemoryMessage{Role: "user", Content: structuredPromptText})

	// --- Step 2: Generate Structured Response (Use MOA if available) ---
	var response string
	var err error

	// --- Use MOA if available ---
	if d.moa != nil {
		log.Println("DelegatorService (StructuredOutput): Using MOA...")
		response, err = d.moa.Generate(ctx, structuredPromptText)
		if err != nil {
			log.Printf("DelegatorService (StructuredOutput): MOA failed: %v. Falling back...", err)
			// Fall through to standard execution if MOA fails
		}
		// If MOA succeeded, add response to memory
		if err == nil {
			d.memory.AddMessage(gollm_types.MemoryMessage{Role: "assistant", Content: response})
		}
	}

	// If MOA not used or failed, use standard fallback
	if response == "" {
		log.Println("DelegatorService (StructuredOutput): Using standard generation...")
		// Get messages for context (including the structured prompt)
		messagesForContext := d.memory.GetMessagesForContext(d.tokenLimitThreshold, d.tokenLimitCheckModel) // Use default check model
		if len(messagesForContext) == 0 {
			return "", fmt.Errorf("structured output generation: No messages fit context window")
		}
		response, err = d.executeGenerationWithRetry(ctx, "", messagesForContext, "", "StructuredOutput") // No specific model, no instruction
		// Note: response is added to memory inside executeGenerationWithFallback on success
	}

	// Handle final error
	if err != nil {
		// Remove the user message we added if the whole operation failed? Optional.
		// For now, leave it in history.
		return "", fmt.Errorf("structured output generation failed: %w", err)
	}

	log.Println("DelegatorService: GenerateStructuredOutput - Generation successful (validation may still be needed)")
	// TODO: Add JSON validation logic here if needed

	return response, nil
}

// Add method to update MOA instance if needed by SetProxy/BaseModel in InferenceService
func (d *DelegatorService) UpdateMOA(moaInstance *gollm.MOA) {
	// This method might not be strictly necessary if NewDelegatorService is always called
	// after model changes, but provides an alternative update path.
	if moaInstance == nil {
		log.Println("[WARN] DelegatorService.UpdateMOA: Received nil MOA instance.")
	}
	d.moa = moaInstance
	log.Println("DelegatorService: Internal MOA instance updated.")
}

// ClearMemory clears the conversation history.
func (d *DelegatorService) ClearMemory() {
	if d.memory != nil {
		d.memory.Clear()
	}
}
