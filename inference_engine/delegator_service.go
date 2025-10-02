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
	primaryAttempts  []LLMAttempt       // Ordered list of primary LLMs to try
	fallbackAttempts []LLMAttempt       // Ordered list of fallback LLMs to try
	memory           ConversationMemory // Manages conversation history
	contextManager   *ContextManager    // ADDED: Reference to context manager

	// Configuration for delegation logic
	tokenLimitThreshold  int        // Token limit to decide initial routing
	tokenLimitCheckModel string     // Model name used for token estimation against the limit
	moa                  *gollm.MOA // MOA instance
}

// NewDelegatorService creates a new delegator instance.
// It requires lists of initialized LLM attempts, an optional MOA instance, and a ContextManager.
func NewDelegatorService(primaryAttempts []LLMAttempt, fallbackAttempts []LLMAttempt, tokenLimit int, tokenModel string, moaInstance *gollm.MOA, ctxManager *ContextManager) *DelegatorService {
	if len(primaryAttempts) == 0 || len(fallbackAttempts) == 0 {
		log.Println("CRITICAL: NewDelegatorService called with empty primary or fallback attempts")
		return nil
	}
	if moaInstance == nil {
		log.Println("[WARN] NewDelegatorService: MOA instance is nil. MOA features will be disabled.")
	}
	if ctxManager == nil {
		log.Println("[WARN] NewDelegatorService: ContextManager instance is nil. Chunking fallback will be disabled.")
	}
	return &DelegatorService{
		primaryAttempts:      primaryAttempts,
		fallbackAttempts:     fallbackAttempts,
		moa:                  moaInstance,
		contextManager:       ctxManager,                        // Store context manager
		memory:               NewSimpleWindowMemory(tokenModel), // Use tokenModel here
		tokenLimitThreshold:  tokenLimit,                        // Use correct field name and passed value
		tokenLimitCheckModel: tokenModel,                        // ADDED: Store the model name for token checking
	}
}

// --- Helper Functions (Moved from OptimizingProxy) ---

// getEncodingForModel returns the appropriate tiktoken encoding for a given model
func getEncodingForModel(model string) (*tiktoken.Tiktoken, error) {
	switch {
	case strings.Contains(model, "gpt-4"), strings.Contains(model, "gpt-3.5"):
		return tiktoken.EncodingForModel(model)
	case strings.Contains(model, "cerebras"):
		// Cerebras uses similar tokenization to GPT-4
		return tiktoken.EncodingForModel("gpt-4")
	case strings.Contains(model, "gemini"):
		// Gemini uses similar tokenization to GPT-4
		return tiktoken.EncodingForModel("gpt-4")
	default:
		// Try default model encoding as a fallback before giving up
		enc, err := tiktoken.GetEncoding("cl100k_base") // Common encoding
		if err == nil {
			log.Printf("Warning: Unsupported model '%s' for token estimation, using cl100k_base encoding.", model)
			return enc, nil
		}
		return nil, fmt.Errorf("unsupported model and failed to get default encoding: %s", model)
	}
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
	if estimatedTokens > d.tokenLimitThreshold && d.contextManager != nil {
		log.Printf("DelegatorService (%s): Estimated tokens exceed limit. Attempting PROACTIVE chunking with ContextManager...", operationName)
		// Find a suitable LLM for chunking (e.g., the first primary or a designated one)
		// Using the first primary attempt for proactive chunking
		chunkingLLM := d.primaryAttempts[0].Instance
		chunkingModelName := d.primaryAttempts[0].Config.ModelName
		log.Printf("DelegatorService (%s): Using LLM '%s' for proactive chunking.", operationName, chunkingModelName)

		fullPromptForChunking := formatMessagesToPrompt(messages)
		chunkInstruction := "Process the following section of text:"                 // Adjust as needed
		wrappedLLM := &LLMAdapter{LLM: chunkingLLM, ProviderName: chunkingModelName} // Pass ProviderName

		chunkedResponse, chunkErr := d.contextManager.ProcessLargePrompt(ctx, wrappedLLM, fullPromptForChunking, chunkInstruction)
		if chunkErr == nil {
			log.Printf("DelegatorService (%s): PROACTIVE ContextManager chunking successful.", operationName)
			d.memory.AddMessage(gollm_types.MemoryMessage{Role: "assistant", Content: chunkedResponse})
			return chunkedResponse, nil // Return successful chunked response
		}
		log.Printf("DelegatorService (%s): PROACTIVE ContextManager chunking failed: %v. Proceeding to standard attempt logic (will likely fail again or trigger reactive chunking).", operationName, chunkErr)
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
			// --- ADDED: Reactive Chunking on Context Error ---
			errStr := err.Error()
			isContextError := strings.Contains(errStr, "context_length_exceeded") || strings.Contains(errStr, "token limit")

			if isContextError && d.contextManager != nil {
				log.Printf("DelegatorService (%s): Attempt with %s failed with context limit. Attempting REACTIVE chunking with ContextManager using the same LLM...", operationName, targetName)

				// Use the current LLM instance that just failed for chunking
				chunkingLLM := attempt.Instance
				if chunkingLLM != nil {
					// Reconstruct the full prompt string from the original messages
					fullPromptForChunking := formatMessagesToPrompt(messages)    // Use the original full messages
					chunkInstruction := "Process the following section of text:" // Adjust as needed

					// Call the context manager
					wrappedLLM := &LLMAdapter{LLM: chunkingLLM, ProviderName: attempt.Config.ProviderName} // Pass ProviderName
					chunkedResponse, chunkErr := d.contextManager.ProcessLargePrompt(ctx, wrappedLLM, fullPromptForChunking, chunkInstruction)
					if chunkErr == nil {
						log.Printf("DelegatorService (%s): REACTIVE ContextManager chunking successful with %s.", operationName, targetName)
						d.memory.AddMessage(gollm_types.MemoryMessage{Role: "assistant", Content: chunkedResponse})
						return chunkedResponse, nil // Return successful chunked response
					}
					log.Printf("DelegatorService (%s): REACTIVE ContextManager chunking with %s failed: %v. Proceeding to next attempt.", operationName, targetName, chunkErr)
					// If chunking fails, store its error (or keep the original context error?) and let the loop proceed.
					// lastError = chunkErr // Optionally update lastError to the chunking error
				}
			} // --- END REACTIVE Chunking Check ---

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

	// --- FINAL FALLBACK: Context Manager Chunking ---
	// Check if the last error suggests a context length issue and if context manager exists
	// This block now acts as a fallback if the *immediate* chunking attempt (for Cerebras) failed,
	// or if a fallback LLM (like Gemini) failed with a context error.
	errStr := lastError.Error()
	isContextError := strings.Contains(errStr, "context_length_exceeded") || strings.Contains(errStr, "token limit")

	if isContextError && d.contextManager != nil {
		log.Printf("DelegatorService (%s): All attempts failed, last error indicates context limit. Attempting FINAL chunking fallback with ContextManager...", operationName)

		// Find the Deepseek instance (or another designated chunking LLM for the final fallback)
		var chunkingLLM llm.LLM
		for _, attempt := range d.fallbackAttempts { // Search fallbacks first
			// Use the first fallback LLM found for the final attempt
			if attempt.Instance != nil {
				chunkingLLM = attempt.Instance
				log.Printf("DelegatorService (%s): Found LLM '%s' from provider '%s' for final chunking fallback.", operationName, attempt.Config.ModelName, attempt.Config.ProviderName)
				break // Use the first one found
			}
		}
		// Could add searching primaryAttempts if not found in fallback

		if chunkingLLM != nil {
			// Reconstruct the full prompt string from the original messages
			fullPromptForChunking := formatMessagesToPrompt(messages)
			// Define a generic instruction for the chunking process
			chunkInstruction := "Process the following section of text:" // Adjust as needed

			// Call the context manager with wrapped LLM
			// Find the provider name for the selected chunkingLLM
			providerName := "unknown"
			for _, attempt := range d.fallbackAttempts { // Search again to get the name
				if attempt.Instance == chunkingLLM {
					providerName = attempt.Config.ProviderName
					break
				}
			}
			// If not found in fallback, check primary (though unlikely path)
			if providerName == "unknown" {
				for _, attempt := range d.primaryAttempts {
					if attempt.Instance == chunkingLLM {
						providerName = attempt.Config.ProviderName
						break
					}
				}
			}
			wrappedLLM := &LLMAdapter{LLM: chunkingLLM, ProviderName: providerName} // Pass ProviderName
			chunkedResponse, chunkErr := d.contextManager.ProcessLargePrompt(ctx, wrappedLLM, fullPromptForChunking, chunkInstruction)
			if chunkErr == nil {
				log.Printf("DelegatorService (%s): FINAL ContextManager chunking fallback successful.", operationName)
				// Add the potentially long, combined response to memory
				d.memory.AddMessage(gollm_types.MemoryMessage{Role: "assistant", Content: chunkedResponse})
				return chunkedResponse, nil // Return successful chunked response
			}
			log.Printf("DelegatorService (%s): FINAL ContextManager chunking fallback failed: %v", operationName, chunkErr)
			// If chunking also fails, return its error wrapped with the original context
			return "", fmt.Errorf("%s failed after all attempts including final chunking, chunking error: %w (original error: %v)", operationName, chunkErr, lastError)
		}
		log.Printf("DelegatorService (%s): Context error detected, but no suitable LLM found/configured for final chunking fallback.", operationName)
	}
	// --- End FINAL FALLBACK ---

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
