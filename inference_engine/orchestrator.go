package inference_engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// SubTask defines a single task to be executed by a worker model.
type SubTask struct {
	ID          int    `json:"id"`
	Description string `json:"description"`
	InputData   string `json:"input_data"` // Data needed for this specific task
}

// TaskPlan is the structured output from the planning model.
type TaskPlan struct {
	OverallGoal string    `json:"overall_goal"`
	SubTasks    []SubTask `json:"sub_tasks"`
}

// TaskOrchestrator manages a multi-step, multi-model workflow.
type TaskOrchestrator struct {
	delegator      *DelegatorService
	plannerModel   string
	executorModels []string // A pool of models for executing sub-tasks
	finalizerModel string
	verifierModel  string
}

// NewTaskOrchestrator creates a new orchestrator.
func NewTaskOrchestrator(delegator *DelegatorService, planner string, executors []string, finalizer string, verifier string) *TaskOrchestrator {
	if delegator == nil {
		log.Println("[ERROR] TaskOrchestrator requires a non-nil DelegatorService.")
		return nil
	}
	if len(executors) == 0 {
		log.Println("[ERROR] TaskOrchestrator requires at least one executor model.")
		return nil
	}
	return &TaskOrchestrator{
		delegator:      delegator,
		plannerModel:   planner,
		executorModels: executors,
		finalizerModel: finalizer,
		verifierModel:  verifier,
	}
}

// ExecuteComplexTask orchestrates the planning, execution, and finalization of a complex prompt.
func (to *TaskOrchestrator) ExecuteComplexTask(ctx context.Context, complexPrompt string) (string, error) {
	log.Println("Orchestrator: Starting complex task execution.")

	// === STEP 1: Planning Phase (using a powerful model like Gemini) ===
	plan, err := to.generatePlan(ctx, complexPrompt)
	if err != nil {
		return "", fmt.Errorf("planning phase failed: %w", err)
	}
	log.Printf("Orchestrator: Plan generated with %d sub-tasks.", len(plan.SubTasks))

	// === STEP 2: Execution Phase (using fast worker models like Cerebras) ===
	subTaskResults, err := to.executeSubTasks(ctx, plan)
	if err != nil {
		// Even if there are errors, we might proceed with partial results.
		log.Printf("Orchestrator: Execution phase completed with errors: %v", err)
	} else {
		log.Println("Orchestrator: Execution phase completed successfully.")
	}

	// === STEP 3: Finalization Phase (using a powerful remediation model) ===
	finalResult, err := to.finalizeResults(ctx, complexPrompt, subTaskResults)
	if err != nil {
		return "", fmt.Errorf("finalization phase failed: %w", err)
	}
	log.Println("Orchestrator: Finalization complete.")

	// === STEP 4: Verification Phase (using a powerful model to check the final output) ===
	verificationResult, err := to.verifyFinalOutput(ctx, complexPrompt, finalResult)
	if err != nil {
		// Don't fail the whole task, just log the verification error
		log.Printf("Orchestrator: Verification phase failed: %v", err)
	} else {
		log.Printf("Orchestrator: Verification result: %s", verificationResult)
	}

	return finalResult, nil // Return the finalized result, not the verification message
}

// generatePlan calls the planning model to break down the complex prompt.
func (to *TaskOrchestrator) generatePlan(ctx context.Context, complexPrompt string) (*TaskPlan, error) {
	planningPrompt := fmt.Sprintf(`
You are a project manager AI. Your task is to break down the following complex request into a series of smaller, independent sub-tasks that can be executed in parallel.
For each sub-task, define a clear description and specify the input data required.

Complex Request: "%s"

Respond ONLY with a JSON object that follows this structure:
{
  "overall_goal": "A brief summary of the main objective.",
  "sub_tasks": [
    {
      "id": 1,
      "description": "Description of the first sub-task.",
      "input_data": "The specific data or context needed for this sub-task."
    }
  ]
}
`, complexPrompt)

	// Target a specific powerful model for planning.
	// We pass the model name to the delegator's GenerateSimple method.
	planJSON, err := to.delegator.GenerateSimple(ctx, to.plannerModel, planningPrompt, "")
	if err != nil {
		return nil, err
	}

	var plan TaskPlan
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		log.Printf("Orchestrator: Failed to unmarshal plan JSON. Raw response: %s", planJSON)
		return nil, fmt.Errorf("failed to parse task plan from planning model: %w", err)
	}

	return &plan, nil
}

// executeSubTasks processes the sub-tasks, often in parallel.
func (to *TaskOrchestrator) executeSubTasks(ctx context.Context, plan *TaskPlan) (map[int]string, error) {
	var wg sync.WaitGroup
	results := make(map[int]string)
	var errorMessages []string
	var mu sync.Mutex

	const maxRetries = 2               // 1 initial attempt + 2 retries
	const retryDelay = 3 * time.Second // Wait 3 seconds between retries

	for _, task := range plan.SubTasks {
		wg.Add(1)
		go func(t SubTask) {
			defer wg.Done()

			workerPrompt := fmt.Sprintf("Execute this task: %s\nInput Data:\n%s", t.Description, t.InputData)

			var result string
			var err error

			// Round-robin selection of executor model
			executorModel := to.executorModels[t.ID%len(to.executorModels)]

			for attempt := 0; attempt <= maxRetries; attempt++ {
				if attempt > 0 {
					log.Printf("Orchestrator: Retrying sub-task %d (attempt %d/%d) after delay...", t.ID, attempt+1, maxRetries+1)
					time.Sleep(retryDelay)
				}

				// Target a fast, efficient model for execution.
				result, err = to.delegator.GenerateSimple(ctx, executorModel, workerPrompt, "")
				if err == nil {
					break // Success, exit retry loop
				}
				log.Printf("Orchestrator: Sub-task %d attempt %d failed: %v", t.ID, attempt+1, err)
			}

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// After all retries, record the final error.
				errorMessages = append(errorMessages, fmt.Sprintf("sub-task %d failed after %d attempts: %v", t.ID, maxRetries+1, err))
				results[t.ID] = fmt.Sprintf("ERROR: %v", err)
			} else {
				results[t.ID] = result
			}
		}(task)
	}

	wg.Wait()

	if len(errorMessages) > 0 {
		return results, errors.New(strings.Join(errorMessages, "; "))
	}
	return results, nil
}

// finalizeResults synthesizes the sub-task results into a final response.
func (to *TaskOrchestrator) finalizeResults(ctx context.Context, originalPrompt string, subTaskResults map[int]string) (string, error) {
	resultsJSON, _ := json.MarshalIndent(subTaskResults, "", "  ")

	finalizerPrompt := fmt.Sprintf(`
You are a final review AI. Your job is to synthesize the results of several sub-tasks into a single, coherent, and high-quality final response that directly addresses the user's original request.

Original Request: "%s"

Sub-task Results (JSON format, with task ID as key):
%s

Synthesize these results into a complete and final answer. If the original request was for code or a patch, generate the final, clean code.
`, originalPrompt, string(resultsJSON))

	// Target a powerful model for the final synthesis/remediation.
	finalResponse, err := to.delegator.GenerateSimple(ctx, to.finalizerModel, finalizerPrompt, "")
	if err != nil {
		return "", err
	}

	return finalResponse, nil
}

// verifyFinalOutput uses a verifier model to check the quality and correctness of the final response.
func (to *TaskOrchestrator) verifyFinalOutput(ctx context.Context, originalPrompt string, finalResponse string) (string, error) {
	log.Println("Orchestrator: Starting verification of final output...")

	verifierPrompt := fmt.Sprintf(`
You are a quality assurance AI. Your task is to verify if the provided "Final Response" correctly and completely addresses the "Original Request".

Check for the following:
1.  **Correctness**: Is the response factually correct and logical?
2.  **Completeness**: Does the response address all parts of the original request?
3.  **Formatting**: If the request asked for code or a patch, is the format correct?

Original Request:
"%s"

Final Response to Verify:
"%s"

Based on your analysis, respond with a single JSON object with two keys:
- "status": "pass" or "fail".
- "feedback": A brief explanation for your decision.
`, originalPrompt, finalResponse)

	// Target a powerful model for verification.
	verificationJSON, err := to.delegator.GenerateSimple(ctx, to.verifierModel, verifierPrompt, "")
	return verificationJSON, err
}
