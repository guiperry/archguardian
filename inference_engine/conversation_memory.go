package inference_engine

import (
	"log"
	"sync"

	gollm_types "github.com/guiperry/gollm_cerebras/types"
)

// ConversationMemory defines the interface for managing conversation history.
type ConversationMemory interface {
	// AddMessage adds a message to the conversation history.
	AddMessage(message gollm_types.MemoryMessage)
	// GetMessagesForContext retrieves messages relevant to the current context,
	// respecting a maximum token limit.
	GetMessagesForContext(maxTokens int, modelName string) []gollm_types.MemoryMessage
	// Clear removes all messages from the history.
	Clear()
	// GetHistory returns all messages in the history (for inspection).
	GetHistory() []gollm_types.MemoryMessage
}

// SimpleWindowMemory implements ConversationMemory using a simple sliding window
// based on estimated token count.
type SimpleWindowMemory struct {
	messages         []gollm_types.MemoryMessage
	defaultModelName string // Used if no specific model is provided to GetMessagesForContext
	mu               sync.RWMutex
}

// NewSimpleWindowMemory creates a new SimpleWindowMemory.
func NewSimpleWindowMemory(defaultModelName string) *SimpleWindowMemory {
	return &SimpleWindowMemory{
		messages:         make([]gollm_types.MemoryMessage, 0),
		defaultModelName: defaultModelName,
	}
}

// AddMessage adds a message to the end of the history.
func (m *SimpleWindowMemory) AddMessage(message gollm_types.MemoryMessage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, message)
	log.Printf("SimpleWindowMemory: Added message (Role: %s). Total messages: %d", message.Role, len(m.messages))
}

// GetMessagesForContext returns the most recent messages that fit within maxTokens.
// modelName parameter specifies the model to use for token estimation for this context.
func (m *SimpleWindowMemory) GetMessagesForContext(maxTokens int, modelName string) []gollm_types.MemoryMessage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var currentTokens int
	var contextMessages []gollm_types.MemoryMessage

	estimationModel := m.defaultModelName
	if modelName != "" {
		estimationModel = modelName
	}
	// Iterate backwards from the most recent message
	for i := len(m.messages) - 1; i >= 0; i-- {
		msg := m.messages[i]
		msgTokens := estimateTokens(msg.Content, estimationModel) // Use specified or default model for token counting

		if currentTokens+msgTokens <= maxTokens {
			// Prepend the message to maintain chronological order in the result
			contextMessages = append([]gollm_types.MemoryMessage{msg}, contextMessages...)
			currentTokens += msgTokens
		} else {
			// Stop if adding the next message exceeds the token limit
			log.Printf("SimpleWindowMemory: Token limit (%d) reached. Returning %d messages (%d tokens).", maxTokens, len(contextMessages), currentTokens)
			break
		}
	}
	return contextMessages
}

// Clear removes all messages.
func (m *SimpleWindowMemory) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = make([]gollm_types.MemoryMessage, 0)
	log.Println("SimpleWindowMemory: History cleared.")
}

// GetHistory returns a copy of all messages.
func (m *SimpleWindowMemory) GetHistory() []gollm_types.MemoryMessage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return a copy to prevent external modification
	historyCopy := make([]gollm_types.MemoryMessage, len(m.messages))
	copy(historyCopy, m.messages)
	return historyCopy
}

// Compile-time check to ensure SimpleWindowMemory implements ConversationMemory
var _ ConversationMemory = (*SimpleWindowMemory)(nil)
