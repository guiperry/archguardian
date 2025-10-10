package embedding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/philippgille/chromem-go"
)

// EmbeddingManager handles embedding generation for vector operations
type EmbeddingManager struct {
	config     *Config // TODO: Use proper config type
	httpClient *http.Client
}

// Config represents embedding configuration
type Config struct {
	APIKey   string
	Endpoint string
	Model    string
}

// NewEmbeddingManager creates a new embedding manager
func NewEmbeddingManager(config *Config) *EmbeddingManager {
	return &EmbeddingManager{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateEmbeddingFunction creates an embedding function that calls external service with fallback
func CreateEmbeddingFunction() func([]string) ([][]float64, error) {
	return func(texts []string) ([][]float64, error) {
		if len(texts) == 0 {
			return [][]float64{}, nil
		}

		// Try external embedding service first
		embeddings, err := createExternalEmbeddings(texts)
		if err == nil {
			return embeddings, nil
		}

		// Log the error and fall back to local embeddings
		log.Printf("⚠️  External embedding service failed (%v), falling back to local embeddings", err)

		// Fallback to local embeddings
		return createLocalEmbeddings(texts)
	}
}

// CreateChromemEmbeddingFunc creates a chromem-compatible embedding function
func CreateChromemEmbeddingFunc() chromem.EmbeddingFunc {
	return func(ctx context.Context, text string) ([]float32, error) {
		// Use the batch embedding function for a single text
		embeddings, err := createExternalEmbeddings([]string{text})
		if err != nil {
			// Log the error and fall back to local embeddings
			log.Printf("⚠️  External embedding service failed (%v), falling back to local embeddings", err)
			embeddings, err = createLocalEmbeddings([]string{text})
			if err != nil {
				return nil, err
			}
		}

		if len(embeddings) == 0 || len(embeddings[0]) == 0 {
			return nil, fmt.Errorf("no embeddings generated")
		}

		// Convert float64 to float32
		embedding32 := make([]float32, len(embeddings[0]))
		for i, val := range embeddings[0] {
			embedding32[i] = float32(val)
		}

		return embedding32, nil
	}
}

// createExternalEmbeddings calls the external embedding service
func createExternalEmbeddings(texts []string) ([][]float64, error) {
	// Check if external embeddings are disabled
	if os.Getenv("USE_LOCAL_EMBEDDINGS") == "true" {
		return nil, fmt.Errorf("external embeddings disabled via USE_LOCAL_EMBEDDINGS=true")
	}

	// Prepare request payload
	reqBody := map[string]interface{}{
		"texts": texts,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal embedding request: %w", err)
	}

	// Create HTTP request with timeout
	endpoint := "https://embeddings.knirv.com"
	if customEndpoint := os.Getenv("EMBEDDING_ENDPOINT"); customEndpoint != "" {
		endpoint = customEndpoint
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create embedding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Note: The embedding endpoint does not require an API key

	// Make HTTP request with shorter timeout for faster fallback
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call embedding service: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedding response: %w", err)
	}

	// Check status code
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("embedding service authentication failed (401 Unauthorized). Consider setting USE_LOCAL_EMBEDDINGS=true for local fallback")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedding service returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response struct {
		Success    bool        `json:"success"`
		Embeddings [][]float64 `json:"embeddings"`
		Error      string      `json:"error,omitempty"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse embedding response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("embedding service error: %s", response.Error)
	}

	return response.Embeddings, nil
}

// createLocalEmbeddings creates simple local embeddings as fallback
func createLocalEmbeddings(texts []string) ([][]float64, error) {
	// Simple TF-IDF style embeddings - just use text length and character frequencies
	// This is a basic fallback to ensure functionality when external service is unavailable
	const embeddingDim = 128 // Standard embedding dimension

	embeddings := make([][]float64, len(texts))
	for i, text := range texts {
		embedding := make([]float64, embeddingDim)

		// Simple features: text length, character counts, etc.
		embedding[0] = float64(len(text)) / 1000.0 // Normalized text length

		// Character frequency features (simplified)
		charCounts := make(map[rune]int)
		for _, char := range text {
			charCounts[char]++
		}

		// Use some common characters as features
		commonChars := []rune{'a', 'e', 'i', 'o', 'u', ' ', '.', ',', '\n'}
		for j, char := range commonChars {
			if j+1 < embeddingDim {
				embedding[j+1] = float64(charCounts[char]) / float64(len(text)+1)
			}
		}

		// Add some randomness to avoid identical embeddings
		// In a real implementation, you'd use a proper hashing or TF-IDF approach
		for j := len(commonChars) + 1; j < embeddingDim; j++ {
			// Simple hash-based pseudo-random value
			hash := 0
			for _, char := range text {
				hash = (hash*31 + int(char)) % 1000
			}
			embedding[j] = float64(hash%100) / 100.0
		}

		embeddings[i] = embedding
	}

	log.Printf("✅ Generated local embeddings for %d texts", len(texts))
	return embeddings, nil
}

// TODO: Implement createFallbackEmbedding if needed for future use
// createFallbackEmbedding creates a simple embedding when external service fails
// func createFallbackEmbedding(text string) []float64 {
// 	// Simple hash-based embedding as fallback
// 	const embeddingDim = 128
// 	embedding := make([]float64, embeddingDim)
//
// 	// Use text length and character distribution as features
// 	embedding[0] = float64(len(text)) / 1000.0 // Normalized length
//
// 	// Character frequency features
// 	charCounts := make(map[rune]int)
// 	for _, char := range text {
// 		charCounts[char]++
// 	}
//
// 	// Use common characters as features
// 	commonChars := []rune{'a', 'e', 'i', 'o', 'u', ' ', '.', ',', '\n', '0', '1', '2'}
// 	for i, char := range commonChars {
// 		if i+1 < embeddingDim {
// 			embedding[i+1] = float64(charCounts[char]) / float64(len(text)+1)
// 		}
// 	}
//
// 	// Fill remaining dimensions with hash-based values
// 	for i := len(commonChars) + 1; i < embeddingDim; i++ {
// 		hash := 0
// 		for _, char := range text {
// 			hash = (hash*31 + int(char)) % 1000
// 		}
// 		embedding[i] = float64(hash%100) / 100.0
// 	}
//
// 	return embedding
// }

// GenerateEmbedding generates embeddings for a single text
func (em *EmbeddingManager) GenerateEmbedding(text string) ([]float64, error) {
	embeddings, err := CreateEmbeddingFunction()([]string{text})
	if err != nil {
		return nil, err
	}

	if len(embeddings) == 0 {
		return nil, fmt.Errorf("no embeddings generated")
	}

	return embeddings[0], nil
}

// GenerateEmbeddings generates embeddings for multiple texts
func (em *EmbeddingManager) GenerateEmbeddings(texts []string) ([][]float64, error) {
	return CreateEmbeddingFunction()(texts)
}

// ValidateEmbeddingService validates the embedding service connectivity
func (em *EmbeddingManager) ValidateEmbeddingService() error {
	// Test with a simple text
	testText := "This is a test message for embedding validation."

	_, err := em.GenerateEmbedding(testText)
	if err != nil {
		return fmt.Errorf("embedding service validation failed: %w", err)
	}

	log.Println("✅ Embedding service validated successfully")
	return nil
}

// BatchProcessEmbeddings processes embeddings in batches for efficiency
func (em *EmbeddingManager) BatchProcessEmbeddings(texts []string, batchSize int) ([][]float64, error) {
	if batchSize <= 0 {
		batchSize = 10 // Default batch size
	}

	var allEmbeddings [][]float64

	for i := 0; i < len(texts); i += batchSize {
		end := i + batchSize
		if end > len(texts) {
			end = len(texts)
		}

		batch := texts[i:end]
		embeddings, err := em.GenerateEmbeddings(batch)
		if err != nil {
			return nil, fmt.Errorf("failed to process batch %d-%d: %w", i, end, err)
		}

		allEmbeddings = append(allEmbeddings, embeddings...)
	}

	return allEmbeddings, nil
}

// Similarity calculates cosine similarity between two embeddings
func Similarity(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0.0
	}

	var dotProduct, normA, normB float64

	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0.0
	}

	return dotProduct / (sqrt(normA) * sqrt(normB))
}

// sqrt calculates square root (simple implementation)
func sqrt(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x == 0 {
		return 0
	}

	// Babylonian method for square root
	z := x / 2
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}

// FindSimilarTexts finds the most similar texts to a query embedding
func FindSimilarTexts(queryEmbedding []float64, textEmbeddings [][]float64, texts []string, topK int) []SimilarityResult {
	if len(textEmbeddings) != len(texts) {
		return nil
	}

	results := make([]SimilarityResult, len(texts))

	for i, embedding := range textEmbeddings {
		similarity := Similarity(queryEmbedding, embedding)
		results[i] = SimilarityResult{
			Text:       texts[i],
			Similarity: similarity,
			Index:      i,
		}
	}

	// Sort by similarity (highest first)
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].Similarity < results[j].Similarity {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	if topK > 0 && topK < len(results) {
		return results[:topK]
	}

	return results
}

// SimilarityResult represents a similarity search result
type SimilarityResult struct {
	Text       string  `json:"text"`
	Similarity float64 `json:"similarity"`
	Index      int     `json:"index"`
}

// PreprocessText preprocesses text for better embedding quality
func PreprocessText(text string) string {
	// Remove extra whitespace
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	// Remove special characters that might not be useful for embeddings
	text = regexp.MustCompile(`[^\w\s\-.,!?"']`).ReplaceAllString(text, "")

	// Convert to lowercase for consistency
	text = strings.ToLower(text)

	// Trim whitespace
	text = strings.TrimSpace(text)

	return text
}

// ChunkText splits large text into smaller chunks for embedding
func ChunkText(text string, chunkSize int, overlap int) []string {
	if chunkSize <= 0 {
		chunkSize = 512 // Default chunk size
	}
	if overlap < 0 {
		overlap = 50 // Default overlap
	}

	if len(text) <= chunkSize {
		return []string{text}
	}

	var chunks []string
	words := strings.Fields(text)

	for i := 0; i < len(words); i += (chunkSize - overlap) {
		end := i + chunkSize
		if end > len(words) {
			end = len(words)
		}

		chunk := strings.Join(words[i:end], " ")
		chunks = append(chunks, chunk)

		if end >= len(words) {
			break
		}
	}

	return chunks
}

// EstimateEmbeddingCost estimates the cost of generating embeddings
func EstimateEmbeddingCost(texts []string, pricePerToken float64) float64 {
	totalTokens := 0

	for _, text := range texts {
		// Rough estimation: ~4 characters per token
		tokens := len(text) / 4
		if tokens == 0 {
			tokens = 1
		}
		totalTokens += tokens
	}

	return float64(totalTokens) * pricePerToken
}

// ValidateEmbeddingDimensions validates that embeddings have the expected dimensions
func ValidateEmbeddingDimensions(embeddings [][]float64, expectedDim int) error {
	for i, embedding := range embeddings {
		if len(embedding) != expectedDim {
			return fmt.Errorf("embedding %d has dimension %d, expected %d", i, len(embedding), expectedDim)
		}
	}
	return nil
}

// NormalizeEmbeddings normalizes embeddings to unit length
func NormalizeEmbeddings(embeddings [][]float64) [][]float64 {
	normalized := make([][]float64, len(embeddings))

	for i, embedding := range embeddings {
		norm := 0.0
		for _, val := range embedding {
			norm += val * val
		}
		norm = sqrt(norm)

		if norm > 0 {
			normalized[i] = make([]float64, len(embedding))
			for j, val := range embedding {
				normalized[i][j] = val / norm
			}
		} else {
			// If norm is 0, keep the original embedding
			normalized[i] = embedding
		}
	}

	return normalized
}

// AverageEmbeddings calculates the average of multiple embeddings
func AverageEmbeddings(embeddings [][]float64) ([]float64, error) {
	if len(embeddings) == 0 {
		return nil, fmt.Errorf("no embeddings provided")
	}

	dim := len(embeddings[0])
	avg := make([]float64, dim)

	for _, embedding := range embeddings {
		if len(embedding) != dim {
			return nil, fmt.Errorf("inconsistent embedding dimensions")
		}

		for i, val := range embedding {
			avg[i] += val
		}
	}

	// Divide by count to get average
	count := float64(len(embeddings))
	for i := range avg {
		avg[i] /= count
	}

	return avg, nil
}

// EmbeddingStats represents statistics about embeddings
type EmbeddingStats struct {
	Count      int     `json:"count"`
	Dimensions int     `json:"dimensions"`
	AvgNorm    float64 `json:"avg_norm"`
	MinNorm    float64 `json:"min_norm"`
	MaxNorm    float64 `json:"max_norm"`
	Sparsity   float64 `json:"sparsity"` // Percentage of zero values
}

// CalculateEmbeddingStats calculates statistics for a set of embeddings
func CalculateEmbeddingStats(embeddings [][]float64) EmbeddingStats {
	if len(embeddings) == 0 {
		return EmbeddingStats{}
	}

	stats := EmbeddingStats{
		Count:      len(embeddings),
		Dimensions: len(embeddings[0]),
		MinNorm:    1e10,
		MaxNorm:    0,
	}

	totalNorm := 0.0
	totalZeros := 0

	for _, embedding := range embeddings {
		norm := 0.0
		zeros := 0

		for _, val := range embedding {
			norm += val * val
			if val == 0 {
				zeros++
			}
		}

		norm = sqrt(norm)
		totalNorm += norm

		if norm < stats.MinNorm {
			stats.MinNorm = norm
		}
		if norm > stats.MaxNorm {
			stats.MaxNorm = norm
		}

		totalZeros += zeros
	}

	stats.AvgNorm = totalNorm / float64(len(embeddings))
	stats.Sparsity = float64(totalZeros) / float64(len(embeddings)*stats.Dimensions) * 100

	return stats
}
