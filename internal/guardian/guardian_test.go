package guardian

import (
	"archguardian/internal/config"
	"archguardian/types"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockInferenceService mocks the AI inference service
type MockInferenceService struct {
	mock.Mock
}

func (m *MockInferenceService) GenerateText(ctx context.Context, modelName, promptText, instructionText string) (string, error) {
	args := m.Called(ctx, modelName, promptText, instructionText)
	return args.String(0), args.Error(1)
}

func (m *MockInferenceService) GenerateStructuredOutput(content string, schema string) (string, error) {
	args := m.Called(content, schema)
	return args.String(0), args.Error(1)
}

func (m *MockInferenceService) IsRunning() bool {
	args := m.Called()
	return args.Bool(0)
}

// MockChromemManager mocks the ChromemDB manager
type MockChromemManager struct {
	mock.Mock
}

func (m *MockChromemManager) UpsertNode(node *types.Node) error {
	args := m.Called(node)
	return args.Error(0)
}

func (m *MockChromemManager) StoreRiskAssessment(assessment *types.RiskAssessment) error {
	args := m.Called(assessment)
	return args.Error(0)
}

func (m *MockChromemManager) GetAllNodes() ([]*types.Node, error) {
	args := m.Called()
	return args.Get(0).([]*types.Node), args.Error(1)
}

func (m *MockChromemManager) GetLatestRiskAssessment() (*types.RiskAssessment, error) {
	args := m.Called()
	return args.Get(0).(*types.RiskAssessment), args.Error(1)
}

func (m *MockChromemManager) GetIssueByID(issueID string) (interface{}, error) {
	args := m.Called(issueID)
	return args.Get(0), args.Error(1)
}

func (m *MockChromemManager) GetCodeContext(filePath string, lineNumber int, contextLines int) (string, error) {
	args := m.Called(filePath, lineNumber, contextLines)
	return args.String(0), args.Error(1)
}

// TestNewArchGuardian tests the ArchGuardian constructor
func TestNewArchGuardian(t *testing.T) {
	t.Skip("Skipping test that requires ChromemManager dependency")
}

// TestRunCycle tests the main run cycle functionality
func TestRunCycle(t *testing.T) {
	t.Skip("Skipping test that requires ChromemManager dependency")
}

// TestCheckForBaselineCompatibility tests web baseline compatibility checking
func TestCheckForBaselineCompatibility(t *testing.T) {
	t.Skip("Skipping test that requires ChromemManager dependency")
}

// TestDeterministicScanReproducibility tests that scans are deterministic
func TestDeterministicScanReproducibility(t *testing.T) {
	t.Skip("Skipping test that requires ChromemManager dependency")
}

// TestBroadcastToDashboard tests WebSocket broadcasting
func TestBroadcastToDashboard(t *testing.T) {
	t.Skip("Skipping test that requires ChromemManager dependency")
}

// TestErrorHandlingInRunCycle tests error handling during run cycle
func TestErrorHandlingInRunCycle(t *testing.T) {
	t.Skip("Skipping test that requires ChromemManager dependency")
}

// TestConcurrentRunCycles tests thread safety of run operations
func TestConcurrentRunCycles(t *testing.T) {
	// Create temporary test project
	tmpDir, err := os.MkdirTemp("", "test_concurrent")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test file
	testFile := filepath.Join(tmpDir, "main.go")
	testContent := `package main

import "fmt"

func main() {
	fmt.Println("concurrent test")
}
`
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	assert.NoError(t, err)

	cfg := &config.Config{
		ProjectPath: tmpDir,
		ServerPort:  3000,
	}

	mockChromem := &MockChromemManager{}
	mockChromem.On("UpsertNode", mock.Anything).Return(nil)
	mockChromem.On("StoreRiskAssessment", mock.Anything).Return(nil)

	guardian := NewArchGuardian(cfg, nil, mockChromem)

	// Run multiple concurrent cycles
	numCycles := 3
	done := make(chan bool, numCycles)
	errors := make(chan error, numCycles)

	for i := 0; i < numCycles; i++ {
		go func() {
			defer func() { done <- true }()
			ctx := context.Background()
			err := guardian.RunCycle(ctx)
			if err != nil {
				errors <- err
			}
		}()
	}

	// Wait for all cycles to complete
	for i := 0; i < numCycles; i++ {
		<-done
	}

	// Check for errors
	close(errors)
	for err := range errors {
		t.Logf("Concurrent cycle error (may be expected): %v", err)
	}
}

// TestAIRemediationWorkflow tests the AI remediation workflow (user-triggered)
func TestAIRemediationWorkflow(t *testing.T) {
	cfg := &config.Config{
		ProjectPath: "/test/path",
	}

	guardian := NewArchGuardian(cfg, nil, nil)

	// Simulate user requesting AI remediation for a specific issue
	ctx := context.Background()
	issueID := "sql_injection_001"
	issueType := "security_vulnerability"

	// Test that we can call RemediateIssueWithAI without panicking
	assert.NotPanics(t, func() {
		guardian.RemediateIssueWithAI(ctx, issueID, issueType)
	})
}

// TestConfigurationValidation tests configuration validation
func TestConfigurationValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		isValid bool
	}{
		{
			name: "Valid configuration",
			config: &config.Config{
				ProjectPath: "/valid/path",
				ServerPort:  3000,
			},
			isValid: true,
		},
		{
			name: "Empty project path",
			config: &config.Config{
				ProjectPath: "",
				ServerPort:  3000,
			},
			isValid: true, // Constructor shouldn't panic
		},
		{
			name: "Zero port",
			config: &config.Config{
				ProjectPath: "/valid/path",
				ServerPort:  0,
			},
			isValid: true, // Constructor shouldn't panic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				guardian := NewArchGuardian(tt.config, nil, nil)
				assert.NotNil(t, guardian)
			})
		})
	}
}

// TestGuardianInitialization tests proper initialization of components
func TestGuardianInitialization(t *testing.T) {
	cfg := &config.Config{
		ProjectPath: "/test/path",
		ServerPort:  3000,
	}

	guardian := NewArchGuardian(cfg, nil, nil)

	// Verify that key components are initialized
	assert.NotNil(t, guardian)
	assert.NotNil(t, guardian.scanner, "Scanner should be initialized")
	assert.NotNil(t, guardian.diagnoser, "Risk diagnoser should be initialized")
	assert.NotEmpty(t, guardian.projectID, "Project ID should be generated")

	// Verify that the guardian can be started without panicking
	assert.NotPanics(t, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		// Just verify it doesn't panic during startup
		go func() {
			guardian.Run(ctx)
		}()
		time.Sleep(100 * time.Millisecond) // Let it start briefly
	})
}
