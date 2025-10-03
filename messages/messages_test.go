package messages

import (
	"archguardian/types"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAlertLevel_String(t *testing.T) {
	testCases := []struct {
		level    AlertLevel
		expected string
	}{
		{InfoAlert, "INFO"},
		{WarningAlert, "WARNING"},
		{ErrorAlert, "ERROR"},
		{CriticalAlert, "CRITICAL"},
		{AlertLevel(999), "UNKNOWN"}, // Test unknown level
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.level.String())
		})
	}
}

func TestTickMsg(t *testing.T) {
	now := time.Now()
	tick := TickMsg(now)

	// Convert back to time.Time and verify
	tickTime := time.Time(tick)
	assert.Equal(t, now.Unix(), tickTime.Unix())
}

func TestScanCompleteMsg(t *testing.T) {
	kg := &types.KnowledgeGraph{
		Nodes:         map[string]*types.Node{},
		Edges:         []*types.Edge{},
		LastUpdated:   time.Now(),
		AnalysisDepth: 1,
	}

	ra := &types.RiskAssessment{
		TechnicalDebt:         []types.TechnicalDebtItem{},
		SecurityVulns:         []types.SecurityVulnerability{},
		ObsoleteCode:          []types.ObsoleteCodeItem{},
		DangerousDependencies: []types.DependencyRisk{},
		OverallScore:          50.0,
		Timestamp:             time.Now(),
	}

	msg := ScanCompleteMsg{
		KnowledgeGraph: kg,
		RiskAssessment: ra,
		Timestamp:      time.Now(),
	}

	assert.NotNil(t, msg.KnowledgeGraph)
	assert.NotNil(t, msg.RiskAssessment)
	assert.Equal(t, 50.0, msg.RiskAssessment.OverallScore)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestRemediationCompleteMsg(t *testing.T) {
	msg := RemediationCompleteMsg{
		BranchName:       "archguardian-fixes-123",
		RemediationCount: 5,
		CommitURL:        "https://github.com/example/repo/commit/abc123",
		Timestamp:        time.Now(),
	}

	assert.Equal(t, "archguardian-fixes-123", msg.BranchName)
	assert.Equal(t, 5, msg.RemediationCount)
	assert.Contains(t, msg.CommitURL, "github.com")
	assert.False(t, msg.Timestamp.IsZero())
}

func TestMetricsUpdateMsg(t *testing.T) {
	msg := MetricsUpdateMsg{
		CPUUsage:    75.5,
		MemoryUsage: 80.2,
		DiskUsage:   45.0,
		Timestamp:   time.Now(),
	}

	assert.Equal(t, 75.5, msg.CPUUsage)
	assert.Equal(t, 80.2, msg.MemoryUsage)
	assert.Equal(t, 45.0, msg.DiskUsage)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestAlertMsg(t *testing.T) {
	testCases := []struct {
		name    string
		level   AlertLevel
		title   string
		message string
	}{
		{"Info Alert", InfoAlert, "System Started", "ArchGuardian is now running"},
		{"Warning Alert", WarningAlert, "High CPU Usage", "CPU usage is above 90%"},
		{"Error Alert", ErrorAlert, "Scan Failed", "Unable to complete security scan"},
		{"Critical Alert", CriticalAlert, "System Down", "Critical component failure"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := AlertMsg{
				Level:     tc.level,
				Title:     tc.title,
				Message:   tc.message,
				Timestamp: time.Now(),
			}

			assert.Equal(t, tc.level, msg.Level)
			assert.Equal(t, tc.title, msg.Title)
			assert.Equal(t, tc.message, msg.Message)
			assert.False(t, msg.Timestamp.IsZero())
		})
	}
}

func TestCommandMsg(t *testing.T) {
	msg := CommandMsg{
		Command:   "git",
		Args:      []string{"status", "--porcelain"},
		Timestamp: time.Now(),
	}

	assert.Equal(t, "git", msg.Command)
	assert.Equal(t, []string{"status", "--porcelain"}, msg.Args)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestCommandResultMsg(t *testing.T) {
	testError := errors.New("command failed")

	msg := CommandResultMsg{
		Command:   "npm install",
		Output:    "installed 50 packages",
		Error:     testError,
		Timestamp: time.Now(),
	}

	assert.Equal(t, "npm install", msg.Command)
	assert.Equal(t, "installed 50 packages", msg.Output)
	assert.Equal(t, testError, msg.Error)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestStatusUpdateMsg(t *testing.T) {
	msg := StatusUpdateMsg{
		Component: "scanner",
		Status:    "running",
		Message:   "Scanning dependencies",
		Timestamp: time.Now(),
	}

	assert.Equal(t, "scanner", msg.Component)
	assert.Equal(t, "running", msg.Status)
	assert.Equal(t, "Scanning dependencies", msg.Message)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestErrorMsg(t *testing.T) {
	testError := errors.New("database connection failed")
	context := map[string]interface{}{
		"host": "localhost",
		"port": 5432,
	}

	msg := ErrorMsg{
		Component: "database",
		Error:     testError,
		Context:   context,
		Timestamp: time.Now(),
	}

	assert.Equal(t, "database", msg.Component)
	assert.Equal(t, testError, msg.Error)
	assert.Equal(t, context, msg.Context)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestSuccessMsg(t *testing.T) {
	details := map[string]interface{}{
		"files_scanned": 150,
		"duration":      "2.5s",
	}

	msg := SuccessMsg{
		Component: "scanner",
		Message:   "Scan completed successfully",
		Details:   details,
		Timestamp: time.Now(),
	}

	assert.Equal(t, "scanner", msg.Component)
	assert.Equal(t, "Scan completed successfully", msg.Message)
	assert.Equal(t, details, msg.Details)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestInitCompleteMsg(t *testing.T) {
	msg := InitCompleteMsg{
		Component: "inference_engine",
		Timestamp: time.Now(),
	}

	assert.Equal(t, "inference_engine", msg.Component)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestShutdownMsg(t *testing.T) {
	msg := ShutdownMsg{
		Reason:    "User requested shutdown",
		Timestamp: time.Now(),
	}

	assert.Equal(t, "User requested shutdown", msg.Reason)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestResizeMsg(t *testing.T) {
	msg := ResizeMsg{
		Width:  1920,
		Height: 1080,
	}

	assert.Equal(t, 1920, msg.Width)
	assert.Equal(t, 1080, msg.Height)
}

func TestLogMsg(t *testing.T) {
	fields := map[string]interface{}{
		"user_id": "12345",
		"action":  "login",
	}

	msg := LogMsg{
		Level:     "INFO",
		Component: "auth",
		Message:   "User logged in successfully",
		Fields:    fields,
		Timestamp: time.Now(),
	}

	assert.Equal(t, "INFO", msg.Level)
	assert.Equal(t, "auth", msg.Component)
	assert.Equal(t, "User logged in successfully", msg.Message)
	assert.Equal(t, fields, msg.Fields)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestHealthCheckMsg(t *testing.T) {
	details := map[string]interface{}{
		"cpu_usage":    25.5,
		"memory_usage": 60.0,
	}

	msg := HealthCheckMsg{
		Component: "system",
		Healthy:   true,
		Details:   details,
		Timestamp: time.Now(),
	}

	assert.Equal(t, "system", msg.Component)
	assert.True(t, msg.Healthy)
	assert.Equal(t, details, msg.Details)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestPerformanceMsg(t *testing.T) {
	msg := PerformanceMsg{
		Component: "scanner",
		Metric:    "scan_duration",
		Value:     2.5,
		Unit:      "seconds",
		Timestamp: time.Now(),
	}

	assert.Equal(t, "scanner", msg.Component)
	assert.Equal(t, "scan_duration", msg.Metric)
	assert.Equal(t, 2.5, msg.Value)
	assert.Equal(t, "seconds", msg.Unit)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestSecurityMsg(t *testing.T) {
	details := map[string]interface{}{
		"source_ip": "192.168.1.100",
		"attempts":  3,
	}

	msg := SecurityMsg{
		EventType: "failed_login",
		Severity:  "high",
		Details:   details,
		Timestamp: time.Now(),
	}

	assert.Equal(t, "failed_login", msg.EventType)
	assert.Equal(t, "high", msg.Severity)
	assert.Equal(t, details, msg.Details)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestBackupMsg(t *testing.T) {
	backupError := errors.New("insufficient disk space")

	testCases := []struct {
		name    string
		msgType string
		path    string
		size    int64
		err     error
	}{
		{"Successful Backup", "completed", "/backup/data.tar.gz", 1024000, nil},
		{"Failed Backup", "failed", "/backup/data.tar.gz", 0, backupError},
		{"Started Backup", "started", "/backup/data.tar.gz", 0, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := BackupMsg{
				Type:      tc.msgType,
				Path:      tc.path,
				Size:      tc.size,
				Error:     tc.err,
				Timestamp: time.Now(),
			}

			assert.Equal(t, tc.msgType, msg.Type)
			assert.Equal(t, tc.path, msg.Path)
			assert.Equal(t, tc.size, msg.Size)
			assert.Equal(t, tc.err, msg.Error)
			assert.False(t, msg.Timestamp.IsZero())
		})
	}
}

func TestUpdateMsg(t *testing.T) {
	updateError := errors.New("download failed")

	testCases := []struct {
		name     string
		msgType  string
		version  string
		progress float64
		err      error
	}{
		{"Update Available", "available", "v1.2.0", 0.0, nil},
		{"Downloading", "downloading", "v1.2.0", 45.5, nil},
		{"Installing", "installing", "v1.2.0", 90.0, nil},
		{"Completed", "completed", "v1.2.0", 100.0, nil},
		{"Failed", "failed", "v1.2.0", 25.0, updateError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := UpdateMsg{
				Type:      tc.msgType,
				Version:   tc.version,
				Progress:  tc.progress,
				Error:     tc.err,
				Timestamp: time.Now(),
			}

			assert.Equal(t, tc.msgType, msg.Type)
			assert.Equal(t, tc.version, msg.Version)
			assert.Equal(t, tc.progress, msg.Progress)
			assert.Equal(t, tc.err, msg.Error)
			assert.False(t, msg.Timestamp.IsZero())
		})
	}
}

// Benchmark tests for message creation
func BenchmarkAlertMsgCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = AlertMsg{
			Level:     ErrorAlert,
			Title:     "Test Alert",
			Message:   "This is a test alert message",
			Timestamp: time.Now(),
		}
	}
}

func BenchmarkLogMsgCreation(b *testing.B) {
	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	for i := 0; i < b.N; i++ {
		_ = LogMsg{
			Level:     "INFO",
			Component: "test",
			Message:   "Test log message",
			Fields:    fields,
			Timestamp: time.Now(),
		}
	}
}
