package messages

import (
	"archguardian/types"
	"time"
)

// TickMsg represents a periodic tick message, useful for UI updates.
type TickMsg time.Time

// ScanCompleteMsg is sent when a full scan and analysis cycle is complete.
type ScanCompleteMsg struct {
	KnowledgeGraph *types.KnowledgeGraph
	RiskAssessment *types.RiskAssessment
	Timestamp      time.Time
}

// RemediationCompleteMsg is sent when an automated remediation attempt is finished.
type RemediationCompleteMsg struct {
	BranchName       string
	RemediationCount int
	CommitURL        string // URL to the commit or pull request
	Timestamp        time.Time
}

// MetricsUpdateMsg represents system metrics updates
type MetricsUpdateMsg struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
	Timestamp   time.Time
}

// AlertMsg represents system alerts
type AlertMsg struct {
	Level     AlertLevel
	Title     string
	Message   string
	Timestamp time.Time
}

// AlertLevel represents the severity of an alert
type AlertLevel int

const (
	InfoAlert AlertLevel = iota
	WarningAlert
	ErrorAlert
	CriticalAlert
)

// String returns the string representation of AlertLevel
func (a AlertLevel) String() string {
	switch a {
	case InfoAlert:
		return "INFO"
	case WarningAlert:
		return "WARNING"
	case ErrorAlert:
		return "ERROR"
	case CriticalAlert:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// CommandMsg represents terminal command messages
type CommandMsg struct {
	Command   string
	Args      []string
	Timestamp time.Time
}

// CommandResultMsg represents the result of a terminal command
type CommandResultMsg struct {
	Command   string
	Output    string
	Error     error
	Timestamp time.Time
}

// StatusUpdateMsg represents general status updates
type StatusUpdateMsg struct {
	Component string
	Status    string
	Message   string
	Timestamp time.Time
}

// ErrorMsg represents error messages
type ErrorMsg struct {
	Component string
	Error     error
	Context   map[string]interface{}
	Timestamp time.Time
}

// SuccessMsg represents success messages
type SuccessMsg struct {
	Component string
	Message   string
	Details   map[string]interface{}
	Timestamp time.Time
}

// InitCompleteMsg indicates that initialization is complete
type InitCompleteMsg struct {
	Component string
	Timestamp time.Time
}

// ShutdownMsg represents shutdown messages
type ShutdownMsg struct {
	Reason    string
	Timestamp time.Time
}

// ResizeMsg represents window resize messages, useful for a TUI or responsive web UI.
type ResizeMsg struct {
	Width  int
	Height int
}

// LogMsg represents log messages
type LogMsg struct {
	Level     string
	Component string
	Message   string
	Fields    map[string]interface{}
	Timestamp time.Time
}

// HealthCheckMsg represents health check messages
type HealthCheckMsg struct {
	Component string
	Healthy   bool
	Details   map[string]interface{}
	Timestamp time.Time
}

// PerformanceMsg represents performance metrics
type PerformanceMsg struct {
	Component string
	Metric    string
	Value     float64
	Unit      string
	Timestamp time.Time
}

// SecurityMsg represents security-related messages
type SecurityMsg struct {
	EventType string
	Severity  string
	Details   map[string]interface{}
	Timestamp time.Time
}

// BackupMsg represents backup-related messages
type BackupMsg struct {
	Type      string // "started", "completed", "failed"
	Path      string
	Size      int64
	Error     error
	Timestamp time.Time
}

// UpdateMsg represents software update messages
type UpdateMsg struct {
	Type      string // "available", "downloading", "installing", "completed"
	Version   string
	Progress  float64
	Error     error
	Timestamp time.Time
}
