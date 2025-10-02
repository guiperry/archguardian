package data_engine

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AlertLevel represents the severity level of an alert
type AlertLevel int

const (
	InfoAlert AlertLevel = iota
	WarningAlert
	ErrorAlert
	CriticalAlert
)

// String returns the string representation of AlertLevel
func (l AlertLevel) String() string {
	switch l {
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

// Alert represents a system alert
type Alert struct {
	ID          string
	Level       AlertLevel
	Title       string
	Description string
	Source      string
	Timestamp   time.Time
	Data        map[string]interface{}
	Resolved    bool
	ResolvedAt  time.Time
}

// AlertRule represents a rule for generating alerts
type AlertRule struct {
	ID            string
	Name          string
	Description   string
	EventType     EventType
	Condition     AlertCondition
	Level         AlertLevel
	Cooldown      time.Duration
	LastTriggered time.Time
}

// AlertCondition is a function that evaluates whether an alert should be triggered
type AlertCondition func(event Event, state *AlertingState) bool

// AlertHandler is a function that handles an alert
type AlertHandler func(alert Alert)

// AlertingSystem manages alert rules and generates alerts
type AlertingSystem struct {
	mutex     sync.RWMutex
	rules     map[string]AlertRule
	alerts    []Alert
	handlers  []AlertHandler
	state     *AlertingState
	maxAlerts int
	ctx       context.Context
	cancel    context.CancelFunc
}

// AlertingState maintains state for alert conditions
type AlertingState struct {
	mutex           sync.RWMutex
	eventCounts     map[EventType]int64
	eventRates      map[EventType]float64
	lastEventTimes  map[EventType]time.Time
	errorCounts     map[string]int64
	customMetrics   map[string]float64
	windowedMetrics map[string][]float64
	windowSize      int
}

// NewAlertingSystem creates a new alerting system
func NewAlertingSystem(maxAlerts int) *AlertingSystem {
	if maxAlerts <= 0 {
		maxAlerts = 1000
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &AlertingSystem{
		rules:     make(map[string]AlertRule),
		alerts:    make([]Alert, 0, maxAlerts),
		handlers:  make([]AlertHandler, 0),
		maxAlerts: maxAlerts,
		state:     newAlertingState(),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// newAlertingState creates a new alerting state
func newAlertingState() *AlertingState {
	return &AlertingState{
		eventCounts:     make(map[EventType]int64),
		eventRates:      make(map[EventType]float64),
		lastEventTimes:  make(map[EventType]time.Time),
		errorCounts:     make(map[string]int64),
		customMetrics:   make(map[string]float64),
		windowedMetrics: make(map[string][]float64),
		windowSize:      60, // 1 minute window (60 seconds)
	}
}

// RegisterRule registers an alert rule
func (a *AlertingSystem) RegisterRule(rule AlertRule) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.rules[rule.ID] = rule
}

// RegisterHandler registers an alert handler
func (a *AlertingSystem) RegisterHandler(handler AlertHandler) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.handlers = append(a.handlers, handler)
}

// ProcessEvent processes an event and generates alerts if needed
func (a *AlertingSystem) ProcessEvent(event Event) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Update state
	a.updateState(event)

	// Check rules
	for _, rule := range a.rules {
		// Skip if in cooldown
		if !rule.LastTriggered.IsZero() && time.Since(rule.LastTriggered) < rule.Cooldown {
			continue
		}

		// Skip if event type doesn't match
		if rule.EventType != "" && rule.EventType != event.Type {
			continue
		}

		// Check condition
		if rule.Condition(event, a.state) {
			// Generate alert
			alert := Alert{
				ID:          fmt.Sprintf("alert-%d", time.Now().UnixNano()),
				Level:       rule.Level,
				Title:       rule.Name,
				Description: rule.Description,
				Source:      string(event.Type),
				Timestamp:   time.Now(),
				Data:        event.Data,
				Resolved:    false,
			}

			// Add alert to list
			a.alerts = append(a.alerts, alert)

			// Trim if exceeding max alerts
			if len(a.alerts) > a.maxAlerts {
				a.alerts = a.alerts[len(a.alerts)-a.maxAlerts:]
			}

			// Update last triggered time
			ruleCopy := rule
			ruleCopy.LastTriggered = time.Now()
			a.rules[rule.ID] = ruleCopy

			// Notify handlers
			for _, handler := range a.handlers {
				go handler(alert)
			}
		}
	}
}

// updateState updates the alerting state with a new event
func (a *AlertingSystem) updateState(event Event) {
	a.state.mutex.Lock()
	defer a.state.mutex.Unlock()

	// Update event counts
	a.state.eventCounts[event.Type]++

	// Update last event time
	a.state.lastEventTimes[event.Type] = event.Timestamp

	// Update error counts
	if event.Type == ErrorEvent {
		if source, ok := event.Data["source"].(string); ok {
			a.state.errorCounts[source]++
		}
	}

	// Update event rates
	for eventType, count := range a.state.eventCounts {
		lastTime, ok := a.state.lastEventTimes[eventType]
		if !ok {
			continue
		}

		// Calculate rate over the last minute
		duration := time.Since(lastTime).Seconds()
		if duration > 0 {
			a.state.eventRates[eventType] = float64(count) / duration
		}
	}

	// Update windowed metrics
	for key, value := range event.Data {
		if num, ok := value.(float64); ok {
			metricKey := fmt.Sprintf("%s_%s", event.Type, key)

			// Initialize if needed
			if _, ok := a.state.windowedMetrics[metricKey]; !ok {
				a.state.windowedMetrics[metricKey] = make([]float64, 0, a.state.windowSize)
			}

			// Add to window
			a.state.windowedMetrics[metricKey] = append(a.state.windowedMetrics[metricKey], num)

			// Trim if exceeding window size
			if len(a.state.windowedMetrics[metricKey]) > a.state.windowSize {
				a.state.windowedMetrics[metricKey] = a.state.windowedMetrics[metricKey][1:]
			}

			// Calculate average
			var sum float64
			for _, v := range a.state.windowedMetrics[metricKey] {
				sum += v
			}

			avgKey := fmt.Sprintf("avg_%s", metricKey)
			a.state.customMetrics[avgKey] = sum / float64(len(a.state.windowedMetrics[metricKey]))
		}
	}
}

// GetAlerts returns all alerts
func (a *AlertingSystem) GetAlerts() []Alert {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	alerts := make([]Alert, len(a.alerts))
	copy(alerts, a.alerts)

	return alerts
}

// GetActiveAlerts returns all active (unresolved) alerts
func (a *AlertingSystem) GetActiveAlerts() []Alert {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	var activeAlerts []Alert

	for _, alert := range a.alerts {
		if !alert.Resolved {
			activeAlerts = append(activeAlerts, alert)
		}
	}

	return activeAlerts
}

// ResolveAlert resolves an alert
func (a *AlertingSystem) ResolveAlert(alertID string) bool {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	for i, alert := range a.alerts {
		if alert.ID == alertID {
			alert.Resolved = true
			alert.ResolvedAt = time.Now()
			a.alerts[i] = alert
			return true
		}
	}

	return false
}

// Close closes the alerting system
func (a *AlertingSystem) Close() {
	a.cancel()
}

// Common alert conditions

// ThresholdCondition creates a condition that triggers when a metric exceeds a threshold
func ThresholdCondition(metricKey string, threshold float64, isGreaterThan bool) AlertCondition {
	return func(event Event, state *AlertingState) bool {
		state.mutex.RLock()
		defer state.mutex.RUnlock()

		// Check if the metric exists
		value, ok := event.Data[metricKey]
		if !ok {
			return false
		}

		// Convert to float64
		var floatValue float64
		switch v := value.(type) {
		case float64:
			floatValue = v
		case int:
			floatValue = float64(v)
		case int64:
			floatValue = float64(v)
		default:
			return false
		}

		// Compare with threshold
		if isGreaterThan {
			return floatValue > threshold
		}

		return floatValue < threshold
	}
}

// SpikeCondition creates a condition that triggers when a metric spikes
func SpikeCondition(metricKey string, percentChange float64) AlertCondition {
	return func(event Event, state *AlertingState) bool {
		state.mutex.RLock()
		defer state.mutex.RUnlock()

		// Check if the metric exists
		value, ok := event.Data[metricKey]
		if !ok {
			return false
		}

		// Convert to float64
		var floatValue float64
		switch v := value.(type) {
		case float64:
			floatValue = v
		case int:
			floatValue = float64(v)
		case int64:
			floatValue = float64(v)
		default:
			return false
		}

		// Get the average
		avgKey := fmt.Sprintf("avg_%s_%s", event.Type, metricKey)
		avg, ok := state.customMetrics[avgKey]
		if !ok || avg == 0 {
			return false
		}

		// Calculate percent change
		change := (floatValue - avg) / avg * 100

		// Check if it exceeds the threshold
		return change > percentChange
	}
}

// ErrorRateCondition creates a condition that triggers when the error rate exceeds a threshold
func ErrorRateCondition(errorsPerMinute float64) AlertCondition {
	return func(event Event, state *AlertingState) bool {
		state.mutex.RLock()
		defer state.mutex.RUnlock()

		// Only check for error events
		if event.Type != ErrorEvent {
			return false
		}

		// Get the error rate
		rate, ok := state.eventRates[ErrorEvent]
		if !ok {
			return false
		}

		// Convert to errors per minute
		ratePerMinute := rate * 60

		// Check if it exceeds the threshold
		return ratePerMinute > errorsPerMinute
	}
}

// EventFrequencyCondition creates a condition that triggers when an event occurs too frequently
func EventFrequencyCondition(eventType EventType, eventsPerMinute float64) AlertCondition {
	return func(event Event, state *AlertingState) bool {
		state.mutex.RLock()
		defer state.mutex.RUnlock()

		// Only check for the specified event type
		if event.Type != eventType {
			return false
		}

		// Get the event rate
		rate, ok := state.eventRates[eventType]
		if !ok {
			return false
		}

		// Convert to events per minute
		ratePerMinute := rate * 60

		// Check if it exceeds the threshold
		return ratePerMinute > eventsPerMinute
	}
}

// InactivityCondition creates a condition that triggers when an event hasn't occurred for a while
func InactivityCondition(eventType EventType, maxInactivitySeconds float64) AlertCondition {
	return func(event Event, state *AlertingState) bool {
		state.mutex.RLock()
		defer state.mutex.RUnlock()

		// Get the last event time
		lastTime, ok := state.lastEventTimes[eventType]
		if !ok {
			return false
		}

		// Calculate inactivity duration
		inactivity := time.Since(lastTime).Seconds()

		// Check if it exceeds the threshold
		return inactivity > maxInactivitySeconds
	}
}

// CreateLogAlertHandler creates an alert handler that sends alerts to the log system
func CreateLogAlertHandler() AlertHandler {
	return func(alert Alert) {
		// Get alert level string for logging
		_ = alert.Level.String()

		// Send to log channel (this would be handled by the UI)
		// In a real implementation, this would use a channel to send to the UI
		fmt.Printf("ALERT [%s]: %s - %s\n", alert.Level.String(), alert.Title, alert.Description)
	}
}
