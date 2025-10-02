package data_engine

import (
	"fmt"
	"sync"
	"time"
)

// WindowType represents different types of time windows
type WindowType int

const (
	TumblingWindow WindowType = iota // Non-overlapping fixed-size windows
	SlidingWindow                    // Overlapping fixed-size windows
	SessionWindow                    // Variable-size windows based on activity
)

// Window represents a time window for aggregation
type Window struct {
	StartTime time.Time
	EndTime   time.Time
	Type      WindowType
	Size      time.Duration
	Slide     time.Duration // For sliding windows
}

// WindowedAggregator handles windowed aggregations of events
type WindowedAggregator struct {
	mutex       sync.RWMutex
	windows     map[string]*WindowData
	windowType  WindowType
	windowSize  time.Duration
	slideSize   time.Duration
	sessionGap  time.Duration
	aggregators map[string]AggregatorFunc
}

// WindowData contains data for a specific window
type WindowData struct {
	Window     Window
	Data       map[string]interface{}
	EventCount int64
	LastUpdate time.Time
}

// AggregatorFunc is a function that aggregates events in a window
type AggregatorFunc func(window *WindowData, event Event) error

// NewWindowedAggregator creates a new windowed aggregator
func NewWindowedAggregator(windowType WindowType, windowSize time.Duration) *WindowedAggregator {
	wa := &WindowedAggregator{
		windows:     make(map[string]*WindowData),
		windowType:  windowType,
		windowSize:  windowSize,
		slideSize:   windowSize / 2,  // Default slide is half the window size
		sessionGap:  5 * time.Minute, // Default session gap
		aggregators: make(map[string]AggregatorFunc),
	}

	// Register default aggregators
	wa.RegisterAggregator("count", countAggregator)
	wa.RegisterAggregator("sum", sumAggregator)
	wa.RegisterAggregator("avg", avgAggregator)
	wa.RegisterAggregator("min", minAggregator)
	wa.RegisterAggregator("max", maxAggregator)

	return wa
}

// SetSlideSize sets the slide size for sliding windows
func (wa *WindowedAggregator) SetSlideSize(slideSize time.Duration) {
	wa.mutex.Lock()
	defer wa.mutex.Unlock()

	wa.slideSize = slideSize
}

// SetSessionGap sets the session gap for session windows
func (wa *WindowedAggregator) SetSessionGap(sessionGap time.Duration) {
	wa.mutex.Lock()
	defer wa.mutex.Unlock()

	wa.sessionGap = sessionGap
}

// RegisterAggregator registers an aggregator function
func (wa *WindowedAggregator) RegisterAggregator(name string, fn AggregatorFunc) {
	wa.mutex.Lock()
	defer wa.mutex.Unlock()

	wa.aggregators[name] = fn
}

// ProcessEvent processes an event and updates the appropriate windows
func (wa *WindowedAggregator) ProcessEvent(event Event) error {
	wa.mutex.Lock()
	defer wa.mutex.Unlock()

	// Find or create the appropriate windows for this event
	windows := wa.findWindows(event.Timestamp)

	// Update each window with this event
	for _, window := range windows {
		// Apply all aggregators to this window
		for name, fn := range wa.aggregators {
			err := fn(window, event)
			if err != nil {
				return fmt.Errorf("aggregator %s failed: %w", name, err)
			}
		}

		// Update window metadata
		window.EventCount++
		window.LastUpdate = time.Now()
	}

	// Clean up old windows
	wa.cleanupWindows()

	return nil
}

// findWindows finds or creates windows for a timestamp
func (wa *WindowedAggregator) findWindows(timestamp time.Time) []*WindowData {
	var windows []*WindowData

	switch wa.windowType {
	case TumblingWindow:
		// For tumbling windows, find the window that contains this timestamp
		windowStart := timestamp.Truncate(wa.windowSize)
		windowEnd := windowStart.Add(wa.windowSize)
		windowKey := fmt.Sprintf("%s-%s", windowStart.Format(time.RFC3339), windowEnd.Format(time.RFC3339))

		window, ok := wa.windows[windowKey]
		if !ok {
			// Create a new window
			window = &WindowData{
				Window: Window{
					StartTime: windowStart,
					EndTime:   windowEnd,
					Type:      TumblingWindow,
					Size:      wa.windowSize,
				},
				Data:       make(map[string]interface{}),
				EventCount: 0,
				LastUpdate: time.Now(),
			}
			wa.windows[windowKey] = window
		}

		windows = append(windows, window)

	case SlidingWindow:
		// For sliding windows, find all windows that contain this timestamp
		currentTime := timestamp
		for i := 0; i < int(wa.windowSize/wa.slideSize); i++ {
			windowStart := currentTime.Truncate(wa.slideSize)
			windowEnd := windowStart.Add(wa.windowSize)
			windowKey := fmt.Sprintf("%s-%s", windowStart.Format(time.RFC3339), windowEnd.Format(time.RFC3339))

			window, ok := wa.windows[windowKey]
			if !ok {
				// Create a new window
				window = &WindowData{
					Window: Window{
						StartTime: windowStart,
						EndTime:   windowEnd,
						Type:      SlidingWindow,
						Size:      wa.windowSize,
						Slide:     wa.slideSize,
					},
					Data:       make(map[string]interface{}),
					EventCount: 0,
					LastUpdate: time.Now(),
				}
				wa.windows[windowKey] = window
			}

			windows = append(windows, window)
			currentTime = currentTime.Add(-wa.slideSize)
		}

	case SessionWindow:
		// For session windows, use timestamp as a session identifier
		// In a real implementation, we would need the user ID from the event
		userID := "session-" + timestamp.Format(time.RFC3339)

		// Find the most recent session for this user
		var mostRecentSession *WindowData
		for _, window := range wa.windows {
			if data, ok := window.Data["user_id"]; ok && data == userID {
				if mostRecentSession == nil || window.LastUpdate.After(mostRecentSession.LastUpdate) {
					mostRecentSession = window
				}
			}
		}

		// Check if we need to create a new session
		if mostRecentSession == nil || time.Since(mostRecentSession.LastUpdate) > wa.sessionGap {
			// Create a new session
			sessionStart := timestamp
			sessionEnd := timestamp.Add(wa.sessionGap)
			sessionKey := fmt.Sprintf("session-%s-%s", userID, sessionStart.Format(time.RFC3339))

			newSession := &WindowData{
				Window: Window{
					StartTime: sessionStart,
					EndTime:   sessionEnd,
					Type:      SessionWindow,
					Size:      wa.sessionGap,
				},
				Data: map[string]interface{}{
					"user_id": userID,
				},
				EventCount: 0,
				LastUpdate: time.Now(),
			}

			wa.windows[sessionKey] = newSession
			windows = append(windows, newSession)
		} else {
			// Extend the existing session
			mostRecentSession.Window.EndTime = timestamp.Add(wa.sessionGap)
			windows = append(windows, mostRecentSession)
		}
	}

	return windows
}

// cleanupWindows removes old windows
func (wa *WindowedAggregator) cleanupWindows() {
	now := time.Now()

	// Keep windows for the last hour
	cutoff := now.Add(-1 * time.Hour)

	for key, window := range wa.windows {
		if window.Window.EndTime.Before(cutoff) {
			delete(wa.windows, key)
		}
	}
}

// GetWindows returns all current windows
func (wa *WindowedAggregator) GetWindows() []*WindowData {
	wa.mutex.RLock()
	defer wa.mutex.RUnlock()

	windows := make([]*WindowData, 0, len(wa.windows))
	for _, window := range wa.windows {
		windows = append(windows, window)
	}

	return windows
}

// GetWindowsInRange returns windows that overlap with a time range
func (wa *WindowedAggregator) GetWindowsInRange(start, end time.Time) []*WindowData {
	wa.mutex.RLock()
	defer wa.mutex.RUnlock()

	var windows []*WindowData

	for _, window := range wa.windows {
		// Check if the window overlaps with the range
		if (window.Window.StartTime.Before(end) || window.Window.StartTime.Equal(end)) &&
			(window.Window.EndTime.After(start) || window.Window.EndTime.Equal(start)) {
			windows = append(windows, window)
		}
	}

	return windows
}

// GetActiveUsers returns the number of active users in a time range
func (wa *WindowedAggregator) GetActiveUsers(start, end time.Time) int {
	wa.mutex.RLock()
	defer wa.mutex.RUnlock()

	userIDs := make(map[string]bool)

	for _, window := range wa.windows {
		// Check if the window overlaps with the range
		if (window.Window.StartTime.Before(end) || window.Window.StartTime.Equal(end)) &&
			(window.Window.EndTime.After(start) || window.Window.EndTime.Equal(start)) {

			// Check if this window has a user ID
			if userID, ok := window.Data["user_id"].(string); ok {
				userIDs[userID] = true
			}
		}
	}

	return len(userIDs)
}

// GetEventRate returns the events per second in a time range
func (wa *WindowedAggregator) GetEventRate(start, end time.Time) float64 {
	wa.mutex.RLock()
	defer wa.mutex.RUnlock()

	var totalEvents int64

	for _, window := range wa.windows {
		// Check if the window overlaps with the range
		if (window.Window.StartTime.Before(end) || window.Window.StartTime.Equal(end)) &&
			(window.Window.EndTime.After(start) || window.Window.EndTime.Equal(start)) {

			totalEvents += window.EventCount
		}
	}

	duration := end.Sub(start).Seconds()
	if duration <= 0 {
		return 0
	}

	return float64(totalEvents) / duration
}

// Default aggregator functions

// countAggregator counts events
func countAggregator(window *WindowData, event Event) error {
	count, ok := window.Data["count"].(int64)
	if !ok {
		count = 0
	}

	window.Data["count"] = count + 1
	return nil
}

// sumAggregator sums a numeric field
func sumAggregator(window *WindowData, event Event) error {
	// Look for numeric fields to sum
	for key, value := range event.Data {
		if num, ok := value.(float64); ok {
			sumKey := fmt.Sprintf("sum_%s", key)
			sum, ok := window.Data[sumKey].(float64)
			if !ok {
				sum = 0
			}

			window.Data[sumKey] = sum + num
		}
	}

	return nil
}

// avgAggregator calculates the average of a numeric field
func avgAggregator(window *WindowData, event Event) error {
	// First update the sum
	err := sumAggregator(window, event)
	if err != nil {
		return err
	}

	// Then update the count for each field
	for key := range event.Data {
		countKey := fmt.Sprintf("count_%s", key)
		count, ok := window.Data[countKey].(int64)
		if !ok {
			count = 0
		}

		window.Data[countKey] = count + 1

		// Calculate the average
		sumKey := fmt.Sprintf("sum_%s", key)
		if sum, ok := window.Data[sumKey].(float64); ok {
			avgKey := fmt.Sprintf("avg_%s", key)
			window.Data[avgKey] = sum / float64(count+1)
		}
	}

	return nil
}

// minAggregator calculates the minimum of a numeric field
func minAggregator(window *WindowData, event Event) error {
	for key, value := range event.Data {
		if num, ok := value.(float64); ok {
			minKey := fmt.Sprintf("min_%s", key)
			min, ok := window.Data[minKey].(float64)
			if !ok || num < min {
				window.Data[minKey] = num
			}
		}
	}

	return nil
}

// maxAggregator calculates the maximum of a numeric field
func maxAggregator(window *WindowData, event Event) error {
	for key, value := range event.Data {
		if num, ok := value.(float64); ok {
			maxKey := fmt.Sprintf("max_%s", key)
			max, ok := window.Data[maxKey].(float64)
			if !ok || num > max {
				window.Data[maxKey] = num
			}
		}
	}

	return nil
}
