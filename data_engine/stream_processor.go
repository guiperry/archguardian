package data_engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
)

// StreamProcessor handles consuming and processing events from Kafka
type StreamProcessor struct {
	reader       *kafka.Reader
	isRunning    bool
	config       StreamProcessorConfig
	handlers     map[EventType][]EventHandler
	handlerMutex sync.RWMutex
	metrics      *MetricsAggregator
	ctx          context.Context
	cancel       context.CancelFunc
}

// StreamProcessorConfig contains configuration for the stream processor
type StreamProcessorConfig struct {
	KafkaBrokers   []string
	ConsumerGroup  string
	Topics         []string
	BatchSize      int
	CommitInterval time.Duration
}

// EventHandler is a function that processes an event
type EventHandler func(event Event) error

// NewStreamProcessor creates a new stream processor
func NewStreamProcessor(config StreamProcessorConfig) *StreamProcessor {
	if len(config.KafkaBrokers) == 0 {
		config.KafkaBrokers = []string{"localhost:9092"}
	}

	if config.ConsumerGroup == "" {
		config.ConsumerGroup = "KNIRVORACLE-terminal"
	}

	if len(config.Topics) == 0 {
		config.Topics = []string{"KNIRVORACLE-events"}
	}

	if config.BatchSize == 0 {
		config.BatchSize = 100
	}

	if config.CommitInterval == 0 {
		config.CommitInterval = 1 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &StreamProcessor{
		config:   config,
		handlers: make(map[EventType][]EventHandler),
		metrics:  NewMetricsAggregator(),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start starts the stream processor
func (p *StreamProcessor) Start() error {
	// Create a new Kafka reader
	p.reader = kafka.NewReader(kafka.ReaderConfig{
		Brokers:        p.config.KafkaBrokers,
		GroupID:        p.config.ConsumerGroup,
		Topic:          p.config.Topics[0], // Use the first topic
		MinBytes:       10e3,               // 10KB
		MaxBytes:       10e6,               // 10MB
		CommitInterval: p.config.CommitInterval,
		StartOffset:    kafka.LastOffset,
	})

	// Start processing in a goroutine
	go p.processMessages()

	p.isRunning = true
	return nil
}

// Stop stops the stream processor
func (p *StreamProcessor) Stop() error {
	if p.reader != nil {
		p.cancel()
		err := p.reader.Close()
		p.reader = nil
		p.isRunning = false
		return err
	}

	return nil
}

// RegisterHandler registers a handler for a specific event type
func (p *StreamProcessor) RegisterHandler(eventType EventType, handler EventHandler) {
	p.handlerMutex.Lock()
	defer p.handlerMutex.Unlock()

	if _, ok := p.handlers[eventType]; !ok {
		p.handlers[eventType] = make([]EventHandler, 0)
	}

	p.handlers[eventType] = append(p.handlers[eventType], handler)
}

// processMessages processes messages from Kafka
func (p *StreamProcessor) processMessages() {
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			// Read a message
			message, err := p.reader.ReadMessage(p.ctx)
			if err != nil {
				// Handle error (log, retry, etc.)
				continue
			}

			// Parse the event
			var event Event
			err = json.Unmarshal(message.Value, &event)
			if err != nil {
				// Handle error (log, skip, etc.)
				continue
			}

			// Process the event
			p.processEvent(event)

			// Update metrics
			p.metrics.RecordEvent(event)
		}
	}
}

// processEvent processes a single event
func (p *StreamProcessor) processEvent(event Event) {
	p.handlerMutex.RLock()
	defer p.handlerMutex.RUnlock()

	// Call handlers for this event type
	if handlers, ok := p.handlers[event.Type]; ok {
		for _, handler := range handlers {
			err := handler(event)
			if err != nil {
				// Handle error (log, retry, etc.)
			}
		}
	}

	// Call handlers for the parent event type (e.g., "blockchain" for "block_created")
	parentEventTypes := []EventType{
		ScanCycleEventType,
		SystemEventType,
	}

	for _, part := range parentEventTypes {
		if event.Type != part && strings.HasPrefix(string(event.Type), string(part)) {
			if handlers, ok := p.handlers[part]; ok {
				for _, handler := range handlers {
					err := handler(event)
					if err != nil {
						// Handle error (log, retry, etc.)
					}
				}
			}
		}
	}
}

// GetMetrics returns the current metrics
func (p *StreamProcessor) GetMetrics() *MetricsSnapshot {
	return p.metrics.GetSnapshot()
}

// IsRunning returns whether the processor is running
func (p *StreamProcessor) IsRunning() bool {
	return p.isRunning
}

// MetricsAggregator aggregates metrics from events
type MetricsAggregator struct {
	mutex            sync.RWMutex
	eventCounts      map[EventType]int64
	eventCountsByMin map[string]map[EventType]int64
	lastMinute       string
	startTime        time.Time
	totalEvents      int64
}

// MetricsSnapshot represents a snapshot of metrics
type MetricsSnapshot struct {
	EventCounts      map[EventType]int64
	EventCountsByMin map[string]map[EventType]int64
	StartTime        time.Time
	TotalEvents      int64
	UptimeSeconds    int64
}

// NewMetricsAggregator creates a new metrics aggregator
func NewMetricsAggregator() *MetricsAggregator {
	now := time.Now()
	currentMinute := now.Format("2006-01-02 15:04")

	return &MetricsAggregator{
		eventCounts: make(map[EventType]int64),
		eventCountsByMin: map[string]map[EventType]int64{
			currentMinute: make(map[EventType]int64),
		},
		lastMinute: currentMinute,
		startTime:  now,
	}
}

// RecordEvent records an event in the metrics
func (m *MetricsAggregator) RecordEvent(event Event) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Increment total events
	m.totalEvents++

	// Increment count for this event type
	m.eventCounts[event.Type]++

	// Record by minute
	minute := event.Timestamp.Format("2006-01-02 15:04")
	if _, ok := m.eventCountsByMin[minute]; !ok {
		m.eventCountsByMin[minute] = make(map[EventType]int64)

		// Clean up old minutes (keep last 60 minutes)
		if len(m.eventCountsByMin) > 60 {
			oldest := ""
			for min := range m.eventCountsByMin {
				if oldest == "" || min < oldest {
					oldest = min
				}
			}

			if oldest != "" {
				delete(m.eventCountsByMin, oldest)
			}
		}
	}

	m.eventCountsByMin[minute][event.Type]++
	m.lastMinute = minute
}

// GetSnapshot returns a snapshot of the current metrics
func (m *MetricsAggregator) GetSnapshot() *MetricsSnapshot {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Copy event counts
	eventCounts := make(map[EventType]int64)
	for k, v := range m.eventCounts {
		eventCounts[k] = v
	}

	// Copy event counts by minute
	eventCountsByMin := make(map[string]map[EventType]int64)
	for min, counts := range m.eventCountsByMin {
		eventCountsByMin[min] = make(map[EventType]int64)
		for k, v := range counts {
			eventCountsByMin[min][k] = v
		}
	}

	return &MetricsSnapshot{
		EventCounts:      eventCounts,
		EventCountsByMin: eventCountsByMin,
		StartTime:        m.startTime,
		TotalEvents:      m.totalEvents,
		UptimeSeconds:    int64(time.Since(m.startTime).Seconds()),
	}
}

// GetEventRate returns the events per second over the lifetime
func (m *MetricsSnapshot) GetEventRate() float64 {
	if m.UptimeSeconds == 0 {
		return 0
	}

	return float64(m.TotalEvents) / float64(m.UptimeSeconds)
}

// GetEventRateForType returns the events per second for a specific type
func (m *MetricsSnapshot) GetEventRateForType(eventType EventType) float64 {
	if m.UptimeSeconds == 0 {
		return 0
	}

	count, ok := m.EventCounts[eventType]
	if !ok {
		return 0
	}

	return float64(count) / float64(m.UptimeSeconds)
}

// GetRecentEventRate returns the events per second over the last minute
func (m *MetricsSnapshot) GetRecentEventRate() float64 {
	// Find the most recent minute
	var mostRecent string
	var total int64

	for min := range m.EventCountsByMin {
		if mostRecent == "" || min > mostRecent {
			mostRecent = min
		}
	}

	if mostRecent == "" {
		return 0
	}

	// Sum all events in the most recent minute
	for _, count := range m.EventCountsByMin[mostRecent] {
		total += count
	}

	return float64(total) / 60.0
}

// String returns a string representation of the metrics
func (m *MetricsSnapshot) String() string {
	return fmt.Sprintf(
		"Total Events: %d, Uptime: %ds, Rate: %.2f events/sec",
		m.TotalEvents,
		m.UptimeSeconds,
		m.GetEventRate(),
	)
}
