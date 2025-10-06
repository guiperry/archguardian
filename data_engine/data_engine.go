package data_engine

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"archguardian/messages"
)

// DataEngine is the main manager for all data engineering components
type DataEngine struct {
	producer   *EventProducer
	processor  *StreamProcessor
	aggregator *WindowedAggregator
	chromaDB   *ChromaDB
	alerting   *AlertingSystem
	websocket  *WebSocketServer
	restAPI    *RESTAPIServer

	config    DataEngineConfig
	isRunning bool
	ctx       context.Context
	cancel    context.CancelFunc
	mutex     sync.RWMutex

	// Channels for communication with UI
	alertChan   chan Alert
	metricsChan chan *MetricsSnapshot

	// Callback for when WebSocket client is ready
	onClientReadyCallback func()
}

// DataEngineConfig contains configuration for the data engine
type DataEngineConfig struct {
	KafkaBrokers     []string
	KafkaClientID    string
	ChromaDBURL      string
	ChromaCollection string
	EnableKafka      bool
	EnableChromaDB   bool
	EnableWebSocket  bool
	EnableRESTAPI    bool
	WebSocketPort    int
	RESTAPIPort      int
	WindowSize       time.Duration
	MetricsInterval  time.Duration
}

// NewDataEngine creates a new data engine
func NewDataEngine(config DataEngineConfig) *DataEngine {
	ctx, cancel := context.WithCancel(context.Background())

	return &DataEngine{
		config:      config,
		ctx:         ctx,
		cancel:      cancel,
		alertChan:   make(chan Alert, 100),
		metricsChan: make(chan *MetricsSnapshot, 10),
	}
}

// GetAlertChannel returns the alert channel
func (d *DataEngine) GetAlertChannel() <-chan Alert {
	return d.alertChan
}

// GetMetricsChannel returns the metrics channel
func (d *DataEngine) GetMetricsChannel() <-chan *MetricsSnapshot {
	return d.metricsChan
}

// Start starts the data engine
func (d *DataEngine) Start() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.isRunning {
		return fmt.Errorf("data engine is already running")
	}

	// Initialize components
	if d.config.EnableKafka {
		// Create event producer
		d.producer = NewEventProducer(EventProducerConfig{
			KafkaBrokers: d.config.KafkaBrokers,
			ClientID:     d.config.KafkaClientID,
			BatchSize:    100,
			BatchTimeout: 1 * time.Second,
			Async:        true,
		})

		// Connect to Kafka
		err := d.producer.Connect(d.ctx)
		if err != nil {
			return fmt.Errorf("failed to connect to Kafka: %w", err)
		}

		// Create stream processor
		d.processor = NewStreamProcessor(StreamProcessorConfig{
			KafkaBrokers:   d.config.KafkaBrokers,
			ConsumerGroup:  d.config.KafkaClientID + "-consumer",
			Topics:         []string{"KNIRVORACLE-events"},
			BatchSize:      100,
			CommitInterval: 1 * time.Second,
		})

		// Start stream processor
		err = d.processor.Start()
		if err != nil {
			return fmt.Errorf("failed to start stream processor: %w", err)
		}
	}

	// Create windowed aggregator
	d.aggregator = NewWindowedAggregator(SlidingWindow, d.config.WindowSize)

	// Create ChromaDB client
	if d.config.EnableChromaDB {
		d.chromaDB = NewChromaDB(d.config.ChromaDBURL, d.config.ChromaCollection)

		// Connect to ChromaDB
		err := d.chromaDB.Connect(d.ctx)
		if err != nil {
			return fmt.Errorf("failed to connect to ChromaDB: %w", err)
		}
	}

	// Create alerting system
	d.alerting = NewAlertingSystem(1000)

	// Register alert handler
	d.alerting.RegisterHandler(d.handleAlert)

	// Register default alert rules
	d.registerDefaultAlertRules()

	// Create WebSocket server if enabled and not embedded in reverse proxy
	if d.config.EnableWebSocket {
		d.websocket = NewWebSocketServer(WebSocketConfig{
			Port:            d.config.WebSocketPort,
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     true,
		}, d)

		// Start WebSocket server
		err := d.websocket.Start()
		if err != nil {
			return fmt.Errorf("failed to start WebSocket server: %w", err)
		}
	}

	// Create REST API server if enabled and not embedded in reverse proxy
	if d.config.EnableRESTAPI {
		d.restAPI = NewRESTAPIServer(RESTAPIConfig{
			Port:           d.config.RESTAPIPort,
			EnableCORS:     true,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20, // 1MB
		}, d)

		// Start REST API server
		err := d.restAPI.Start()
		if err != nil {
			log.Printf("⚠️  Failed to start REST API server: %v", err)
			// Don't fail the entire startup for REST API issues
			d.restAPI = nil
		} else {
			log.Printf("✅ REST API server started on port %d", d.config.RESTAPIPort)
		}
	}

	// Start metrics reporting
	go d.reportMetrics()

	d.isRunning = true
	return nil
}

// Stop stops the data engine
func (d *DataEngine) Stop() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if !d.isRunning {
		return nil
	}

	// Cancel context
	d.cancel()

	// Stop components
	if d.producer != nil {
		d.producer.Close()
	}

	if d.processor != nil {
		d.processor.Stop()
	}

	if d.chromaDB != nil {
		d.chromaDB.Close()
	}

	if d.alerting != nil {
		d.alerting.Close()
	}

	// Stop WebSocket server
	if d.websocket != nil {
		err := d.websocket.Stop()
		if err != nil {
			fmt.Printf("Failed to stop WebSocket server: %s\n", err.Error())
		}
	}

	// Stop REST API server
	if d.restAPI != nil {
		err := d.restAPI.Stop()
		if err != nil {
			fmt.Printf("Failed to stop REST API server: %s\n", err.Error())
		}
	}

	d.isRunning = false
	return nil
}

// ProcessEvent processes an event through the data engine
func (d *DataEngine) ProcessEvent(event Event) error {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if !d.isRunning {
		return fmt.Errorf("data engine is not running")
	}

	// Process through windowed aggregator
	err := d.aggregator.ProcessEvent(event)
	if err != nil {
		return fmt.Errorf("failed to process event through aggregator: %w", err)
	}

	// Process through alerting system
	d.alerting.ProcessEvent(event)

	// Send to Kafka if enabled
	if d.config.EnableKafka && d.producer != nil && d.producer.IsConnected() {
		err := d.producer.ProduceEvent(d.ctx, event)
		if err != nil {
			return fmt.Errorf("failed to produce event to Kafka: %w", err)
		}
	}

	// Store in ChromaDB if enabled
	if d.config.EnableChromaDB && d.chromaDB != nil && d.chromaDB.IsConnected() {
		err := d.chromaDB.AddEvent(d.ctx, event)
		if err != nil {
			return fmt.Errorf("failed to add event to ChromaDB: %w", err)
		}
	}

	// Broadcast to WebSocket clients if enabled
	if d.config.EnableWebSocket && d.websocket != nil && d.websocket.IsRunning() {
		d.websocket.Broadcast(map[string]interface{}{
			"type":  "event",
			"event": event,
		})
	}

	return nil
}

// BroadcastLog sends a raw log message to all WebSocket clients.
func (d *DataEngine) BroadcastLog(message string) {
	if d.config.EnableWebSocket && d.websocket != nil && d.websocket.IsRunning() {
		d.websocket.BroadcastLog(message)
	}
}

// BroadcastSecurityVulnerability broadcasts a security vulnerability found event
func (d *DataEngine) BroadcastSecurityVulnerability(vuln interface{}) {
	if d.config.EnableWebSocket && d.websocket != nil && d.websocket.IsRunning() {
		d.websocket.BroadcastSecurityVulnerability(vuln)
	}
}

// BroadcastRemediationCompleted broadcasts a remediation completed event
func (d *DataEngine) BroadcastRemediationCompleted(result interface{}) {
	if d.config.EnableWebSocket && d.websocket != nil && d.websocket.IsRunning() {
		d.websocket.BroadcastRemediationCompleted(result)
	}
}

// ProcessLogMsg processes a log message
func (d *DataEngine) ProcessLogMsg(msg messages.LogMsg) error {
	event := ConvertLogMsg(msg)
	return d.ProcessEvent(event)
}

// SetOnClientReadyCallback sets the callback function to be called when a WebSocket client is ready
func (d *DataEngine) SetOnClientReadyCallback(callback func()) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.onClientReadyCallback = callback
}

// TriggerClientReady triggers the client ready callback
func (d *DataEngine) TriggerClientReady() {
	d.mutex.RLock()
	callback := d.onClientReadyCallback
	d.mutex.RUnlock()

	if callback != nil {
		callback()
	}
}

// handleAlert handles an alert
func (d *DataEngine) handleAlert(alert Alert) {
	// Send to alert channel
	select {
	case d.alertChan <- alert:
		// Alert sent successfully
	default:
		// Channel is full, log and continue
		fmt.Printf("Alert channel is full, dropping alert: %s\n", alert.Title)
	}

	// Broadcast to WebSocket clients if enabled
	if d.config.EnableWebSocket && d.websocket != nil && d.websocket.IsRunning() {
		d.websocket.Broadcast(map[string]interface{}{
			"type":  "alert",
			"alert": alert,
		})
	}
}

// reportMetrics periodically reports metrics
func (d *DataEngine) reportMetrics() {
	ticker := time.NewTicker(d.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			if d.processor != nil {
				// Get metrics from processor
				metrics := d.processor.GetMetrics()

				// Send to metrics channel
				select {
				case d.metricsChan <- metrics:
					// Metrics sent successfully
				default:
					// Channel is full, skip this update
				}

				// Broadcast to WebSocket clients if enabled
				if d.config.EnableWebSocket && d.websocket != nil && d.websocket.IsRunning() {
					d.websocket.Broadcast(map[string]interface{}{
						"type":    "metrics",
						"metrics": metrics,
					})
				}
			}
		}
	}
}

// registerDefaultAlertRules registers default alert rules
func (d *DataEngine) registerDefaultAlertRules() {
	// Register error rate alert
	d.alerting.RegisterRule(AlertRule{
		ID:          "error-rate",
		Name:        "High Error Rate",
		Description: "Error rate exceeds threshold",
		EventType:   ErrorEvent,
		Condition:   ErrorRateCondition(10), // 10 errors per minute
		Level:       ErrorAlert,
		Cooldown:    5 * time.Minute,
	})

	// Register scan cycle completion alert (example)
	d.alerting.RegisterRule(AlertRule{
		ID:          "scan-inactivity",
		Name:        "Scan Cycle Inactivity",
		Description: "No scan cycles completed recently",
		EventType:   ScanCompletedEvent,
		Condition:   InactivityCondition(ScanCompletedEvent, float64(d.config.MetricsInterval.Seconds()*2)), // 2x metrics interval
		Level:       WarningAlert,
		Cooldown:    15 * time.Minute,
	})

	// Register high risk score alert (example)
	d.alerting.RegisterRule(AlertRule{
		ID:          "high-risk-score",
		Name:        "High Overall Risk Score",
		Description: "Overall project risk score exceeds acceptable threshold",
		EventType:   ScanCompletedEvent,                              // Triggered after a scan completes
		Condition:   ThresholdCondition("overall_score", 50.0, true), // >50.0
		Level:       CriticalAlert,
		Cooldown:    30 * time.Minute,
	})
}

// GetActiveAlerts returns all active alerts
func (d *DataEngine) GetActiveAlerts() []Alert {
	if d.alerting == nil {
		return nil
	}

	return d.alerting.GetActiveAlerts()
}

// ResolveAlert resolves an alert
func (d *DataEngine) ResolveAlert(alertID string) bool {
	if d.alerting == nil {
		return false
	}

	resolved := d.alerting.ResolveAlert(alertID)

	// Broadcast to WebSocket clients if enabled
	if resolved && d.config.EnableWebSocket && d.websocket != nil && d.websocket.IsRunning() {
		d.websocket.Broadcast(map[string]interface{}{
			"type":     "alert_resolved",
			"alert_id": alertID,
		})
	}

	return resolved
}

// IsRunning returns whether the data engine is running
func (d *DataEngine) IsRunning() bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	return d.isRunning
}

// GetProducer returns the event producer
func (d *DataEngine) GetProducer() *EventProducer {
	return d.producer
}

// GetChromaDB returns the ChromaDB instance
func (d *DataEngine) GetChromaDB() *ChromaDB {
	return d.chromaDB
}

// GetAlerting returns the alerting system
func (d *DataEngine) GetAlerting() *AlertingSystem {
	return d.alerting
}

// GetAggregator returns the windowed aggregator
func (d *DataEngine) GetAggregator() *WindowedAggregator {
	return d.aggregator
}

// GetMetrics returns the current metrics
func (d *DataEngine) GetMetrics() *MetricsSnapshot {
	if d.processor == nil {
		return nil
	}

	return d.processor.GetMetrics()
}

// GetWebSocketClientCount returns the number of connected WebSocket clients
func (d *DataEngine) GetWebSocketClientCount() int {
	if d.websocket == nil {
		return 0
	}

	return d.websocket.GetClientCount()
}

// IsWebSocketRunning returns whether the WebSocket server is running
func (d *DataEngine) IsWebSocketRunning() bool {
	if d.websocket == nil {
		return false
	}

	return d.websocket.IsRunning()
}

// IsRESTAPIRunning returns whether the REST API server is running
func (d *DataEngine) IsRESTAPIRunning() bool {
	if d.restAPI == nil {
		return false
	}

	return d.restAPI.IsRunning()
}

// GetWebSocketServer returns the WebSocket server instance
func (d *DataEngine) GetWebSocketServer() *WebSocketServer {
	return d.websocket
}
