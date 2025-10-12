package guardian

import (
	"archguardian/data_engine"
	"archguardian/inference_engine"
	"archguardian/internal/config"
	"archguardian/internal/remediation"
	"archguardian/internal/risk"
	"archguardian/internal/scanner"
	"archguardian/internal/utils"
	"archguardian/types"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	"github.com/gorilla/websocket"
)

// wsConnection wraps a WebSocket connection with a mutex for safe concurrent writes
type wsConnection struct {
	conn  *websocket.Conn
	mutex *sync.Mutex
}

// WriteMessage safely writes a message to the WebSocket connection
func (wsc *wsConnection) WriteMessage(messageType int, data []byte) error {
	wsc.mutex.Lock()
	defer wsc.mutex.Unlock()
	// Set write deadline to prevent blocking indefinitely
	// Increased to 30 seconds to accommodate slower network conditions and busy clients
	wsc.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return wsc.conn.WriteMessage(messageType, data)
}

// WriteJSON safely writes JSON to the WebSocket connection
func (wsc *wsConnection) WriteJSON(v interface{}) error {
	wsc.mutex.Lock()
	defer wsc.mutex.Unlock()
	// Set write deadline to prevent blocking indefinitely
	// Increased to 30 seconds to accommodate slower network conditions and busy clients
	wsc.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return wsc.conn.WriteJSON(v)
}

// broadcastMessage represents a message to be broadcast to all WebSocket clients
type broadcastMessage struct {
	data []byte
}

// ArchGuardian is the main orchestration component that coordinates all services
type ArchGuardian struct {
	config          *config.Config
	scanner         *scanner.Scanner
	diagnoser       *risk.RiskDiagnoser
	remediator      *remediation.Remediator
	baseline        *BaselineChecker
	dataEngine      *data_engine.DataEngine
	chromemManager  *data_engine.ChromemManager // Persistent storage for knowledge graph and risks
	logWriter       *logWriter                  // Real-time log streaming to dashboard
	triggerScan     chan bool                   // Channel to trigger manual scans
	dashboardConns  []*wsConnection             // Connected dashboard WebSocket clients
	connMutex       sync.Mutex                  // Mutex for dashboard connections list
	baselineStarted bool                        // Whether baseline periodic updates have been started
	baselineMutex   sync.Mutex                  // Protects baselineStarted
	projectID       string                      // Unique identifier for the current project
	broadcastChan   chan broadcastMessage       // Channel for broadcasting messages to WebSocket clients
	broadcastDone   chan struct{}               // Channel to signal broadcast goroutine shutdown
}

const (
	baselineFeaturesURL = "https://raw.githubusercontent.com/web-platform-dx/web-features/main/feature-group-definitions/baseline.json"
	updateInterval      = 24 * time.Hour
)

// BaselineFeature represents a single feature from the web-features dataset.
type BaselineFeature struct {
	Identifier string `json:"identifier"`
	MdnURL     string `json:"mdn_url"`
}

// BaselineChecker holds the set of baseline features for quick lookups.
type BaselineChecker struct {
	cssProperties  map[string]BaselineFeature
	jsAPIs         map[string]BaselineFeature
	htmlElements   map[string]BaselineFeature
	htmlAttributes map[string]BaselineFeature // Global attributes
	lastUpdated    time.Time
	mutex          sync.RWMutex
	stopChan       chan struct{}
}

// NewBaselineChecker initializes the checker and starts periodic updates.
func NewBaselineChecker(ctx context.Context) *BaselineChecker {
	bc := &BaselineChecker{
		cssProperties:  make(map[string]BaselineFeature),
		jsAPIs:         make(map[string]BaselineFeature),
		htmlElements:   make(map[string]BaselineFeature),
		htmlAttributes: make(map[string]BaselineFeature),
		stopChan:       make(chan struct{}),
	}
	return bc
}

// ensureFeaturesLoaded ensures that baseline features are loaded before use
func (bc *BaselineChecker) ensureFeaturesLoaded() {
	bc.mutex.RLock()
	featuresLoaded := len(bc.cssProperties) > 0 || len(bc.jsAPIs) > 0 || len(bc.htmlElements) > 0
	bc.mutex.RUnlock()

	if !featuresLoaded {
		log.Println("🔄 Loading Baseline web features for the first time...")
		bc.updateFeatures()
	}
}

// updateFeatures fetches the latest Baseline feature set.
func (bc *BaselineChecker) updateFeatures() {
	log.Println("🔄 Updating Baseline web features...")
	resp, err := http.Get(baselineFeaturesURL)
	if err != nil {
		log.Printf("⚠️  Failed to fetch Baseline features: %v", err)
		return
	}
	defer resp.Body.Close()

	// Check if response is successful
	if resp.StatusCode != http.StatusOK {
		log.Printf("⚠️  Failed to fetch Baseline features: HTTP %d", resp.StatusCode)
		return
	}

	var payload struct {
		Features []struct {
			Identifier string `json:"identifier"`
			MdnUrl     string `json:"mdn_url"`
		} `json:"features"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		log.Printf("⚠️  Failed to parse Baseline features JSON: %v", err)
		return
	}

	// Validate that we got features data
	if len(payload.Features) == 0 {
		log.Printf("⚠️  No features found in Baseline data")
		return
	}

	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// Clear old data
	bc.cssProperties = make(map[string]BaselineFeature)
	bc.jsAPIs = make(map[string]BaselineFeature)
	bc.htmlElements = make(map[string]BaselineFeature)
	bc.htmlAttributes = make(map[string]BaselineFeature)

	for _, f := range payload.Features {
		identifier := f.Identifier
		feature := BaselineFeature{Identifier: identifier, MdnURL: f.MdnUrl}

		if strings.HasPrefix(identifier, "css.properties.") {
			// e.g., css.properties.border-radius -> border-radius
			prop := strings.TrimPrefix(identifier, "css.properties.")
			bc.cssProperties[prop] = feature
		} else if strings.HasPrefix(identifier, "api.") {
			// e.g., api.Fetch -> Fetch
			api := strings.TrimPrefix(identifier, "api.")
			bc.jsAPIs[api] = feature
		} else if strings.HasPrefix(identifier, "html.elements.") {
			// e.g., html.elements.a -> a
			element := strings.TrimPrefix(identifier, "html.elements.")
			if !strings.Contains(element, ".attributes.") {
				bc.htmlElements[element] = feature
			}
		} else if strings.HasPrefix(identifier, "html.global_attributes.") {
			// e.g., html.global_attributes.hidden -> hidden
			attr := strings.TrimPrefix(identifier, "html.global_attributes.")
			bc.htmlAttributes[attr] = feature
		}
	}

	bc.lastUpdated = time.Now()
	log.Printf("✅ Baseline features updated. Found %d CSS properties, %d JS APIs, %d HTML elements.", len(bc.cssProperties), len(bc.jsAPIs), len(bc.htmlElements))
}

// startPeriodicUpdates runs updateFeatures immediately and then on a ticker.
func (bc *BaselineChecker) startPeriodicUpdates() {
	bc.updateFeatures() // Initial fetch
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bc.updateFeatures()
		case <-bc.stopChan:
			return
		}
	}
}

// Stop halts the periodic updates.
func (bc *BaselineChecker) Stop() {
	close(bc.stopChan)
}

// GetCSSProperty checks if a CSS property is in the Baseline set.
func (bc *BaselineChecker) GetCSSProperty(property string) (BaselineFeature, bool) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	feature, exists := bc.cssProperties[strings.ToLower(property)]
	return feature, exists
}

// GetJSAPI checks if a JavaScript API is in the Baseline set.
func (bc *BaselineChecker) GetJSAPI(api string) (BaselineFeature, bool) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	feature, exists := bc.jsAPIs[api]
	return feature, exists
}

// GetHTMLElement checks if an HTML element is in the Baseline set.
func (bc *BaselineChecker) GetHTMLElement(element string) (BaselineFeature, bool) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	feature, exists := bc.htmlElements[strings.ToLower(element)]
	return feature, exists
}

// GetHTMLAttribute checks if an HTML attribute is in the Baseline set (global attributes).
func (bc *BaselineChecker) GetHTMLAttribute(attribute string) (BaselineFeature, bool) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	feature, exists := bc.htmlAttributes[strings.ToLower(attribute)]
	return feature, exists
}

// logWriter is a custom writer to pipe log output to the WebSocket
type logWriter struct {
	ag            *ArchGuardian
	initialLogs   [][]byte
	bufferMutex   sync.Mutex
	clientReady   bool
	maxBufferSize int
}

// Write implements io.Writer interface for log redirection
func (lw *logWriter) Write(p []byte) (n int, err error) {
	// Write to original stdout
	n, err = os.Stdout.Write(p)

	// Create standardized WebSocket message for frontend compatibility
	message := createWebSocketMessage("log", map[string]interface{}{
		"message": strings.TrimSpace(string(p)),
		"level":   "info",
	})

	jsonMessage, jsonErr := json.Marshal(message)
	if jsonErr != nil {
		// If JSON marshaling fails, fall back to original behavior
		jsonMessage = p
	}

	lw.bufferMutex.Lock()
	clientReady := lw.clientReady
	shouldBuffer := !clientReady
	if shouldBuffer {
		// Buffer the initial logs
		if lw.maxBufferSize == 0 {
			lw.maxBufferSize = 100 // Default max buffer size
		}
		if len(lw.initialLogs) < lw.maxBufferSize {
			// Create a copy of the byte slice to avoid data races
			logCopy := make([]byte, len(jsonMessage))
			copy(logCopy, jsonMessage)
			lw.initialLogs = append(lw.initialLogs, logCopy)
		}
	}
	lw.bufferMutex.Unlock()

	// Broadcast outside the lock to avoid holding it during I/O
	if clientReady && lw.ag != nil {
		lw.ag.broadcastLogToDashboard(string(jsonMessage))
	}

	return n, err
}

// FlushInitialLogs flushes buffered logs to the WebSocket client when it connects
func (lw *logWriter) FlushInitialLogs() {
	lw.bufferMutex.Lock()
	defer lw.bufferMutex.Unlock()
	lw.clientReady = true
	for _, logBytes := range lw.initialLogs {
		if lw.ag != nil {
			lw.ag.broadcastLogToDashboard(string(logBytes))
		}
	}
	// Clear the buffer after flushing
	lw.initialLogs = nil
}

// createWebSocketMessage creates a standardized WebSocket message for frontend compatibility
func createWebSocketMessage(msgType string, data interface{}) map[string]interface{} {
	message := map[string]interface{}{
		"type":      msgType,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	// Handle different data formats for frontend compatibility
	switch msgType {
	case "log":
		if logData, ok := data.(map[string]interface{}); ok {
			message["data"] = logData
		} else {
			message["data"] = map[string]interface{}{
				"message": data,
				"level":   "info",
			}
		}
	case "scan_cycle_completed", "security_vulnerability_found", "remediation_completed":
		message["data"] = data
	case "scan_progress":
		message["data"] = data
	default:
		message["data"] = data
	}

	return message
}

// NewArchGuardian creates a new ArchGuardian instance with all dependencies
func NewArchGuardian(config *config.Config, aiEngine *inference_engine.InferenceService, chromemManager *data_engine.ChromemManager) *ArchGuardian {
	log.Println("🚀 Initializing ArchGuardian Core...")

	// Initialize data engine if enabled
	var de *data_engine.DataEngine
	if config.DataEngine.Enable {
		log.Println("📈 Initializing Data Engine...")
		// Convert main.go config to data_engine config
		deConfig := data_engine.DataEngineConfig{
			EnableKafka:      config.DataEngine.EnableKafka,
			KafkaBrokers:     config.DataEngine.KafkaBrokers,
			ChromaDBURL:      config.DataEngine.ChromaDBURL,
			ChromaCollection: config.DataEngine.ChromaCollection,
			EnableChromaDB:   config.DataEngine.EnableChromaDB,
			EnableWebSocket:  config.DataEngine.EnableWebSocket,
			WebSocketPort:    config.DataEngine.WebSocketPort,
			EnableRESTAPI:    config.DataEngine.EnableRESTAPI,
			RESTAPIPort:      config.DataEngine.RESTAPIPort,
			WindowSize:       1 * time.Minute,
			MetricsInterval:  30 * time.Second,
		}
		de = data_engine.NewDataEngine(deConfig)
		if err := de.Start(); err != nil {
			log.Printf("⚠️  Data Engine failed to start: %v. Continuing without it.", err)
			de = nil // Ensure data engine is nil if it fails
		} else {
			log.Println("✅ Data Engine started successfully.")
		}
	}

	// Initialize scanner
	scannerInstance := scanner.NewScanner(config, aiEngine)
	log.Println("✅ Scanner initialized successfully")

	// Initialize risk diagnoser
	diagnoser := risk.NewRiskDiagnoser(scannerInstance, aiEngine, nil) // TODO: Pass proper Codacy client when implemented
	log.Println("✅ Risk diagnoser initialized successfully")

	// Initialize remediator
	remediatorInstance := remediation.NewRemediator(config, diagnoser, aiEngine)
	log.Println("✅ Remediator initialized successfully")

	// Generate project ID from project path
	projectID := generateProjectID(config.ProjectPath)
	log.Printf("📋 Project ID: %s", projectID)

	guardian := &ArchGuardian{
		config:         config,
		scanner:        scannerInstance,
		diagnoser:      diagnoser,
		remediator:     remediatorInstance,
		baseline:       NewBaselineChecker(context.Background()),
		dataEngine:     de,
		chromemManager: chromemManager,
		triggerScan:    make(chan bool), // Initialize the channel
		projectID:      projectID,
		broadcastChan:  make(chan broadcastMessage, 100), // Buffered channel for broadcasts
		broadcastDone:  make(chan struct{}),
	}

	// Start the broadcast worker goroutine
	go guardian.broadcastWorker()

	// Initialize and activate logWriter for real-time log streaming to dashboard
	lw := &logWriter{
		ag:          guardian,
		initialLogs: make([][]byte, 0, 100),
		clientReady: false,
	}
	guardian.logWriter = lw

	// Set up callback to flush logs when WebSocket client connects
	if guardian.dataEngine != nil {
		guardian.dataEngine.SetOnClientReadyCallback(func() {
			guardian.FlushInitialLogs()
		})
	}

	// Redirect standard log output to our custom writer
	log.SetOutput(lw)

	log.Println("✅ ArchGuardian Core initialized successfully")
	return guardian
}

// Run starts the main ArchGuardian event loop
func (ag *ArchGuardian) Run(ctx context.Context) error {
	log.Println("🚀 ArchGuardian starting...")
	log.Printf("📁 Project: %s", ag.config.ProjectPath)
	log.Printf("🤖 AI Providers: Gemini (primary), DeepSeek (fallback), %s (remediation)",
		ag.config.AIProviders.CodeRemediationProvider)
	log.Println("✅ ArchGuardian is running. Waiting for scan trigger from API or periodic schedule...")

	// Baseline periodic updates are started lazily when a project scan is triggered
	// to avoid performing network requests during initial application load. However,
	// tests or developer workflows can opt-in to start baseline on init by setting
	// the START_BASELINE_ON_INIT environment variable to true.
	if getEnvBool("START_BASELINE_ON_INIT", false) {
		go ag.baseline.startPeriodicUpdates()
		log.Println("🔄 Baseline periodic updates started at initialization (START_BASELINE_ON_INIT=true).")
	}

	// Log environment information using getEnv function
	log.Printf("📁 Project path: %s", getEnv("PROJECT_PATH", ag.config.ProjectPath))
	log.Printf("🤖 AI Provider: %s", getEnv("AI_PROVIDER", "gemini"))

	ticker := time.NewTicker(ag.config.ScanInterval)
	defer ticker.Stop()

	// Run scans based on ticker or manual trigger
	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 ArchGuardian shutting down...")
			return ctx.Err()
		case <-ag.triggerScan: // Handle manual scan trigger
			log.Println("⚡ Manual scan triggered via API.")
			if err := ag.runCycle(ctx); err != nil {
				log.Printf("❌ Manual scan cycle failed: %v", err)
			}
			// Reset the ticker to align with the manual scan time, preventing immediate double scan
			ticker.Reset(ag.config.ScanInterval)
		case <-ticker.C:
			if err := ag.runCycle(ctx); err != nil {
				log.Printf("❌ Scan cycle failed: %v", err)
			}
		}
	}
}

// StartBaselineIfNeeded starts the baseline checker's periodic updates the first time
// it is required (for example when a project scan is initiated). This avoids
// performing network calls during application startup.
func (ag *ArchGuardian) StartBaselineIfNeeded(ctx context.Context) {
	ag.baselineMutex.Lock()
	started := ag.baselineStarted
	if !started {
		ag.baselineStarted = true
	}
	ag.baselineMutex.Unlock()

	if started {
		return
	}

	if ag.baseline != nil {
		go ag.baseline.startPeriodicUpdates()
		log.Println("🔄 Baseline periodic updates started on demand.")
	}
}

// RunCycle executes a complete scan cycle with all phases (public method for external callers)
func (ag *ArchGuardian) RunCycle(ctx context.Context) error {
	return ag.runCycle(ctx)
}

// runCycle executes a complete scan cycle with all phases
func (ag *ArchGuardian) runCycle(ctx context.Context) error {
	log.Println("\n" + strings.Repeat("=", 80))
	log.Printf("🔄 Starting scan cycle at %s", time.Now().Format(time.RFC3339))
	log.Println(strings.Repeat("=", 80))

	ag.produceSystemEvent(data_engine.SystemEventType, "scan_cycle_started", nil)
	ag.sendProgressUpdate("scan_started", 0, "Initializing scan cycle...")

	// Phase 1: Scan project
	ag.sendProgressUpdate("scan_project", 5, "Starting project scan...")
	ag.sendProgressUpdate("scan_project", 10, "Analyzing project structure...")

	if err := ag.scanner.ScanProject(ctx); err != nil {
		ag.sendProgressUpdate("scan_failed", 0, fmt.Sprintf("Scan failed: %v", err))
		ag.produceSystemEvent(data_engine.ErrorEvent, "scan_project_failed", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("scan failed: %w", err)
	}
	ag.sendProgressUpdate("scan_project", 40, fmt.Sprintf("Project scan completed. Found %d nodes.", len(ag.scanner.GetKnowledgeGraph().Nodes)))
	ag.produceSystemEvent(data_engine.SystemEventType, "scan_project_completed", map[string]interface{}{"node_count": len(ag.scanner.GetKnowledgeGraph().Nodes)})

	// Phase 1.5: Check for non-Baseline web features
	ag.sendProgressUpdate("compatibility_check", 45, "Checking web compatibility...")
	compatIssues := ag.checkForBaselineCompatibility()
	log.Printf("✅ Web compatibility check complete. Found %d non-Baseline features.", len(compatIssues))
	ag.diagnoser.AddManualIssues(compatIssues)
	ag.sendProgressUpdate("compatibility_check", 50, fmt.Sprintf("Compatibility check completed. Found %d issues.", len(compatIssues)))

	// Export knowledge graph
	ag.sendProgressUpdate("export_data", 55, "Exporting knowledge graph...")
	if err := ag.exportKnowledgeGraph(); err != nil {
		log.Printf("⚠️  Failed to export knowledge graph: %v", err)
	}
	ag.sendProgressUpdate("export_data", 60, "Knowledge graph exported.")

	// Phase 2: Diagnose risks
	ag.sendProgressUpdate("risk_analysis", 65, "Analyzing security risks...")
	ag.sendProgressUpdate("risk_analysis", 70, "Checking for vulnerabilities...")
	ag.sendProgressUpdate("risk_analysis", 75, "Analyzing technical debt...")

	assessment, err := ag.diagnoser.DiagnoseRisks(ctx)
	if err != nil {
		ag.sendProgressUpdate("risk_analysis_failed", 0, fmt.Sprintf("Risk analysis failed: %v", err))
		ag.produceSystemEvent(data_engine.ErrorEvent, "diagnose_risks_failed", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("risk diagnosis failed: %w", err)
	}
	ag.sendProgressUpdate("risk_analysis", 80, fmt.Sprintf("Risk analysis completed. Score: %.1f/100", assessment.OverallScore))
	ag.produceSystemEvent(data_engine.SystemEventType, "diagnose_risks_completed", map[string]interface{}{"overall_score": assessment.OverallScore})

	// Broadcast security vulnerabilities found
	for _, vuln := range assessment.SecurityVulns {
		if ag.dataEngine != nil {
			ag.dataEngine.BroadcastSecurityVulnerability(vuln)
		}
		ag.sendProgressUpdate("security_alert", 82, fmt.Sprintf("Security vulnerability found: %s", vuln.CVE))
	}

	// Export risk assessment
	ag.sendProgressUpdate("export_assessment", 85, "Exporting risk assessment...")
	if err := ag.exportRiskAssessment(assessment); err != nil {
		log.Printf("⚠️  Failed to export risk assessment: %v", err)
	}
	ag.sendProgressUpdate("export_assessment", 90, "Risk assessment exported.")

	// Phase 3: Automated remediation
	if assessment.OverallScore > 20.0 { // Only remediate if risk score is significant
		ag.sendProgressUpdate("remediation", 95, "Starting automated remediation...")
		ag.sendProgressUpdate("remediation", 96, "Analyzing remediation options...")

		if err := ag.remediator.RemediateRisks(ctx, assessment); err != nil {
			ag.sendProgressUpdate("remediation_failed", 0, fmt.Sprintf("Remediation failed: %v", err))
			ag.produceSystemEvent(data_engine.ErrorEvent, "remediation_failed", map[string]interface{}{"error": err.Error()})
			log.Printf("⚠️  Remediation failed: %v", err)
		} else {
			ag.sendProgressUpdate("remediation", 100, "Remediation completed successfully.")
			if ag.dataEngine != nil {
				ag.dataEngine.BroadcastRemediationCompleted(map[string]interface{}{
					"status":    "completed",
					"timestamp": time.Now(),
				})
			}
		}
	} else {
		ag.sendProgressUpdate("remediation_skipped", 100, "System health is good, no remediation needed.")
		ag.produceSystemEvent(data_engine.SystemEventType, "remediation_skipped", map[string]interface{}{"reason": "System health is good", "overall_score": assessment.OverallScore})
		log.Println("✅ System health is good, no remediation needed")
	}

	log.Println(strings.Repeat("=", 80))
	log.Printf("✅ Scan cycle complete. Overall risk score: %.2f/100", assessment.OverallScore)
	log.Println(strings.Repeat("=", 80) + "\n")

	ag.sendProgressUpdate("scan_completed", 100, fmt.Sprintf("Scan cycle complete. Risk score: %.1f/100", assessment.OverallScore))
	ag.produceSystemEvent(data_engine.SystemEventType, "scan_cycle_completed", map[string]interface{}{"overall_score": assessment.OverallScore})
	return nil
}

// checkForBaselineCompatibility scans frontend files for non-Baseline features.
func (ag *ArchGuardian) checkForBaselineCompatibility() []types.TechnicalDebtItem {
	// Ensure baseline features are loaded before checking compatibility
	ag.baseline.ensureFeaturesLoaded()

	var issues []types.TechnicalDebtItem
	cssRegex := regexp.MustCompile(`([a-zA-Z-]+)\s*:`)

	for _, node := range ag.scanner.GetKnowledgeGraph().Nodes {
		if node.Type != types.NodeTypeCode {
			continue
		}

		switch {
		case strings.HasSuffix(node.Path, ".css"):
			content, err := os.ReadFile(node.Path)
			if err != nil {
				continue
			}
			matches := cssRegex.FindAllStringSubmatch(string(content), -1)
			for _, match := range matches {
				prop := match[1]
				if _, exists := ag.baseline.GetCSSProperty(prop); !exists {
					issues = append(issues, createCompatIssue(node.Path, "css", prop, "CSS Property"))
				}
			}

		case strings.HasSuffix(node.Path, ".js") || strings.HasSuffix(node.Path, ".ts"):
			content, err := os.ReadFile(node.Path)
			if err != nil {
				continue
			}
			// Use esbuild for robust JS/TS parsing
			apis := ag.parseJavaScriptAPIs(string(content))
			for api := range apis {
				if _, exists := ag.baseline.GetJSAPI(api); !exists {
					issues = append(issues, createCompatIssue(node.Path, "js", api, "JavaScript API"))
				}
			}

		case strings.HasSuffix(node.Path, ".html"):
			content, err := os.ReadFile(node.Path)
			if err != nil {
				continue
			}
			issues = append(issues, ag.parseHTMLFeatures(node.Path, string(content))...)
		}
	}

	return issues
}

// parseJavaScriptAPIs parses JavaScript/TypeScript files to extract API usage patterns
func (ag *ArchGuardian) parseJavaScriptAPIs(content string) map[string]bool {
	apis := make(map[string]bool)

	// Simple regex patterns to detect common JavaScript APIs
	patterns := []string{
		`\b(document\.[a-zA-Z]+)\b`,
		`\b(window\.[a-zA-Z]+)\b`,
		`\b(navigator\.[a-zA-Z]+)\b`,
		`\b(console\.[a-zA-Z]+)\b`,
		`\b(Math\.[a-zA-Z]+)\b`,
		`\b(JSON\.[a-zA-Z]+)\b`,
		`\b(Promise\.[a-zA-Z]+)\b`,
		`\b(fetch\.[a-zA-Z]+)\b`,
		`\b(localStorage\.[a-zA-Z]+)\b`,
		`\b(sessionStorage\.[a-zA-Z]+)\b`,
		`\b(history\.[a-zA-Z]+)\b`,
		`\b(location\.[a-zA-Z]+)\b`,
		`\b(performance\.[a-zA-Z]+)\b`,
		`\b(Intl\.[a-zA-Z]+)\b`,
		`\b(URL\.[a-zA-Z]+)\b`,
		`\b(URLSearchParams\.[a-zA-Z]+)\b`,
		`\b(Headers\.[a-zA-Z]+)\b`,
		`\b(Request\.[a-zA-Z]+)\b`,
		`\b(Response\.[a-zA-Z]+)\b`,
		`\b(FormData\.[a-zA-Z]+)\b`,
		`\b(Blob\.[a-zA-Z]+)\b`,
		`\b(File\.[a-zA-Z]+)\b`,
		`\b(FileReader\.[a-zA-Z]+)\b`,
		`\b(WebSocket\.[a-zA-Z]+)\b`,
		`\b(EventSource\.[a-zA-Z]+)\b`,
		`\b(Worker\.[a-zA-Z]+)\b`,
		`\b(SharedWorker\.[a-zA-Z]+)\b`,
		`\b(ServiceWorker\.[a-zA-Z]+)\b`,
		`\b(Cache\.[a-zA-Z]+)\b`,
		`\b(IndexedDB\.[a-zA-Z]+)\b`,
		`\b(WebGL\.[a-zA-Z]+)\b`,
		`\b(CanvasRenderingContext2D\.[a-zA-Z]+)\b`,
		`\b(CanvasRenderingContextWebGL\.[a-zA-Z]+)\b`,
		`\b(AudioContext\.[a-zA-Z]+)\b`,
		`\b(MediaStream\.[a-zA-Z]+)\b`,
		`\b(MediaRecorder\.[a-zA-Z]+)\b`,
		`\b(Geolocation\.[a-zA-Z]+)\b`,
		`\b(Notification\.[a-zA-Z]+)\b`,
		`\b(Permissions\.[a-zA-Z]+)\b`,
		`\b(CredentialsContainer\.[a-zA-Z]+)\b`,
		`\b(PaymentRequest\.[a-zA-Z]+)\b`,
		`\b(IntersectionObserver\.[a-zA-Z]+)\b`,
		`\b(MutationObserver\.[a-zA-Z]+)\b`,
		`\b(ResizeObserver\.[a-zA-Z]+)\b`,
		`\b(PerformanceObserver\.[a-zA-Z]+)\b`,
		`\b(ReportingObserver\.[a-zA-Z]+)\b`,
		`\b(AbortController\.[a-zA-Z]+)\b`,
		`\b(AbortSignal\.[a-zA-Z]+)\b`,
		`\b(CustomEvent\.[a-zA-Z]+)\b`,
		`\b(Event\.[a-zA-Z]+)\b`,
		`\b(Error\.[a-zA-Z]+)\b`,
		`\b(TypeError\.[a-zA-Z]+)\b`,
		`\b(ReferenceError\.[a-zA-Z]+)\b`,
		`\b(SyntaxError\.[a-zA-Z]+)\b`,
		`\b(RangeError\.[a-zA-Z]+)\b`,
		`\b(EvalError\.[a-zA-Z]+)\b`,
		`\b(URIError\.[a-zA-Z]+)\b`,
		`\b(InternalError\.[a-zA-Z]+)\b`,
		`\b(AggregateError\.[a-zA-Z]+)\b`,
		`\b(Proxy\.[a-zA-Z]+)\b`,
		`\b(Reflect\.[a-zA-Z]+)\b`,
		`\b(Symbol\.[a-zA-Z]+)\b`,
		`\b(Map\.[a-zA-Z]+)\b`,
		`\b(Set\.[a-zA-Z]+)\b`,
		`\b(WeakMap\.[a-zA-Z]+)\b`,
		`\b(WeakSet\.[a-zA-Z]+)\b`,
		`\b(Array\.[a-zA-Z]+)\b`,
		`\b(Object\.[a-zA-Z]+)\b`,
		`\b(Function\.[a-zA-Z]+)\b`,
		`\b(String\.[a-zA-Z]+)\b`,
		`\b(Number\.[a-zA-Z]+)\b`,
		`\b(Boolean\.[a-zA-Z]+)\b`,
		`\b(Date\.[a-zA-Z]+)\b`,
		`\b(RegExp\.[a-zA-Z]+)\b`,
		`\b(Error\.[a-zA-Z]+)\b`,
		`\b(ArrayBuffer\.[a-zA-Z]+)\b`,
		`\b(DataView\.[a-zA-Z]+)\b`,
		`\b(Int8Array\.[a-zA-Z]+)\b`,
		`\b(Uint8Array\.[a-zA-Z]+)\b`,
		`\b(Uint8ClampedArray\.[a-zA-Z]+)\b`,
		`\b(Int16Array\.[a-zA-Z]+)\b`,
		`\b(Uint16Array\.[a-zA-Z]+)\b`,
		`\b(Int32Array\.[a-zA-Z]+)\b`,
		`\b(Uint32Array\.[a-zA-Z]+)\b`,
		`\b(Float32Array\.[a-zA-Z]+)\b`,
		`\b(Float64Array\.[a-zA-Z]+)\b`,
		`\b(BigInt64Array\.[a-zA-Z]+)\b`,
		`\b(BigUint64Array\.[a-zA-Z]+)\b`,
		`\b(Atomics\.[a-zA-Z]+)\b`,
		`\b(SharedArrayBuffer\.[a-zA-Z]+)\b`,
		`\b(WebAssembly\.[a-zA-Z]+)\b`,
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				apis[match[1]] = true
			}
		}
	}

	return apis
}

// parseHTMLFeatures uses the standard HTML parser to find tags and attributes.
func (ag *ArchGuardian) parseHTMLFeatures(filePath, content string) []types.TechnicalDebtItem {
	var issues []types.TechnicalDebtItem
	tokenizer := html.NewTokenizer(strings.NewReader(content))

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return issues // End of document
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			// Check element
			if _, exists := ag.baseline.GetHTMLElement(token.Data); !exists {
				issues = append(issues, createCompatIssue(filePath, "html", token.Data, "HTML Element"))
			}
			// Check attributes
			for _, attr := range token.Attr {
				// Check if attribute is in baseline (global attributes)
				if _, exists := ag.baseline.GetHTMLAttribute(attr.Key); !exists {
					issues = append(issues, createCompatIssue(filePath, "html", fmt.Sprintf("%s.%s", token.Data, attr.Key), "HTML Attribute"))
				}
			}
		}
	}
}

// createCompatIssue is a helper to create a TechnicalDebtItem for compatibility issues.
func createCompatIssue(location, featureType, featureName, featureDescription string) types.TechnicalDebtItem {
	// A more sophisticated version could fetch the MDN URL from the baseline checker
	mdnURL := fmt.Sprintf("https://developer.mozilla.org/en-US/search?q=%s", url.QueryEscape(featureName))

	return types.TechnicalDebtItem{
		ID:          fmt.Sprintf("COMPAT-%s-%s", featureType, featureName),
		Location:    location,
		Type:        "compatibility",
		Severity:    "low",
		Description: fmt.Sprintf("Usage of non-Baseline %s: '%s'", featureDescription, featureName),
		Remediation: fmt.Sprintf("This feature may not be supported in all browsers. Consider replacing it with a widely-supported alternative or adding fallbacks/polyfills. See MDN for details: %s", mdnURL),
	}
}

// generateProjectID generates a unique project ID from the project path
func generateProjectID(projectPath string) string {
	// Get absolute path to ensure consistency
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		absPath = projectPath
	}

	// Create a hash of the absolute path
	hash := sha256.Sum256([]byte(absPath))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes (16 hex chars)
}

// getProjectDataDir returns the OS-specific data directory for the current project
func (ag *ArchGuardian) getProjectDataDir() (string, error) {
	// Get the base ArchGuardian data directory
	baseDataPath, err := utils.GetArchGuardianDataPath()
	if err != nil {
		return "", fmt.Errorf("failed to get data directory: %w", err)
	}

	// Create project-specific subdirectory
	projectDataDir := filepath.Join(baseDataPath, "projects", ag.projectID)

	// Ensure directory exists
	if err := os.MkdirAll(projectDataDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create project data directory: %w", err)
	}

	return projectDataDir, nil
}

// exportKnowledgeGraph exports the knowledge graph to a file
func (ag *ArchGuardian) exportKnowledgeGraph() error {
	// Get the project-specific data directory
	projectDataDir, err := ag.getProjectDataDir()
	if err != nil {
		return fmt.Errorf("failed to get project data directory: %w", err)
	}

	// Save to OS-specific data directory
	outputPath := filepath.Join(projectDataDir, "knowledge-graph.json")

	data, err := json.MarshalIndent(ag.scanner.GetKnowledgeGraph().ToAPIFormat(), "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal knowledge graph: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write knowledge graph: %w", err)
	}

	log.Printf("📊 Knowledge graph exported to: %s", outputPath)

	// Persist knowledge graph nodes to chromem database for structured querying and vector search
	if ag.chromemManager != nil {
		kg := ag.scanner.GetKnowledgeGraph()
		nodeCount := 0
		errorCount := 0

		for _, node := range kg.Nodes {
			if err := ag.chromemManager.UpsertNode(node); err != nil {
				log.Printf("⚠️  Failed to persist node %s to chromem database: %v", node.ID, err)
				errorCount++
			} else {
				nodeCount++
			}
		}

		if errorCount > 0 {
			log.Printf("⚠️  Persisted %d/%d knowledge graph nodes to chromem database (%d errors)",
				nodeCount, len(kg.Nodes), errorCount)
		} else {
			log.Printf("✅ Persisted %d knowledge graph nodes to chromem database", nodeCount)
		}
	}

	return nil
}

// exportRiskAssessment exports the risk assessment to a file
func (ag *ArchGuardian) exportRiskAssessment(assessment *types.RiskAssessment) error {
	// Get the project-specific data directory
	projectDataDir, err := ag.getProjectDataDir()
	if err != nil {
		return fmt.Errorf("failed to get project data directory: %w", err)
	}

	// Save to OS-specific data directory
	outputPath := filepath.Join(projectDataDir, "risk-assessment.json")

	data, err := json.MarshalIndent(assessment, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal risk assessment: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write risk assessment: %w", err)
	}

	log.Printf("📊 Risk assessment exported to: %s", outputPath)

	// Persist to chromem database for structured querying and vector search
	if ag.chromemManager != nil {
		if err := ag.chromemManager.StoreRiskAssessment(assessment); err != nil {
			log.Printf("⚠️  Failed to persist risk assessment to chromem database: %v", err)
			// Don't fail the entire operation if database persistence fails
		} else {
			log.Println("✅ Risk assessment persisted to chromem database")
		}
	}

	return nil
}

// produceSystemEvent produces events to the data engine
func (ag *ArchGuardian) produceSystemEvent(eventType data_engine.EventType, subType string, data map[string]interface{}) {
	if ag.dataEngine == nil {
		return
	}

	if data == nil {
		data = make(map[string]interface{})
	}
	data["sub_type"] = subType

	event := data_engine.Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Source:    "archguardian_core",
		Data:      data,
	}

	if err := ag.dataEngine.ProcessEvent(event); err != nil {
		log.Printf("⚠️  Failed to produce system event to data engine: %v", err)
	}
}

// AddDashboardConnection adds a WebSocket connection to the list of dashboard clients
func (ag *ArchGuardian) AddDashboardConnection(conn *websocket.Conn) {
	ag.connMutex.Lock()
	defer ag.connMutex.Unlock()
	wsConn := &wsConnection{conn: conn, mutex: &sync.Mutex{}}
	ag.dashboardConns = append(ag.dashboardConns, wsConn)
	log.Printf("Dashboard client connected. Total clients: %d", len(ag.dashboardConns))
}

// RemoveDashboardConnection removes a WebSocket connection from the list of dashboard clients
func (ag *ArchGuardian) RemoveDashboardConnection(conn *websocket.Conn) {
	ag.connMutex.Lock()
	defer ag.connMutex.Unlock()

	for i, c := range ag.dashboardConns {
		if c.conn == conn {
			ag.dashboardConns = append(ag.dashboardConns[:i], ag.dashboardConns[i+1:]...)
			log.Printf("Dashboard client disconnected. Total clients: %d", len(ag.dashboardConns))
			break
		}
	}
}

// removeDashboardConnectionByWrapper removes a WebSocket connection by wrapper reference
func (ag *ArchGuardian) removeDashboardConnectionByWrapper(wsConn *wsConnection) {
	ag.connMutex.Lock()
	defer ag.connMutex.Unlock()

	for i, c := range ag.dashboardConns {
		if c == wsConn {
			ag.dashboardConns = append(ag.dashboardConns[:i], ag.dashboardConns[i+1:]...)
			log.Printf("Dashboard client disconnected. Total clients: %d", len(ag.dashboardConns))
			break
		}
	}
}

// broadcastWorker is a dedicated goroutine that handles all WebSocket broadcasts
// This ensures all writes happen sequentially, preventing concurrent write panics
func (ag *ArchGuardian) broadcastWorker() {
	for {
		select {
		case msg := <-ag.broadcastChan:
			ag.connMutex.Lock()
			// Create a copy of connections to avoid holding lock during writes
			conns := make([]*wsConnection, len(ag.dashboardConns))
			copy(conns, ag.dashboardConns)
			ag.connMutex.Unlock()

			// Write to connections without holding the list mutex
			for _, conn := range conns {
				if err := conn.WriteMessage(websocket.TextMessage, msg.data); err != nil {
					// Don't log here to avoid recursive logging
					// Remove broken connection
					go ag.removeDashboardConnectionByWrapper(conn)
				}
			}
		case <-ag.broadcastDone:
			return
		}
	}
}

// broadcastLogToDashboard broadcasts a raw string message to all connected dashboard clients.
func (ag *ArchGuardian) broadcastLogToDashboard(message string) {
	// Send to broadcast channel instead of writing directly
	select {
	case ag.broadcastChan <- broadcastMessage{data: []byte(message)}:
		// Message queued successfully
	default:
		// Channel full, drop message to avoid blocking
	}
}

// BroadcastToDashboard marshals a structured message and sends it to all connected clients.
// This is the centralized function for all WebSocket writes to prevent concurrent access.
func (ag *ArchGuardian) BroadcastToDashboard(messageType string, data interface{}) {
	wsMessage := createWebSocketMessage(messageType, data)

	jsonData, err := json.Marshal(wsMessage)
	if err != nil {
		log.Printf("Failed to marshal WebSocket message: %v", err)
		return
	}

	// Send to broadcast channel instead of writing directly
	select {
	case ag.broadcastChan <- broadcastMessage{data: jsonData}:
		// Message queued successfully
	default:
		// Channel full, drop message to avoid blocking
	}
}

// FlushInitialLogs flushes buffered logs to the WebSocket client when it connects
func (ag *ArchGuardian) FlushInitialLogs() {
	if ag.logWriter != nil {
		ag.logWriter.FlushInitialLogs()
	}
}

// sendProgressUpdate sends a progress update via WebSocket to all connected dashboard clients
func (ag *ArchGuardian) sendProgressUpdate(phase string, progress float64, message string) {
	progressUpdate := map[string]interface{}{
		"type":      "scan_progress",
		"phase":     phase,
		"progress":  progress,
		"message":   message,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	ag.BroadcastToDashboard("scan_progress", progressUpdate)
}

// GetScanner returns the scanner instance
func (ag *ArchGuardian) GetScanner() *scanner.Scanner {
	return ag.scanner
}

// GetDiagnoser returns the risk diagnoser instance
func (ag *ArchGuardian) GetDiagnoser() *risk.RiskDiagnoser {
	return ag.diagnoser
}

// GetRemediator returns the remediator instance
func (ag *ArchGuardian) GetRemediator() *remediation.Remediator {
	return ag.remediator
}

// GetDataEngine returns the data engine instance
func (ag *ArchGuardian) GetDataEngine() *data_engine.DataEngine {
	return ag.dataEngine
}

// GetChromemManager returns the chromem manager instance
func (ag *ArchGuardian) GetChromemManager() *data_engine.ChromemManager {
	return ag.chromemManager
}

// TriggerScan triggers a manual scan
func (ag *ArchGuardian) TriggerScan() {
	select {
	case ag.triggerScan <- true:
		log.Println("Manual scan triggered successfully")
	default:
		log.Println("Scan already in progress or trigger channel blocked")
	}
}

// GetStatus returns the current status of ArchGuardian
func (ag *ArchGuardian) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"running":             true,
		"project_path":        ag.config.ProjectPath,
		"scan_interval":       ag.config.ScanInterval.String(),
		"last_scan":           ag.scanner.GetKnowledgeGraph().LastUpdated,
		"node_count":          len(ag.scanner.GetKnowledgeGraph().Nodes),
		"edge_count":          len(ag.scanner.GetKnowledgeGraph().Edges),
		"dashboard_clients":   len(ag.dashboardConns),
		"data_engine_enabled": ag.dataEngine != nil,
		"baseline_started":    ag.baselineStarted,
	}
}

// Utility functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}
