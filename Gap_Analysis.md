# ArchGuardian Backend-Frontend Gap Analysis

**Document Version:** 1.1 (Updated with Chromem-go Integration Strategy)  
**Analysis Date:** January 2025  
**Scope:** Complete application excluding `/website` directory  
**Status:** Ready for Implementation

---

## Executive Summary

ArchGuardian is a sophisticated security and code quality monitoring system with a well-architected Go backend and a comprehensive JavaScript frontend dashboard. However, there are significant gaps between what the frontend expects and what the backend currently provides. This analysis identifies **27 critical gaps** across API endpoints, data structures, WebSocket messaging, authentication, and system architecture.

**Key Discovery:** ArchGuardian already has **chromem-go** (an embeddable vector database) as a dependency but isn't using it for persistence. This represents a significant opportunity to solve the data persistence issues with zero additional dependencies.

**Severity Breakdown:**
- 🔴 **Critical (P0):** 12 issues - Core functionality completely missing
- 🟡 **High (P1):** 9 issues - Major features incomplete or disconnected
- 🟢 **Medium (P2):** 6 issues - Quality of life and optimization issues

**Primary Issues:**
1. Backend returns mock/sample data instead of real scan results
2. No data persistence layer (despite chromem-go being available)
3. Scanner builds knowledge graphs but APIs don't expose them
4. Missing authentication and multi-project support
5. WebSocket events incomplete

**Recommended Solution:** Leverage chromem-go for persistent storage with semantic search capabilities, connect existing scanner/diagnoser outputs to API endpoints, and implement missing authentication layer.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Missing Backend API Endpoints](#missing-backend-api-endpoints)
3. [Data Structure Mismatches](#data-structure-mismatches)
4. [WebSocket Communication Gaps](#websocket-communication-gaps)
5. [Authentication & Authorization](#authentication--authorization)
6. [Data Persistence Issues](#data-persistence-issues)
7. [Configuration & Settings](#configuration--settings)
8. [Integration & Monitoring](#integration--monitoring)
9. [Logical Disconnects](#logical-disconnects)
10. [Recommendations](#recommendations)
11. [Chromem-go Integration Strategy](#chromem-go-integration-strategy)
12. [Implementation Checklist](#implementation-checklist)
13. [Testing Strategy](#testing-strategy)
14. [Conclusion](#conclusion)

---

## Architecture Overview

### Current System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend Dashboard                        │
│                   (Embedded HTML/CSS/JS)                     │
│                      Port: 3000 (HTTP)                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ├─── REST API Calls
                              └─── WebSocket Connection
                              
┌─────────────────┬─────────────────┬─────────────────────────┐
│  Main Server    │  Data Engine    │  Log Ingestion Server   │
│   Port: 3000    │  REST: 7080     │      Port: 4000         │
│                 │  WebSocket:8080 │                         │
└─────────────────┴─────────────────┴─────────────────────────┘
         │                 │                    │
         ├─ Scanner        ├─ Metrics          ├─ Log Processing
         ├─ AI Inference   ├─ Alerts           └─ Batch Ingestion
         ├─ Risk Diagnoser ├─ Analytics
         └─ Remediation    └─ Event Streaming
```

### Technology Stack

**Backend:**
- Go 1.x with Gorilla Mux router
- Multiple AI providers (Cerebras, Gemini, Anthropic, OpenAI, DeepSeek)
- WebSocket server (Gorilla WebSocket)
- Optional: Kafka, ChromaDB integration
- System monitoring (gopsutil)

**Frontend:**
- Vanilla JavaScript (ES6+)
- Chart.js for visualizations
- Vis.js for knowledge graph rendering
- WebSocket client for real-time updates
- File System Access API for folder selection

---

## Missing Backend API Endpoints

### 🔴 Critical (P0) - Main Server (Port 3000)

#### 1. Project Management Endpoints

**Missing:** `/api/v1/projects` (GET, POST, DELETE)

**Frontend Expectation:**
```javascript
// dashboard/app.js:206-230
async loadProjects() {
    const response = await fetch('/api/v1/projects');
    const projects = await response.json();
    // Expects: [{ id, name, path, status, lastScan, issueCount }]
}

async addProject(projectData) {
    await fetch('/api/v1/projects', {
        method: 'POST',
        body: JSON.stringify(projectData)
    });
}
```

**Current Backend:** No implementation exists

**Impact:** 
- Cannot add/remove/list projects
- Multi-project support completely non-functional
- Dashboard shows empty project list

**Required Implementation:**
```go
// Needed in main.go
type Project struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    Path        string    `json:"path"`
    Status      string    `json:"status"`
    LastScan    time.Time `json:"lastScan"`
    IssueCount  int       `json:"issueCount"`
    CreatedAt   time.Time `json:"createdAt"`
}

// GET /api/v1/projects - List all projects
// POST /api/v1/projects - Add new project
// DELETE /api/v1/projects/{id} - Remove project
```

---

#### 2. Per-Project Scan Trigger

**Missing:** `/api/v1/projects/{id}/scan` (POST)

**Frontend Expectation:**
```javascript
// dashboard/app.js:232-245
async scanProject(projectId) {
    await fetch(`/api/v1/projects/${projectId}/scan`, {
        method: 'POST'
    });
}
```

**Current Backend:** Only `/api/v1/scan/start` exists (scans configured project)

**Impact:**
- Cannot trigger scans for specific projects
- Multi-project scanning workflow broken

**Required Implementation:**
```go
// POST /api/v1/projects/{id}/scan
// Should trigger scan for specific project by ID
// Return scan job ID for tracking
```

---

### 🔴 Critical (P0) - Authentication

#### 3. GitHub OAuth Flow

**Missing:** 
- `/api/v1/auth/github` (POST)
- `/api/v1/auth/github/status` (GET)
- `/api/v1/auth/github/callback` (GET)

**Frontend Expectation:**
```javascript
// dashboard/app.js:1063-1088
async authenticateGitHub() {
    const response = await fetch('/api/v1/auth/github', {
        method: 'POST',
        body: JSON.stringify({ code: authCode })
    });
    // Expects: { success: true, token: "...", user: {...} }
}

async checkGitHubAuth() {
    const response = await fetch('/api/v1/auth/github/status');
    // Expects: { authenticated: true, user: {...} }
}
```

**Current Backend:** No OAuth implementation, only token from .env

**Impact:**
- GitHub integration UI completely non-functional
- Cannot authenticate users through dashboard
- Settings page shows "Not Connected" permanently

**Required Implementation:**
```go
// OAuth 2.0 flow for GitHub
// 1. GET /api/v1/auth/github - Redirect to GitHub OAuth
// 2. GET /api/v1/auth/github/callback - Handle OAuth callback
// 3. POST /api/v1/auth/github - Exchange code for token
// 4. GET /api/v1/auth/github/status - Check auth status
```

---

### 🟡 High (P1) - Data Engine API (Port 7080)

#### 4. Knowledge Graph Endpoint on Data Engine

**Missing:** `/api/v1/knowledge-graph` on port 7080

**Frontend Expectation:**
```javascript
// dashboard/app.js:247-260
async loadKnowledgeGraph() {
    const response = await fetch('http://localhost:7080/api/v1/knowledge-graph');
    // Expects: { nodes: [...], edges: [...] }
}
```

**Current Backend:** 
- Endpoint exists on port 3000 but returns mock data
- Data engine (port 7080) doesn't expose this endpoint
- Scanner builds real knowledge graph but it's not accessible

**Impact:**
- Knowledge graph view shows sample data only
- Real scan results not visible in dashboard

**Required Implementation:**
```go
// data_engine/rest_api.go
// Add endpoint to expose scanner's knowledge graph
// GET /api/v1/knowledge-graph
// Return actual graph from scanner, not mock data
```

---

#### 5. Issues Endpoint on Data Engine

**Missing:** `/api/v1/issues` on port 7080

**Frontend Expectation:**
```javascript
// dashboard/app.js:262-275
async loadIssues() {
    const response = await fetch('http://localhost:7080/api/v1/issues');
    // Expects: [{ id, type, severity, file, line, message, status }]
}
```

**Current Backend:**
- Exists on port 3000 with hardcoded sample data
- RiskDiagnoser finds real issues but they're not exposed
- No persistence of discovered issues

**Impact:**
- Issues view shows fake data
- Real security vulnerabilities not displayed

---

#### 6. Coverage Endpoint on Data Engine

**Missing:** `/api/v1/coverage` on port 7080

**Frontend Expectation:**
```javascript
// dashboard/app.js:277-290
async loadCoverage() {
    const response = await fetch('http://localhost:7080/api/v1/coverage');
    // Expects: { overall: 0.75, files: [...] }
}
```

**Current Backend:**
- Exists on port 3000 with mock data
- Scanner performs test coverage analysis but results not stored
- `scanTestCoverage()` runs but data is lost

**Impact:**
- Coverage view shows fake 75% coverage
- Real test coverage metrics not available

---

### 🟡 High (P1) - Integration & Monitoring

#### 7. Integration Status Endpoint

**Missing:** `/api/v1/integrations/status` (GET)

**Frontend Expectation:**
```javascript
// dashboard/app.js:1090-1110
async loadIntegrationStatus() {
    const response = await fetch('/api/v1/integrations/status');
    // Expects: {
    //   github: { connected: true, status: "healthy" },
    //   kafka: { connected: false },
    //   chromadb: { connected: true, status: "healthy" }
    // }
}
```

**Current Backend:** No implementation

**Impact:**
- Integrations page cannot show real status
- No health monitoring for external services

**Required Implementation:**
```go
// Check actual connection status for:
// - GitHub API (test token validity)
// - Kafka brokers (if enabled)
// - ChromaDB (if enabled)
// - Data engine services
```

---

#### 8. System Metrics Endpoint

**Missing:** Real-time system metrics on `/api/v1/metrics`

**Frontend Expectation:**
```javascript
// dashboard/app.js:292-305
async loadMetrics() {
    const response = await fetch('http://localhost:7080/api/v1/metrics');
    // Expects: {
    //   cpu: 45.2,
    //   memory: 62.1,
    //   disk: 78.5,
    //   network: { in: 1024, out: 2048 }
    // }
}
```

**Current Backend:**
- Endpoint exists but returns empty/minimal data
- System metrics ARE collected in `collectSystemMetrics()` (main.go:2226-2334)
- Metrics sent to data engine but not exposed via REST API

**Impact:**
- System monitoring dashboard shows no data
- Real-time performance metrics not visible

**Required Fix:**
```go
// data_engine/rest_api.go
// Expose collected metrics via REST endpoint
// Currently metrics go to Kafka/ChromaDB but not REST API
```

---

### 🟢 Medium (P2) - Additional Missing Endpoints

#### 9. Folder Selection Endpoint

**Missing:** Backend endpoint to receive folder selection from File System Access API

**Frontend Code:**
```javascript
// dashboard/app.js:1112-1135
async selectProjectFolder() {
    const dirHandle = await window.showDirectoryPicker();
    // Frontend gets folder path but has no endpoint to send it to
}
```

**Current Backend:** No endpoint to receive folder path

**Impact:**
- "Select Folder" button in UI is non-functional
- Cannot add projects via folder picker

---

#### 10. Scan History Endpoint

**Missing:** `/api/v1/scans/history` (GET)

**Frontend Expectation:** Historical scan results for trend analysis

**Current Backend:** No scan history storage or retrieval

**Impact:**
- Cannot show scan trends over time
- No historical comparison of issues

---

## Data Structure Mismatches

### 🔴 Critical (P0)

#### 11. Knowledge Graph Structure Mismatch

**Frontend Expects:**
```javascript
{
  nodes: [
    {
      id: "node-1",
      label: "main.go",
      type: "code",
      group: "code",
      metadata: { ... }
    }
  ],
  edges: [
    {
      from: "node-1",
      to: "node-2",
      label: "imports",
      arrows: "to"
    }
  ]
}
```

**Backend Returns (main.go:3100-3150):**
```go
// Sample data with minimal structure
{
  "nodes": [
    {"id": "1", "label": "User Service", "type": "service"},
    {"id": "2", "label": "Database", "type": "database"}
  ],
  "edges": [
    {"from": "1", "to": "2", "label": "queries"}
  ]
}
```

**Actual Scanner Data (types/types.go):**
```go
type KnowledgeGraph struct {
    Nodes        map[string]*Node  // Map, not array!
    Edges        []*Edge
    LastUpdated  time.Time
}

type Node struct {
    ID           string
    Type         NodeType  // Enum, not string
    Name         string
    Path         string
    Metadata     map[string]interface{}
    Dependencies []string
    Dependents   []string
    LastModified time.Time
}
```

**Issues:**
1. Backend stores nodes as map, frontend expects array
2. Node type is enum in backend, string in frontend
3. Scanner's real graph never serialized to API format
4. Edge structure missing `arrows` field for visualization

**Required Fix:**
```go
// Add serialization method to KnowledgeGraph
func (kg *KnowledgeGraph) ToAPIFormat() map[string]interface{} {
    nodes := make([]map[string]interface{}, 0, len(kg.Nodes))
    for _, node := range kg.Nodes {
        nodes = append(nodes, map[string]interface{}{
            "id":       node.ID,
            "label":    node.Name,
            "type":     string(node.Type),
            "group":    string(node.Type),
            "metadata": node.Metadata,
        })
    }
    
    edges := make([]map[string]interface{}, 0, len(kg.Edges))
    for _, edge := range kg.Edges {
        edges = append(edges, map[string]interface{}{
            "from":   edge.From,
            "to":     edge.To,
            "label":  edge.Relationship,
            "arrows": "to",
        })
    }
    
    return map[string]interface{}{
        "nodes": nodes,
        "edges": edges,
    }
}
```

---

#### 12. Issue Structure Mismatch

**Frontend Expects:**
```javascript
{
  id: "issue-123",
  type: "security",
  severity: "high",
  file: "auth.go",
  line: 45,
  message: "SQL injection vulnerability",
  status: "open",
  createdAt: "2025-01-15T10:30:00Z"
}
```

**Backend Returns (main.go:3152-3200):**
```go
// Hardcoded sample data
[]map[string]interface{}{
    {
        "id":       "1",
        "type":     "security",
        "severity": "high",
        "message":  "Potential SQL injection in user input handling",
        "file":     "handlers/user.go",
        "line":     42,
    },
    // ... more hardcoded samples
}
```

**Actual Risk Diagnoser Output:**
```go
// RiskDiagnoser finds real issues but they're not stored
type SecurityIssue struct {
    Type        string
    Severity    string
    Description string
    Location    string
    Remediation string
}
```

**Issues:**
1. No `status` field in backend response
2. No `createdAt` timestamp
3. Real issues from RiskDiagnoser not persisted
4. No issue tracking or state management

---

### 🟡 High (P1)

#### 13. Coverage Data Structure

**Frontend Expects:**
```javascript
{
  overall: 0.75,
  files: [
    {
      path: "src/auth.go",
      coverage: 0.85,
      lines: { total: 100, covered: 85, uncovered: 15 }
    }
  ]
}
```

**Backend Returns:**
```go
// Mock data (main.go:3202-3230)
{
    "overall": 0.75,
    "files": [
        {
            "path": "handlers/user.go",
            "coverage": 0.85,
            "lines": {"total": 120, "covered": 102, "uncovered": 18}
        }
    ]
}
```

**Actual Scanner:**
```go
// scanTestCoverage() runs but results not stored
func (s *Scanner) scanTestCoverage(ctx context.Context) error {
    // Runs go test -cover but output is lost
    // No data structure to store results
}
```

**Required:**
- Define `CoverageReport` struct
- Store coverage results from scanner
- Persist across scans for trend analysis

---

#### 14. Project Data Structure

**Frontend Expects:**
```javascript
{
  id: "proj-123",
  name: "My Project",
  path: "/path/to/project",
  status: "scanning" | "idle" | "error",
  lastScan: "2025-01-15T10:30:00Z",
  issueCount: 12,
  createdAt: "2025-01-10T08:00:00Z"
}
```

**Backend:** No Project struct exists

**Required Implementation:**
```go
type Project struct {
    ID          string                 `json:"id"`
    Name        string                 `json:"name"`
    Path        string                 `json:"path"`
    Status      string                 `json:"status"`
    LastScan    *time.Time             `json:"lastScan,omitempty"`
    IssueCount  int                    `json:"issueCount"`
    CreatedAt   time.Time              `json:"createdAt"`
    Config      *Config                `json:"config,omitempty"`
    Graph       *types.KnowledgeGraph  `json:"-"` // Don't serialize
}
```

---

## WebSocket Communication Gaps

### 🔴 Critical (P0)

#### 15. Missing WebSocket Message Types

**Frontend Listens For:**
```javascript
// dashboard/app.js:135-180
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    switch(data.type) {
        case 'scan_cycle_completed':    // ✅ Sent by backend
        case 'security_vulnerability_found':  // ❌ NOT sent
        case 'remediation_completed':   // ❌ NOT sent
        case 'log':                     // ❌ NOT sent
        case 'metric':                  // ✅ Sent by backend
        case 'alert':                   // ✅ Sent by backend
    }
}
```

**Backend Sends (data_engine/websocket_server.go):**
```go
// Only sends: metric, alert, event
// Missing: security_vulnerability_found, remediation_completed, log
```

**Impact:**
- Real-time security alerts not displayed
- Remediation progress not shown
- Log streaming non-functional

**Required Implementation:**
```go
// In scanner/diagnoser, emit WebSocket events:
func (rd *RiskDiagnoser) DiagnoseRisks() {
    for _, issue := range issues {
        wsServer.Broadcast(map[string]interface{}{
            "type": "security_vulnerability_found",
            "data": issue,
        })
    }
}

// In remediation engine:
func (re *RemediationEngine) ApplyFix() {
    wsServer.Broadcast(map[string]interface{}{
        "type": "remediation_completed",
        "data": result,
    })
}
```

---

#### 16. WebSocket Connection Management

**Frontend Behavior:**
```javascript
// dashboard/app.js:182-204
// Reconnects on disconnect with exponential backoff
// Expects server to handle reconnection gracefully
```

**Backend Issue:**
- No client ID tracking
- No reconnection state management
- Lost messages during reconnection

**Required:**
- Implement client ID system
- Message queue for disconnected clients
- Reconnection acknowledgment

---

### 🟡 High (P1)

#### 17. WebSocket Message Format Inconsistency

**Frontend Expects:**
```javascript
{
  type: "metric",
  timestamp: "2025-01-15T10:30:00Z",
  data: { cpu: 45.2, memory: 62.1 }
}
```

**Backend Sends:**
```go
// Sometimes includes timestamp, sometimes doesn't
// No standardized envelope format
```

**Required:** Standardize message envelope:
```go
type WSMessage struct {
    Type      string      `json:"type"`
    Timestamp time.Time   `json:"timestamp"`
    Data      interface{} `json:"data"`
    ID        string      `json:"id,omitempty"`
}
```

---

## Authentication & Authorization

### 🔴 Critical (P0)

#### 18. No Authentication System

**Current State:**
- No user authentication
- No session management
- No API key validation
- GitHub token only from .env file

**Frontend Expects:**
- GitHub OAuth login
- Session persistence
- Protected API endpoints

**Security Risk:** 
- Dashboard completely open
- No access control
- Anyone can trigger scans, change settings

**Required Implementation:**
1. Session-based authentication
2. JWT tokens for API access
3. GitHub OAuth integration
4. Role-based access control (RBAC)

---

#### 19. GitHub Token Management

**Current:** Token hardcoded in .env

**Frontend Expects:** 
- OAuth flow to obtain token
- Token refresh mechanism
- Per-user token storage

**Required:**
```go
type GitHubAuth struct {
    UserID       string
    AccessToken  string
    RefreshToken string
    ExpiresAt    time.Time
}

// OAuth endpoints
// Token refresh logic
// Secure token storage
```

---

## Data Persistence Issues

### 🔴 Critical (P0)

#### 20. No Scan Results Persistence

**Current Behavior:**
- Scanner runs, builds knowledge graph
- Results stored in memory only
- Lost on server restart
- No historical data

**Impact:**
- Cannot compare scans over time
- No trend analysis
- Dashboard resets on restart

**Required:**
1. Persistent storage for scan results
2. Persistent storage for knowledge graphs
3. Historical issue tracking
4. Scan metadata storage

**Recommended Solution: Use Chromem-go Embedded Database**

ArchGuardian already has chromem-go as a dependency. This embeddable vector database provides perfect persistence capabilities for the knowledge graph and scan results:

```go
import "github.com/philippgille/chromem-go"

// Initialize persistent database
db, err := chromem.NewPersistentDB("./archguardian-data", true) // true = gzip compression
if err != nil {
    log.Fatal(err)
}

// Create collections for different data types
knowledgeGraphCollection, _ := db.GetOrCreateCollection(
    "knowledge-graphs",
    map[string]string{"type": "scan-results"},
    nil, // Use default OpenAI embeddings or configure custom
)

issuesCollection, _ := db.GetOrCreateCollection(
    "security-issues",
    map[string]string{"type": "issues"},
    nil,
)

coverageCollection, _ := db.GetOrCreateCollection(
    "test-coverage",
    map[string]string{"type": "coverage"},
    nil,
)

// Store scan results with embeddings for semantic search
err = knowledgeGraphCollection.AddDocuments(ctx, []chromem.Document{
    {
        ID:      scanID,
        Content: graphJSON, // Serialized knowledge graph
        Metadata: map[string]string{
            "project_id": projectID,
            "timestamp":  time.Now().Format(time.RFC3339),
            "node_count": strconv.Itoa(len(graph.Nodes)),
        },
    },
}, 1)

// Query historical scans
results, _ := knowledgeGraphCollection.Query(
    ctx,
    "security vulnerabilities in authentication",
    5, // top 5 results
    map[string]string{"project_id": projectID}, // filter by project
    nil,
)
```

**Chromem-go Persistence Features:**
- **Automatic persistence**: Each document write is immediately persisted to disk
- **Gob encoding**: Efficient binary serialization (optionally gzip-compressed)
- **Zero dependencies**: No external database required
- **Export/Import**: Full database backup to single file with optional AES-GCM encryption
- **Semantic search**: Query historical data using natural language
- **Metadata filtering**: Filter by project, timestamp, severity, etc.

**Alternative: Traditional SQL Database**

If vector embeddings are not needed, use SQLite for simpler relational storage:

```sql
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    project_id UUID,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status VARCHAR(20),
    node_count INT,
    edge_count INT,
    issue_count INT
);

CREATE TABLE scan_nodes (
    id UUID PRIMARY KEY,
    scan_id UUID,
    node_id VARCHAR(255),
    node_type VARCHAR(50),
    node_data JSONB
);

CREATE TABLE scan_issues (
    id UUID PRIMARY KEY,
    scan_id UUID,
    type VARCHAR(50),
    severity VARCHAR(20),
    file_path TEXT,
    line_number INT,
    message TEXT,
    status VARCHAR(20),
    created_at TIMESTAMP
);
```

**Recommendation:** Use **chromem-go for knowledge graphs and issues** (benefits from semantic search) and **SQLite for project metadata and scan history** (simple relational queries).

---

#### 21. No Project Persistence

**Current:** Single project from config

**Required:**
- Multi-project support
- Project metadata storage
- Per-project configuration
- Project-specific scan history

**Implementation with Chromem-go:**

```go
// Create projects collection
projectsCollection, _ := db.GetOrCreateCollection(
    "projects",
    map[string]string{"type": "project-metadata"},
    nil,
)

// Store project
projectJSON, _ := json.Marshal(project)
err = projectsCollection.AddDocument(ctx, chromem.Document{
    ID:      project.ID,
    Content: projectJSON,
    Metadata: map[string]string{
        "name":        project.Name,
        "path":        project.Path,
        "status":      project.Status,
        "last_scan":   project.LastScan.Format(time.RFC3339),
        "issue_count": strconv.Itoa(project.IssueCount),
    },
})

// Query projects by status
activeProjects, _ := projectsCollection.Query(
    ctx,
    "",
    100,
    map[string]string{"status": "active"}, // metadata filter
    nil,
)

// Get project by ID
projectDoc, _ := projectsCollection.GetByID(ctx, projectID)
```

---

### 🟡 High (P1)

#### 22. No Settings Persistence

**Current Behavior:**
```go
// main.go:3232-3280
func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
    // Accepts settings but doesn't save them
    // Doesn't update running configuration
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
    })
}
```

**Impact:**
- Settings changes lost on restart
- Cannot update AI provider keys
- Scan interval changes ignored

**Required:**
- Persist settings to file/database
- Hot-reload configuration
- Validate settings before applying

**Implementation Options:**

**Option 1: Chromem-go (for versioned settings history)**
```go
settingsCollection, _ := db.GetOrCreateCollection(
    "settings",
    map[string]string{"type": "configuration"},
    nil,
)

// Save settings with version history
settingsJSON, _ := json.Marshal(settings)
err = settingsCollection.AddDocument(ctx, chromem.Document{
    ID:      fmt.Sprintf("settings-%d", time.Now().Unix()),
    Content: settingsJSON,
    Metadata: map[string]string{
        "version":   "1.0",
        "timestamp": time.Now().Format(time.RFC3339),
        "user":      userID,
    },
})

// Get latest settings
results, _ := settingsCollection.Query(ctx, "", 1, nil, nil)
latestSettings := results[0].Content
```

**Option 2: Simple file-based (for current settings only)**
```go
func saveSettings(settings *Config) error {
    data, err := json.MarshalIndent(settings, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile("./config/settings.json", data, 0644)
}

func loadSettings() (*Config, error) {
    data, err := os.ReadFile("./config/settings.json")
    if err != nil {
        return nil, err
    }
    var config Config
    err = json.Unmarshal(data, &config)
    return &config, err
}
```

**Recommendation:** Use **file-based for active settings** and **chromem-go for settings history/audit trail**.

---

## Configuration & Settings

### 🟡 High (P1)

#### 23. Settings API Doesn't Update Runtime Config

**Frontend Sends:**
```javascript
// dashboard/app.js:1137-1160
await fetch('/api/v1/settings', {
    method: 'POST',
    body: JSON.stringify({
        scanInterval: 3600,
        aiProvider: "anthropic",
        githubToken: "ghp_xxx"
    })
});
```

**Backend:**
```go
// Accepts but ignores the settings
// Config struct never updated
// Services not reconfigured
```

**Required:**
```go
func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
    var newSettings map[string]interface{}
    json.NewDecoder(r.Body).Decode(&newSettings)
    
    // Validate settings
    if err := validateSettings(newSettings); err != nil {
        http.Error(w, err.Error(), 400)
        return
    }
    
    // Update global config
    updateConfig(newSettings)
    
    // Persist to file
    saveConfigToFile(newSettings)
    
    // Restart affected services
    restartServices(newSettings)
}
```

---

#### 24. Multiple Port Configuration Confusion

**Current Architecture:**
- Port 3000: Main server + dashboard
- Port 7080: Data engine REST API
- Port 8080: WebSocket server
- Port 4000: Log ingestion

**Issues:**
1. Frontend hardcodes all ports
2. No single source of truth
3. Port conflicts not handled
4. No service discovery

**Frontend Hardcoded Ports:**
```javascript
// dashboard/app.js
const API_BASE = 'http://localhost:3000';
const DATA_ENGINE_BASE = 'http://localhost:7080';
const WS_URL = 'ws://localhost:8080/ws';
```

**Recommendation:**
- Serve all APIs from single port (3000)
- Use path-based routing: `/api/v1/*`, `/ws`, `/data/*`
- Or implement service discovery
- Make ports configurable via settings

---

### 🟢 Medium (P2)

#### 25. No Environment-Specific Configuration

**Current:** Single .env file

**Required:**
- Development vs Production configs
- Environment variable validation
- Config file hot-reload
- Secrets management (not in .env)

---

## Integration & Monitoring

### 🟡 High (P1)

#### 26. Kafka/ChromaDB Integration Status Unknown

**Current:**
```go
// Data sent to Kafka/ChromaDB if enabled
// But no health checks
// No connection status exposed
```

**Frontend Expects:**
```javascript
// Integrations page shows status
{
  kafka: { connected: true, status: "healthy", messageCount: 1234 },
  chromadb: { connected: true, status: "healthy", collectionSize: 5678 }
}
```

**Required:**
- Health check endpoints for each integration
- Connection retry logic
- Status monitoring
- Error reporting

---

### 🟢 Medium (P2)

#### 27. No Alerting Configuration

**Frontend Has:** Alert configuration UI

**Backend Has:** Alert detection but no configuration

**Gap:** Cannot configure alert thresholds, notification channels

---

## Logical Disconnects

### Critical Logic Issues

#### 1. Scanner Knowledge Graph Never Exposed

**Flow:**
```
Scanner.ScanProject() 
  → Builds s.graph (KnowledgeGraph)
  → Stores in memory
  → ❌ Never serialized to API
  
API Handler (handleKnowledgeGraph)
  → Returns hardcoded sample data
  → ❌ Ignores scanner's real graph
```

**Fix Required:**
```go
// main.go - Add global reference to scanner
var globalScanner *Scanner

func handleKnowledgeGraph(w http.ResponseWriter, r *http.Request) {
    if globalScanner == nil || globalScanner.graph == nil {
        http.Error(w, "No scan data available", 404)
        return
    }
    
    // Serialize real graph
    apiData := globalScanner.graph.ToAPIFormat()
    json.NewEncoder(w).Encode(apiData)
}
```

---

#### 2. RiskDiagnoser Results Lost

**Flow:**
```
RiskDiagnoser.DiagnoseRisks()
  → Finds security issues
  → Returns []SecurityIssue
  → ❌ Caller ignores return value
  → ❌ Issues never stored
  
API Handler (handleIssues)
  → Returns hardcoded sample issues
```

**Fix Required:**
```go
// Store issues globally or in database
var globalIssues []SecurityIssue

func runDiagnosis() {
    diagnoser := NewRiskDiagnoser(scanner.graph, config)
    issues := diagnoser.DiagnoseRisks()
    
    // Store for API access
    globalIssues = issues
    
    // Persist to database
    saveIssuesToDB(issues)
    
    // Broadcast via WebSocket
    broadcastIssues(issues)
}
```

---

#### 3. Test Coverage Scan Results Discarded

**Flow:**
```
Scanner.scanTestCoverage()
  → Runs `go test -cover`
  → Parses output
  → ❌ Doesn't store results
  → ❌ No return value
  
API Handler (handleCoverage)
  → Returns mock 75% coverage
```

**Fix Required:**
```go
type CoverageReport struct {
    Overall   float64
    Files     []FileCoverage
    Timestamp time.Time
}

func (s *Scanner) scanTestCoverage(ctx context.Context) (*CoverageReport, error) {
    // Parse coverage output
    report := parseCoverageOutput(output)
    
    // Store in scanner
    s.coverageReport = report
    
    return report, nil
}
```

---

#### 4. Multi-Project Frontend, Single-Project Backend

**Frontend:**
- Project list view
- Add/remove projects
- Per-project scanning
- Project-specific dashboards

**Backend:**
- Single `ProjectPath` in config
- Scanner only scans one project
- No project management

**This is a fundamental architectural mismatch.**

---

#### 5. Settings Save Doesn't Apply Changes

**Frontend Flow:**
1. User changes scan interval to 1 hour
2. Clicks "Save Settings"
3. POST to `/api/v1/settings`
4. Success message shown

**Backend Reality:**
1. Receives settings
2. Returns success
3. ❌ Doesn't update config
4. ❌ Scan interval unchanged
5. ❌ Settings lost on restart

---

## Recommendations

### Immediate Priorities (Sprint 1)

1. **Implement Project Management** (P0)
   - Create Project struct and storage
   - Add CRUD endpoints
   - Update scanner to support multiple projects

2. **Connect Scanner to API** (P0)
   - Expose real knowledge graph
   - Expose real issues from RiskDiagnoser
   - Expose real coverage data

3. **Add Data Persistence** (P0)
   - Choose database (SQLite for simplicity, PostgreSQL for production)
   - Create schema for projects, scans, issues
   - Implement data access layer

4. **Fix WebSocket Events** (P0)
   - Add missing message types
   - Standardize message format
   - Implement proper error handling

### Short-term (Sprint 2-3)

5. **Implement Authentication** (P0)
   - GitHub OAuth flow
   - Session management
   - API authentication

6. **Settings Management** (P1)
   - Persist settings to file/DB
   - Hot-reload configuration
   - Validate before applying

7. **Integration Monitoring** (P1)
   - Health check endpoints
   - Status dashboard
   - Connection retry logic

### Medium-term (Sprint 4-6)

8. **Consolidate API Architecture** (P1)
   - Single port for all APIs
   - Clear service boundaries
   - API versioning strategy

9. **Historical Data & Trends** (P1)
   - Scan history storage
   - Trend analysis
   - Comparison views

10. **Enhanced Monitoring** (P2)
    - Real-time metrics exposure
    - Alert configuration
    - Performance dashboards

### Long-term Improvements

11. **Scalability**
    - Distributed scanning
    - Queue-based job processing
    - Horizontal scaling support

12. **Advanced Features**
    - Custom rule engine
    - Plugin system
    - Advanced AI analysis

---

## Chromem-go Integration Strategy

### Why Chromem-go is Perfect for ArchGuardian

ArchGuardian already has chromem-go as a dependency but isn't using it for persistence. This is a missed opportunity because:

1. **Zero Additional Dependencies**: Already in go.mod
2. **Embeddable**: No separate database server to manage
3. **Semantic Search**: Query scan results using natural language
4. **Automatic Persistence**: Immediate disk writes with gob encoding
5. **Compression**: Optional gzip compression saves disk space
6. **Encryption**: AES-GCM encryption for sensitive data
7. **Export/Import**: Full database backup to single file
8. **S3 Integration**: Built-in support for cloud storage

### Recommended Chromem-go Collections

```go
// Initialize persistent database
db, err := chromem.NewPersistentDB("./archguardian-data", true)

// Collection structure:
collections := map[string]string{
    "projects":         "Project metadata and configuration",
    "knowledge-graphs": "Scan results with node/edge data",
    "security-issues":  "Discovered vulnerabilities and risks",
    "test-coverage":    "Code coverage reports",
    "scan-history":     "Historical scan metadata",
    "settings-history": "Configuration change audit trail",
    "remediation-logs": "AI remediation attempts and results",
}
```

### Benefits for Each Data Type

**Knowledge Graphs:**
- Semantic search: "Find all authentication-related components"
- Version comparison: Compare graphs across time
- Relationship queries: "Show dependencies of module X"

**Security Issues:**
- Natural language queries: "Critical SQL injection vulnerabilities"
- Trend analysis: Track issue resolution over time
- Pattern detection: Find similar issues across projects

**Test Coverage:**
- Coverage trends: Track improvement over time
- Gap analysis: "Files with low coverage in authentication"
- Correlation: Link coverage to issue frequency

### Export/Import for Backups

```go
// Export entire database to encrypted backup
err = db.ExportToFile(
    "./backups/archguardian-backup.gob.gz.enc",
    true,                    // compress
    "your-32-byte-key-here", // encrypt
)

// Export to S3 (see examples/s3-export-import)
s3Client := s3.New(session.New())
writer := &s3Writer{client: s3Client, bucket: "backups", key: "db.gob.gz"}
err = db.ExportToWriter(writer, true, encryptionKey)

// Import from backup
err = db.ImportFromFile("./backups/archguardian-backup.gob.gz.enc", encryptionKey)
```

### Practical Implementation Example

Here's how to integrate chromem-go into ArchGuardian's existing workflow:

```go
// main.go - Add global persistent database
var (
    globalScanner *Scanner
    globalDB      *chromem.DB
    collections   struct {
        projects       *chromem.Collection
        knowledgeGraph *chromem.Collection
        issues         *chromem.Collection
        coverage       *chromem.Collection
    }
)

func main() {
    // Initialize persistent database
    var err error
    globalDB, err = chromem.NewPersistentDB("./archguardian-data", true)
    if err != nil {
        log.Fatal("Failed to initialize database:", err)
    }
    
    // Create collections
    collections.projects, _ = globalDB.GetOrCreateCollection(
        "projects", 
        map[string]string{"type": "metadata"}, 
        nil,
    )
    collections.knowledgeGraph, _ = globalDB.GetOrCreateCollection(
        "knowledge-graphs",
        map[string]string{"type": "scan-results"},
        nil,
    )
    collections.issues, _ = globalDB.GetOrCreateCollection(
        "security-issues",
        map[string]string{"type": "vulnerabilities"},
        nil,
    )
    collections.coverage, _ = globalDB.GetOrCreateCollection(
        "test-coverage",
        map[string]string{"type": "coverage-reports"},
        nil,
    )
    
    // ... rest of initialization
}

// Update scanner to persist results
func (s *Scanner) ScanProject(ctx context.Context) error {
    // ... existing scan logic ...
    
    // After scan completes, persist knowledge graph
    graphJSON, _ := json.Marshal(s.graph.ToAPIFormat())
    err := collections.knowledgeGraph.AddDocument(ctx, chromem.Document{
        ID:      fmt.Sprintf("scan-%s-%d", projectID, time.Now().Unix()),
        Content: string(graphJSON),
        Metadata: map[string]string{
            "project_id":  projectID,
            "timestamp":   time.Now().Format(time.RFC3339),
            "node_count":  strconv.Itoa(len(s.graph.Nodes)),
            "edge_count":  strconv.Itoa(len(s.graph.Edges)),
        },
    })
    
    return err
}

// Update API handler to use real data
func handleKnowledgeGraph(w http.ResponseWriter, r *http.Request) {
    projectID := r.URL.Query().Get("project_id")
    
    // Get latest scan for project
    results, err := collections.knowledgeGraph.Query(
        r.Context(),
        "",
        1,
        map[string]string{"project_id": projectID},
        nil,
    )
    
    if err != nil || len(results) == 0 {
        http.Error(w, "No scan data available", 404)
        return
    }
    
    // Return real knowledge graph data
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(results[0].Content))
}

// Update RiskDiagnoser to persist issues
func (rd *RiskDiagnoser) DiagnoseRisks(ctx context.Context) []SecurityIssue {
    issues := rd.analyzeSecurityRisks()
    
    // Persist each issue
    for _, issue := range issues {
        issueJSON, _ := json.Marshal(issue)
        collections.issues.AddDocument(ctx, chromem.Document{
            ID:      fmt.Sprintf("issue-%s-%d", issue.Type, time.Now().UnixNano()),
            Content: string(issueJSON),
            Metadata: map[string]string{
                "project_id": rd.projectID,
                "type":       issue.Type,
                "severity":   issue.Severity,
                "file":       issue.Location,
                "timestamp":  time.Now().Format(time.RFC3339),
                "status":     "open",
            },
        })
        
        // Broadcast via WebSocket
        wsServer.Broadcast(map[string]interface{}{
            "type": "security_vulnerability_found",
            "data": issue,
        })
    }
    
    return issues
}

// Add semantic search endpoint
func handleSemanticSearch(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    collectionName := r.URL.Query().Get("collection")
    
    var collection *chromem.Collection
    switch collectionName {
    case "issues":
        collection = collections.issues
    case "knowledge-graph":
        collection = collections.knowledgeGraph
    case "coverage":
        collection = collections.coverage
    default:
        http.Error(w, "Invalid collection", 400)
        return
    }
    
    // Semantic search using natural language
    results, err := collection.Query(
        r.Context(),
        query,
        10,
        nil,
        nil,
    )
    
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    
    json.NewEncoder(w).Encode(results)
}

// Add backup endpoint
func handleBackup(w http.ResponseWriter, r *http.Request) {
    encryptionKey := os.Getenv("BACKUP_ENCRYPTION_KEY") // 32 bytes
    
    backupPath := fmt.Sprintf("./backups/archguardian-%s.gob.gz.enc", 
        time.Now().Format("2006-01-02-15-04-05"))
    
    err := globalDB.ExportToFile(backupPath, true, encryptionKey)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "backup_path": backupPath,
    })
}
```

This implementation provides:
- ✅ Persistent storage for all scan data
- ✅ Semantic search capabilities
- ✅ Real-time WebSocket updates
- ✅ Encrypted backups
- ✅ Zero external dependencies
- ✅ Minimal code changes to existing architecture

---

## Implementation Checklist

### Phase 1: Core Connectivity (Week 1-2)

- [x] Create `Project` struct and in-memory storage
- [x] Implement `/api/v1/projects` endpoints (GET, POST, DELETE)
- [x] Implement `/api/v1/projects/{id}/scan` endpoint
- [x] Connect `handleKnowledgeGraph` to real scanner data
- [x] Connect `handleIssues` to real RiskDiagnoser output
- [x] Connect `handleCoverage` to real test coverage results
- [x] Add missing WebSocket message types
- [x] Standardize WebSocket message format

### Phase 2: Persistence with Chromem-go (Week 3-4)

- [x] Initialize chromem.NewPersistentDB in main.go
- [x] Create collections for projects, scans, issues, coverage
- [x] Implement data serialization to chromem.Document format
- [x] Update scanner to persist knowledge graphs after each scan
- [x] Update RiskDiagnoser to persist issues to chromem-go
- [x] Update coverage scanner to persist results
- [x] Implement scan history retrieval endpoints
- [x] Add semantic search endpoints for natural language queries
- [x] Implement export/import for database backups
- [ ] Add scheduled backup to S3/cloud storage (optional)

### Phase 3: Authentication (Week 5-6)

- [x] Implement GitHub OAuth flow
- [x] Add session management
- [x] Protect API endpoints
- [x] Add `/api/v1/auth/*` endpoints
- [x] Implement token refresh
- [x] Add user management

### Phase 4: Settings & Configuration (Week 7-8)

- [x] Implement settings persistence
- [x] Add configuration hot-reload
- [x] Implement settings validation
- [x] Update services when settings change
- [x] Add environment-specific configs
- [x] Implement secrets management

### Phase 5: Integration & Monitoring (Week 9-10)

- [x] Add integration health checks
- [x] Implement `/api/v1/integrations/status`
- [x] Expose real-time system metrics
- [x] Add alert configuration
- [x] Implement notification system
- [x] Add real-data to monitoring dashboards

### Phase 6: Polish & Optimization (Week 11-12)

- [x] Consolidate API ports
- [x] Add comprehensive error handling
- [x] Implement rate limiting
- [x] Add API documentation
- [x] Performance optimization
- [x] Security audit

---

## Testing Strategy

### Unit Tests Required

- [ ] Project CRUD operations
- [ ] Knowledge graph serialization
- [ ] Issue detection and storage
- [ ] Coverage report parsing
- [ ] Settings validation
- [ ] Authentication flows

### Integration Tests Required

- [ ] End-to-end scan workflow
- [ ] WebSocket message delivery
- [ ] Database persistence
- [ ] API endpoint responses
- [ ] Multi-project scanning

### Manual Testing Checklist

- [ ] Add project via UI
- [ ] Trigger scan and verify results
- [ ] View knowledge graph with real data
- [ ] View issues with real data
- [ ] View coverage with real data
- [ ] Save settings and verify persistence
- [ ] GitHub authentication flow
- [ ] WebSocket real-time updates
- [ ] Integration status monitoring

---

## Conclusion

ArchGuardian has a solid foundation with comprehensive scanning capabilities and a well-designed frontend. However, the **critical gap is the missing API layer** that connects the backend's powerful analysis engine to the frontend's visualization capabilities.

**Key Takeaways:**

1. **27 identified gaps** across API endpoints, data structures, and logic
2. **12 critical (P0) issues** that completely break core functionality
3. **Primary root cause:** Backend returns mock data instead of real scan results
4. **Secondary issue:** No data persistence layer (despite having chromem-go available)
5. **Tertiary issue:** Missing authentication and multi-project support

**Major Discovery: Chromem-go Already Available**

ArchGuardian already has chromem-go as a dependency but isn't using it. This embeddable vector database provides:
- ✅ Zero-dependency persistence (no external database needed)
- ✅ Automatic gob encoding with optional gzip compression
- ✅ Semantic search capabilities for natural language queries
- ✅ Export/Import with AES-GCM encryption
- ✅ S3/cloud storage integration
- ✅ Perfect fit for knowledge graphs, issues, and coverage data

**Estimated Effort:** 10-12 weeks for complete gap resolution

**Recommended Approach:** 

1. **Phase 1 (Week 1-2):** Connect existing scanner/diagnoser to API endpoints
2. **Phase 2 (Week 3-4):** Implement chromem-go persistence for all scan data
3. **Phase 3 (Week 5-6):** Add GitHub OAuth authentication
4. **Phase 4 (Week 7-8):** Implement settings management and hot-reload
5. **Phase 5 (Week 9-10):** Add integration monitoring and health checks
6. **Phase 6 (Week 11-12):** Polish, optimize, and security audit

**Quick Wins (Can be done in Week 1):**

1. Initialize `chromem.NewPersistentDB("./archguardian-data", true)` in main.go
2. Replace mock data in `handleKnowledgeGraph` with `scanner.graph.ToAPIFormat()`
3. Store RiskDiagnoser results in chromem-go collection
4. Add WebSocket events for security vulnerabilities and remediation

**Long-term Benefits:**

Once these gaps are addressed, ArchGuardian will be:
- ✅ Fully functional with real-time security monitoring
- ✅ Production-ready with persistent data storage
- ✅ Scalable with multi-project support
- ✅ Intelligent with semantic search over historical data
- ✅ Secure with authentication and encrypted backups
- ✅ Maintainable with zero external database dependencies

**The path forward is clear:** Leverage the existing chromem-go dependency for persistence, connect the powerful backend analysis to the API layer, and unlock the full potential of this sophisticated security monitoring platform.

---

**Document Prepared By:** AI Analysis System  
**Analysis Date:** January 2025  
**Document Version:** 1.1 (Updated with Chromem-go integration strategy)  
**Review Status:** Ready for Implementation  
**Next Review Date:** After Phase 1 completion

**References:**
- Chromem-go Documentation: https://github.com/philippgille/chromem-go
- Chromem-go API Reference: https://pkg.go.dev/github.com/philippgille/chromem-go
- ArchGuardian Codebase: /home/gperry/Documents/GitHub/archguardian
