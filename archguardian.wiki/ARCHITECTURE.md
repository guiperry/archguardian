# ArchGuardian Architecture

**Version:** 1.0.0  
**Last Updated:** 2024-01-15

---

## Table of Contents

- [Overview](#overview)
- [Core Principles](#core-principles)
- [System Architecture](#system-architecture)
- [Data Flow](#data-flow)
- [Component Details](#component-details)
- [Deterministic Scanning Pipeline](#deterministic-scanning-pipeline)
- [AI Remediation Workflow](#ai-remediation-workflow)
- [Storage Architecture](#storage-architecture)
- [API Architecture](#api-architecture)
- [Security Architecture](#security-architecture)

---

## Overview

ArchGuardian is an autonomous technical debt prevention and architecture intelligence platform built on a **deterministic scanning architecture** with **user-triggered AI remediation**.

### Key Architectural Decisions

1. **Deterministic Scanning**: All scanning and detection is rule-based, reproducible, and works offline
2. **Separation of Concerns**: AI is completely separated from scanning/detection
3. **User-Triggered AI**: AI only generates solutions when explicitly requested by users
4. **Unified Port Architecture**: All services consolidated on port 3000
5. **Embedded Storage**: Chromem-go vector database for persistent storage

---

## Core Principles

### 1. Determinism First

**Principle:** Scanning and detection must produce identical results for identical inputs.

**Implementation:**
- AST parsing for code analysis
- Pattern matching for vulnerability detection
- Cyclomatic complexity calculation for code quality
- CVE database lookups for dependency risks
- Static analysis for dead code detection

**Benefits:**
- 100% reproducible results
- Offline capability
- Fast execution (no AI latency)
- Zero cost for scanning
- Reliable CI/CD integration

### 2. AI for Remediation Only

**Principle:** AI should only be used to generate solutions, never for scanning or detection.

**Implementation:**
- User selects a detected issue
- AI generates fix recommendation
- User reviews the solution
- User approves and applies the fix

**Benefits:**
- Predictable scanning behavior
- Cost-effective (AI only when needed)
- User control over AI usage
- Transparent decision-making

### 3. Separation of Concerns

**Principle:** Each component has a single, well-defined responsibility.

**Components:**
- **Scanner**: Deterministic code analysis
- **Risk Diagnoser**: Deterministic issue detection
- **AI Remediation Service**: User-triggered solution generation
- **Data Engine**: Metrics and event streaming
- **Dashboard**: User interface and visualization

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER LAYER                               │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Browser    │  │   CLI Tool   │  │  IDE Plugin  │          │
│  │  Dashboard   │  │              │  │   (Future)   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │  HTTP + WebSocket  │
                    └─────────┬─────────┘
                              │
┌─────────────────────────────▼─────────────────────────────────────┐
│                   ARCHGUARDIAN SERVER (Port 3000)                  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐│
│  │                      API GATEWAY                               ││
│  │  /api/v1/projects  │  /api/v1/scan  │  /api/v1/issues        ││
│  │  /api/v1/coverage  │  /api/v1/search │  /api/v1/remediate    ││
│  └───────────────────────────────────────────────────────────────┘│
│                              │                                      │
│  ┌───────────────────────────▼───────────────────────────────────┐│
│  │                   ORCHESTRATION LAYER                          ││
│  │                    (Guardian Service)                          ││
│  └───────────────────────────────────────────────────────────────┘│
│                              │                                      │
│  ┌───────────────────────────┴───────────────────────────────────┐│
│  │                    CORE SERVICES                               ││
│  │                                                                ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       ││
│  │  │   SCANNER    │  │     RISK     │  │      AI      │       ││
│  │  │              │  │   DIAGNOSER  │  │ REMEDIATION  │       ││
│  │  │ Deterministic│→ │ Deterministic│  │User-Triggered│       ││
│  │  │   (No AI)    │  │   (No AI)    │  │  (On-Demand) │       ││
│  │  └──────────────┘  └──────────────┘  └──────────────┘       ││
│  │         │                  │                  ↑               ││
│  │         │                  │                  │               ││
│  │         │                  └──────────────────┘               ││
│  │         │                  (User selects issue)               ││
│  │         │                                                     ││
│  │  ┌──────▼──────────────────────────────────────────────────┐ ││
│  │  │                   DATA ENGINE                            │ ││
│  │  │  • Metrics Collection  • Event Streaming                │ ││
│  │  │  • WebSocket Management • Analytics                     │ ││
│  │  └──────────────────────────────────────────────────────────┘ ││
│  └───────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
                              │
           ┌──────────────────┴──────────────────┐
           │                                     │
┌──────────▼──────────┐              ┌──────────▼──────────┐
│  STORAGE LAYER      │              │  EXTERNAL SERVICES  │
│                     │              │                     │
│  • Chromem-go DB    │              │  • AI Providers     │
│  • File Storage     │              │  • CVE Databases    │
│  • Backup Storage   │              │  • GitHub API       │
└─────────────────────┘              └─────────────────────┘
```

---

## Data Flow

### Phase 1-4: Deterministic Scanning (No AI)

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 1: CODE SCANNING                        │
│                      (DETERMINISTIC)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  INPUT: Project directory path                                  │
│                                                                  │
│  PROCESS:                                                        │
│  1. File System Traversal                                       │
│     • Discover all source files                                 │
│     • Filter by language (.go, .js, .py, .java)                │
│     • Respect .gitignore patterns                               │
│                                                                  │
│  2. AST Parsing                                                 │
│     • Parse Go files with go/parser                             │
│     • Parse JavaScript with regex patterns                      │
│     • Parse Python with regex patterns                          │
│     • Extract imports, functions, classes                       │
│                                                                  │
│  3. Dependency Extraction                                       │
│     • Parse go.mod for Go dependencies                          │
│     • Parse package.json for Node dependencies                  │
│     • Parse requirements.txt for Python dependencies            │
│     • Build dependency graph                                    │
│                                                                  │
│  4. Metrics Calculation                                         │
│     • Lines of code (LOC)                                       │
│     • Cyclomatic complexity                                     │
│     • Function/class counts                                     │
│     • Import counts                                             │
│                                                                  │
│  5. Knowledge Graph Construction                                │
│     • Create nodes for files, functions, classes                │
│     • Create edges for imports, calls, inheritance              │
│     • Calculate graph metrics                                   │
│                                                                  │
│  OUTPUT: Knowledge graph with code structure                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 2: RISK DETECTION                       │
│                      (DETERMINISTIC)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  INPUT: Knowledge graph from Phase 1                            │
│                                                                  │
│  PROCESS:                                                        │
│                                                                  │
│  1. Security Vulnerability Detection                            │
│     • SQL Injection: Pattern matching for unsafe queries        │
│     • XSS: Pattern matching for unsafe HTML rendering           │
│     • Insecure Crypto: Pattern matching for weak algorithms     │
│     • Hardcoded Secrets: Regex for API keys, passwords          │
│     • Path Traversal: Pattern matching for unsafe file access   │
│                                                                  │
│  2. Technical Debt Identification                               │
│     • High Complexity: Cyclomatic complexity > threshold        │
│     • Long Functions: LOC > threshold                           │
│     • Deep Nesting: Nesting level > threshold                   │
│     • Code Duplication: Token-based similarity detection        │
│     • TODO/FIXME Comments: Regex extraction                     │
│                                                                  │
│  3. Obsolete Code Detection                                     │
│     • Unused Imports: Reference counting                        │
│     • Dead Code: Unreachable code detection                     │
│     • Deprecated APIs: Pattern matching against known list      │
│     • Unused Functions: Call graph analysis                     │
│                                                                  │
│  4. Dependency Risk Assessment                                  │
│     • Outdated Versions: Compare with package registries        │
│     • Known Vulnerabilities: CVE database lookups               │
│     • Unmaintained Packages: Last update date check             │
│     • License Issues: License compatibility check               │
│                                                                  │
│  5. Compatibility Analysis                                      │
│     • Web Baseline: CSS/JS/HTML feature checking                │
│     • Browser Compatibility: Feature support matrix             │
│     • API Deprecations: Known deprecation list                  │
│                                                                  │
│  OUTPUT: List of detected issues with severity and location     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 3: DATA PERSISTENCE                     │
│                      (DETERMINISTIC)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  INPUT: Knowledge graph + Detected issues                       │
│                                                                  │
│  PROCESS:                                                        │
│  1. Store knowledge graph in Chromem-go                         │
│  2. Store detected issues in Chromem-go                         │
│  3. Store scan metadata (timestamp, duration, file count)       │
│  4. Update project status                                       │
│  5. Create scan history record                                  │
│                                                                  │
│  OUTPUT: Persisted data in vector database                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 4: DASHBOARD DISPLAY                    │
│                      (DETERMINISTIC)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  INPUT: Persisted data from Phase 3                             │
│                                                                  │
│  PROCESS:                                                        │
│  1. Retrieve knowledge graph from database                      │
│  2. Retrieve detected issues from database                      │
│  3. Calculate summary statistics                                │
│  4. Render visualization                                        │
│  5. Enable user interaction (filtering, sorting, selection)     │
│                                                                  │
│  OUTPUT: Interactive dashboard with detected issues             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 5: AI-Powered Remediation (User-Triggered)

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 5: AI REMEDIATION                       │
│                      (USER-TRIGGERED)                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  TRIGGER: User selects an issue and clicks "Generate Solution"  │
│                                                                  │
│  PROCESS:                                                        │
│                                                                  │
│  1. Context Building                                            │
│     • Retrieve issue details (type, severity, location)         │
│     • Extract code snippet around issue                         │
│     • Gather related code (imports, dependencies)               │
│     • Include project context (language, framework)             │
│                                                                  │
│  2. AI Solution Generation                                      │
│     • Select AI provider (Gemini, Claude, etc.)                 │
│     • Build prompt with context                                 │
│     • Request solution from AI                                  │
│     • Parse AI response                                         │
│     • Validate solution format                                  │
│                                                                  │
│  3. Solution Presentation                                       │
│     • Display proposed fix to user                              │
│     • Show before/after code comparison                         │
│     • Explain the fix                                           │
│     • Highlight potential side effects                          │
│     • Provide "Apply" and "Reject" options                      │
│                                                                  │
│  4. User Review                                                 │
│     • User reviews the proposed solution                        │
│     • User can request modifications                            │
│     • User can ask questions about the fix                      │
│     • User approves or rejects                                  │
│                                                                  │
│  5. Solution Application (if approved)                          │
│     • Create backup of original file                            │
│     • Apply the fix to the codebase                             │
│     • Run tests (if configured)                                 │
│     • Log the remediation action                                │
│     • Update issue status to "resolved"                         │
│                                                                  │
│  OUTPUT: Applied fix + Remediation log                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### Scanner Component

**Location:** `internal/scanner/scanner.go`

**Responsibility:** Deterministic code scanning and analysis

**Key Functions:**

```go
// Scan performs a complete scan of a project directory
func (s *Scanner) Scan(ctx context.Context, projectPath string) (*types.KnowledgeGraph, error)

// ScanFile analyzes a single source code file
func (s *Scanner) ScanFile(path string) (*types.Node, error)

// BuildKnowledgeGraph constructs a graph from scanned data
func (s *Scanner) BuildKnowledgeGraph() *types.KnowledgeGraph

// parseFileDependencies extracts imports from a file
func (s *Scanner) parseFileDependencies(path string, content []byte) []string
```

**Detection Methods:**
- AST parsing for Go files
- Regex patterns for JavaScript, Python, Java
- File system traversal
- Dependency manifest parsing

**No AI Usage:** ✅ Completely deterministic

---

### Risk Diagnoser Component

**Location:** `internal/risk/diagnoser.go`

**Responsibility:** Deterministic issue detection

**Key Functions:**

```go
// Diagnose analyzes a knowledge graph and detects issues
func (rd *RiskDiagnoser) Diagnose(graph *types.KnowledgeGraph) (*types.RiskAssessment, error)

// detectSecurityVulnerabilities finds security issues via pattern matching
func (rd *RiskDiagnoser) detectSecurityVulnerabilities(code string) []types.Issue

// detectTechnicalDebt identifies code quality issues
func (rd *RiskDiagnoser) detectTechnicalDebt(node *types.Node) []types.Issue

// detectObsoleteCode finds unused or deprecated code
func (rd *RiskDiagnoser) detectObsoleteCode(graph *types.KnowledgeGraph) []types.Issue

// assessDependencyRisks checks dependencies against CVE databases
func (rd *RiskDiagnoser) assessDependencyRisks(deps []types.Dependency) []types.Issue
```

**Detection Methods:**
- Regex pattern matching for vulnerabilities
- Cyclomatic complexity calculation
- Reference counting for unused code
- CVE database lookups
- Version comparison with package registries

**No AI Usage:** ✅ Completely deterministic

---

### AI Remediation Service

**Location:** `internal/remediation/service.go` (to be created)

**Responsibility:** User-triggered solution generation

**Key Functions:**

```go
// GenerateSolution creates a fix recommendation for an issue
func (r *RemediationService) GenerateSolution(issueID string, userID string) (*Solution, error)

// ApplySolution applies an approved fix to the codebase
func (r *RemediationService) ApplySolution(solutionID string, userID string) error

// ExplainIssue provides a detailed explanation of an issue
func (r *RemediationService) ExplainIssue(issueID string) (string, error)
```

**AI Usage:** ✅ Only when user explicitly requests

---

### Data Engine

**Location:** `data_engine/`

**Responsibility:** Metrics collection, event streaming, WebSocket management

**Key Functions:**
- Real-time system metrics (CPU, memory, disk, network)
- Event streaming to Kafka (optional)
- WebSocket broadcasting for live updates
- Analytics and trend analysis

**No AI Usage:** ✅ Completely deterministic

---

## Deterministic Scanning Pipeline

### Input

```
Project Directory: /path/to/project
```

### Processing Steps

1. **File Discovery** (deterministic)
   - Traverse directory tree
   - Filter by file extensions
   - Respect .gitignore

2. **AST Parsing** (deterministic)
   - Parse each file with language-specific parser
   - Extract structure (functions, classes, imports)

3. **Dependency Extraction** (deterministic)
   - Parse manifest files (go.mod, package.json, etc.)
   - Build dependency graph

4. **Metrics Calculation** (deterministic)
   - Calculate LOC, complexity, etc.
   - Compute graph metrics

5. **Issue Detection** (deterministic)
   - Apply pattern matching rules
   - Check against CVE databases
   - Calculate severity scores

### Output

```json
{
  "knowledgeGraph": {
    "nodes": [...],
    "edges": [...]
  },
  "issues": [
    {
      "id": "issue-1",
      "type": "security",
      "severity": "high",
      "title": "SQL Injection Vulnerability",
      "location": {
        "file": "/path/to/file.go",
        "line": 42
      }
    }
  ],
  "metrics": {
    "filesScanned": 150,
    "linesOfCode": 12500,
    "issuesFound": 42
  }
}
```

### Guarantees

- ✅ Same input always produces same output
- ✅ No randomness or AI inference
- ✅ Works offline (except CVE updates)
- ✅ Fast execution (no AI latency)
- ✅ Zero cost

---

## AI Remediation Workflow

### User Workflow

```
1. User views detected issues in dashboard
   ↓
2. User selects an issue
   ↓
3. User clicks "Generate Solution"
   ↓
4. AI generates fix recommendation
   ↓
5. User reviews the proposed solution
   ↓
6. User approves or rejects
   ↓
7. If approved, fix is applied
   ↓
8. Issue status updated to "resolved"
```

### API Flow

```
POST /api/v1/remediate/generate
{
  "issueId": "issue-1",
  "userId": "user-123"
}

↓

AI Remediation Service:
1. Retrieve issue details
2. Build context
3. Call AI provider
4. Parse response
5. Return solution

↓

Response:
{
  "solutionId": "sol-456",
  "fix": {
    "file": "/path/to/file.go",
    "line": 42,
    "before": "db.Query(\"SELECT * FROM users WHERE id = \" + userId)",
    "after": "db.Query(\"SELECT * FROM users WHERE id = ?\", userId)",
    "explanation": "Use parameterized queries to prevent SQL injection"
  }
}

↓

User reviews and approves

↓

POST /api/v1/remediate/apply
{
  "solutionId": "sol-456",
  "userId": "user-123"
}

↓

Fix applied to codebase
```

---

## Storage Architecture

### Chromem-go Vector Database

**Location:** `./archguardian-data/`

**Collections:**

1. **projects**
   - Project metadata
   - Configuration settings
   - Last scan timestamp

2. **knowledge-graphs**
   - Nodes (files, functions, classes)
   - Edges (imports, calls, inheritance)
   - Graph metrics

3. **security-issues**
   - Detected vulnerabilities
   - Severity scores
   - Location information

4. **test-coverage**
   - Coverage metrics
   - Uncovered files
   - Test file counts

5. **scan-history**
   - Historical scan results
   - Trend data
   - Performance metrics

6. **remediation-logs**
   - Applied fixes
   - User approvals
   - AI interactions

---

## API Architecture

### REST API Endpoints

**Base URL:** `http://localhost:3000/api/v1`

**Endpoint Categories:**

1. **Project Management**
   - `GET /projects` - List projects
   - `POST /projects` - Create project
   - `GET /projects/{id}` - Get project details
   - `DELETE /projects/{id}` - Delete project
   - `POST /projects/{id}/scan` - Trigger scan

2. **Scanning**
   - `POST /scan/start` - Start scan
   - `GET /scan/status` - Get scan status

3. **Data Retrieval**
   - `GET /knowledge-graph` - Get knowledge graph
   - `GET /issues` - Get detected issues
   - `GET /coverage` - Get test coverage

4. **Remediation** (User-Triggered)
   - `POST /remediate/generate` - Generate solution
   - `POST /remediate/apply` - Apply solution
   - `GET /remediate/history` - Get remediation history

5. **Monitoring**
   - `GET /metrics` - System metrics
   - `GET /integrations/status` - Integration health

6. **Administration**
   - `GET /settings` - Get settings
   - `POST /settings` - Update settings
   - `POST /backup` - Create backup
   - `GET /backup` - List backups

### WebSocket API

**Endpoint:** `ws://localhost:3000/ws`

**Event Types:**
- `scan_progress` - Scan progress updates
- `scan_complete` - Scan completion
- `issue_detected` - New issue found
- `metrics_update` - System metrics update
- `remediation_complete` - Fix applied

---

## Security Architecture

### Authentication

- **GitHub OAuth** for user authentication
- **JWT tokens** for API authentication
- **Token expiration** and refresh

### Authorization

- **Role-based access control** (RBAC)
- **Project-level permissions**
- **API key management**

### Data Security

- **AES-GCM encryption** for backups
- **Secure storage** of API keys
- **HTTPS** for production deployments

### AI Security

- **User approval required** for all AI-generated fixes
- **Audit logging** of all AI interactions
- **Rate limiting** on AI requests
- **API key rotation** for AI providers

---

## Performance Characteristics

### Scanning Performance

- **Speed:** 100-1000x faster than AI-based scanning
- **Throughput:** ~100 files/second
- **Memory:** O(n) where n = number of files
- **Disk:** Minimal (only for persistence)

### Detection Performance

- **Speed:** Instant (pattern matching)
- **Accuracy:** High (rule-based)
- **False Positives:** Low (tunable rules)
- **False Negatives:** Low (comprehensive patterns)

### AI Remediation Performance

- **Speed:** 2-10 seconds per solution
- **Cost:** $0.001-0.01 per solution
- **Quality:** High (context-aware)
- **User Control:** 100% (review required)

---

## Scalability

### Horizontal Scaling

- **Stateless API servers** for easy scaling
- **Load balancing** across multiple instances
- **Distributed scanning** for large codebases

### Vertical Scaling

- **Parallel file processing** with goroutines
- **Efficient memory usage** with streaming
- **Optimized database queries**

---

## Monitoring & Observability

### Metrics

- Scan duration
- Issues detected per scan
- AI solution generation time
- API response times
- System resource usage

### Logging

- Structured logging with levels
- Request/response logging
- Error tracking
- Audit logging for AI interactions

### Alerting

- Scan failures
- High issue counts
- System resource thresholds
- Integration failures

---

## Future Enhancements

1. **Multi-language Support**
   - Add support for more programming languages
   - Language-specific detection rules

2. **Custom Rules**
   - User-defined detection patterns
   - Custom severity scoring

3. **CI/CD Integration**
   - GitHub Actions integration
   - GitLab CI integration
   - Jenkins plugin

4. **IDE Plugins**
   - VS Code extension
   - IntelliJ plugin
   - Vim plugin

5. **Advanced Analytics**
   - Trend analysis
   - Predictive modeling
   - Technical debt forecasting

---

## References

- [Determinism Implementation Plan](./determinism_implementation.md)
- [API Documentation](./API_DOCUMENTATION.md)
- [Contributing Guidelines](../CONTRIBUTING.md)
- [README](../README.md)

---

**Document Version:** 1.0.0  
**Last Updated:** 2024-01-15  
**Maintained By:** ArchGuardian Team