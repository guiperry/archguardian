### ArchGuardian: Final Polish & Enhancement Plan

This document outlines the final implementation phases to elevate `ArchGuardian` from an integrated system to a production-ready, feature-rich application. These steps focus on improving accuracy, adding new visibility layers, and ensuring robustness.

---

#### **Phase 1: Advanced Dependency Parsing with AST**

**Goal:** Replace the current simple string-matching for dependency scanning with precise Abstract Syntax Tree (AST) parsing. This will dramatically improve the accuracy of the knowledge graph's dependency links.

**Implementation Steps:**

1.  **Refactor `scanStaticCode`:** Modify the `filepath.Walk` function to use language-specific parsers.

2.  **Implement for Go:** For files ending in `.go`, use the standard library's `go/parser` to read the import declarations.

    ```go
    // In main.go, inside scanStaticCode's filepath.Walk
    if strings.HasSuffix(path, ".go") {
        fset := token.NewFileSet()
        // Parse only imports for efficiency
        node, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
        if err == nil {
            for _, imp := range node.Imports {
                // imp.Path.Value is the import path (e.g., "\"fmt\"")
                // Clean the quotes and add to the code node's dependency list
                depPath := strings.Trim(imp.Path.Value, "\"")
                // ... logic to find or create the dependency node and link it
            }
        }
    }
    ```

3.  **Implement for JavaScript/TypeScript:** Use a Go-based JS/TS parser like `esbuild` to parse `.js` and `.ts` files. This is more robust than regex for handling different module formats (ESM, CommonJS).

4.  **Update Knowledge Graph:** Ensure that the `buildKnowledgeGraph` function correctly uses the newly accurate dependency information to create edges between code nodes and library nodes.

---

#### **Phase 2: Runtime Inspection Integration**

**Goal:** Complement static analysis with runtime data by adding a new scanner that inspects live environments. This provides a more complete picture of the application's actual behavior.

**Implementation Steps:**

1.  **Create `RuntimeScanner`:**
    *   Define a new `RuntimeScanner` struct in `main.go`.
    *   This scanner will use a library like `gopsutil` to inspect running processes, open files, and network connections on the host machine.

2.  **Add New Node Types:** Extend the `types` package with new `NodeType` constants for runtime entities.

    ```go
    // In types/types.go
    const (
        // ... existing types
        NodeTypeProcess    NodeType = "process"
        NodeTypeConnection NodeType = "connection"
    )
    ```

3.  **Integrate into Scan Cycle:**
    *   Add a new `scanRuntime(ctx)` method to the main `Scanner` struct.
    *   This method will invoke the `RuntimeScanner` to gather data.
    *   The `RuntimeScanner` will create nodes for discovered processes and edges for network connections between them, adding them to the main knowledge graph.

---

#### **Phase 3: Enhanced Web Dashboard**

**Goal:** Leverage the `DataEngine`'s WebSocket and REST API capabilities to build a comprehensive, real-time web dashboard for visualizing the project's health and architecture.

**Implementation Steps:**

1.  **Create `dashboard` Directory:** In the project root, create a `dashboard` directory containing `index.html`, `style.css`, and `app.js`.

2.  **Serve Static Files:** Add a simple HTTP server to `main.go` that serves the files from the `./dashboard` directory.

3.  **Implement `app.js` with Multiple Views:**
    *   **Knowledge Graph View:** Use a library like `vis.js` or `D3.js` to render the graph. On page load, fetch the initial `knowledge-graph.json` from the `DataEngine`'s REST API. Use a WebSocket connection to listen for `scan_cycle_completed` events and trigger a refresh.
    *   **Issues Overview:** Create a table or list view that fetches data from a new `/api/v1/issues` endpoint. This endpoint will consolidate all items from the `RiskAssessment` (Technical Debt, Security Vulns, etc.).
    *   **Coverage Overview:** Create a view to display test coverage data. This will fetch a coverage report from a new `/api/v1/coverage` endpoint, which is populated during the test analysis phase.
    *   **Integrations View:** A settings page to configure and view the status of third-party integrations like Codacy.
    *   **Settings View:** A page to view and potentially modify `ArchGuardian`'s configuration.

---

#### **Phase 4: Enhanced Security Scanning with CVE Database**

**Goal:** Augment the AI-based security analysis with a reliable, structured CVE database to provide more accurate and actionable vulnerability information.

**Implementation Steps:**

1.  **Choose a CVE Data Source:** Integrate with a public CVE database.
    *   **Online Source (Default):** The NVD API 2.0 is a standard choice for real-time data.
    *   **Offline Source:** For environments without consistent internet access, `ArchGuardian` can be configured to use bulk CVE data from `cve.org`. The CVE Project hosts bulk download files in the `cvelistV5` repository on GitHub: https://github.com/CVEProject/cvelistV5. A separate process can be created to periodically download these JSON files, allowing `ArchGuardian` to perform offline CVE lookups.

2.  **Create a `CVEScanner`:**
    *   Define a new `CVEScanner` struct responsible for querying the chosen CVE database.
    *   This struct will manage the HTTP client and API key for making requests to the NVD API.

    ```go
    // This can be added to main.go or a new security.go file.

    // CVEScanner handles querying CVE databases like the NVD.
    type CVEScanner struct {
        httpClient *http.Client
        apiKey     string // For NVD API v2
    }

    // NewCVEScanner creates a new CVE scanner.
    func NewCVEScanner(apiKey string) *CVEScanner {
        return &CVEScanner{
            httpClient: &http.Client{Timeout: 30 * time.Second},
            apiKey:     apiKey,
        }
    }

    // QueryNVD queries the National Vulnerability Database for a given package.
    // This is a placeholder implementation.
    func (cs *CVEScanner) QueryNVD(packageName, version string) ([]types.SecurityVulnerability, error) {
        log.Printf("  🔍 Querying NVD for vulnerabilities in %s@%s...", packageName, version)

        // Placeholder: In a real implementation, you would construct the NVD API URL,
        // make an HTTP GET request with the API key, and parse the JSON response
        // into `types.SecurityVulnerability` structs.
        
        // For now, returning an empty slice to indicate no vulnerabilities found.
        return []types.SecurityVulnerability{}, nil
    }
    ```

3.  **Update `RiskDiagnoser`:**
    *   In `DiagnoseRisks`, after scanning dependencies, iterate through all `NodeTypeLibrary` nodes.
    *   For each library, use the `CVEScanner` to query the NVD API with the package name and version.
    *   If vulnerabilities are found, create `SecurityVulnerability` items from the structured API response, which is more reliable than AI-only detection.
    *   Merge these findings with any additional security risks identified by the AI in the `AnalyzeRisks` step.

---

#### **Phase 5: Test Suite & Coverage Analysis**

**Goal:** Ensure long-term stability and gain insights into test effectiveness by adding a comprehensive test suite and coverage analysis.

**Implementation Steps:**

1.  **Implement Unit & Integration Tests:**
    *   Create a `main_test.go` file.
    *   Write a `TestScanGoMod` function that creates a temporary `go.mod` file and asserts that the `Scanner` correctly parses the dependencies.
    *   Write a `TestCalculateOverallRisk` function with a mock `RiskAssessment` to assert that the scoring logic is correct.
    *   Write a `TestApplyFixPatch` function to test the `git apply` logic in the `Remediator`.

2.  **Implement Coverage Scanning:**
    *   Enhance the `Scanner` with a `scanTestCoverage(ctx)` method.
    *   This method will execute the appropriate command for the project (e.g., `go test -coverprofile=coverage.out`) and parse the output.
    *   Store the coverage percentage in the metadata of the corresponding code `Node` in the knowledge graph.

3.  **AI-Powered Test Generation:**
    *   Enhance the `Remediator` with a new `generateMissingTests` method.
    *   This method will identify code nodes with low coverage and use an AI model to generate new unit tests to improve the coverage score.

4.  **Set up CI:** Integrate all tests and coverage scans into a GitHub Actions workflow that runs on every push.

---

#### **Phase 6: Log Stream Analysis & Remediation**

**Goal:** Proactively identify and fix issues from runtime logs by creating a feedback loop from production errors back to code remediation.

**Implementation Steps:**

1.  **Create a Log Ingestion Endpoint:** In the `DataEngine`, add a new HTTP or UDP endpoint to receive log streams from external applications (e.g., via Fluentd or a direct logger hook).

2.  **Implement a `LogAnalyzer`:**
    *   Create a new `LogAnalyzer` component that listens for `LogMsg` events from the `DataEngine`.
    *   When a stream of error logs is detected for a specific component, use an AI model (e.g., Gemini) to analyze the log content, identify the root cause, and determine if it's a new, actionable issue.

3.  **Integrate with `RiskDiagnoser`:** If the `LogAnalyzer` identifies a new issue, it should create a `TechnicalDebtItem` and add it to a new `RiskAssessment` cycle.

4.  **Trigger Remediation:** The new issue will be picked up by the `Remediator` in the next cycle, which will attempt to generate and apply a patch, completing the feedback loop.

---

#### **Phase 7: Codacy API Integration**

**Goal:** Enrich `ArchGuardian`'s analysis by integrating with Codacy to pull in its static analysis results and manage repository configurations programmatically.

**Implementation Steps:**

1.  **Create `CodacyClient`:**
    *   Develop a new client in Go to interact with the Codacy REST API, handling authentication with a Codacy API token.

2.  **Fetch and Integrate Issues:**
    *   In the `RiskDiagnoser`, use the `CodacyClient` to fetch the list of open issues for the repository.
    *   For each issue from Codacy, create a corresponding `TechnicalDebtItem` in `ArchGuardian`'s `RiskAssessment`, mapping severities and descriptions. This provides an immediate, rich source of data without waiting for AI analysis.

3.  **Programmatic Configuration (Advanced):**
    *   Extend the `CodacyClient` to allow for configuration changes.
    *   In the `Remediator`, add logic to, for example, disable a specific Codacy rule that is causing consistent false positives, by making a `POST` or `PUT` request to the relevant Codacy API endpoint. This demonstrates `ArchGuardian`'s ability to not only fix code but also manage the surrounding toolchain.