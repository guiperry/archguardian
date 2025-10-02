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

#### **Phase 3: Web Dashboard for Visualization**

**Goal:** Leverage the `DataEngine`'s WebSocket and REST API capabilities to build a simple, real-time web dashboard for visualizing the knowledge graph and risk assessment.

**Implementation Steps:**

1.  **Create `dashboard` Directory:** In the project root, create a `dashboard` directory containing `index.html`, `style.css`, and `app.js`.

2.  **Serve Static Files:** Add a simple HTTP server to `main.go` that serves the files from the `./dashboard` directory.

3.  **Implement `app.js`:**
    *   Use a visualization library like `vis.js` or `D3.js` to render the graph.
    *   On page load, make a REST API call to the `DataEngine`'s endpoint (e.g., `http://localhost:7080/api/knowledge-graph`) to fetch the initial `knowledge-graph.json`.
    *   Establish a WebSocket connection to the `DataEngine` (e.g., `ws://localhost:8080/ws`).
    *   Listen for `SystemEvent` messages on the WebSocket. When an event like `scan_cycle_completed` is received, re-fetch the graph data to update the visualization in real-time.

---

#### **Phase 4: Enhance Security Scanning with CVE Database**

**Goal:** Augment the AI-based security analysis with a reliable, structured CVE database to provide more accurate and actionable vulnerability information.

**Implementation Steps:**

1.  **Choose a CVE Data Source:** Integrate with a public CVE database. The NVD API is a standard choice.

2.  **Create a `CVEScanner`:**
    *   Define a new `CVEScanner` struct.
    *   This component will be responsible for querying the chosen CVE database.

3.  **Update `RiskDiagnoser`:**
    *   In `DiagnoseRisks`, after scanning dependencies, iterate through all `NodeTypeLibrary` nodes.
    *   For each library, use the `CVEScanner` to query the NVD API with the package name and version.
    *   If vulnerabilities are found, create `SecurityVulnerability` items from the structured API response, which is more reliable than AI-only detection.
    *   Merge these findings with any additional security risks identified by the AI in the `AnalyzeRisks` step.

---

#### **Phase 5: Implement Unit & Integration Tests**

**Goal:** Ensure the long-term stability and reliability of `ArchGuardian` by adding a comprehensive test suite.

**Implementation Steps:**

1.  **Test the `Scanner`:**
    *   Create a `main_test.go` file.
    *   Write a `TestScanGoMod` function that creates a temporary `go.mod` file and asserts that the `Scanner` correctly parses the dependencies into `Node` objects.
    *   Write similar tests for `scanPackageJSON` and `scanRequirementsTxt`.

2.  **Test the `RiskDiagnoser`:**
    *   Write a `TestCalculateOverallRisk` function.
    *   Create a mock `RiskAssessment` struct with a known number of vulnerabilities and technical debt items.
    *   Assert that `calculateOverallRisk` returns the expected score based on the defined weights.

3.  **Test the `Remediator`:**
    *   Write a `TestApplyFixPatch` function.
    *   Create a temporary file with some content.
    *   Define a `diff`-formatted patch string.
    *   Call `applyFix` with the patch and assert that the temporary file's content has been correctly modified.

4.  **Set up CI:** Integrate these tests into a GitHub Actions workflow that runs on every push to ensure that new changes do not break existing functionality.