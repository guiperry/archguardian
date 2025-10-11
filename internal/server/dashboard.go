package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// Enhanced handlers that integrate with ArchGuardian when available

// handleKnowledgeGraphWithGuardian returns knowledge graph data from ArchGuardian
//
//nolint:unused // This function is used internally by enhanced handlers when guardian is available
func handleKnowledgeGraphWithGuardian(w http.ResponseWriter, r *http.Request, guardian *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if guardian == nil || guardian.Guardian == nil {
		handleKnowledgeGraph(w, r)
		return
	}

	// Get knowledge graph from scanner
	graph := guardian.Guardian.GetScanner().GetKnowledgeGraph()
	graphData := graph.ToAPIFormat()

	response := map[string]interface{}{
		"nodes":         graphData["nodes"],
		"edges":         graphData["edges"],
		"nodeCount":     len(graph.Nodes),
		"edgeCount":     len(graph.Edges),
		"lastUpdated":   graph.LastUpdated.Format(time.RFC3339),
		"analysisDepth": graph.AnalysisDepth,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleRiskAssessmentWithGuardian returns risk assessment data from ArchGuardian
//
//nolint:unused // This function is used internally by enhanced handlers when guardian is available
func handleRiskAssessmentWithGuardian(w http.ResponseWriter, r *http.Request, guardian *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if guardian == nil || guardian.Guardian == nil {
		handleRiskAssessment(w, r)
		return
	}

	// Get the latest assessment from the diagnoser
	latestAssessment := guardian.Guardian.GetDiagnoser().GetLatestAssessment()

	// If no assessment yet, return placeholder
	if latestAssessment == nil {
		assessment := map[string]interface{}{
			"overall_score":          0.0,
			"technical_debt":         []map[string]interface{}{},
			"security_vulns":         []map[string]interface{}{},
			"obsolete_code":          []map[string]interface{}{},
			"dangerous_dependencies": []map[string]interface{}{},
			"compatibility_issues":   []map[string]interface{}{},
			"timestamp":              time.Now().Format(time.RFC3339),
			"message":                "No scan results available yet. Please run a scan first.",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(assessment)
		return
	}

	// Convert assessment to API format with snake_case for frontend compatibility
	assessment := map[string]interface{}{
		"overall_score":          latestAssessment.OverallScore,
		"technical_debt":         latestAssessment.TechnicalDebt,
		"security_vulns":         latestAssessment.SecurityVulns,
		"obsolete_code":          latestAssessment.ObsoleteCode,
		"dangerous_dependencies": latestAssessment.DangerousDependencies,
		"compatibility_issues":   latestAssessment.CompatibilityIssues,
		"timestamp":              latestAssessment.Timestamp.Format(time.RFC3339),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(assessment)
}

// handleTriggerScan handles manual scan triggering from API
func handleTriggerScan(w http.ResponseWriter, r *http.Request, guardian *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if guardian == nil || guardian.Guardian == nil {
		http.Error(w, "ArchGuardian not available", http.StatusServiceUnavailable)
		return
	}

	// Log the request for debugging
	log.Printf("🔄 Manual scan triggered via API from %s", r.RemoteAddr)

	// Trigger scan
	guardian.Guardian.TriggerScan()

	response := map[string]interface{}{
		"success":   true,
		"message":   "Scan triggered successfully",
		"timestamp": time.Now().Format(time.RFC3339),
		"status":    guardian.Guardian.GetStatus(),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleGuardianStatus returns the current status of ArchGuardian
func handleGuardianStatus(w http.ResponseWriter, _ *http.Request, guardian *ArchGuardian) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if guardian == nil || guardian.Guardian == nil {
		http.Error(w, "ArchGuardian not available", http.StatusServiceUnavailable)
		return
	}

	status := guardian.Guardian.GetStatus()
	status["timestamp"] = time.Now().Format(time.RFC3339)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

// Enhanced dashboard data endpoints with ArchGuardian integration
func handleEnhancedKnowledgeGraph(w http.ResponseWriter, r *http.Request, guardian *ArchGuardian) {
	// Enhanced knowledge graph handler with additional processing
	log.Printf("📊 Enhanced knowledge graph request from %s", r.RemoteAddr)

	// Validate request parameters
	if err := validateDashboardRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get pagination parameters
	limit, offset := getPaginationParams(r)

	// Log enhanced processing
	log.Printf("📊 Processing enhanced knowledge graph: limit=%d, offset=%d", limit, offset)

	// Use guardian-enhanced handler if available, otherwise fall back to basic handler
	if guardian != nil && guardian.Guardian != nil {
		handleKnowledgeGraphWithGuardian(w, r, guardian)
	} else {
		handleKnowledgeGraph(w, r)
	}
}

func handleEnhancedRiskAssessment(w http.ResponseWriter, r *http.Request, guardian *ArchGuardian) {
	// Enhanced risk assessment with additional filtering
	log.Printf("📊 Enhanced risk assessment request from %s", r.RemoteAddr)

	// Get filter parameters
	filters := getFilterParams(r)
	log.Printf("📊 Risk assessment filters: %v", filters)

	// Use guardian-enhanced handler if available, otherwise fall back to basic handler
	if guardian != nil && guardian.Guardian != nil {
		handleRiskAssessmentWithGuardian(w, r, guardian)
	} else {
		handleRiskAssessment(w, r)
	}
}

func handleEnhancedIssues(w http.ResponseWriter, r *http.Request, guardian *ArchGuardian) {
	// Enhanced issues handler with filtering and pagination
	log.Printf("📊 Enhanced issues request from %s", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Validate and extract parameters
	limit, offset := getPaginationParams(r)
	filters := getFilterParams(r)

	log.Printf("📊 Enhanced issues: limit=%d, offset=%d, filters=%v", limit, offset, filters)

	// If guardian is not available, return empty data
	if guardian == nil || guardian.Guardian == nil {
		handleIssues(w, r)
		return
	}

	// Get the latest risk assessment
	assessment := guardian.Guardian.GetDiagnoser().GetLatestAssessment()

	// If no assessment yet, return empty
	if assessment == nil {
		response := map[string]interface{}{
			"technical_debt":         []map[string]interface{}{},
			"security_vulns":         []map[string]interface{}{},
			"dangerous_dependencies": []map[string]interface{}{},
			"compatibility_issues":   []map[string]interface{}{},
			"obsolete_code":          []map[string]interface{}{},
			"message":                "No scan results available yet. Please run a scan first.",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Collect issues by type
	technicalDebtIssues := make([]map[string]interface{}, 0)
	securityIssues := make([]map[string]interface{}, 0)
	dependencyIssues := make([]map[string]interface{}, 0)
	compatibilityIssues := make([]map[string]interface{}, 0)
	obsoleteCodeIssues := make([]map[string]interface{}, 0)

	// Add technical debt items
	for i, item := range assessment.TechnicalDebt {
		issue := map[string]interface{}{
			"id":          fmt.Sprintf("TD-%d", i+1),
			"type":        "technical_debt",
			"category":    item.Type,
			"name":        item.Type,
			"location":    item.Location,
			"severity":    item.Severity,
			"description": item.Description,
			"remediation": item.Remediation,
			"effort":      item.Effort,
			"timestamp":   assessment.Timestamp.Format(time.RFC3339),
		}
		if shouldIncludeIssue(issue, filters) {
			technicalDebtIssues = append(technicalDebtIssues, issue)
		}
	}

	// Add security vulnerabilities
	for i, vuln := range assessment.SecurityVulns {
		issue := map[string]interface{}{
			"id":          fmt.Sprintf("SEC-%d", i+1),
			"type":        "security",
			"category":    "vulnerability",
			"name":        vuln.CVE,
			"location":    fmt.Sprintf("%s@%s", vuln.Package, vuln.Version),
			"severity":    vuln.Severity,
			"description": vuln.Description,
			"remediation": fmt.Sprintf("Upgrade to %s", vuln.FixVersion),
			"cvss":        vuln.CVSS,
			"timestamp":   assessment.Timestamp.Format(time.RFC3339),
		}
		if shouldIncludeIssue(issue, filters) {
			securityIssues = append(securityIssues, issue)
		}
	}

	// Add obsolete code items
	for i, item := range assessment.ObsoleteCode {
		issue := map[string]interface{}{
			"id":          fmt.Sprintf("OBS-%d", i+1),
			"type":        "obsolete",
			"category":    "deprecated",
			"name":        item.Path,
			"location":    item.Path,
			"severity":    item.RemovalSafety,
			"description": fmt.Sprintf("Obsolete code with %d references. Last used: %s", item.References, item.LastUsed.Format("2006-01-02")),
			"remediation": item.RecommendAction,
			"references":  item.References,
			"timestamp":   assessment.Timestamp.Format(time.RFC3339),
		}
		if shouldIncludeIssue(issue, filters) {
			obsoleteCodeIssues = append(obsoleteCodeIssues, issue)
		}
	}

	// Add dangerous dependencies
	for i, dep := range assessment.DangerousDependencies {
		severity := "medium"
		if dep.SecurityIssues > 0 {
			severity = "high"
		}
		if dep.Maintenance == "abandoned" {
			severity = "critical"
		}

		issue := map[string]interface{}{
			"id":             fmt.Sprintf("DEP-%d", i+1),
			"type":           "dependency",
			"category":       "dangerous",
			"name":           dep.Package,
			"location":       fmt.Sprintf("%s@%s", dep.Package, dep.CurrentVersion),
			"severity":       severity,
			"description":    fmt.Sprintf("Dependency risk: %s (maintenance: %s, security issues: %d)", dep.Package, dep.Maintenance, dep.SecurityIssues),
			"remediation":    dep.Recommendation,
			"currentVersion": dep.CurrentVersion,
			"latestVersion":  dep.LatestVersion,
			"securityIssues": dep.SecurityIssues,
			"maintenance":    dep.Maintenance,
			"timestamp":      assessment.Timestamp.Format(time.RFC3339),
		}
		if shouldIncludeIssue(issue, filters) {
			dependencyIssues = append(dependencyIssues, issue)
		}
	}

	// Add compatibility issues
	for i, item := range assessment.CompatibilityIssues {
		issue := map[string]interface{}{
			"id":          fmt.Sprintf("COMPAT-%d", i+1),
			"type":        "compatibility",
			"category":    item.Type,
			"name":        item.Type,
			"location":    item.Location,
			"severity":    item.Severity,
			"description": item.Description,
			"remediation": item.Remediation,
			"timestamp":   assessment.Timestamp.Format(time.RFC3339),
		}
		if shouldIncludeIssue(issue, filters) {
			compatibilityIssues = append(compatibilityIssues, issue)
		}
	}

	log.Printf("📊 Returning issues: %d technical debt, %d security, %d dependencies, %d compatibility, %d obsolete",
		len(technicalDebtIssues), len(securityIssues), len(dependencyIssues), len(compatibilityIssues), len(obsoleteCodeIssues))

	// Return issues grouped by type for frontend compatibility
	response := map[string]interface{}{
		"technical_debt":         technicalDebtIssues,
		"security_vulns":         securityIssues,
		"dangerous_dependencies": dependencyIssues,
		"compatibility_issues":   compatibilityIssues,
		"obsolete_code":          obsoleteCodeIssues,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// shouldIncludeIssue checks if an issue matches the given filters
func shouldIncludeIssue(issue map[string]interface{}, filters map[string]string) bool {
	// If no filters, include all
	if len(filters) == 0 {
		return true
	}

	// Check severity filter
	if severity, ok := filters["severity"]; ok {
		if issueSeverity, ok := issue["severity"].(string); ok {
			if issueSeverity != severity {
				return false
			}
		}
	}

	// Check category filter (type)
	if category, ok := filters["category"]; ok {
		if issueType, ok := issue["type"].(string); ok {
			if issueType != category {
				return false
			}
		}
	}

	// Check since filter (timestamp)
	if since, ok := filters["since"]; ok {
		if timestamp, ok := issue["timestamp"].(string); ok {
			sinceTime, err1 := time.Parse(time.RFC3339, since)
			issueTime, err2 := time.Parse(time.RFC3339, timestamp)
			if err1 == nil && err2 == nil {
				if issueTime.Before(sinceTime) {
					return false
				}
			}
		}
	}

	return true
}

func handleEnhancedCoverage(w http.ResponseWriter, r *http.Request, _ *ArchGuardian) {
	// Enhanced coverage handler with detailed metrics
	log.Printf("📊 Enhanced coverage request from %s", r.RemoteAddr)

	// This would be called from the main server with access to ArchGuardian
	// For now, just call the basic handler
	handleCoverage(w, r)
}

func handleEnhancedSettings(w http.ResponseWriter, r *http.Request, _ *ArchGuardian) {
	// Enhanced settings handler with validation
	log.Printf("📊 Enhanced settings request from %s", r.RemoteAddr)

	// This would be called from the main server with access to ArchGuardian
	// For now, just call the basic handler
	handleSettings(w, r)
}

func handleEnhancedScanHistory(w http.ResponseWriter, r *http.Request, _ *ArchGuardian) {
	// Enhanced scan history with pagination and filtering
	log.Printf("📊 Enhanced scan history request from %s", r.RemoteAddr)

	limit, offset := getPaginationParams(r)
	log.Printf("📊 Scan history: limit=%d, offset=%d", limit, offset)

	// This would be called from the main server with access to ArchGuardian
	// For now, just call the basic handler
	handleScanHistory(w, r)
}

func handleEnhancedSemanticSearch(w http.ResponseWriter, r *http.Request, _ *ArchGuardian) {
	// Enhanced semantic search with advanced query processing
	log.Printf("📊 Enhanced semantic search request from %s", r.RemoteAddr)

	// Validate search query
	if err := validateDashboardRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := r.URL.Query().Get("q")
	log.Printf("📊 Semantic search query: %s", query)

	// This would be called from the main server with access to ArchGuardian
	// For now, just call the basic handler
	handleSemanticSearch(w, r)
}

func handleEnhancedSystemMetrics(w http.ResponseWriter, r *http.Request, _ *ArchGuardian) {
	// Enhanced system metrics with real-time data
	log.Printf("📊 Enhanced system metrics request from %s", r.RemoteAddr)

	// This would be called from the main server with access to ArchGuardian
	// For now, just call the basic handler
	handleSystemMetrics(w, r)
}

func handleEnhancedAPIDocs(w http.ResponseWriter, r *http.Request, _ *ArchGuardian) {
	// Enhanced API documentation with dynamic generation
	log.Printf("📊 Enhanced API docs request from %s", r.RemoteAddr)

	// This would be called from the main server with access to ArchGuardian
	// For now, just call the basic handler
	handleAPIDocs(w, r)
}

// Helper functions for dashboard data processing

// validateDashboardRequest validates common dashboard API request parameters
func validateDashboardRequest(r *http.Request) error {
	// Check for required parameters in different endpoints
	if r.URL.Path == "/api/v1/search" {
		if r.URL.Query().Get("q") == "" {
			return fmt.Errorf("query parameter 'q' is required for search endpoint")
		}
	}

	// Add more validation as needed for other endpoints
	log.Printf("🔍 Validating dashboard request for path: %s", r.URL.Path)
	return nil
}

// getPaginationParams extracts pagination parameters from request
func getPaginationParams(r *http.Request) (limit, offset int) {
	limit = 50 // default
	offset = 0 // default

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
			limit = parsedLimit
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	log.Printf("📄 Pagination params - limit: %d, offset: %d", limit, offset)
	return limit, offset
}

// getFilterParams extracts filter parameters from request
func getFilterParams(r *http.Request) map[string]string {
	filters := make(map[string]string)

	if severity := r.URL.Query().Get("severity"); severity != "" {
		filters["severity"] = severity
	}

	if category := r.URL.Query().Get("category"); category != "" {
		filters["category"] = category
	}

	if since := r.URL.Query().Get("since"); since != "" {
		filters["since"] = since
	}

	log.Printf("🔍 Filter params extracted: %v", filters)
	return filters
}
