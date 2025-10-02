package inference_engine

// Prompts for ArchGuardian Code Analysis and Remediation
const (
	// CodeFileAnalysisPrompt asks the AI to analyze a single code file for quality, complexity, and issues.
	// It expects a structured JSON response.
	CodeFileAnalysisPrompt = `
Analyze the following code file and provide a structured JSON response with the following keys:
- "complexity_score": A float from 1.0 (simple) to 10.0 (very complex).
- "quality_score": A float from 1.0 (poor) to 10.0 (excellent).
- "key_issues": An array of strings, where each string describes a potential issue (e.g., "Hardcoded credentials", "Inefficient loop", "Lack of error handling").
- "summary": A brief one-sentence summary of the file's purpose.

Respond ONLY with the raw JSON object.

--- CODE ---
%s
--- END CODE ---
`

	// DatabaseModelAnalysisPrompt asks the AI to analyze a database schema file.
	// It expects a structured JSON response detailing tables, relationships, and potential issues.
	DatabaseModelAnalysisPrompt = `
Analyze the following database model or schema file. Identify tables, columns, relationships, potential performance bottlenecks, and normalization issues.
Provide a structured JSON response with the following keys:
- "tables": An array of objects, where each object has "name" (string) and "columns" (array of strings).
- "relationships": An array of objects describing foreign key relationships, each with "from_table", "from_column", "to_table", and "to_column".
- "performance_issues": An array of strings describing potential performance issues (e.g., "Missing index on foreign key 'user_id'").
- "normalization_issues": An array of strings describing potential normalization problems (e.g., "Redundant data in 'address' column").

Respond ONLY with the raw JSON object.

--- SCHEMA ---
%s
--- END SCHEMA ---
`

	// RelationshipInferencePrompt asks the AI to infer connections between different code components (nodes).
	// It expects a JSON array of relationship objects.
	RelationshipInferencePrompt = `
Given the following list of software components (nodes) from a codebase, infer the relationships between them.
A relationship could be a function call, data flow, dependency, or API usage.

For each inferred relationship, provide a confidence score from 0.0 to 1.0.

Return a JSON array of relationship objects, where each object has the following keys:
- "from": The ID of the source node.
- "to": The ID of the target node.
- "type": The type of relationship (e.g., "CALLS", "DEPENDS_ON", "USES_API", "READS_FROM", "WRITES_TO").
- "confidence": A float from 0.0 to 1.0 indicating your confidence in this inference.
- "metadata": An object for any additional context, like the specific function call name.

Respond ONLY with the raw JSON array.

--- NODES ---
%s
--- END NODES ---
`

	// RiskAnalysisPrompt asks the AI to perform a comprehensive risk assessment on the entire knowledge graph.
	// It expects a structured JSON object categorizing different types of risks.
	RiskAnalysisPrompt = `
Analyze the provided knowledge graph of a software project for potential risks.
Identify and categorize risks into the following four areas: "technical_debt", "security", "obsolete_code", and "dependencies".

Return a single JSON object with keys for each risk category. Each key should map to an array of risk items.

Example format for a "technical_debt" item:
{ "location": "path/to/file.go:42", "severity": "high", "description": "Complex function with high cyclomatic complexity.", "effort_hours": 8 }

Example format for a "security" item:
{ "cve": "CVE-2023-12345", "package": "some-library", "version": "1.2.3", "severity": "critical", "description": "Remote code execution vulnerability." }

Respond ONLY with the raw JSON object.

--- KNOWLEDGE GRAPH ---
%s
--- END KNOWLEDGE GRAPH ---
`

	// RemediationPrompt asks the AI to generate a specific code fix or command for a given issue.
	// It expects only the raw code or command as output.
	RemediationPrompt = `
You are an expert automated code remediation assistant.
Generate a code patch, a full replacement file, or a shell command to fix the following issue.
Provide ONLY the raw code, patch, or command as your response, with no explanations or markdown formatting.

--- ISSUE ---
%s
--- END ISSUE ---
`
)

// GetCodeFileAnalysisPrompt formats the prompt for code file analysis.
func GetCodeFileAnalysisPrompt(codeContent string) string {
	return formatPrompt(CodeFileAnalysisPrompt, codeContent)
}

// GetDatabaseModelAnalysisPrompt formats the prompt for database schema analysis.
func GetDatabaseModelAnalysisPrompt(schemaContent string) string {
	return formatPrompt(DatabaseModelAnalysisPrompt, schemaContent)
}

// GetRelationshipInferencePrompt formats the prompt for inferring relationships from graph nodes.
func GetRelationshipInferencePrompt(nodesJSON string) string {
	return formatPrompt(RelationshipInferencePrompt, nodesJSON)
}

// GetRiskAnalysisPrompt formats the prompt for comprehensive risk analysis of the knowledge graph.
func GetRiskAnalysisPrompt(graphJSON string) string {
	return formatPrompt(RiskAnalysisPrompt, graphJSON)
}

// GetRemediationPrompt formats the prompt for generating a fix for a specific issue.
func GetRemediationPrompt(issueJSON string) string {
	return formatPrompt(RemediationPrompt, issueJSON)
}

// formatPrompt formats a prompt with the given arguments
func formatPrompt(format string, args ...interface{}) string {
	return sprintf(format, args...)
}

// sprintf is a simple implementation of fmt.Sprintf to avoid importing fmt
func sprintf(format string, args ...interface{}) string {
	result := format
	for _, arg := range args {
		// Replace the first occurrence of %s with the string representation of arg
		// This is a simplified version and doesn't handle all format specifiers
		if s, ok := arg.(string); ok {
			result = replaceFirst(result, "%s", s)
		}
	}
	return result
}

// replaceFirst replaces the first occurrence of old with new in s
func replaceFirst(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

// indexOf returns the index of the first occurrence of substr in s, or -1 if substr is not present
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
