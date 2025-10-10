package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Utility functions for file operations, validation, and common tasks

// IsCodeFile determines if a file is a code file based on its extension
func IsCodeFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	codeExts := []string{".go", ".py", ".js", ".ts", ".java", ".cpp", ".c", ".rs", ".rb",
		".php", ".cs", ".swift", ".kt", ".scala", ".sql"}

	for _, codeExt := range codeExts {
		if ext == codeExt {
			return true
		}
	}
	return false
}

// GenerateNodeID generates a unique ID for a node based on its path
func GenerateNodeID(path string) string {
	// Simple hash-based ID generation
	return fmt.Sprintf("node_%x", []byte(path))
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsValidPackageName validates package names to prevent command injection
func IsValidPackageName(pkg string) bool {
	// Package names should only contain letters, numbers, hyphens, dots, and slashes
	if pkg == "" {
		return false
	}

	// Check for dangerous characters
	dangerousChars := []string{";", "&", "|", "$", "(", ")", "<", ">", "`", "\\", "\n", "\r", "\t"}
	for _, char := range dangerousChars {
		if strings.Contains(pkg, char) {
			return false
		}
	}

	// Check for path traversal
	if strings.Contains(pkg, "..") {
		return false
	}

	return true
}

// SanitizePackageName sanitizes package names for safe command execution
func SanitizePackageName(pkg string) string {
	// Remove any potentially dangerous characters
	sanitized := strings.Map(func(r rune) rune {
		// Allow only safe characters: letters, numbers, hyphens, dots, forward slashes, underscores
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '.' ||
			r == '/' || r == '_' || r == '@' {
			return r
		}
		return -1 // Remove this character
	}, pkg)

	// Remove any path traversal attempts
	if strings.Contains(sanitized, "..") {
		return ""
	}

	return sanitized
}

// IsValidVersion validates version strings to prevent command injection
func IsValidVersion(version string) bool {
	// Version should only contain letters, numbers, dots, hyphens, and plus signs
	if version == "" {
		return false
	}

	// Check for dangerous characters
	dangerousChars := []string{";", "&", "|", "$", "(", ")", "<", ">", "`", "\\", "\n", "\r", "\t"}
	for _, char := range dangerousChars {
		if strings.Contains(version, char) {
			return false
		}
	}

	return true
}

// IsValidFilePath validates file paths to prevent directory traversal attacks
func IsValidFilePath(filePath, basePath string) bool {
	// Convert to absolute paths for comparison
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return false
	}

	absBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return false
	}

	// Ensure the file path is within the base path
	relPath, err := filepath.Rel(absBasePath, absFilePath)
	if err != nil {
		return false
	}

	// Check for path traversal attempts
	if strings.HasPrefix(relPath, "..") || strings.Contains(relPath, ".."+string(filepath.Separator)) {
		return false
	}

	// Check for absolute paths that escape the base directory
	if filepath.IsAbs(relPath) {
		return false
	}

	// Check for dangerous file extensions or names
	dangerousNames := []string{"passwd", "shadow", "hosts", "sudoers", ".bashrc", ".profile", ".ssh/"}
	fileName := filepath.Base(filePath)
	for _, dangerous := range dangerousNames {
		if strings.EqualFold(fileName, dangerous) {
			return false
		}
	}

	return true
}

// IsValidProjectPath validates project paths to prevent directory traversal
func IsValidProjectPath(projectPath string) bool {
	// Project paths should be safe and not contain dangerous path elements
	if projectPath == "" {
		return false
	}

	// Check for dangerous characters and path traversal
	dangerousPatterns := []string{"../", "..\\", "/..", "\\..", "/etc/", "/proc/", "/sys/", "/dev/", "/var/", "/tmp/", "/home/", "/root/"}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(projectPath), pattern) {
			return false
		}
	}

	// Check for absolute paths that aren't in safe locations
	if strings.HasPrefix(projectPath, "/") {
		// Allow only specific safe directories
		safePrefixes := []string{"/home/", "/Users/", "/opt/", "/app/", "/workspace/", "/project/"}
		isSafe := false
		for _, prefix := range safePrefixes {
			if strings.HasPrefix(projectPath, prefix) {
				isSafe = true
				break
			}
		}
		if !isSafe {
			return false
		}
	}

	// Check for dangerous file extensions or names
	dangerousNames := []string{"passwd", "shadow", "hosts", "sudoers", ".bashrc", ".profile", ".ssh/"}
	fileName := filepath.Base(projectPath)
	for _, dangerous := range dangerousNames {
		if strings.EqualFold(fileName, dangerous) {
			return false
		}
	}

	return true
}

// IsValidConfigFilePath validates config file paths to prevent directory traversal
func IsValidConfigFilePath(filePath string) bool {
	// Config files should be in safe locations and not contain dangerous path elements
	if filePath == "" {
		return false
	}

	// Check for dangerous characters and path traversal
	dangerousPatterns := []string{"../", "..\\", "/..", "\\..", "/etc/", "/proc/", "/sys/", "/dev/", "/var/", "/home/", "/root/"}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(filePath), pattern) {
			return false
		}
	}

	// Allow /tmp/ paths for testing purposes
	if strings.HasPrefix(filePath, "/tmp/") || strings.HasPrefix(filePath, "/var/tmp/") {
		// Additional validation for temp files
		if strings.Contains(filePath, "..") {
			return false
		}
		// Check for dangerous file extensions or names
		dangerousNames := []string{"passwd", "shadow", "hosts", "sudoers", ".bashrc", ".profile", ".ssh/"}
		fileName := filepath.Base(filePath)
		for _, dangerous := range dangerousNames {
			if strings.EqualFold(fileName, dangerous) {
				return false
			}
		}
		return true
	}

	// Check for absolute paths that aren't in safe locations
	if strings.HasPrefix(filePath, "/") {
		// Allow only specific safe directories
		safePrefixes := []string{"./", ".archguardian/", "config/", "configs/"}
		isSafe := false
		for _, prefix := range safePrefixes {
			if strings.HasPrefix(filePath, prefix) {
				isSafe = true
				break
			}
		}
		if !isSafe {
			return false
		}
	}

	// Check for dangerous file extensions or names
	dangerousNames := []string{"passwd", "shadow", "hosts", "sudoers", ".bashrc", ".profile", ".ssh/"}
	fileName := filepath.Base(filePath)
	for _, dangerous := range dangerousNames {
		if strings.EqualFold(fileName, dangerous) {
			return false
		}
	}

	return true
}

// ReadFileSafely reads a file with path validation to prevent directory traversal
func ReadFileSafely(filePath string) ([]byte, error) {
	// Basic validation - ensure path doesn't contain dangerous patterns
	if strings.Contains(filePath, "..") {
		return nil, fmt.Errorf("invalid file path: contains path traversal")
	}

	// Check for absolute paths that aren't in safe locations
	if filepath.IsAbs(filePath) {
		// Allow only specific safe directories
		safePrefixes := []string{"/home/", "/Users/", "/opt/", "/app/", "/workspace/", "/project/", "/tmp/", "/var/tmp/"}
		isSafe := false
		for _, prefix := range safePrefixes {
			if strings.HasPrefix(filePath, prefix) {
				isSafe = true
				break
			}
		}
		if !isSafe {
			return nil, fmt.Errorf("invalid file path: absolute path in unsafe location")
		}
	}

	// Read the file
	return os.ReadFile(filePath)
}

// IsValidGitHubTokenURL validates GitHub OAuth token URLs to prevent hardcoded credential issues
func IsValidGitHubTokenURL(tokenURL string) bool {
	// Only allow the official GitHub OAuth token URL
	validURLs := []string{
		"https://github.com/login/oauth/access_token",
		"https://www.github.com/login/oauth/access_token",
	}

	for _, validURL := range validURLs {
		if tokenURL == validURL {
			return true
		}
	}

	return false
}

// ParseFileDependencies uses AST parsing to extract accurate dependencies from source files
func ParseFileDependencies(filePath string, content []byte) []string {
	var dependencies []string

	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".go":
		dependencies = parseGoDependencies(filePath, content)
	case ".js", ".ts", ".jsx", ".tsx":
		dependencies = parseJavaScriptDependencies(filePath, content)
	case ".py":
		dependencies = parsePythonDependencies(filePath, content)
	case ".java":
		dependencies = parseJavaDependencies(filePath, content)
	default:
		// Fallback to simple regex parsing for unknown file types
		dependencies = parseDependenciesWithRegex(filePath, content)
	}

	return dependencies
}

// parseGoDependencies uses go/parser to extract import declarations from Go files
func parseGoDependencies(filePath string, content []byte) []string {
	var dependencies []string

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, content, parser.ImportsOnly)
	if err != nil {
		log.Printf("  ⚠️  Failed to parse Go file %s: %v", filePath, err)
		return parseDependenciesWithRegex(filePath, content)
	}

	for _, imp := range node.Imports {
		// imp.Path.Value is the import path (e.g., "\"fmt\"")
		depPath := strings.Trim(imp.Path.Value, "\"")
		if depPath != "" {
			dependencies = append(dependencies, depPath)
		}
	}

	return dependencies
}

// parseJavaScriptDependencies uses regex to extract import/require statements from JS/TS files
func parseJavaScriptDependencies(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Match ES6 imports: import ... from 'module'
	importRegex := regexp.MustCompile(`import\s+.*?\s+from\s+['"]([^'"]+)['"]`)
	matches := importRegex.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) > 1 && match[1] != "" {
			dependencies = append(dependencies, match[1])
		}
	}

	// Match CommonJS requires: require('module')
	requireRegex := regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	requireMatches := requireRegex.FindAllStringSubmatch(text, -1)
	for _, match := range requireMatches {
		if len(match) > 1 && match[1] != "" {
			dependencies = append(dependencies, match[1])
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// parsePythonDependencies uses regex to extract import statements from Python files
func parsePythonDependencies(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Match import statements: import module or from module import ...
	importRegex := regexp.MustCompile(`(?m)^(?:import\s+(\S+)|from\s+(\S+)\s+import)`)
	matches := importRegex.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		for i := 1; i < len(match); i++ {
			if match[i] != "" {
				// Extract the module name (first part before dots)
				moduleName := strings.Split(match[i], ".")[0]
				if moduleName != "" {
					dependencies = append(dependencies, moduleName)
				}
				break
			}
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// parseJavaDependencies uses regex to extract import statements from Java files
func parseJavaDependencies(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Match Java import statements: import package.Class;
	importRegex := regexp.MustCompile(`import\s+([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)*)\s*;`)
	matches := importRegex.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) > 1 && match[1] != "" {
			dependencies = append(dependencies, match[1])
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// parseDependenciesWithRegex is a fallback method using regex for unknown file types
func parseDependenciesWithRegex(_ string, content []byte) []string {
	var dependencies []string
	text := string(content)

	// Generic patterns for various languages
	patterns := []string{
		`import\s+['"]([^'"]+)['"]`,            // import 'module'
		`from\s+['"]([^'"]+)['"]`,              // from 'module'
		`require\s*\(\s*['"]([^'"]+)['"]\s*\)`, // require('module')
		`#include\s+[<"]([^>"]+)[>"]`,          // #include <header>
		`use\s+(\S+)`,                          // use module (Perl)
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				dependencies = append(dependencies, match[1])
			}
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueDeps []string
	for _, dep := range dependencies {
		if !seen[dep] {
			seen[dep] = true
			uniqueDeps = append(uniqueDeps, dep)
		}
	}

	return uniqueDeps
}

// ParseJavaScriptAPIs parses JavaScript/TypeScript files to extract API usage patterns
func ParseJavaScriptAPIs(content string) map[string]bool {
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

// ParseHTMLFeatures uses the standard HTML parser to find tags and attributes
func ParseHTMLFeatures(filePath, content string) []map[string]interface{} {
	var features []map[string]interface{}
	tokenizer := html.NewTokenizer(strings.NewReader(content))

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return features // End of document
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			// Record element
			features = append(features, map[string]interface{}{
				"type":       "element",
				"name":       token.Data,
				"file_path":  filePath,
				"attributes": token.Attr,
			})
			// Record attributes
			for _, attr := range token.Attr {
				features = append(features, map[string]interface{}{
					"type":      "attribute",
					"element":   token.Data,
					"name":      attr.Key,
					"value":     attr.Val,
					"file_path": filePath,
				})
			}
		}
	}
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		length = 32 // Default length
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// Min returns the minimum of two float64 values
func Min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// Max returns the maximum of two float64 values
func Max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// Clamp clamps a value between min and max
func Clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// FormatDuration formats a duration in a human-readable way
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// IsInSlice checks if a string is in a slice
func IsInSlice(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RemoveFromSlice removes a string from a slice
func RemoveFromSlice(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// UniqueStrings returns a slice with unique strings
func UniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

// GetEnvWithDefault gets an environment variable with a default value
func GetEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvIntWithDefault gets an environment variable as int with a default value
func GetEnvIntWithDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := parseInt(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// GetEnvBoolWithDefault gets an environment variable as bool with a default value
func GetEnvBoolWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := parseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

// Helper functions for parsing
func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

func parseBool(s string) (bool, error) {
	return fmt.Sprintf("%s", s) == "true", nil
}
