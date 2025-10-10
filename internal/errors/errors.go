package errors

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeValidation     ErrorType = "validation"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeNotFound       ErrorType = "not_found"
	ErrorTypeConflict       ErrorType = "conflict"
	ErrorTypeInternal       ErrorType = "internal"
	ErrorTypeExternal       ErrorType = "external"
	ErrorTypeRateLimit      ErrorType = "rate_limit"
	ErrorTypeTimeout        ErrorType = "timeout"
)

// AppError represents a structured application error
type AppError struct {
	Type       ErrorType              `json:"type"`
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Cause      error                  `json:"-"`
	StatusCode int                    `json:"-"`
	Timestamp  time.Time              `json:"timestamp"`
	RequestID  string                 `json:"request_id,omitempty"`
	UserID     string                 `json:"user_id,omitempty"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause
func (e *AppError) Unwrap() error {
	return e.Cause
}

// Is implements error comparison for errors.Is()
func (e *AppError) Is(target error) bool {
	if appErr, ok := target.(*AppError); ok {
		return e.Type == appErr.Type && e.Code == appErr.Code
	}
	return false
}

// NewAppError creates a new application error
func NewAppError(errorType ErrorType, code, message string, cause error) *AppError {
	statusCode := getStatusCodeForErrorType(errorType)

	return &AppError{
		Type:       errorType,
		Code:       code,
		Message:    message,
		Cause:      cause,
		StatusCode: statusCode,
		Timestamp:  time.Now(),
	}
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// WithRequestID adds request ID to the error
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// WithUserID adds user ID to the error
func (e *AppError) WithUserID(userID string) *AppError {
	e.UserID = userID
	return e
}

// getStatusCodeForErrorType maps error types to HTTP status codes
func getStatusCodeForErrorType(errorType ErrorType) int {
	switch errorType {
	case ErrorTypeValidation:
		return http.StatusBadRequest
	case ErrorTypeAuthentication:
		return http.StatusUnauthorized
	case ErrorTypeAuthorization:
		return http.StatusForbidden
	case ErrorTypeNotFound:
		return http.StatusNotFound
	case ErrorTypeConflict:
		return http.StatusConflict
	case ErrorTypeRateLimit:
		return http.StatusTooManyRequests
	case ErrorTypeTimeout:
		return http.StatusRequestTimeout
	case ErrorTypeExternal:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// Common error constructors for frequent use cases

// NewValidationError creates a validation error
func NewValidationError(message string, details map[string]interface{}) *AppError {
	return NewAppError(ErrorTypeValidation, "VALIDATION_FAILED", message, nil).WithDetails(details)
}

// NewNotFoundError creates a not found error
func NewNotFoundError(resource string) *AppError {
	return NewAppError(ErrorTypeNotFound, "RESOURCE_NOT_FOUND", fmt.Sprintf("%s not found", resource), nil)
}

// NewInternalError creates an internal server error
func NewInternalError(message string, cause error) *AppError {
	return NewAppError(ErrorTypeInternal, "INTERNAL_ERROR", message, cause)
}

// NewExternalError creates an external service error
func NewExternalError(service string, cause error) *AppError {
	return NewAppError(ErrorTypeExternal, "EXTERNAL_SERVICE_ERROR",
		fmt.Sprintf("External service %s failed", service), cause)
}

// NewAuthenticationError creates an authentication error
func NewAuthenticationError(message string) *AppError {
	return NewAppError(ErrorTypeAuthentication, "AUTHENTICATION_FAILED", message, nil)
}

// NewAuthorizationError creates an authorization error
func NewAuthorizationError(message string) *AppError {
	return NewAppError(ErrorTypeAuthorization, "AUTHORIZATION_FAILED", message, nil)
}

// ErrorHandler handles errors consistently across the application
type ErrorHandler struct {
	logger     *log.Logger
	notifyFunc func(*AppError) // Optional notification function
}

// NewErrorHandler creates a new error handler
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		logger: log.Default(),
	}
}

// SetNotificationFunction sets a function to call when errors occur
func (eh *ErrorHandler) SetNotificationFunction(fn func(*AppError)) {
	eh.notifyFunc = fn
}

// HandleError handles an error by logging it and optionally notifying
func (eh *ErrorHandler) HandleError(err error) {
	if err == nil {
		return
	}

	// Convert to AppError if not already
	var appErr *AppError
	if ae, ok := err.(*AppError); ok {
		appErr = ae
	} else {
		appErr = NewInternalError("Unexpected error occurred", err)
	}

	// Log the error
	eh.logger.Printf("🚨 Error [%s]: %s", appErr.Type, appErr.Error())
	if appErr.Details != nil {
		eh.logger.Printf("   Details: %+v", appErr.Details)
	}
	if appErr.RequestID != "" {
		eh.logger.Printf("   Request ID: %s", appErr.RequestID)
	}
	if appErr.UserID != "" {
		eh.logger.Printf("   User ID: %s", appErr.UserID)
	}

	// Send notification if configured
	if eh.notifyFunc != nil {
		eh.notifyFunc(appErr)
	}
}

// APIError represents a standardized API error response
type APIError struct {
	Error     string                 `json:"error"`
	Message   string                 `json:"message"`
	Code      string                 `json:"code,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	RequestID string                 `json:"request_id,omitempty"`
}

// APIResponse represents a standardized API response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

// sendError sends a standardized error response
func SendError(w http.ResponseWriter, appErr *AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(appErr.StatusCode)

	response := APIResponse{
		Success: false,
		Error: &APIError{
			Error:     http.StatusText(appErr.StatusCode),
			Message:   appErr.Message,
			Code:      appErr.Code,
			Details:   appErr.Details,
			Timestamp: appErr.Timestamp,
			RequestID: appErr.RequestID,
		},
	}

	json.NewEncoder(w).Encode(response)
}

// sendSuccess sends a standardized success response
func SendSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := APIResponse{
		Success: true,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

// RateLimiter implements simple rate limiting
type RateLimiter struct {
	requests map[string][]time.Time
	window   time.Duration
	limit    int
	mutex    sync.RWMutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(window time.Duration, limit int) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		limit:    limit,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// IsAllowed checks if a request is allowed
func (rl *RateLimiter) IsAllowed(key string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	requests := rl.requests[key]

	// Remove old requests outside the window
	var validRequests []time.Time
	for _, req := range requests {
		if now.Sub(req) < rl.window {
			validRequests = append(validRequests, req)
		}
	}

	// Check if under limit
	if len(validRequests) >= rl.limit {
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	rl.requests[key] = validRequests

	return true
}

// cleanup removes old entries periodically
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()

	for range ticker.C {
		rl.mutex.Lock()
		now := time.Now()

		for key, requests := range rl.requests {
			var validRequests []time.Time
			for _, req := range requests {
				if now.Sub(req) < rl.window {
					validRequests = append(validRequests, req)
				}
			}

			if len(validRequests) == 0 {
				delete(rl.requests, key)
			} else {
				rl.requests[key] = validRequests
			}
		}
		rl.mutex.Unlock()
	}
}

// rateLimitMiddleware implements rate limiting middleware
func RateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use client IP as key
			clientIP := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				clientIP = forwarded
			}

			if !rl.IsAllowed(clientIP) {
				SendError(w, NewAppError(ErrorTypeRateLimit, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded", nil).WithDetails(map[string]interface{}{
					"retry_after": "60", // seconds
				}))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// securityHeadersMiddleware adds security headers
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' ws: wss: http://localhost:3000 https://api.github.com https://unpkg.com https://cdn.jsdelivr.net")

		// CORS headers (updated for security)
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validationMiddleware validates request data
func ValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Content-Type for POST/PUT requests
		if r.Method == "POST" || r.Method == "PUT" {
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				SendError(w, NewValidationError("Content-Type must be application/json", nil))
				return
			}
		}

		// Check request size (limit to 10MB)
		if r.ContentLength > 10*1024*1024 {
			SendError(w, NewValidationError("Request too large", nil))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// corsMiddleware adds CORS headers to all responses
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
