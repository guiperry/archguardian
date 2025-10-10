package server

import (
	"net/http"
	"sync"
	"time"
)

// corsMiddleware adds CORS headers to all responses
func corsMiddleware(next http.Handler) http.Handler {
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

// securityHeadersMiddleware adds security headers to all responses
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// RateLimiter implements a simple rate limiter
type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     time.Duration
	limit    int
}

type visitor struct {
	lastSeen time.Time
	count    int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate time.Duration, limit int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		limit:    limit,
	}

	// Cleanup old visitors every minute
	go func() {
		for {
			time.Sleep(time.Minute)
			rl.cleanup()
		}
	}()

	return rl
}

// Allow checks if a request from the given IP should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	now := time.Now()

	if !exists {
		rl.visitors[ip] = &visitor{
			lastSeen: now,
			count:    1,
		}
		return true
	}

	// Reset count if rate period has passed
	if now.Sub(v.lastSeen) > rl.rate {
		v.count = 1
		v.lastSeen = now
		return true
	}

	// Check if limit exceeded
	if v.count >= rl.limit {
		return false
	}

	v.count++
	return true
}

// cleanup removes old visitors
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, v := range rl.visitors {
		if now.Sub(v.lastSeen) > rl.rate*2 {
			delete(rl.visitors, ip)
		}
	}
}

// rateLimitMiddleware applies rate limiting to requests
func rateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if !rl.Allow(ip) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// validationMiddleware performs basic request validation
func validationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add any request validation logic here
		next.ServeHTTP(w, r)
	})
}
