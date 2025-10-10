package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// AuthMiddleware validates JWT tokens and adds user to request context
func (as *AuthService) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for Authorization header (JWT)
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			user, err := as.ValidateJWT(tokenString)
			if err == nil {
				log.Printf("AuthMiddleware: Looking for user ID: %s", user.ID)

				// Verify user exists in our users map
				if storedUser, exists := as.GetUser(user.ID); exists {
					log.Printf("AuthMiddleware: User found in users map: %+v", storedUser)
					// Add user to request context
					ctx := context.WithValue(r.Context(), userContextKey, storedUser)
					r = r.WithContext(ctx)
					next(w, r)
					return
				} else {
					log.Printf("AuthMiddleware: User ID %s not found in users map", user.ID)
				}
			} else {
				log.Printf("AuthMiddleware: JWT validation failed: %v", err)
			}
		}

		// Check for session cookie
		session, err := as.sessionStore.Get(r, "archguardian-session")
		if err == nil {
			if userID, ok := session.Values["user_id"].(string); ok {
				if user, exists := as.GetUser(userID); exists {
					ctx := context.WithValue(r.Context(), userContextKey, user)
					r = r.WithContext(ctx)
					next(w, r)
					return
				}
			}
		}

		// No valid authentication found
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "Unauthorized",
			"message": "Authentication required",
		})
	}
}

// OptionalAuthMiddleware adds user to context if authentication is present but doesn't require it
func (as *AuthService) OptionalAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try JWT first
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			user, err := as.ValidateJWT(tokenString)
			if err == nil {
				ctx := context.WithValue(r.Context(), userContextKey, user)
				r = r.WithContext(ctx)
				next(w, r)
				return
			}
		}

		// Try session
		session, err := as.sessionStore.Get(r, "archguardian-session")
		if err == nil {
			if userID, ok := session.Values["user_id"].(string); ok {
				if user, exists := as.GetUser(userID); exists {
					ctx := context.WithValue(r.Context(), userContextKey, user)
					r = r.WithContext(ctx)
					next(w, r)
					return
				}
			}
		}

		// No authentication, but that's okay
		next(w, r)
	}
}

// GetUserFromContext retrieves the user from request context
func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userContextKey).(*User)
	return user, ok
}
