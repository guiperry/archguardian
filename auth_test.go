package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthService(t *testing.T) {
	authService := NewAuthService()

	assert.NotNil(t, authService)
	assert.NotNil(t, authService.jwtSecret)
	assert.NotNil(t, authService.sessionStore)
	assert.NotNil(t, authService.users)
	assert.NotNil(t, authService.tokens)
	assert.Equal(t, 0, len(authService.users))
	assert.Equal(t, 0, len(authService.tokens))
}

func TestAuthService_GenerateJWT(t *testing.T) {
	authService := NewAuthService()
	user := &User{
		ID:       "123",
		Username: "testuser",
		Email:    "test@example.com",
		Provider: "github",
	}

	token, err := authService.GenerateJWT(user)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token has 3 parts (header.payload.signature)
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3)
}

func TestAuthService_ValidateJWT(t *testing.T) {
	authService := NewAuthService()
	user := &User{
		ID:       "123",
		Username: "testuser",
		Email:    "test@example.com",
		Provider: "github",
	}

	// Generate a valid token
	token, err := authService.GenerateJWT(user)
	require.NoError(t, err)

	// Validate the token
	validatedUser, err := authService.ValidateJWT(token)
	require.NoError(t, err)
	assert.Equal(t, user.ID, validatedUser.ID)
	assert.Equal(t, user.Username, validatedUser.Username)
	assert.Equal(t, user.Email, validatedUser.Email)
	assert.Equal(t, user.Provider, validatedUser.Provider)

	// Test invalid token
	_, err = authService.ValidateJWT("invalid.token.here")
	assert.Error(t, err)

	// Test malformed token
	_, err = authService.ValidateJWT("malformed")
	assert.Error(t, err)
}

func TestAuthService_CreateOrUpdateUser(t *testing.T) {
	authService := NewAuthService()

	githubUser := map[string]interface{}{
		"id":         123,
		"login":      "testuser",
		"email":      "test@example.com",
		"name":       "Test User",
		"avatar_url": "https://github.com/avatar.jpg",
	}

	// Create new user
	user := authService.CreateOrUpdateUser(githubUser)
	assert.Equal(t, "123", user.ID)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test User", user.Name)
	assert.Equal(t, "https://github.com/avatar.jpg", user.AvatarURL)
	assert.Equal(t, "github", user.Provider)
	assert.False(t, user.CreatedAt.IsZero())
	assert.False(t, user.LastLogin.IsZero())

	// Update existing user
	originalCreatedAt := user.CreatedAt
	time.Sleep(time.Millisecond) // Ensure different timestamp
	user2 := authService.CreateOrUpdateUser(githubUser)
	assert.Equal(t, user.ID, user2.ID)
	assert.Equal(t, originalCreatedAt, user2.CreatedAt)   // CreatedAt should not change
	assert.True(t, user2.LastLogin.After(user.LastLogin)) // LastLogin should update
}

func TestAuthService_StoreAndGetGitHubToken(t *testing.T) {
	authService := NewAuthService()
	userID := "123"
	auth := &GitHubAuth{
		UserID:       userID,
		AccessToken:  "gho_test_token",
		RefreshToken: "refresh_token",
		ExpiresAt:    time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	}

	// Store token
	authService.StoreGitHubToken(userID, auth)

	// Retrieve token
	retrievedAuth, exists := authService.GetGitHubToken(userID)
	assert.True(t, exists)
	assert.Equal(t, auth.AccessToken, retrievedAuth.AccessToken)
	assert.Equal(t, auth.RefreshToken, retrievedAuth.RefreshToken)
	assert.Equal(t, auth.TokenType, retrievedAuth.TokenType)

	// Test non-existent token
	_, exists = authService.GetGitHubToken("nonexistent")
	assert.False(t, exists)
}

func TestAuthService_GetUser(t *testing.T) {
	authService := NewAuthService()
	user := &User{
		ID:       "123",
		Username: "testuser",
		Email:    "test@example.com",
		Provider: "github",
	}

	// Store user manually
	authService.users["123"] = user

	// Get existing user
	retrievedUser, exists := authService.GetUser("123")
	assert.True(t, exists)
	assert.Equal(t, user, retrievedUser)

	// Get non-existent user
	_, exists = authService.GetUser("nonexistent")
	assert.False(t, exists)
}

func TestAuthService_GetGitHubAuthURL(t *testing.T) {
	authService := NewAuthService()
	authService.githubClientID = "test_client_id"

	url := authService.GetGitHubAuthURL("test_state")

	assert.Contains(t, url, "https://github.com/login/oauth/authorize")
	assert.Contains(t, url, "client_id=test_client_id")
	assert.Contains(t, url, "state=test_state")
	assert.Contains(t, url, "scope=read%3Auser+user%3Aemail")
	assert.Contains(t, url, "response_type=code")
}

func TestAuthMiddleware(t *testing.T) {
	authService := NewAuthService()

	// Create a test user
	user := &User{
		ID:       "123",
		Username: "testuser",
		Email:    "test@example.com",
		Provider: "github",
	}
	authService.users["123"] = user

	// Create a valid JWT
	token, err := authService.GenerateJWT(user)
	require.NoError(t, err)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is in context
		ctxUser := r.Context().Value("user")
		if ctxUser == nil {
			t.Error("User not found in context")
			return
		}

		userFromCtx, ok := ctxUser.(*User)
		if !ok {
			t.Error("User in context is not of correct type")
			return
		}

		assert.Equal(t, user.ID, userFromCtx.ID)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authenticated"))
	})

	// Test with valid JWT in Authorization header
	t.Run("Valid JWT Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := authService.AuthMiddleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "authenticated", rr.Body.String())
	})

	// Test with invalid token
	t.Run("Invalid JWT Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid_token")
		rr := httptest.NewRecorder()

		handler := authService.AuthMiddleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		var response map[string]interface{}
		err := json.NewDecoder(rr.Body).Decode(&response)
		require.NoError(t, err)
		assert.Equal(t, "Unauthorized", response["error"])
	})

	// Test without Authorization header
	t.Run("No Authorization Header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler := authService.AuthMiddleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestOptionalAuthMiddleware(t *testing.T) {
	authService := NewAuthService()

	// Create a test user
	user := &User{
		ID:       "123",
		Username: "testuser",
		Email:    "test@example.com",
		Provider: "github",
	}
	authService.users["123"] = user

	// Create a valid JWT
	token, err := authService.GenerateJWT(user)
	require.NoError(t, err)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxUser := r.Context().Value("user")
		if ctxUser != nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("authenticated"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("anonymous"))
		}
	})

	// Test with valid token
	t.Run("With Valid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := authService.OptionalAuthMiddleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "authenticated", rr.Body.String())
	})

	// Test without token
	t.Run("Without Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler := authService.OptionalAuthMiddleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "anonymous", rr.Body.String())
	})

	// Test with invalid token (should still pass but not authenticate)
	t.Run("With Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid_token")
		rr := httptest.NewRecorder()

		handler := authService.OptionalAuthMiddleware(testHandler)
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "anonymous", rr.Body.String())
	})
}

func TestAuthServiceConcurrency(t *testing.T) {
	authService := NewAuthService()

	// Test concurrent access to user operations
	const numGoroutines = 10
	const numOperations = 100

	// Create users concurrently
	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				githubUser := map[string]interface{}{
					"id":         id*numOperations + j,
					"login":      "user" + string(rune(id*numOperations+j)),
					"email":      "test@example.com",
					"name":       "Test User",
					"avatar_url": "https://github.com/avatar.jpg",
				}
				authService.CreateOrUpdateUser(githubUser)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all users were created
	assert.Equal(t, numGoroutines*numOperations, len(authService.users))
}

func TestUserStructSerialization(t *testing.T) {
	user := &User{
		ID:        "123",
		Username:  "testuser",
		Email:     "test@example.com",
		Name:      "Test User",
		AvatarURL: "https://github.com/avatar.jpg",
		Provider:  "github",
		CreatedAt: time.Now(),
		LastLogin: time.Now(),
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(user)
	require.NoError(t, err)

	var deserializedUser User
	err = json.Unmarshal(jsonData, &deserializedUser)
	require.NoError(t, err)

	assert.Equal(t, user.ID, deserializedUser.ID)
	assert.Equal(t, user.Username, deserializedUser.Username)
	assert.Equal(t, user.Email, deserializedUser.Email)
	assert.Equal(t, user.Name, deserializedUser.Name)
	assert.Equal(t, user.AvatarURL, deserializedUser.AvatarURL)
	assert.Equal(t, user.Provider, deserializedUser.Provider)
}

func TestGitHubAuthStructSerialization(t *testing.T) {
	auth := &GitHubAuth{
		UserID:       "123",
		AccessToken:  "gho_test_token",
		RefreshToken: "refresh_token",
		ExpiresAt:    time.Now(),
		TokenType:    "Bearer",
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(auth)
	require.NoError(t, err)

	var deserializedAuth GitHubAuth
	err = json.Unmarshal(jsonData, &deserializedAuth)
	require.NoError(t, err)

	assert.Equal(t, auth.UserID, deserializedAuth.UserID)
	assert.Equal(t, auth.AccessToken, deserializedAuth.AccessToken)
	assert.Equal(t, auth.RefreshToken, deserializedAuth.RefreshToken)
	assert.Equal(t, auth.TokenType, deserializedAuth.TokenType)
}
