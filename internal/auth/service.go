package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

// NewAuthService creates a new authentication service
func NewAuthService() *AuthService {
	jwtSecret := []byte(getEnv("JWT_SECRET", "your-secret-key-change-in-production"))
	sessionSecret := getEnv("SESSION_SECRET", "another-secret-key-change-in-production")

	return &AuthService{
		githubClientID:     getEnv("GITHUB_CLIENT_ID", ""),
		githubClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		jwtSecret:          jwtSecret,
		sessionStore:       sessions.NewCookieStore([]byte(sessionSecret)),
		users:              make(map[string]*User),
		tokens:             make(map[string]*GitHubAuth),
		baseURL:            getEnv("APP_BASE_URL", "http://localhost:3000"),
	}
}

// GenerateJWT generates a JWT token for the user
func (as *AuthService) GenerateJWT(user *User) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"email":    user.Email,
		"provider": user.Provider,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(as.jwtSecret)
}

// ValidateJWT validates a JWT token and returns the user
func (as *AuthService) ValidateJWT(tokenString string) (*User, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return as.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["user_id"].(string)
		if !ok {
			return nil, fmt.Errorf("user_id claim not found or not a string")
		}

		username, _ := claims["username"].(string)
		email, _ := claims["email"].(string)
		provider, _ := claims["provider"].(string)

		user := &User{
			ID:       userID,
			Username: username,
			Email:    email,
			Provider: provider,
		}

		log.Printf("JWT validated for user ID: %s", userID)
		return user, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// CreateOrUpdateUser creates a new user or updates an existing one
func (as *AuthService) CreateOrUpdateUser(githubUser map[string]interface{}) *User {
	userID := fmt.Sprintf("%v", githubUser["id"])
	now := time.Now()

	user, exists := as.users[userID]
	if !exists {
		user = &User{
			ID:        userID,
			Username:  githubUser["login"].(string),
			Email:     githubUser["email"].(string),
			Name:      githubUser["name"].(string),
			AvatarURL: githubUser["avatar_url"].(string),
			Provider:  "github",
			CreatedAt: now,
		}
		as.users[userID] = user
	}

	user.LastLogin = now
	return user
}

// StoreGitHubToken stores a GitHub token for a user
func (as *AuthService) StoreGitHubToken(userID string, auth *GitHubAuth) {
	as.tokens[userID] = auth
}

// GetGitHubToken retrieves a GitHub token for a user
func (as *AuthService) GetGitHubToken(userID string) (*GitHubAuth, bool) {
	token, exists := as.tokens[userID]
	return token, exists
}

// GetUser retrieves a user by ID
func (as *AuthService) GetUser(userID string) (*User, bool) {
	user, exists := as.users[userID]
	return user, exists
}

// GetGitHubAuthURL generates the GitHub OAuth URL
func (as *AuthService) GetGitHubAuthURL(r *http.Request) (string, string, error) {
	originHost := r.URL.Query().Get("origin_host")
	if originHost == "" {
		originHost = as.baseURL
	}

	csrfToken := uuid.New().String()
	statePayload := AuthState{
		CSRFToken:    csrfToken,
		RedirectHost: originHost,
	}
	stateBytes, err := json.Marshal(statePayload)
	if err != nil {
		return "", "", fmt.Errorf("failed to create auth state: %w", err)
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	baseURL := "https://github.com/login/oauth/authorize"
	params := url.Values{}
	params.Add("client_id", as.githubClientID)
	params.Add("redirect_uri", as.baseURL+"/api/v1/auth/github/callback")
	params.Add("scope", "read:user user:email")
	params.Add("state", state)
	params.Add("response_type", "code")
	return baseURL + "?" + params.Encode(), csrfToken, nil
}

// ExchangeGitHubCode exchanges a GitHub authorization code for an access token
func (as *AuthService) ExchangeGitHubCode(code string) (*GitHubAuth, error) {
	tokenURL := getEnv("GITHUB_OAUTH_TOKEN_URL", "https://github.com/login/oauth/access_token")

	if !isValidGitHubTokenURL(tokenURL) {
		return nil, fmt.Errorf("invalid GitHub token URL")
	}

	data := url.Values{}
	data.Set("client_id", as.githubClientID)
	data.Set("client_secret", as.githubClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", as.baseURL+"/api/v1/auth/github/callback")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("GitHub OAuth error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	return &GitHubAuth{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}, nil
}

// GetGitHubUser retrieves user information from GitHub
func (as *AuthService) GetGitHubUser(accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return user, nil
}

// HandleGitHubAuth handles GitHub authentication requests
func (as *AuthService) HandleGitHubAuth(w http.ResponseWriter, r *http.Request) (string, string, error) {
	authURL, csrfToken, err := as.GetGitHubAuthURL(r)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate auth URL: %w", err)
	}

	// Store CSRF token in session for validation
	session, _ := as.sessionStore.Get(r, "archguardian-auth")
	session.Values["csrf_token"] = csrfToken
	if err := session.Save(r, w); err != nil {
		return "", "", fmt.Errorf("failed to save session: %w", err)
	}

	return authURL, csrfToken, nil
}

// HandleGitHubCallback handles the OAuth callback from GitHub
func (as *AuthService) HandleGitHubCallback(r *http.Request) (string, error) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Validate state here against session state...

	githubAuth, err := as.ExchangeGitHubCode(code)
	if err != nil {
		return "/", fmt.Errorf("failed to exchange github code: %w", err)
	}

	githubUser, err := as.GetGitHubUser(githubAuth.AccessToken)
	if err != nil {
		return "/", fmt.Errorf("failed to get github user: %w", err)
	}

	user := as.CreateOrUpdateUser(githubUser)
	as.StoreGitHubToken(user.ID, githubAuth)

	// For now, just redirect to dashboard - session management will be handled by the auth service
	redirectURL, err := as.getRedirectURLFromState(state)
	if err != nil {
		log.Printf("Invalid state in github callback: %v", err)
		return "/?auth_success=true", nil // fallback
	}
	return redirectURL + "?auth_success=true", nil
}

// HandleGitHubAuthStatus handles GitHub authentication status check
func (as *AuthService) HandleGitHubAuthStatus(w http.ResponseWriter, r *http.Request) {
	session, _ := as.sessionStore.Get(r, "archguardian-auth")
	userID, ok := session.Values["user_id"].(string)

	response := map[string]interface{}{
		"authenticated": ok && userID != "",
	}

	if ok && userID != "" {
		if user, exists := as.GetUser(userID); exists {
			response["user"] = user
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleLogout handles user logout by clearing the session
func (as *AuthService) HandleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := as.sessionStore.Get(r, "archguardian-auth")
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1 // Delete the session
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// getEnv retrieves environment variable with fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getRedirectURLFromState extracts the redirect URL from the state parameter
func (as *AuthService) getRedirectURLFromState(state string) (string, error) {
	stateBytes, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return "", fmt.Errorf("failed to decode state: %w", err)
	}

	var authState AuthState
	if err := json.Unmarshal(stateBytes, &authState); err != nil {
		return "", fmt.Errorf("failed to unmarshal state: %w", err)
	}

	return authState.RedirectHost, nil
}

// isValidGitHubTokenURL validates GitHub OAuth token URLs
func isValidGitHubTokenURL(tokenURL string) bool {
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
