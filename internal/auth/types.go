package auth

import (
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
)

// User represents a user in the system
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	AvatarURL string    `json:"avatar_url"`
	Provider  string    `json:"provider"` // "github"
	CreatedAt time.Time `json:"created_at"`
	LastLogin time.Time `json:"last_login"`
}

// GitHubAuth represents GitHub OAuth authentication data
type GitHubAuth struct {
	UserID       string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	TokenType    string
}

// AuthState represents the state for OAuth flow
type AuthState struct {
	CSRFToken    string `json:"csrf_token"`
	RedirectHost string `json:"redirect_host"`
	ProjectID    string `json:"project_id,omitempty"`
}

// AuthService handles authentication operations
type AuthService struct {
	githubClientID     string
	githubClientSecret string
	jwtSecret          []byte
	sessionStore       *sessions.CookieStore
	users              map[string]*User
	tokens             map[string]*GitHubAuth
	baseURL            string
	mutex              sync.RWMutex
}

// contextKey represents custom context key types to avoid collisions
type contextKey string

const (
	userContextKey contextKey = "user"
)

// JWT claims structure
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Provider string `json:"provider"`
	jwt.RegisteredClaims
}
