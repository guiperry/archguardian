package project

import (
	"archguardian/types"
	"sync"
	"time"

	"github.com/philippgille/chromem-go"
)

// Project represents a project in the system
type Project struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Path       string                `json:"path"`
	Status     string                `json:"status"` // "idle", "scanning", "error"
	LastScan   *time.Time            `json:"lastScan,omitempty"`
	IssueCount int                   `json:"issueCount"`
	CreatedAt  time.Time             `json:"createdAt"`
	Config     *Config               `json:"-"` // Don't serialize
	Graph      *types.KnowledgeGraph `json:"-"` // Don't serialize
}

// ProjectStore manages project persistence and retrieval
type ProjectStore struct {
	projects map[string]*Project
	mutex    sync.RWMutex
	db       *chromem.DB
}

// Config represents project-specific configuration
type Config struct {
	ProjectPath       string `json:"project_path"`
	GitHubToken       string `json:"github_token"`
	GitHubRepo        string `json:"github_repo"`
	ScanInterval      time.Duration
	RemediationBranch string `json:"remediation_branch"`
}
