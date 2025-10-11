package scan

import (
	"archguardian/internal/config"
	"archguardian/internal/guardian"
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ScanState represents the state of a scan job
type ScanState string

const (
	ScanStateIdle      ScanState = "idle"
	ScanStateQueued    ScanState = "queued"
	ScanStateScanning  ScanState = "scanning"
	ScanStateAnalyzing ScanState = "analyzing"
	ScanStateComplete  ScanState = "complete"
	ScanStateError     ScanState = "error"
	ScanStateCancelled ScanState = "cancelled"
)

// ScanJob represents a scan job with metadata and state tracking
type ScanJob struct {
	ID          string                 `json:"id"`
	ProjectID   string                 `json:"project_id"`
	ProjectPath string                 `json:"project_path"`
	State       ScanState              `json:"state"`
	Progress    float64                `json:"progress"`
	Message     string                 `json:"message"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	Result      *ScanResult            `json:"result,omitempty"`
}

// GetID returns the job ID (implements ScanJobInterface)
func (sj *ScanJob) GetID() string {
	return sj.ID
}

// ScanResult contains the results of a completed scan
type ScanResult struct {
	KnowledgeGraph *KnowledgeGraphResult `json:"knowledge_graph"`
	RiskAssessment *RiskAssessmentResult `json:"risk_assessment"`
	Issues         []IssueResult         `json:"issues"`
	Coverage       *CoverageResult       `json:"coverage"`
	Duration       time.Duration         `json:"duration"`
}

// KnowledgeGraphResult contains knowledge graph scan results
type KnowledgeGraphResult struct {
	NodeCount   int    `json:"node_count"`
	EdgeCount   int    `json:"edge_count"`
	ScanTime    string `json:"scan_time"`
	LastUpdated string `json:"last_updated"`
}

// RiskAssessmentResult contains risk assessment scan results
type RiskAssessmentResult struct {
	OverallScore float64 `json:"overall_score"`
	IssueCount   int     `json:"issue_count"`
	ScanTime     string  `json:"scan_time"`
}

// IssueResult represents a single issue found during scanning
type IssueResult struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Location string `json:"location"`
	Message  string `json:"message"`
}

// CoverageResult contains test coverage scan results
type CoverageResult struct {
	Overall   float64 `json:"overall"`
	Language  string  `json:"language"`
	FileCount int     `json:"file_count"`
	ScanTime  string  `json:"scan_time"`
}

// ScanManager manages scan jobs and prevents concurrent scans
type ScanManager struct {
	config           *config.Config
	guardian         *guardian.ArchGuardian
	jobs             map[string]*ScanJob
	jobMutex         sync.RWMutex
	projectLocks     map[string]*sync.Mutex // Per-project locking
	projectLockMutex sync.RWMutex
	queue            []*ScanJob
	queueMutex       sync.RWMutex
	maxConcurrent    int
	workerCount      int
	workers          []*scanWorker
	workerMutex      sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

// scanWorker represents a worker that processes scan jobs
type scanWorker struct {
	id       int
	manager  *ScanManager
	jobChan  chan *ScanJob
	quit     chan bool
	running  bool
	jobCount int
}

// NewScanManager creates a new scan manager
func NewScanManager(cfg *config.Config, guardian *guardian.ArchGuardian) *ScanManager {
	ctx, cancel := context.WithCancel(context.Background())

	sm := &ScanManager{
		config:        cfg,
		guardian:      guardian,
		jobs:          make(map[string]*ScanJob),
		projectLocks:  make(map[string]*sync.Mutex),
		maxConcurrent: 5, // Default max concurrent scans
		workerCount:   5, // Default worker count
		ctx:           ctx,
		cancel:        cancel,
	}

	// Initialize workers
	sm.workers = make([]*scanWorker, sm.workerCount)
	for i := 0; i < sm.workerCount; i++ {
		sm.workers[i] = &scanWorker{
			id:      i,
			manager: sm,
			jobChan: make(chan *ScanJob, 1),
			quit:    make(chan bool),
			running: false,
		}
	}

	// Start workers
	sm.startWorkers()

	log.Printf("✅ Scan Manager initialized with %d workers", sm.workerCount)
	return sm
}

// CreateJob creates a new scan job
func (sm *ScanManager) CreateJob(projectID, projectPath string) (*ScanJob, error) {
	sm.jobMutex.Lock()
	defer sm.jobMutex.Unlock()

	// Check if project is already being scanned
	sm.projectLockMutex.RLock()
	projectLock, exists := sm.projectLocks[projectID]
	sm.projectLockMutex.RUnlock()

	if exists {
		// Check if any job for this project is currently running
		for _, job := range sm.jobs {
			if job.ProjectID == projectID && (job.State == ScanStateScanning || job.State == ScanStateAnalyzing) {
				return nil, fmt.Errorf("project %s is already being scanned", projectID)
			}
		}
	} else {
		// Create new project lock
		sm.projectLockMutex.Lock()
		sm.projectLocks[projectID] = &sync.Mutex{}
		sm.projectLockMutex.Unlock()
		projectLock = sm.projectLocks[projectID]
	}

	// Acquire project lock
	projectLock.Lock()

	// Create new job
	job := &ScanJob{
		ID:          generateUUID(),
		ProjectID:   projectID,
		ProjectPath: projectPath,
		State:       ScanStateQueued,
		Progress:    0.0,
		Message:     "Job created and queued",
		CreatedAt:   time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	// Store job
	sm.jobs[job.ID] = job

	// Add to queue
	sm.queueMutex.Lock()
	sm.queue = append(sm.queue, job)
	sm.queueMutex.Unlock()

	log.Printf("📋 Created scan job %s for project %s", job.ID, projectID)
	return job, nil
}

// StartJob starts processing a queued job
func (sm *ScanManager) StartJob(jobID string) error {
	sm.jobMutex.RLock()
	job, exists := sm.jobs[jobID]
	sm.jobMutex.RUnlock()

	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	if job.State != ScanStateQueued {
		return fmt.Errorf("job %s is not in queued state", jobID)
	}

	// Update job state
	sm.jobMutex.Lock()
	job.State = ScanStateScanning
	now := time.Now()
	job.StartedAt = &now
	job.Progress = 5.0
	job.Message = "Scan started"
	sm.jobMutex.Unlock()

	log.Printf("🚀 Starting scan job %s", jobID)

	// Try to assign to a worker
	sm.assignJobToWorker(job)

	return nil
}

// UpdateJobProgress updates the progress of a running job
func (sm *ScanManager) UpdateJobProgress(jobID string, progress float64, message string) error {
	sm.jobMutex.Lock()
	defer sm.jobMutex.Unlock()

	job, exists := sm.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	job.Progress = progress
	job.Message = message

	// Broadcast progress update via WebSocket if ArchGuardian is available
	if sm.guardian != nil {
		sm.guardian.BroadcastToDashboard(fmt.Sprintf(`{
			"type": "scan_progress",
			"job_id": "%s",
			"project_id": "%s",
			"progress": %.1f,
			"message": "%s",
			"timestamp": "%s"
		}`, jobID, job.ProjectID, progress, message, time.Now().Format(time.RFC3339)))
	}

	return nil
}

// CompleteJob marks a job as completed
func (sm *ScanManager) CompleteJob(jobID string, result *ScanResult) error {
	sm.jobMutex.Lock()
	defer sm.jobMutex.Unlock()

	job, exists := sm.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	job.State = ScanStateComplete
	now := time.Now()
	job.CompletedAt = &now
	job.Result = result
	job.Progress = 100.0
	job.Message = "Scan completed successfully"

	// Broadcast completion via WebSocket
	if sm.guardian != nil {
		sm.guardian.BroadcastToDashboard(fmt.Sprintf(`{
			"type": "scan_complete",
			"job_id": "%s",
			"project_id": "%s",
			"timestamp": "%s"
		}`, jobID, job.ProjectID, time.Now().Format(time.RFC3339)))
	}

	// Release project lock
	sm.releaseProjectLock(job.ProjectID)

	log.Printf("✅ Scan job %s completed successfully", jobID)
	return nil
}

// FailJob marks a job as failed
func (sm *ScanManager) FailJob(jobID string, err error) error {
	sm.jobMutex.Lock()
	defer sm.jobMutex.Unlock()

	job, exists := sm.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	job.State = ScanStateError
	now := time.Now()
	job.CompletedAt = &now
	job.Error = err.Error()
	job.Progress = 0.0
	job.Message = fmt.Sprintf("Scan failed: %v", err)

	// Release project lock
	sm.releaseProjectLock(job.ProjectID)

	log.Printf("❌ Scan job %s failed: %v", jobID, err)
	return nil
}

// CancelJob cancels a queued or running job
func (sm *ScanManager) CancelJob(jobID string) error {
	sm.jobMutex.Lock()
	defer sm.jobMutex.Unlock()

	job, exists := sm.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	if job.State == ScanStateComplete || job.State == ScanStateError {
		return fmt.Errorf("job %s is already finished", jobID)
	}

	job.State = ScanStateCancelled
	now := time.Now()
	job.CompletedAt = &now
	job.Message = "Job cancelled by user"

	// Release project lock
	sm.releaseProjectLock(job.ProjectID)

	log.Printf("🛑 Scan job %s cancelled", jobID)
	return nil
}

// GetJob returns a specific job by ID
func (sm *ScanManager) GetJob(jobID string) (*ScanJob, error) {
	sm.jobMutex.RLock()
	defer sm.jobMutex.RUnlock()

	job, exists := sm.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	return job, nil
}

// GetJobsByProject returns all jobs for a specific project
func (sm *ScanManager) GetJobsByProject(projectID string) []*ScanJob {
	sm.jobMutex.RLock()
	defer sm.jobMutex.RUnlock()

	var projectJobs []*ScanJob
	for _, job := range sm.jobs {
		if job.ProjectID == projectID {
			projectJobs = append(projectJobs, job)
		}
	}

	return projectJobs
}

// GetJobsByState returns all jobs in a specific state
func (sm *ScanManager) GetJobsByState(state ScanState) []*ScanJob {
	sm.jobMutex.RLock()
	defer sm.jobMutex.RUnlock()

	var stateJobs []*ScanJob
	for _, job := range sm.jobs {
		if job.State == state {
			stateJobs = append(stateJobs, job)
		}
	}

	return stateJobs
}

// GetAllJobs returns all jobs
func (sm *ScanManager) GetAllJobs() []*ScanJob {
	sm.jobMutex.RLock()
	defer sm.jobMutex.RUnlock()

	jobs := make([]*ScanJob, 0, len(sm.jobs))
	for _, job := range sm.jobs {
		jobs = append(jobs, job)
	}

	return jobs
}

// GetQueueStatus returns the current queue status
func (sm *ScanManager) GetQueueStatus() map[string]interface{} {
	sm.queueMutex.RLock()
	queueLength := len(sm.queue)
	sm.queueMutex.RUnlock()

	sm.jobMutex.RLock()
	activeJobs := len(sm.GetJobsByState(ScanStateScanning)) + len(sm.GetJobsByState(ScanStateAnalyzing))
	sm.jobMutex.RUnlock()

	return map[string]interface{}{
		"queue_length":   queueLength,
		"active_jobs":    activeJobs,
		"max_concurrent": sm.maxConcurrent,
		"worker_count":   sm.workerCount,
		"total_jobs":     len(sm.jobs),
	}
}

// startWorkers starts the worker goroutines
func (sm *ScanManager) startWorkers() {
	for _, worker := range sm.workers {
		sm.wg.Add(1)
		go worker.run()
	}
	log.Printf("🚀 Started %d scan workers", len(sm.workers))
}

// assignJobToWorker assigns a job to an available worker
func (sm *ScanManager) assignJobToWorker(job *ScanJob) {
	// Find an available worker
	for _, worker := range sm.workers {
		if !worker.running {
			select {
			case worker.jobChan <- job:
				worker.running = true
				log.Printf("👷 Assigned job %s to worker %d", job.ID, worker.id)
				return
			default:
				continue
			}
		}
	}

	log.Printf("⚠️ No available workers for job %s", job.ID)
}

// releaseProjectLock releases the lock for a project
func (sm *ScanManager) releaseProjectLock(projectID string) {
	sm.projectLockMutex.Lock()
	projectLock, exists := sm.projectLocks[projectID]
	sm.projectLockMutex.Unlock()

	if exists {
		projectLock.Unlock()
	}
}

// run is the main loop for a scan worker
func (sw *scanWorker) run() {
	log.Printf("👷 Worker %d started", sw.id)
	defer func() {
		log.Printf("👷 Worker %d stopped", sw.id)
		sw.manager.wg.Done()
	}()

	for {
		select {
		case job := <-sw.jobChan:
			sw.running = true
			sw.processJob(job)
			sw.running = false

		case <-sw.quit:
			return

		case <-sw.manager.ctx.Done():
			return
		}
	}
}

// processJob processes a single scan job
func (sw *scanWorker) processJob(job *ScanJob) {
	log.Printf("👷 Worker %d processing job %s", sw.id, job.ID)
	sw.jobCount++

	// Update progress
	sw.manager.UpdateJobProgress(job.ID, 10.0, "Initializing scan...")

	// Perform the actual scan using ArchGuardian
	if sw.manager.guardian != nil {
		// Create a context with timeout for this scan
		ctx, cancel := context.WithTimeout(sw.manager.ctx, 30*time.Minute)
		defer cancel()

		// Update progress
		sw.manager.UpdateJobProgress(job.ID, 20.0, "Running scan cycle...")

		// Run the scan cycle
		err := sw.manager.guardian.RunCycle(ctx)
		if err != nil {
			sw.manager.FailJob(job.ID, err)
			return
		}

		// Create scan result
		result := &ScanResult{
			Duration: time.Since(*job.StartedAt),
		}

		// Get knowledge graph results
		if sw.manager.guardian.GetScanner() != nil {
			graph := sw.manager.guardian.GetScanner().GetKnowledgeGraph()
			result.KnowledgeGraph = &KnowledgeGraphResult{
				NodeCount:   len(graph.Nodes),
				EdgeCount:   len(graph.Edges),
				ScanTime:    time.Now().Format(time.RFC3339),
				LastUpdated: graph.LastUpdated.Format(time.RFC3339),
			}
		}

		// Update progress
		sw.manager.UpdateJobProgress(job.ID, 90.0, "Finalizing scan...")

		// Complete the job
		sw.manager.CompleteJob(job.ID, result)

		log.Printf("👷 Worker %d completed job %s", sw.id, job.ID)
	} else {
		sw.manager.FailJob(job.ID, fmt.Errorf("ArchGuardian not available"))
	}
}

// Stop stops the scan manager and all workers
func (sm *ScanManager) Stop() error {
	log.Println("🛑 Stopping Scan Manager...")

	// Cancel context
	sm.cancel()

	// Stop all workers
	for _, worker := range sm.workers {
		select {
		case worker.quit <- true:
		default:
		}
	}

	// Wait for workers to finish
	done := make(chan struct{})
	go func() {
		sm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("✅ Scan Manager stopped successfully")
		return nil
	case <-time.After(30 * time.Second):
		log.Println("⚠️ Scan Manager stop timed out")
		return fmt.Errorf("stop timeout")
	}
}

// GetWorkerStats returns statistics about worker performance
func (sm *ScanManager) GetWorkerStats() map[string]interface{} {
	stats := make(map[string]interface{})

	sm.workerMutex.Lock()
	defer sm.workerMutex.Unlock()

	totalJobs := 0
	for _, worker := range sm.workers {
		stats[fmt.Sprintf("worker_%d_jobs", worker.id)] = worker.jobCount
		totalJobs += worker.jobCount
	}

	stats["total_jobs_processed"] = totalJobs
	stats["worker_count"] = len(sm.workers)
	stats["average_jobs_per_worker"] = float64(totalJobs) / float64(len(sm.workers))

	return stats
}

// CleanupOldJobs removes old completed jobs to prevent memory leaks
func (sm *ScanManager) CleanupOldJobs(maxAge time.Duration) int {
	sm.jobMutex.Lock()
	defer sm.jobMutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	cleaned := 0

	for id, job := range sm.jobs {
		if job.State == ScanStateComplete || job.State == ScanStateError || job.State == ScanStateCancelled {
			if job.CreatedAt.Before(cutoff) {
				delete(sm.jobs, id)
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		log.Printf("🧹 Cleaned up %d old scan jobs", cleaned)
	}

	return cleaned
}

// TriggerProjectScan triggers a scan for a specific project
func (sm *ScanManager) TriggerProjectScan(projectID, projectPath string) (*ScanJob, error) {
	log.Printf("🚀 Triggering scan for project %s", projectID)

	// Create job
	job, err := sm.CreateJob(projectID, projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan job: %w", err)
	}

	// Start job
	if err := sm.StartJob(job.ID); err != nil {
		return nil, fmt.Errorf("failed to start scan job: %w", err)
	}

	return job, nil
}

// GetProjectLockStatus returns the lock status for all projects
func (sm *ScanManager) GetProjectLockStatus() map[string]interface{} {
	sm.projectLockMutex.RLock()
	defer sm.projectLockMutex.RUnlock()

	status := make(map[string]interface{})

	for projectID := range sm.projectLocks {
		// Check if any jobs for this project are running
		runningJobs := 0
		sm.jobMutex.RLock()
		for _, job := range sm.jobs {
			if job.ProjectID == projectID && (job.State == ScanStateScanning || job.State == ScanStateAnalyzing) {
				runningJobs++
			}
		}
		sm.jobMutex.RUnlock()

		status[projectID] = map[string]interface{}{
			"locked":       runningJobs > 0,
			"running_jobs": runningJobs,
		}
	}

	return status
}

// UUID generation helper (simplified version)
func generateUUID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// Initialize UUID package properly
func init() {
	// This would normally use a proper UUID library
	// For now, using simple timestamp-based IDs
}
