// ArchGuardian Dashboard JavaScript

class ArchGuardianDashboard {
    constructor() {
        this.currentView = 'console';
        this.network = null;
        this.riskChart = null;
        this.coverageChart = null;
        this.coverageDetailsChart = null;
        this.githubAuthenticated = false;
        this.currentTheme = 'light'; // Default theme
        this.projectStarted = false; // Track if a project has been started

        this.init();
    }

    init() {
        this.loadThemePreference();
        this.checkProjectStarted();
        this.setupNavigation();
        this.setupWebSocket();
        this.loadInitialData();
        this.setupCharts();
        this.setupConnectionTabs();
        this.setupAlertsTabs();
        this.setupThemeToggle();
        // Print an initialization message to the dashboard console
        try { this.appendConsoleLog('Dashboard initialized'); } catch (e) { /* silent */ }
    }
    checkProjectStarted() {
        // Clear project state on fresh load - user must select a project each time
        localStorage.removeItem('projectStarted');
        this.projectStarted = false;
        this.currentProjectId = null;
        this.currentProjectName = null;
        this.projectProgress = {}; // Track progress for each project
        
        // Ensure project navigation is hidden on load
        const projectNav = document.getElementById('project-nav');
        if (projectNav) {
            projectNav.style.display = 'none';
        }
    }

    setupNavigation() {
        const navBtns = document.querySelectorAll('.nav-btn');
        navBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const view = btn.dataset.view;
                // Only switch view if the button has a data-view attribute
                if (view) {
                    this.switchView(view);
                }
            });
        });

    }

    switchView(view) {
        // Check if view exists before trying to switch
        const viewElement = document.getElementById(`${view}-view`);
        if (!viewElement) {
            console.warn(`View "${view}" does not exist`);
            return;
        }

        // Hide all views
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

        // Remove active class from nav buttons
        document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));

        // Show selected view
        viewElement.classList.add('active');

        // Add active class to nav button
        const navButton = document.querySelector(`[data-view="${view}"]`);
        if (navButton) {
            navButton.classList.add('active');
        }

        this.currentView = view;

        // Load view-specific data
        this.loadViewData(view);
        if (view === 'settings') {
            this.loadSettings();
        }
    }

    setupWebSocket() {
        this.wsState = 'disconnected'; // 'disconnected', 'connecting', 'connected'
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000; // Start with 1 second
        this.maxReconnectDelay = 30000; // Max 30 seconds
        this.messageQueue = []; // Queue messages during disconnect
        this.heartbeatInterval = null;

        this.connectWebSocket();
    }

    connectWebSocket() {
        if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) {
            return; // Already connecting or connected
        }

        this.wsState = 'connecting';
        this.updateConnectionStatus();

        try {
            this.ws = new WebSocket(`ws://${window.location.host}/ws`);
        } catch (error) {
            console.error('Failed to create WebSocket:', error);
            this.handleConnectionError();
            return;
        }

        this.ws.onopen = () => {
            console.log('Connected to ArchGuardian WebSocket');
            this.wsState = 'connected';
            this.reconnectAttempts = 0;
            this.reconnectDelay = 1000; // Reset delay
            this.updateConnectionStatus();

            // Start heartbeat
            this.startHeartbeat();

            // Notify the backend that the client is ready to receive initial logs
            this.appendConsoleLog('WebSocket connected');
            try {
                this.ws.send(JSON.stringify({ type: 'client_ready' }));
                this.appendConsoleLog('Sent client_ready to server');

                // Flush any queued messages
                this.flushMessageQueue();
            } catch (e) {
                console.error('Failed to send client_ready:', e);
                this.appendConsoleLog('Failed to send client_ready');
            }
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleWebSocketMessage(data);
            } catch (error) {
                console.error('Failed to parse WebSocket message:', error);
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.appendConsoleLog('WebSocket error: ' + (error && error.message ? error.message : JSON.stringify(error)));
        };

        this.ws.onclose = (ev) => {
            console.warn('WebSocket closed', ev);
            this.wsState = 'disconnected';
            this.updateConnectionStatus();

            // Stop heartbeat
            this.stopHeartbeat();

            this.appendConsoleLog('WebSocket disconnected');

            // Attempt to reconnect if not intentionally closed
            if (ev.code !== 1000 && this.reconnectAttempts < this.maxReconnectAttempts) {
                this.scheduleReconnect();
            } else if (this.reconnectAttempts >= this.maxReconnectAttempts) {
                this.appendConsoleLog('Max reconnection attempts reached. Please refresh the page.');
                this.showNotification('Connection lost. Please refresh the page.', 'error');
            }
        };
    }

    handleConnectionError() {
        this.wsState = 'disconnected';
        this.updateConnectionStatus();

        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.scheduleReconnect();
        }
    }

    scheduleReconnect() {
        this.reconnectAttempts++;
        const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), this.maxReconnectDelay);

        this.appendConsoleLog(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts}) in ${delay/1000}s...`);

        setTimeout(() => {
            this.connectWebSocket();
        }, delay);
    }

    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                try {
                    this.ws.send(JSON.stringify({ type: 'ping' }));
                } catch (error) {
                    console.error('Failed to send heartbeat:', error);
                }
            }
        }, 30000); // Send ping every 30 seconds
    }

    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    updateConnectionStatus() {
        const statusElement = document.getElementById('connection-status');
        if (!statusElement) return;

        let statusText = '';
        let statusClass = '';

        switch (this.wsState) {
            case 'connected':
                statusText = '🟢 Connected';
                statusClass = 'connected';
                break;
            case 'connecting':
                statusText = '🟡 Connecting...';
                statusClass = 'connecting';
                break;
            case 'disconnected':
                statusText = '🔴 Disconnected';
                statusClass = 'disconnected';
                break;
        }

        statusElement.textContent = statusText;
        statusElement.className = `connection-status ${statusClass}`;

        // Show reconnection info if attempting to reconnect
        if (this.wsState === 'disconnected' && this.reconnectAttempts > 0) {
            statusElement.textContent += ` (Attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`;
        }
    }

    queueMessage(message) {
        // Queue messages when disconnected
        if (this.wsState !== 'connected') {
            this.messageQueue.push(message);
            if (this.messageQueue.length > 100) {
                this.messageQueue.shift(); // Remove oldest message if queue gets too large
            }
        }
    }

    flushMessageQueue() {
        if (this.messageQueue.length === 0) return;

        this.appendConsoleLog(`Flushing ${this.messageQueue.length} queued messages...`);

        // Send queued messages
        while (this.messageQueue.length > 0) {
            const message = this.messageQueue.shift();
            try {
                this.ws.send(message);
            } catch (error) {
                console.error('Failed to send queued message:', error);
                // Put message back in queue for retry
                this.messageQueue.unshift(message);
                break;
            }
        }
    }

    // Override send method to queue messages when disconnected
    sendWebSocketMessage(type, data) {
        const message = JSON.stringify({
            type: type,
            data: data,
            timestamp: new Date().toISOString()
        });

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            try {
                this.ws.send(message);
            } catch (error) {
                console.error('Failed to send WebSocket message:', error);
                this.queueMessage(message);
            }
        } else {
            this.queueMessage(message);
        }
    }

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'scan_cycle_completed':
                this.updateOverviewData(data);
                break;
            case 'security_vulnerability_found':
                this.updateIssuesData(data);
                break;
            case 'remediation_completed':
                this.showNotification('Remediation completed successfully!', 'success');
                break;
            case 'alert':
                this.handleAlertMessage(data);
                break;
            case 'log':
                // Log message is nested in data.data.message
                const logMessage = data.data?.message || data.message || '';
                this.appendConsoleLog(logMessage);
                break;
            case 'scan_progress':
                this.handleScanProgress(data);
                break;
            case 'scan_complete':
                this.handleScanComplete(data);
                break;
        }
    }

    handleAlertMessage(data) {
        const alertData = data.data || data;
        const alertId = alertData.alert_id || alertData.id;
        const alertName = alertData.alert_name || alertData.title;
        const alertDescription = alertData.description || alertData.message;
        const alertLevel = alertData.level || 'info';

        // Show browser notification if supported
        this.showBrowserNotification(alertName, alertDescription, alertLevel);

        // Show in-app notification
        this.showNotification(`${alertName}: ${alertDescription}`, alertLevel);

        // Log to console
        this.appendConsoleLog(`🚨 ALERT [${alertLevel.toUpperCase()}]: ${alertName} - ${alertDescription}`);

        // Update alerts view if it's currently visible
        if (this.currentView === 'alerts') {
            this.loadAlerts();
        }
    }

    showBrowserNotification(title, body, level = 'info') {
        // Check if browser notifications are supported and permitted
        if ('Notification' in window) {
            if (Notification.permission === 'granted') {
                const notification = new Notification(`ArchGuardian - ${title}`, {
                    body: body,
                    icon: '/favicon.ico',
                    tag: 'archguardian-alert',
                    requireInteraction: level === 'critical' || level === 'error'
                });

                // Auto-close after 5 seconds for non-critical alerts
                if (level !== 'critical' && level !== 'error') {
                    setTimeout(() => notification.close(), 5000);
                }
            } else if (Notification.permission !== 'denied') {
                // Request permission if not already denied
                Notification.requestPermission().then(permission => {
                    if (permission === 'granted') {
                        this.showBrowserNotification(title, body, level);
                    }
                });
            }
        }
    }

    handleScanProgress(data) {
        const projectId = data.project_id;
        const progress = data.progress || 0;
        const message = data.message || 'Scanning...';
        
        // Store progress data
        this.projectProgress[projectId] = {
            progress: progress,
            message: message
        };
        
        // Update the navbar status if this is the current project
        if (this.currentProjectId === projectId) {
            this.updateProjectStatusLabel(this.currentProjectName, 'Scanning', progress, message);
        }
        
        // Update the project card if visible
        this.updateProjectCardProgress(projectId, progress, message);
        
        // Log progress
        this.appendConsoleLog(`📊 Scan progress: ${Math.round(progress)}% - ${message}`);
    }

    updateProjectStatusLabel(projectName, status, progress = null, message = null) {
        const statusLabel = document.getElementById('project-status-label');
        if (!statusLabel) return;
        
        const projectNameEl = statusLabel.querySelector('.status-project-name');
        const statusTextEl = statusLabel.querySelector('.status-text');
        const progressContainer = statusLabel.querySelector('.status-progress-container');
        const progressFill = statusLabel.querySelector('.status-progress-fill');
        const progressText = statusLabel.querySelector('.status-progress-text');
        
        if (projectName) {
            statusLabel.style.display = 'flex';
            if (projectNameEl) projectNameEl.textContent = projectName;
        }
        
        if (statusTextEl) {
            statusTextEl.textContent = status;
            statusTextEl.className = 'status-text';
            if (status.toLowerCase() === 'scanning') {
                statusTextEl.classList.add('scanning');
            } else if (status.toLowerCase() === 'idle') {
                statusTextEl.classList.add('idle');
            } else if (status.toLowerCase() === 'error') {
                statusTextEl.classList.add('error');
            }
        }
        
        // Show/hide progress bar
        if (progress !== null && status.toLowerCase() === 'scanning') {
            if (progressContainer) progressContainer.style.display = 'flex';
            if (progressFill) progressFill.style.width = `${progress}%`;
            if (progressText) progressText.textContent = `${Math.round(progress)}%`;
        } else {
            if (progressContainer) progressContainer.style.display = 'none';
        }
    }

    updateProjectCardProgress(projectId, progress, message) {
        const projectCard = document.querySelector(`.project-card[data-project-id="${projectId}"]`);
        if (!projectCard) return;
        
        const statusEl = projectCard.querySelector('.project-status');
        if (!statusEl) return;
        
        // Check if progress bar already exists
        let progressBar = projectCard.querySelector('.project-progress-bar');
        if (!progressBar) {
            // Create progress bar
            progressBar = document.createElement('div');
            progressBar.className = 'project-progress-bar';
            progressBar.innerHTML = `
                <div class="project-progress-fill" style="width: 0%"></div>
                <div class="project-progress-text">0%</div>
            `;
            statusEl.appendChild(progressBar);
        }
        
        // Update progress
        const progressFill = progressBar.querySelector('.project-progress-fill');
        const progressText = progressBar.querySelector('.project-progress-text');
        if (progressFill) progressFill.style.width = `${progress}%`;
        if (progressText) progressText.textContent = `${Math.round(progress)}% - ${message}`;
    }

    handleScanComplete(data) {
        const projectId = data.project_id;
        
        // Clear progress data
        delete this.projectProgress[projectId];
        
        // Update the navbar status if this is the current project
        if (this.currentProjectId === projectId) {
            this.updateProjectStatusLabel(this.currentProjectName, 'Idle', null, null);
        }
        
        // Remove progress bar from project card
        const projectCard = document.querySelector(`.project-card[data-project-id="${projectId}"]`);
        if (projectCard) {
            const progressBar = projectCard.querySelector('.project-progress-bar');
            if (progressBar) {
                progressBar.remove();
            }
        }
        
        // Show notification
        this.showNotification('Scan completed successfully!', 'success');
        this.appendConsoleLog('✅ Scan completed successfully');
        
        // Refresh project list to update status
        this.loadProjects();
    }

    async loadInitialData() {
        try {
            // Load knowledge graph data
            await this.loadKnowledgeGraph();

            // Load risk assessment data
            await this.loadRiskAssessment();

            // Load coverage data
            await this.loadCoverageData();

        } catch (error) {
            console.error('Failed to load initial data:', error);
        }
    }

    openProjectsModal() {
        const modal = document.getElementById('projects-modal');
        if (modal) {
            // Setup listeners specifically for the modal's tabs
            this.setupModalConnectionTabs();
            modal.style.display = 'flex';
            this.loadProjects();
            this.checkGitHubAuthStatus(); // Check auth status when modal opens
        }
    }

    closeProjectsModal() {
        const modal = document.getElementById('projects-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }
    async loadProjects() {
        try {
            // show spinner in modal if present
            const modalList = document.getElementById('modal-projects-list');
            if (modalList) modalList.innerHTML = '<div class="projects-spinner">Loading projects...</div>'; // Use relative path for API calls
            const response = await fetch('/api/v1/projects');
            const data = await response.json();
            // Extract projects array from response object
            const projects = data.projects || [];
            // Render projects in both the main projects view and the modal (if open)
            this.renderProjects(projects, '#projects-list');
            this.renderProjects(projects, '#modal-projects-list');
        } catch (error) {
            console.error('Failed to load projects:', error);
            const mainList = document.getElementById('projects-list');
            if (mainList) mainList.innerHTML = '<div class="error">Failed to load projects.</div>';
            const modalList = document.getElementById('modal-projects-list');
            if (modalList) modalList.innerHTML = '<div class="error">Failed to load projects.</div>';
        }
    }

    renderProjects(projects, targetSelector = '#projects-list') {
        const container = document.querySelector(targetSelector);
        if (!container) return;

        if (!projects || projects.length === 0) {
            container.innerHTML = '<div class="no-issues">No projects connected yet.</div>';
            return;
        }

        container.innerHTML = projects.map(p => `
            <div class="project-card${this.currentProjectId === p.id ? ' project-active' : ''}" data-project-id="${p.id}">
                <div class="project-card-header">
                    <h4>${p.name}</h4>
                    <span class="project-badge project-badge-${(p.status === 'scanning' ? 'active' : 'idle')}">${p.status === 'scanning' ? 'Active' : 'Idle'}</span>
                </div>
                <p class="project-path">${p.path}</p>
                <div class="project-status">Status: <span class="status-${(p.status || 'idle').toLowerCase()}">${p.status || 'idle'}</span></div>
                <div class="project-ingest" data-project-id="${p.id}">Checking ingestion...</div>
                <div class="project-buttons">
                    <button class="start-scan-btn" data-project-id="${p.id}" ${p.status === 'scanning' ? 'disabled' : ''}>
                        <span class="btn-spinner" aria-hidden="true"></span>
                        <span class="btn-label">${p.status === 'scanning' ? 'Scanning...' : 'Start'}</span>
                    </button>
                    <button class="stop-scan-btn" data-project-id="${p.id}" ${p.status !== 'scanning' ? 'disabled' : ''}>
                        Stop
                    </button>
                </div>
            </div>
        `).join('');

        // Attach event listeners for new buttons within the container
        container.querySelectorAll('.start-scan-btn').forEach(btn => {
            btn.addEventListener('click', (ev) => {
                const id = btn.dataset.projectId;
                // Close modal if the button is inside it
                const modal = document.getElementById('projects-modal');
                if (modal && modal.style.display === 'flex') {
                    // Start scan and navigate to issues for that project
                    this.startScan(id, btn).then(() => this.closeProjectsModal());
                } else {
                    this.startScan(id, btn);
                }
            });
        });

        container.querySelectorAll('.stop-scan-btn').forEach(btn => {
            btn.addEventListener('click', (ev) => {
                const id = btn.dataset.projectId;
                this.stopScan(id);
            });
        });
        // If there is a current active project, update labels
        if (this.currentProjectId) this.updateActiveProjectUI(this.currentProjectId);

        // Kick off ingestion checks for projects rendered in this container
        try {
            const items = projects || [];
            items.forEach(p => {
                // Only check ingestion for projects in the modal or main list
                this.checkProjectIngested(p.id);
            });
        } catch (e) {
            // ignore
        }
    }

    // Check whether a given project has scan history (i.e., ingested into DB)
    async checkProjectIngested(projectId) {
        try {
            const resp = await fetch(`/api/v1/scans/history?project_id=${encodeURIComponent(projectId)}&limit=1`);
            if (!resp.ok) {
                // can't determine, show unknown
                const el = document.querySelector(`.project-ingest[data-project-id="${projectId}"]`);
                if (el) el.textContent = 'Ingestion: unknown';
                return;
            }

            const data = await resp.json();
            const el = document.querySelector(`.project-ingest[data-project-id="${projectId}"]`);
            if (!el) return;

            if (data && data.total && data.total > 0) {
                el.innerHTML = '<span class="ingested">Ingested</span>';
            } else {
                el.innerHTML = '<span class="not-ingested">No scans yet</span> <button class="ingest-now-btn">Ingest Now</button>';
                const btn = el.querySelector('.ingest-now-btn');
                if (btn) {
                    btn.addEventListener('click', () => {
                        // call startScan for the project, show inline spinner on this button
                        this.startScan(projectId, btn);
                    });
                }
            }
        } catch (error) {
            const el = document.querySelector(`.project-ingest[data-project-id="${projectId}"]`);
            if (el) el.textContent = 'Ingestion: error';
        }
    }

    updateActiveProjectUI(projectId) {
        // Update nav label
        const label = document.getElementById('active-project-label');
        const issuesLabel = document.getElementById('active-issues-project');
        // Try to find project name from the DOM lists
        let name = null;
        const card = document.querySelector(`[data-project-id=\"${projectId}\"]`);
        if (card) {
            name = card.querySelector('h4')?.textContent || name;
        }
        if (!name) name = projectId;

        if (label) label.textContent = name;
        if (issuesLabel) issuesLabel.textContent = name;

        // Highlight active project cards across lists
        document.querySelectorAll('.project-card').forEach(c => {
            if (c.dataset.projectId === projectId) c.classList.add('project-active');
            else c.classList.remove('project-active');
        });
    }

    async addProject() {
        const projectType = document.getElementById('project-type').value;
        const projectPath = document.getElementById('project-path').value;

        if (!projectPath) {
            this.showNotification('Project path or URL cannot be empty.', 'error');
            return;
        }

        try {
            const response = await fetch('/api/v1/projects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: projectType, path: projectPath })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.message || 'Failed to add project');
            }

            this.showNotification('Project added successfully!', 'success');
            document.getElementById('project-path').value = ''; // Clear input

            // Show project-specific navigation
            this.showProjectNavigation();

            // Mark project as started
            this.projectStarted = true;
            localStorage.setItem('projectStarted', 'true');

            this.loadProjects(); // Refresh the list
        } catch (error) {
            console.error('Failed to add project:', error);
            this.showNotification(error.message, 'error');
        }
    }

    // startScan optionally accepts a button element to show inline loading
    async startScan(projectId, buttonElement = null) {
        // Track the active project id for view-specific loads
        this.currentProjectId = projectId;

        // Fetch project details to get the name
        try {
            const projectResp = await fetch(`/api/v1/projects/${projectId}`);
            if (projectResp.ok) {
                const projectData = await projectResp.json();
                this.currentProjectName = projectData.name || 'Unknown Project';
                // Update status label to show project is being started
                this.updateProjectStatusLabel(this.currentProjectName, 'Starting...', null, null);
            }
        } catch (e) {
            console.warn('Failed to fetch project details:', e);
        }

        // Show the project-specific navigation links when starting a scan
        this.showProjectNavigation();

        this.showNotification(`Starting scan for project...`, 'info');

        // Trigger the scan via API and wait for confirmation
        let originalBtnText = null;
        try {
            if (buttonElement) {
                originalBtnText = buttonElement.textContent;
                buttonElement.disabled = true;
                buttonElement.textContent = 'Starting...';
                buttonElement.classList.add('btn-loading');
            }

            const resp = await fetch(`/api/v1/projects/${projectId}/scan`, { method: 'POST' });
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                const msg = err.message || `Failed to start scan (status ${resp.status})`;
                this.showNotification(msg, 'error');
                if (buttonElement) {
                    buttonElement.disabled = false;
                    buttonElement.textContent = originalBtnText || 'Start';
                    buttonElement.classList.remove('btn-loading');
                }
                return; // don't proceed to issues view
            }

            // After starting, poll the project's status until it becomes 'scanning' or timeout
            const pollInterval = 1000; // 1s
            const timeoutMs = 15000; // 15s
            const start = Date.now();
            let scanningConfirmed = false;

            while ((Date.now() - start) < timeoutMs) {
                try {
                    const sresp = await fetch(`/api/v1/projects/${projectId}`);
                    if (sresp.ok) {
                        const pdata = await sresp.json();
                        if (pdata && (pdata.status === 'scanning' || pdata.status === 'active')) {
                            scanningConfirmed = true;
                            break;
                        }
                    }
                } catch (e) {
                    // ignore transient errors
                }
                await new Promise(r => setTimeout(r, pollInterval));
            }

            if (!scanningConfirmed) {
                // still proceed but warn the user
                this.showNotification('Scan started but the project status did not update quickly. You may need to refresh.', 'warning');
            } else {
                this.showNotification('Scan started and confirmed!', 'success');
                // Update status label to show scanning
                this.updateProjectStatusLabel(this.currentProjectName, 'Scanning', 0, 'Initializing...');
            }

            // Mark project as started
            this.projectStarted = true;
            localStorage.setItem('projectStarted', 'true');

            // Update UI highlighting for active project
            this.updateActiveProjectUI(projectId);

            // Switch to issues view to show project-specific issues
            this.switchView('issues');
            // Load issues for this specific project (technical-debt default)
            this.loadIssuesData('technical-debt', projectId);

            // The UI will be updated via WebSocket events, but we can also force a refresh
            setTimeout(() => this.loadProjects(), 1000);
        } catch (error) {
            console.error('Failed to start scan:', error);
            this.showNotification('Failed to start scan: ' + (error.message || error), 'error');
            if (buttonElement) {
                buttonElement.disabled = false;
                buttonElement.textContent = originalBtnText || 'Start';
                buttonElement.classList.remove('btn-loading');
            }
        }
        finally {
            if (buttonElement) {
                buttonElement.disabled = false;
                buttonElement.textContent = originalBtnText || 'Start';
                buttonElement.classList.remove('btn-loading');
            }
        }
    }

    async stopScan(projectId) {
        this.showNotification(`Stopping scan for project...`, 'info');

        // For now, we'll just show a notification since the backend doesn't have a stop endpoint
        // In a real implementation, you would call an API endpoint to stop the scan
        try {
            // Try to call a stop endpoint if it exists
            await fetch(`/api/v1/projects/${projectId}/stop`, { method: 'POST' });
        } catch (error) {
            // If stop endpoint doesn't exist, just show notification
            console.log('Stop endpoint not available, scan will continue');
        }

        // Refresh projects list to update button states
        setTimeout(() => this.loadProjects(), 1000);
    }

    showProjectNavigation() {
        const projectNav = document.getElementById('project-nav');
        if (projectNav) {
            projectNav.style.display = 'block';
        }
        this.setupNavigation(); // Re-run setup to include new buttons

        this.showNotification('Project started! Navigation links are now available.', 'success');
    }

    async loadKnowledgeGraph() {
        try {
            const response = await fetch('/api/v1/knowledge-graph');
            const data = await response.json();

            if (data.nodes && data.edges) {
                this.renderKnowledgeGraph(data);
            }
        } catch (error) {
            console.error('Failed to load knowledge graph:', error);
        }
    }

    async loadRiskAssessment() {
        try {
            const response = await fetch('/api/v1/risk-assessment');
            const data = await response.json();

            this.updateOverviewData(data);
        } catch (error) {
            console.error('Failed to load risk assessment:', error);
        }
    }

    async loadCoverageData() {
        try {
            const response = await fetch('/api/v1/coverage');
            const data = await response.json();

            this.updateCoverageData(data);
        } catch (error) {
            console.error('Failed to load coverage data:', error);
        }
    }

    updateOverviewData(data) {
        // Update risk score
        const riskScore = data.overall_score || 0;
        document.getElementById('overall-risk').textContent = `${riskScore.toFixed(1)}/100`;

        // Update risk score color based on severity
        const riskElement = document.getElementById('overall-risk');
        riskElement.className = 'risk-score';
        if (riskScore < 20) riskElement.classList.add('low-risk');
        else if (riskScore < 50) riskElement.classList.add('medium-risk');
        else riskElement.classList.add('high-risk');

        // Update quality score (estimated from risk score)
        const qualityScore = Math.max(0, 100 - riskScore);
        document.getElementById('quality-score').textContent = `${qualityScore.toFixed(1)}/100`;

        // Update dependency count
        const depCount = data.dangerous_dependencies?.length || 0;
        document.getElementById('dep-count').textContent = depCount;

        // Update runtime status
        document.getElementById('runtime-status').textContent = 'Operational';

        // Update charts
        this.updateCharts(data);
    }

    updateCharts(data) {
        // Update risk trend chart
        if (this.riskChart) {
            this.riskChart.data.datasets[0].data = [data.overall_score || 0];
            this.riskChart.update();
        }

        // Update coverage chart
        if (this.coverageChart) {
            const coverage = Math.max(0, 100 - (data.overall_score || 0));
            this.coverageChart.data.datasets[0].data = [coverage, 100 - coverage];
            this.coverageChart.update();
        }
    }

    setupCharts() {
        // Risk trend chart
        const riskCtx = document.getElementById('risk-chart').getContext('2d');
        this.riskChart = new Chart(riskCtx, {
            type: 'line',
            data: {
                labels: ['Current'],
                datasets: [{
                    label: 'Risk Score',
                    data: [0],
                    borderColor: 'rgb(239, 68, 68)',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });

        // Coverage chart
        const coverageCtx = document.getElementById('coverage-chart').getContext('2d');
        this.coverageChart = new Chart(coverageCtx, {
            type: 'doughnut',
            data: {
                labels: ['Covered', 'Not Covered'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: [
                        'rgb(16, 185, 129)',
                        'rgb(229, 231, 235)'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Coverage details chart
        const coverageDetailsCtx = document.getElementById('coverage-details-chart').getContext('2d');
        this.coverageDetailsChart = new Chart(coverageDetailsCtx, {
            type: 'bar',
            data: {
                labels: ['File1.go', 'File2.go', 'File3.go'],
                datasets: [{
                    label: 'Coverage %',
                    data: [85, 92, 78],
                    backgroundColor: 'rgba(37, 99, 235, 0.8)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    }

    renderKnowledgeGraph(data) {
        const container = document.getElementById('knowledge-graph');

        // Clear existing graph
        container.innerHTML = '';

        // Create nodes for visualization
        const nodes = new vis.DataSet();
        const edges = new vis.DataSet();

        // Add nodes based on type
        data.nodes.forEach(node => {
            let color = '#97c2fc'; // Default blue

            switch (node.type) {
                case 'code':
                    color = '#fbbf24'; // Yellow
                    break;
                case 'library':
                    color = '#a78bfa'; // Purple
                    break;
                case 'process':
                    color = '#4ade80'; // Green
                    break;
                case 'connection':
                    color = '#f87171'; // Red
                    break;
                case 'database':
                    color = '#60a5fa'; // Blue
                    break;
                case 'api':
                    color = '#fb7185'; // Pink
                    break;
            }

            nodes.add({
                id: node.id,
                label: node.name,
                color: color,
                shape: node.type === 'process' ? 'square' : 'circle',
                type: node.type // keep original type for filtering
            });
        });

        // Add edges
        data.edges.forEach(edge => {
            edges.add({
                from: edge.from,
                to: edge.to,
                label: edge.relationship,
                arrows: 'to'
            });
        });

        // Create network
        const graphData = {
            nodes: nodes,
            edges: edges
        };

        // keep a reference to the original graph data so filtering can restore it
        this.currentGraphData = graphData;

        const options = {
            nodes: {
                font: {
                    size: 12
                }
            },
            edges: {
                font: {
                    size: 10,
                    align: 'middle'
                },
                color: '#848884',
                arrows: {
                    to: { enabled: true, scaleFactor: 0.5 }
                }
            },
            physics: {
                stabilization: false,
                barnesHut: {
                    gravitationalConstant: -80000,
                    springConstant: 0.001,
                    springLength: 200
                }
            },
            interaction: {
                hover: true,
                tooltipDelay: 300
            }
        };

        this.network = new vis.Network(container, graphData, options);
    }

    filterNodes(type) {
        if (!this.network) return;

        let nodes = [];

        if (type === 'all') {
            this.network.setData(this.currentGraphData);
        } else {
            // Filter nodes by type
            const filteredNodes = this.currentGraphData.nodes.get({
                filter: function (node) {
                    return node.type === type;
                }
            });
            nodes = filteredNodes;
        }

        // Update network with filtered data
        const graphData = {
            nodes: new vis.DataSet(nodes),
            edges: this.currentGraphData.edges
        };

        this.network.setData(graphData);
    }

    appendConsoleLog(message) {
        const consoleOutput = document.getElementById('console-output');
        if (consoleOutput) {
            consoleOutput.textContent += message + '\n';
            // Auto-scroll to the bottom
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
        }
    }

    clearConsole() {
        const consoleOutput = document.getElementById('console-output');
        if (consoleOutput) consoleOutput.textContent = '';
    }

    refreshGraph() {
        this.loadKnowledgeGraph();
    }

    async loadIssuesData(type) {
        try {
            // Accept optional projectId as second argument
            const projectId = arguments.length > 1 ? arguments[1] : null;
            const projectParam = projectId ? `&project_id=${encodeURIComponent(projectId)}` : '';
            const response = await fetch(`/api/v1/issues?type=${type}${projectParam}`);
            const data = await response.json();

            this.renderIssues(data, type);
        } catch (error) {
            console.error('Failed to load issues:', error);
            document.getElementById('issues-container').innerHTML =
                '<div class="error">Failed to load issues data</div>';
        }
    }

    renderIssues(data, type) {
        const container = document.getElementById('issues-container');
        let html = '';

        switch (type) {
            case 'technical-debt':
                html = this.renderTechnicalDebt(data.technical_debt || []);
                break;
            case 'security':
                html = this.renderSecurityIssues(data.security_vulns || []);
                break;
            case 'dependencies':
                html = this.renderDependencyIssues(data.dangerous_dependencies || []);
                break;
            case 'compatibility':
                html = this.renderCompatibilityIssues(data.compatibility_issues || []);
                break;
        }

        container.innerHTML = html;
    }

    renderTechnicalDebt(items) {
        if (items.length === 0) {
            return '<div class="no-issues">No technical debt found!</div>';
        }

        return items.map(item => `
            <div class="issue-item">
                <div class="issue-header">
                    <span class="issue-id">${item.id}</span>
                    <span class="issue-severity severity-${item.severity}">${item.severity}</span>
                </div>
                <div class="issue-description">${item.description}</div>
                <div class="issue-location">Location: ${item.location}</div>
                <div class="issue-effort">Effort: ${item.effort} hours</div>
            </div>
        `).join('');
    }

    renderSecurityIssues(items) {
        if (items.length === 0) {
            return '<div class="no-issues">No security vulnerabilities found!</div>';
        }

        return items.map(item => `
            <div class="issue-item">
                <div class="issue-header">
                    <span class="issue-id">${item.cve}</span>
                    <span class="issue-severity severity-${item.severity}">${item.severity}</span>
                </div>
                <div class="issue-description">${item.description}</div>
                <div class="issue-package">Package: ${item.package}@${item.version}</div>
                <div class="issue-cvss">CVSS: ${item.cvss}</div>
            </div>
        `).join('');
    }

    renderObsoleteCode(items) {
        if (items.length === 0) {
            return '<div class="no-issues">No obsolete code found!</div>';
        }

        return items.map(item => `
            <div class="issue-item">
                <div class="issue-header">
                    <span class="issue-path">${item.path}</span>
                    <span class="issue-safety safety-${item.removal_safety}">${item.removal_safety}</span>
                </div>
                <div class="issue-description">${item.recommend_action}</div>
                <div class="issue-references">References: ${item.references}</div>
            </div>
        `).join('');
    }

    renderDependencyIssues(items) {
        if (items.length === 0) {
            return '<div class="no-issues">No dependency issues found!</div>';
        }

        return items.map(item => `
            <div class="issue-item">
                <div class="issue-header">
                    <span class="issue-package">${item.package}</span>
                    <span class="issue-maintenance status-${item.maintenance}">${item.maintenance}</span>
                </div>
                <div class="issue-description">${item.recommendation}</div>
                <div class="issue-versions">
                    Current: ${item.current_version} → Latest: ${item.latest_version}
                </div>
                <div class="issue-issues">Security Issues: ${item.security_issues}</div>
            </div>
        `).join('');
    }

    renderCompatibilityIssues(items) {
        if (items.length === 0) {
            return '<div class="no-issues">🎉 No web compatibility issues found!</div>';
        }

        return items.map(item => `
            <div class="issue-item compatibility-issue">
                <div class="issue-header">
                    <span class="issue-id">
                        <span class="compat-icon">🌐</span>
                        ${item.id}
                    </span>
                    <span class="issue-severity severity-${item.severity}">${item.severity}</span>
                </div>
                <div class="issue-description">${item.description}</div>
                <div class="issue-location">Location: ${item.location}</div>
                <div class="issue-remediation">💡 ${item.remediation}</div>
            </div>
        `).join('');
    }

    updateCoverageData(data) {
        // Update coverage percentage
        const coverage = data.overall_coverage || 0;
        document.getElementById('overall-coverage').textContent = `${coverage}%`;

        // Update lines covered
        document.getElementById('lines-covered').textContent = data.lines_covered || 0;

        // Update test files
        document.getElementById('test-files').textContent = data.test_files || 0;

        // Update coverage chart
        if (this.coverageChart) {
            this.coverageChart.data.datasets[0].data = [coverage, 100 - coverage];
            this.coverageChart.update();
        }

        // Update coverage details chart
        if (this.coverageDetailsChart && data.file_coverage) {
            this.coverageDetailsChart.data.labels = Object.keys(data.file_coverage);
            this.coverageDetailsChart.data.datasets[0].data = Object.values(data.file_coverage);
            this.coverageDetailsChart.update();
        }
    }

    async loadViewData(view) {
        // Don't load data if no project has been started, except for settings
        if (!this.projectStarted && view !== 'settings') {
            console.log(`Project not started yet, skipping data load for ${view} view`);
            return;
        }

        switch (view) {
            case 'issues':
                // If a currentProjectId is set, load issues for it
                this.loadIssuesData('technical-debt', this.currentProjectId || null);
                break;
            case 'coverage':
                this.loadCoverageData();
                break;
            case 'graph':
                this.loadKnowledgeGraph();
                break;
            case 'alerts':
                this.loadAlerts();
                break;
            case 'settings':
                this.loadSettings();
                break;
            // No specific data to load for 'console' view as it's real-time
        }
    }

    refreshIssues() {
        const activeTab = document.querySelector('.tab-btn.active')?.dataset.tab || 'technical-debt';
        this.loadIssuesData(activeTab);
    }

    refreshCoverage() {
        this.loadCoverageData();
    }

    async loadAlerts() {
        try {
            const response = await fetch('/api/v1/alerts');
            const data = await response.json();

            this.renderAlerts(data.alerts || []);
        } catch (error) {
            console.error('Failed to load alerts:', error);
            document.getElementById('alerts-container').innerHTML =
                '<div class="error">Failed to load alerts data</div>';
        }
    }

    async clearResolvedAlerts() {
        try {
            const response = await fetch('/api/v1/alerts/clear-resolved', {
                method: 'POST'
            });

            if (response.ok) {
                this.showNotification('Resolved alerts cleared successfully!', 'success');
                this.loadAlerts(); // Refresh the alerts list
            } else {
                throw new Error('Failed to clear resolved alerts');
            }
        } catch (error) {
            console.error('Failed to clear resolved alerts:', error);
            this.showNotification('Failed to clear resolved alerts', 'error');
        }
    }

    renderAlerts(alerts) {
        const container = document.getElementById('alerts-container');
        const activeTab = document.querySelector('.alerts-tabs .tab-btn.active')?.dataset.tab || 'active';

        // Filter alerts based on active tab
        let filteredAlerts = alerts;
        if (activeTab === 'active') {
            filteredAlerts = alerts.filter(alert => alert.status !== 'resolved');
        }

        if (filteredAlerts.length === 0) {
            const message = activeTab === 'active' ? 'No active alerts!' : 'No alerts found!';
            container.innerHTML = `<div class="no-issues">${message}</div>`;
            return;
        }

        container.innerHTML = filteredAlerts.map(alert => `
            <div class="alert-item alert-${alert.level || 'info'} ${alert.status === 'resolved' ? 'alert-resolved' : ''}">
                <div class="alert-header">
                    <div class="alert-meta">
                        <span class="alert-level alert-level-${alert.level || 'info'}">${(alert.level || 'info').toUpperCase()}</span>
                        <span class="alert-timestamp">${this.formatTimestamp(alert.timestamp)}</span>
                        ${alert.status === 'resolved' ? '<span class="alert-status-resolved">RESOLVED</span>' : ''}
                    </div>
                    <div class="alert-actions">
                        ${alert.status !== 'resolved' ? `<button class="alert-resolve-btn" onclick="window.dashboard.resolveAlert('${alert.id}')">Resolve</button>` : ''}
                    </div>
                </div>
                <div class="alert-title">${alert.title || alert.name || 'Alert'}</div>
                <div class="alert-description">${alert.description || alert.message || ''}</div>
                ${alert.details ? `<div class="alert-details">${alert.details}</div>` : ''}
                ${alert.source ? `<div class="alert-source">Source: ${alert.source}</div>` : ''}
            </div>
        `).join('');
    }

    formatTimestamp(timestamp) {
        if (!timestamp) return '';

        try {
            const date = new Date(timestamp);
            const now = new Date();
            const diffMs = now - date;
            const diffMins = Math.floor(diffMs / (1000 * 60));
            const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
            const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

            if (diffMins < 1) return 'Just now';
            if (diffMins < 60) return `${diffMins}m ago`;
            if (diffHours < 24) return `${diffHours}h ago`;
            if (diffDays < 7) return `${diffDays}d ago`;

            return date.toLocaleDateString();
        } catch (error) {
            return timestamp;
        }
    }

    async resolveAlert(alertId) {
        try {
            const response = await fetch(`/api/v1/alerts/${alertId}/resolve`, {
                method: 'POST'
            });

            if (response.ok) {
                this.showNotification('Alert resolved successfully!', 'success');
                this.loadAlerts(); // Refresh the alerts list
            } else {
                throw new Error('Failed to resolve alert');
            }
        } catch (error) {
            console.error('Failed to resolve alert:', error);
            this.showNotification('Failed to resolve alert', 'error');
        }
    }

    async loadSettings() {
        try {
            const response = await fetch('/api/v1/settings');
            const settings = await response.json();

            // Populate form fields with current settings
            if (settings) {
                document.getElementById('scan-interval').value = settings.scan_interval || '24';
                document.getElementById('remediation-threshold').value = settings.remediation_threshold || '20';
                document.getElementById('remediation-provider').value = settings.remediation_provider || 'anthropic';

                // Populate API keys if they exist
                if (settings.ai_providers) {
                    document.getElementById('cerebras-api-key').value = settings.ai_providers.cerebras?.api_key || '';
                    document.getElementById('gemini-api-key').value = settings.ai_providers.gemini?.api_key || '';
                    document.getElementById('anthropic-api-key').value = settings.ai_providers.anthropic?.api_key || '';
                    document.getElementById('openai-api-key').value = settings.ai_providers.openai?.api_key || '';
                    document.getElementById('deepseek-api-key').value = settings.ai_providers.deepseek?.api_key || '';
                }
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
            // Set default values if loading fails
            this.resetSettings();
        }
    }

    saveSettings() {
        // Get form field values safely
        const scanIntervalElement = document.getElementById('scan-interval');
        const remediationThresholdElement = document.getElementById('remediation-threshold');
        const remediationProviderElement = document.getElementById('remediation-provider');
        const cerebrasApiKeyElement = document.getElementById('cerebras-api-key');
        const geminiApiKeyElement = document.getElementById('gemini-api-key');
        const anthropicApiKeyElement = document.getElementById('anthropic-api-key');
        const openaiApiKeyElement = document.getElementById('openai-api-key');
        const deepseekApiKeyElement = document.getElementById('deepseek-api-key');

        // Check if elements exist before accessing their values
        if (!scanIntervalElement || !remediationThresholdElement || !remediationProviderElement) {
            this.showNotification('Settings form elements not found', 'error');
            return;
        }

        const scanInterval = scanIntervalElement.value || '24';
        const remediationThreshold = remediationThresholdElement.value || '20';
        const remediationProvider = remediationProviderElement.value || 'anthropic';

        // Send settings to server
        fetch('/api/v1/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                scan_interval: parseInt(scanInterval),
                remediation_threshold: parseInt(remediationThreshold),
                remediation_provider: remediationProvider,
                ai_providers: {
                    cerebras: { api_key: cerebrasApiKeyElement ? cerebrasApiKeyElement.value : '' },
                    gemini: { api_key: geminiApiKeyElement ? geminiApiKeyElement.value : '' },
                    anthropic: { api_key: anthropicApiKeyElement ? anthropicApiKeyElement.value : '' },
                    openai: { api_key: openaiApiKeyElement ? openaiApiKeyElement.value : '' },
                    deepseek: { api_key: deepseekApiKeyElement ? deepseekApiKeyElement.value : '' }
                }
            })
        })
        .then(response => response.json())
        .then(data => {
            this.showNotification('Settings saved successfully!', 'success');
        })
        .catch(error => {
            console.error('Failed to save settings:', error);
            this.showNotification('Failed to save settings', 'error');
        });
    }

    resetSettings() {
        document.getElementById('scan-interval').value = '24';
        document.getElementById('remediation-threshold').value = '20';
        document.getElementById('remediation-provider').value = 'anthropic';
        document.getElementById('cerebras-api-key').value = '';
        document.getElementById('gemini-api-key').value = '';
        document.getElementById('anthropic-api-key').value = '';
        document.getElementById('openai-api-key').value = '';
        document.getElementById('deepseek-api-key').value = '';
    }

    setupConnectionTabs() {
        const connectionTabs = document.querySelectorAll('.connection-tab');
        connectionTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.dataset.tab;
                this.switchConnectionTab(tabName);
            });
        });

        // Monitor GitHub input fields to enable/disable connect button
        const githubInputs = ['github-owner', 'github-repo'];
        githubInputs.forEach(inputId => {
            document.getElementById(inputId).addEventListener('input', () => {
                this.updateGitHubConnectButton();
            });
        });
    }

    setupAlertsTabs() {
        const alertsTabs = document.querySelectorAll('.alerts-tabs .tab-btn');
        alertsTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.dataset.tab;
                this.switchAlertsTab(tabName);
            });
        });
    }

    switchAlertsTab(tab) {
        // Remove active class from all tabs
        document.querySelectorAll('.alerts-tabs .tab-btn').forEach(t => t.classList.remove('active'));

        // Add active class to selected tab
        document.querySelector(`.alerts-tabs [data-tab="${tab}"]`).classList.add('active');

        // Reload alerts with new filter
        this.loadAlerts();
    }

    setupModalConnectionTabs() {
        const modal = document.getElementById('projects-modal');
        if (!modal) return;

        const connectionTabs = modal.querySelectorAll('.connection-tab');
        connectionTabs.forEach(tab => {
            // Remove any old listeners to prevent duplicates
            tab.replaceWith(tab.cloneNode(true));
        });

        // Add new listeners to the cloned tabs
        modal.querySelectorAll('.connection-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.dataset.tab;
                this.switchConnectionTab(tabName, modal);
            });
        });
    }

    switchConnectionTab(tab) {
        // Remove active class from all tabs and panels
        document.querySelectorAll('.connection-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.connection-panel').forEach(p => p.classList.remove('active'));

        // Add active class to selected tab and panel
        document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
        document.getElementById(`${tab}-connection`).classList.add('active');
    }

    switchConnectionTab(tab, context = document) {
        // Remove active class from all tabs and panels within the given context
        context.querySelectorAll('.connection-tab').forEach(t => t.classList.remove('active'));
        context.querySelectorAll('.connection-panel').forEach(p => p.classList.remove('active'));

        // Add active class to selected tab and panel
        const tabElement = context.querySelector(`[data-tab="${tab}"]`);
        const panelElement = context.querySelector(`#${tab}-connection`);

        if (tabElement) tabElement.classList.add('active');
        if (panelElement) panelElement.classList.add('active');
    }

    async selectFolder() {
        try {
            // Use the native file system access API if available
            if (window.showDirectoryPicker) {
                const directoryHandle = await window.showDirectoryPicker();
                const path = await this.getDirectoryPath(directoryHandle);
                document.getElementById('local-folder-path').value = path;

                // Auto-detect project name from folder name
                const projectName = directoryHandle.name;
                document.getElementById('project-name').value = projectName;

                this.showNotification(`Selected folder: ${projectName}`, 'success');
            } else {
                // Fallback for browsers that don't support the File System Access API
                // We'll create a hidden file input that allows directory selection where supported
                const input = document.createElement('input');
                input.type = 'file';
                // webkitdirectory allows selecting directories in Chromium-based browsers
                input.webkitdirectory = true;
                input.directory = true;
                input.multiple = false;
                input.style.display = 'none';
                document.body.appendChild(input);

                input.addEventListener('change', (ev) => {
                    const files = ev.target.files;
                    if (files && files.length > 0) {
                        // derive a folder name from the first file's path
                        const firstPath = files[0].webkitRelativePath || files[0].name;
                        const folderName = firstPath.split('/')[0];
                        document.getElementById('local-folder-path').value = folderName;
                        document.getElementById('project-name').value = folderName;
                        this.showNotification(`Selected folder: ${folderName}`, 'success');
                    } else {
                        this.showNotification('No folder selected', 'warning');
                    }
                    document.body.removeChild(input);
                });

                input.click();
            }
        } catch (error) {
            if (error.name !== 'AbortError') {
                console.error('Error selecting folder:', error);
                this.showNotification('Failed to select folder. Please try again.', 'error');
            }
        }
    }

    async getDirectoryPath(directoryHandle) {
        // For security reasons, we can't get the full system path
        // Instead, we'll use the folder name as identifier
        return directoryHandle.name;
    }

    async connectLocalProject() {
        const folderPath = document.getElementById('local-folder-path').value;
        const projectName = document.getElementById('project-name').value || folderPath;
        const scanDepth = document.getElementById('scan-depth').value;

        if (!folderPath) {
            this.showNotification('Please select a project folder first.', 'error');
            return;
        }

        try {
            const response = await fetch('/api/v1/projects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: 'local',
                    path: folderPath,
                    name: projectName,
                    scanDepth: scanDepth
                })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.message || 'Failed to connect local project');
            }

            this.showNotification('Local project connected successfully!', 'success');

            // Clear form
            document.getElementById('local-folder-path').value = '';
            document.getElementById('project-name').value = '';

            // Show project-specific navigation
            this.showProjectNavigation();

            // Mark project as started
            this.projectStarted = true;
            localStorage.setItem('projectStarted', 'true');

            // Refresh projects list and auto-select the created project if returned
            const respData = await response.json().catch(() => null);
            this.loadProjects();
            if (respData && respData.id) {
                this.currentProjectId = respData.id;
                // optionally use returned name
                if (respData.name) this.updateActiveProjectUI(respData.id);
            }
        } catch (error) {
            console.error('Failed to connect local project:', error);
            this.showNotification(error.message, 'error');
        }
    }

    async authenticateGitHub() {
        try {
            // The origin_host parameter tells the auth hub where to redirect back to.
            // For a self-hosted app, this would be the instance's URL. For local dev, it's localhost.
            const originHost = window.location.origin;
            const response = await fetch(`/api/v1/auth/github?origin_host=${encodeURIComponent(originHost)}`);
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error?.message || 'Failed to get GitHub authentication URL.');
            }

            const data = await response.json();
            
            // Redirect the user to the GitHub authorization URL.
            window.location.href = data.data.auth_url;
        } catch (error) {
            console.error('GitHub authentication error:', error);
            this.showNotification('Failed to start GitHub authentication', 'error');
        }
    }

    async checkGitHubAuthStatus() {
        try {
            const response = await fetch('/api/v1/auth/github/status');
            const authData = await response.json();

            if (authData.authenticated) {
                this.githubAuthenticated = authData.data.authenticated;
                this.updateGitHubAuthUI(true);
                this.showNotification('GitHub authentication successful!', 'success');
            } else {
                this.updateGitHubAuthUI(false);
            }
        } catch (error) {
            console.error('Failed to check GitHub auth status:', error);
            this.updateGitHubAuthUI(false);
        }
    }

    updateGitHubAuthUI(authenticated) {
        const modal = document.getElementById('projects-modal');
        if (!modal) return;

        const authStatus = modal.querySelector('#github-auth-status');
        const authBtn = modal.querySelector('.auth-btn');
        const connectBtn = modal.querySelector('.github-connect-btn');

        if (authenticated) {
            authStatus.innerHTML = `
                <span class="auth-indicator connected"></span>
                <span>Authenticated</span>
            `;
            authBtn.textContent = 'Re-authenticate';
            connectBtn.disabled = false;
        } else {
            authStatus.innerHTML = `
                <span class="auth-indicator"></span>
                <span>Not authenticated</span>
            `;
            authBtn.textContent = 'Authenticate with GitHub';
            connectBtn.disabled = true;
        }
    }

    updateGitHubConnectButton() {
        const modal = document.getElementById('projects-modal');
        if (!modal) return;

        const owner = modal.querySelector('#github-owner').value;
        const repo = modal.querySelector('#github-repo').value;
        const connectBtn = modal.querySelector('.github-connect-btn');

        connectBtn.disabled = !(owner && repo && this.githubAuthenticated);
    }

    async connectGitHubProject() {
        const owner = document.getElementById('github-owner').value;
        const repo = document.getElementById('github-repo').value;
        const branch = document.getElementById('github-branch').value;
        const includePRs = document.getElementById('github-include-prs').checked;
        const includeIssues = document.getElementById('github-include-issues').checked;
        const watchReleases = document.getElementById('github-watch-releases').checked;

        if (!owner || !repo) {
            this.showNotification('Please enter both owner and repository name.', 'error');
            return;
        }

        try {
            const response = await fetch('/api/v1/projects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: 'github',
                    owner: owner,
                    repo: repo,
                    branch: branch,
                    includePRs: includePRs,
                    includeIssues: includeIssues,
                    watchReleases: watchReleases
                })
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.message || 'Failed to connect GitHub repository');
            }

            this.showNotification('GitHub repository connected successfully!', 'success');

            // Clear form
            document.getElementById('github-owner').value = '';
            document.getElementById('github-repo').value = '';
            document.getElementById('github-branch').value = 'main';

            // Show project-specific navigation
            this.showProjectNavigation();

            // Mark project as started
            this.projectStarted = true;
            localStorage.setItem('projectStarted', 'true');

            // Refresh projects list and auto-select the created project if returned
            const respData = await response.json().catch(() => null);
            this.loadProjects();
            if (respData && respData.id) {
                this.currentProjectId = respData.id;
                if (respData.name) this.updateActiveProjectUI(respData.id);
            }
        } catch (error) {
            console.error('Failed to connect GitHub project:', error);
            this.showNotification(error.message, 'error');
        }
    }

    // Theme Management
    loadThemePreference() {
        const savedTheme = localStorage.getItem('archguardian-theme');
        if (savedTheme) {
            this.currentTheme = savedTheme;
            this.applyTheme(savedTheme);
        } else {
            // Check system preference
            if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                this.currentTheme = 'dark';
                this.applyTheme('dark');
            }
        }
    }

    setupThemeToggle() {
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                this.toggleTheme();
            });
        }
    }

    toggleTheme() {
        this.currentTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.saveThemePreference();
        this.applyTheme(this.currentTheme);
    }

    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        
        // Update theme icon
        const themeIcon = document.querySelector('.theme-icon');
        if (themeIcon) {
            themeIcon.textContent = theme === 'light' ? '🌙' : '☀️';
        }

        // Update charts if they exist
        // A small delay ensures the CSS variables are updated before the chart re-renders
        setTimeout(() => this.updateChartThemes(), 50);
    }

    updateChartThemes() {
        const bodyStyles = getComputedStyle(document.body);
        const primaryColor = bodyStyles.getPropertyValue('--primary-color').trim();
        const errorColor = bodyStyles.getPropertyValue('--error-color').trim();
        const successColor = bodyStyles.getPropertyValue('--success-color').trim();
        const cardBgColor = bodyStyles.getPropertyValue('--card-background').trim();

        // Update chart colors based on theme
        if (this.riskChart) {
            this.riskChart.data.datasets[0].borderColor = errorColor;
            this.riskChart.data.datasets[0].backgroundColor = `${errorColor}1A`; // Add alpha
            this.riskChart.update();
        }

        if (this.coverageChart) {
            const colors = this.currentTheme === 'dark'
                ? ['hsl(142, 76%, 36%)', 'hsl(217, 33%, 17%)']
                : ['rgb(16, 185, 129)', 'rgb(229, 231, 235)'];
            this.coverageChart.data.datasets[0].backgroundColor = [successColor, cardBgColor];
            this.coverageChart.update();
        }

        if (this.coverageDetailsChart) {
            const backgroundColor = this.currentTheme === 'dark'
                ? 'hsla(271, 91%, 65%, 0.8)'
                : 'rgba(37, 99, 235, 0.8)'; // Keep this as is or use primaryColor
            this.coverageDetailsChart.data.datasets[0].backgroundColor = primaryColor;
            this.coverageDetailsChart.data.datasets[0].backgroundColor = backgroundColor;
            this.coverageDetailsChart.update();
        }
    }

    saveThemePreference() {
        localStorage.setItem('archguardian-theme', this.currentTheme);
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;

        // Add styles
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '1rem 1.5rem',
            borderRadius: '0.5rem',
            color: 'white',
            fontWeight: '500',
            zIndex: '1000',
            animation: 'slideIn 0.3s ease-out'
        });

        // Set background color based on type
        switch (type) {
            case 'success':
                notification.style.background = '#10b981';
                break;
            case 'error':
                notification.style.background = '#ef4444';
                break;
            case 'warning':
                notification.style.background = '#f59e0b';
                break;
            default:
                notification.style.background = '#2563eb';
        }

        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new ArchGuardianDashboard();
});

// Add CSS animations for notifications

const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }

    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }

    .low-risk { color: var(--success-color) !important; }
    .medium-risk { color: var(--warning-color) !important; }
    .high-risk { color: var(--error-color) !important; }

    .severity-critical { background: rgba(239,68,68,0.1); color: var(--error-color); }
    .severity-high { background: rgba(245,158,11,0.08); color: var(--warning-color); }
    .severity-medium { background: rgba(37,99,235,0.06); color: var(--primary-color); }
    .severity-low { background: rgba(16,185,129,0.06); color: var(--success-color); }

    .safety-safe { background: rgba(16,185,129,0.06); color: var(--success-color); }
    .safety-risky { background: rgba(245,158,11,0.06); color: var(--warning-color); }

    .status-active { background: rgba(16,185,129,0.06); color: var(--success-color); }
    .status-deprecated { background: rgba(245,158,11,0.06); color: var(--warning-color); }
    .status-abandoned { background: rgba(239,68,68,0.06); color: var(--error-color); }

    .no-issues {
        text-align: center;
        color: var(--success-color);
        font-size: 1.125rem;
        padding: 2rem;
    }

    .error {
        text-align: center;
        color: var(--error-color);
        font-size: 1.125rem;
        padding: 2rem;
    }

    .projects-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 1.5rem;
    }

    /* Modal specific layout: left column for add-project, right column for existing projects */
    .modal-projects-grid {
        display: grid;
        grid-template-columns: 420px 1fr;
        gap: 1.5rem;
        align-items: start;
    }

    .modal-projects-list {
        max-height: 60vh;
        overflow: auto;
        display: grid;
        grid-template-columns: 1fr;
        gap: 1rem;
    }

    .project-active {
        border-color: var(--primary-color);
        box-shadow: 0 4px 14px rgba(0,0,0,0.06);
        position: relative;
    }

    .projects-spinner {
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 2rem;
        color: var(--text-secondary);
        font-weight: 600;
    }

    .btn-loading {
        opacity: 0.9;
        cursor: wait !important;
    }

    /* Inline spinner inside Start button */
    .btn-spinner {
        display: inline-block;
        width: 0.75rem;
        height: 0.75rem;
        border: 2px solid rgba(255,255,255,0.2);
        border-top-color: white;
        border-radius: 50%;
        margin-right: 0.5rem;
        vertical-align: middle;
        visibility: hidden;
    }

    .start-scan-btn.btn-loading .btn-spinner {
        visibility: visible;
        animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }

    .project-badge {
        font-size: 0.75rem;
        padding: 0.25rem 0.5rem;
        border-radius: 999px;
        font-weight: 600;
    }

    .project-badge-active { background: var(--success-color); color: white; }
    .project-badge-idle { background: var(--text-secondary); color: white; }

    .project-ingest { margin-top: 0.75rem; color: var(--text-secondary); font-size: 0.9rem; }
    .ingested { color: var(--success-color); font-weight: 600; }
    .not-ingested { color: var(--warning-color); font-weight: 600; }
    .ingest-now-btn { margin-left: 0.5rem; padding: 0.25rem 0.5rem; font-size: 0.85rem; border-radius: 0.25rem; border: none; background: var(--primary-color); color: white; cursor: pointer; }
    .ingest-now-btn:disabled { opacity: 0.6; cursor: not-allowed; }

    .project-card, .add-project-card {
        background: var(--card-background);
        border: 1px solid var(--border-color);
        border-radius: 0.5rem;
        padding: 1.5rem;
        color: var(--text-primary);
    }

    .project-path {
        font-size: 0.8rem;
        color: var(--text-secondary);
        word-break: break-all;
        margin-bottom: 1rem;
    }

    .project-status .status-idle { color: var(--text-secondary); }
    .project-status .status-scanning { color: var(--primary-color); }

    .project-progress-bar {
        margin-top: 0.5rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .project-progress-fill {
        height: 6px;
        background: var(--primary-color);
        border-radius: 3px;
        transition: width 0.3s ease;
    }

    .project-progress-text {
        font-size: 0.75rem;
        color: var(--text-secondary);
        white-space: nowrap;
    }

    .project-buttons {
        display: flex;
        gap: 0.5rem;
        margin-top: 1rem;
    }

    .start-scan-btn, .stop-scan-btn {
        flex: 1;
        padding: 0.5rem 1rem;
        border: none;
        border-radius: 0.25rem;
        font-size: 0.875rem;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s;
    }

    .start-scan-btn {
        background: var(--primary-color);
        color: white;
    }

    .start-scan-btn:hover:not(:disabled) {
        background: var(--primary-color-dark);
    }

    .start-scan-btn:disabled {
        background: var(--text-secondary);
        cursor: not-allowed;
    }

    .stop-scan-btn {
        background: var(--error-color);
        color: white;
    }

    .stop-scan-btn:hover:not(:disabled) {
        background: #dc2626;
    }

    .stop-scan-btn:disabled {
        background: var(--text-secondary);
        cursor: not-allowed;
    }

    .issue-item {
        background: var(--card-background);
        border: 1px solid var(--border-color);
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 1rem;
        color: var(--text-primary);
    }

    .issue-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }

    .issue-id, .issue-package { font-weight: 600; color: var(--primary-color); }

    .issue-severity, .issue-safety, .issue-maintenance {
        padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 500; text-transform: uppercase;
    }

    .issue-description { margin-bottom: 0.5rem; color: var(--text-secondary); }

    .issue-location, .issue-package, .issue-cvss, .issue-effort,
    .issue-references, .issue-versions, .issue-issues {
        font-size: 0.875rem;
        color: var(--text-secondary);
        margin-bottom: 0.25rem;
    }

    .console-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .console-action-btn {
        background: var(--primary-color);
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 0.25rem;
        cursor: pointer;
        font-weight: 500;
        margin-right: 0.5rem;
    }
    .console-action-btn:hover {
        background: var(--primary-color-dark);
    }

    .getting-started-card {
        background: var(--card-background);
        border: 1px solid var(--border-color);
        border-radius: 0.5rem;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
    }

    .getting-started-card h3 { margin-top: 0; }
    .getting-started-card p { color: var(--text-secondary); }

    .action-btn {
        background: var(--primary-color);
        color: white;
        border: none;
        padding: 0.75rem 1.5rem;
        border-radius: 0.25rem;
        cursor: pointer;
        font-weight: 500;
        width: 100%;
        text-align: center;
        font-size: 1rem;
    }
    .action-btn:hover {
        background: var(--primary-color-dark);
    }

    .settings-section .action-btn {
        margin-top: 1rem;
    }

    /* Alerts View Styles */
    .alerts-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 1.5rem;
    }

    .alerts-controls {
        display: flex;
        gap: 0.5rem;
    }

    .alerts-content {
        margin-top: 1.5rem;
    }

    .alerts-tabs {
        display: flex;
        gap: 0.5rem;
        margin-bottom: 1.5rem;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 0.5rem;
    }

    .alerts-container {
        max-height: 70vh;
        overflow-y: auto;
    }

    .alert-item {
        background: var(--card-background);
        border: 1px solid var(--border-color);
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 1rem;
        color: var(--text-primary);
        transition: all 0.2s;
    }

    .alert-item:hover {
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }

    .alert-item.alert-info {
        border-left: 4px solid var(--primary-color);
    }

    .alert-item.alert-warning {
        border-left: 4px solid var(--warning-color);
    }

    .alert-item.alert-error, .alert-item.alert-critical {
        border-left: 4px solid var(--error-color);
    }

    .alert-item.alert-success {
        border-left: 4px solid var(--success-color);
    }

    .alert-resolved {
        opacity: 0.7;
        background: var(--card-background-secondary);
    }

    .alert-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.75rem;
    }

    .alert-meta {
        display: flex;
        align-items: center;
        gap: 1rem;
        font-size: 0.875rem;
        color: var(--text-secondary);
    }

    .alert-level {
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }

    .alert-level-info {
        background: rgba(37,99,235,0.1);
        color: var(--primary-color);
    }

    .alert-level-warning {
        background: rgba(245,158,11,0.1);
        color: var(--warning-color);
    }

    .alert-level-error, .alert-level-critical {
        background: rgba(239,68,68,0.1);
        color: var(--error-color);
    }

    .alert-level-success {
        background: rgba(16,185,129,0.1);
        color: var(--success-color);
    }

    .alert-timestamp {
        font-size: 0.8rem;
    }

    .alert-status-resolved {
        background: rgba(16,185,129,0.1);
        color: var(--success-color);
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        font-weight: 600;
    }

    .alert-actions {
        display: flex;
        gap: 0.5rem;
    }

    .alert-resolve-btn {
        background: var(--primary-color);
        color: white;
        border: none;
        padding: 0.375rem 0.75rem;
        border-radius: 0.25rem;
        font-size: 0.875rem;
        cursor: pointer;
        transition: background 0.2s;
    }

    .alert-resolve-btn:hover {
        background: var(--primary-color-dark);
    }

    .alert-title {
        font-size: 1.125rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
        color: var(--text-primary);
    }

    .alert-description {
        margin-bottom: 0.5rem;
        color: var(--text-secondary);
        line-height: 1.5;
    }

    .alert-details, .alert-source {
        font-size: 0.875rem;
        color: var(--text-secondary);
        margin-bottom: 0.25rem;
    }

    .alert-source {
        font-style: italic;
    }

    .clear-btn {
        background: var(--text-secondary);
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 0.25rem;
        cursor: pointer;
        font-weight: 500;
        transition: background 0.2s;
    }

    .clear-btn:hover {
        background: #6b7280;
    }
`;

document.head.appendChild(style);

// Expose thin global wrappers so inline onclick handlers in index.html work reliably.
// They simply delegate to the dashboard instance.
window.filterNodes = function(type) { if (window.dashboard && typeof window.dashboard.filterNodes === 'function') window.dashboard.filterNodes(type); };
window.refreshIssues = function() { if (window.dashboard && typeof window.dashboard.refreshIssues === 'function') window.dashboard.refreshIssues(); };
window.refreshCoverage = function() { if (window.dashboard && typeof window.dashboard.refreshCoverage === 'function') window.dashboard.refreshCoverage(); };
window.saveSettings = function() { if (window.dashboard && typeof window.dashboard.saveSettings === 'function') window.dashboard.saveSettings(); };
window.resetSettings = function() { if (window.dashboard && typeof window.dashboard.resetSettings === 'function') window.dashboard.resetSettings(); };
window.selectFolder = function() { if (window.dashboard && typeof window.dashboard.selectFolder === 'function') window.dashboard.selectFolder(); };
window.startScan = function(projectId) { if (window.dashboard && typeof window.dashboard.startScan === 'function') window.dashboard.startScan(projectId); };
window.stopScan = function(projectId) { if (window.dashboard && typeof window.dashboard.stopScan === 'function') window.dashboard.stopScan(projectId); };
window.connectLocalProject = function() { if (window.dashboard && typeof window.dashboard.connectLocalProject === 'function') window.dashboard.connectLocalProject(); };
window.connectGitHubProject = function() { if (window.dashboard && typeof window.dashboard.connectGitHubProject === 'function') window.dashboard.connectGitHubProject(); };
window.authenticateGitHub = function() { if (window.dashboard && typeof window.dashboard.authenticateGitHub === 'function') window.dashboard.authenticateGitHub(); };
window.loadProjects = function() { if (window.dashboard && typeof window.dashboard.loadProjects === 'function') window.dashboard.loadProjects(); };
window.loadKnowledgeGraph = function() { if (window.dashboard && typeof window.dashboard.loadKnowledgeGraph === 'function') window.dashboard.loadKnowledgeGraph(); };
window.loadAlerts = function() { if (window.dashboard && typeof window.dashboard.loadAlerts === 'function') window.dashboard.loadAlerts(); };
window.clearResolvedAlerts = function() { if (window.dashboard && typeof window.dashboard.clearResolvedAlerts === 'function') window.dashboard.clearResolvedAlerts(); };
window.resolveAlert = function(alertId) { if (window.dashboard && typeof window.dashboard.resolveAlert === 'function') window.dashboard.resolveAlert(alertId); };

// Note: Folder browse buttons use inline onclick handlers to maintain user activation context
// for the File System Access API. Event delegation would break this requirement.
