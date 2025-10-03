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
        this.setupNavigation();
        this.setupWebSocket();
        this.loadInitialData();
        this.setupCharts();
        this.loadProjects(); // Load projects on initial load
        this.setupConnectionTabs();
        this.setupThemeToggle();
        // Print an initialization message to the dashboard console
        try { this.appendConsoleLog('Dashboard initialized'); } catch (e) { /* silent */ }
    }

    setupNavigation() {
        const navBtns = document.querySelectorAll('.nav-btn');
        navBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const view = btn.dataset.view;
                this.switchView(view);
            });
        });

        // Setup issues tabs
        const tabBtns = document.querySelectorAll('.tab-btn');
        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tab = btn.dataset.tab;
                this.switchTab(tab);
            });
        });
    }

    switchView(view) {
        // Hide all views
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

        // Remove active class from nav buttons
        document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));

        // Show selected view
        document.getElementById(`${view}-view`).classList.add('active');

        // Add active class to nav button
        document.querySelector(`[data-view="${view}"]`).classList.add('active');

        this.currentView = view;

        // Load view-specific data
        this.loadViewData(view);
        if (view === 'projects') {
            this.loadProjects();
        }
    }

    switchTab(tab) {
        // Remove active class from all tabs
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));

        // Add active class to selected tab
        document.querySelector(`[data-tab="${tab}"]`).classList.add('active');

        // Load tab data
        this.loadIssuesData(tab);
    }

    setupWebSocket() {
        // Connect to ArchGuardian's WebSocket server
        this.ws = new WebSocket(`ws://localhost:3000/ws`);

        this.ws.onopen = () => {
            console.log('Connected to ArchGuardian WebSocket');
            // Notify the backend that the client is ready to receive initial logs
            this.appendConsoleLog('WebSocket connected');
            try {
                this.ws.send(JSON.stringify({ type: 'client_ready' }));
                this.appendConsoleLog('Sent client_ready to server');
            } catch (e) {
                console.error('Failed to send client_ready:', e);
                this.appendConsoleLog('Failed to send client_ready');
            }
        };

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWebSocketMessage(data);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.appendConsoleLog('WebSocket error: ' + (error && error.message ? error.message : JSON.stringify(error)));
        };

        this.ws.onclose = (ev) => {
            console.warn('WebSocket closed', ev);
            this.appendConsoleLog('WebSocket closed');
        };
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
            case 'log':
                // Log message is nested in data.data.message
                const logMessage = data.data?.message || data.message || '';
                this.appendConsoleLog(logMessage);
                break;
        }
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

    async loadProjects() {
        try {
            const response = await fetch('http://localhost:3000/api/v1/projects');
            const projects = await response.json();
            this.renderProjects(projects || []);
        } catch (error) {
            console.error('Failed to load projects:', error);
            document.getElementById('projects-list').innerHTML = '<div class="error">Failed to load projects.</div>';
        }
    }

    renderProjects(projects) {
        const container = document.getElementById('projects-list');
        if (projects.length === 0) {
            container.innerHTML = '<div class="no-issues">No projects connected yet.</div>';
            return;
        }

        container.innerHTML = projects.map(p => `
            <div class="project-card">
                <h4>${p.name}</h4>
                <p class="project-path">${p.path}</p>
                <div class="project-status">Status: <span class="status-${p.status.toLowerCase()}">${p.status}</span></div>
                <div class="project-buttons">
                    <button class="start-scan-btn" onclick="window.dashboard.startScan('${p.id}')" ${p.status === 'scanning' ? 'disabled' : ''}>
                        ${p.status === 'scanning' ? 'Scanning...' : 'Start'}
                    </button>
                    <button class="stop-scan-btn" onclick="window.dashboard.stopScan('${p.id}')" ${p.status !== 'scanning' ? 'disabled' : ''}>
                        Stop
                    </button>
                </div>
            </div>
        `).join('');
    }

    async addProject() {
        const projectType = document.getElementById('project-type').value;
        const projectPath = document.getElementById('project-path').value;

        if (!projectPath) {
            this.showNotification('Project path or URL cannot be empty.', 'error');
            return;
        }

        try {
            const response = await fetch('http://localhost:3000/api/v1/projects', {
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
            this.loadProjects(); // Refresh the list
        } catch (error) {
            console.error('Failed to add project:', error);
            this.showNotification(error.message, 'error');
        }
    }

    async startScan(projectId) {
        // Show the hidden navigation links when starting a scan
        this.showHiddenNavigation();

        this.showNotification(`Starting scan for project...`, 'info');

        // Trigger the scan via API
        await fetch(`http://localhost:3000/api/v1/projects/${projectId}/scan`, { method: 'POST' });

        // Mark project as started
        this.projectStarted = true;

        // The UI will be updated via WebSocket events, but we can also force a refresh
        setTimeout(() => this.loadProjects(), 1000);
    }

    async stopScan(projectId) {
        this.showNotification(`Stopping scan for project...`, 'info');

        // For now, we'll just show a notification since the backend doesn't have a stop endpoint
        // In a real implementation, you would call an API endpoint to stop the scan
        try {
            // Try to call a stop endpoint if it exists
            await fetch(`http://localhost:3000/api/v1/projects/${projectId}/stop`, { method: 'POST' });
        } catch (error) {
            // If stop endpoint doesn't exist, just show notification
            console.log('Stop endpoint not available, scan will continue');
        }

        // Refresh projects list to update button states
        setTimeout(() => this.loadProjects(), 1000);
    }

    showHiddenNavigation() {
        // Show the previously hidden navigation buttons
        const hiddenNavButtons = document.querySelectorAll('.hidden-nav');
        hiddenNavButtons.forEach(button => {
            button.style.display = 'block';
        });

        this.showNotification('Project started! Navigation links are now available.', 'success');
    }

    async loadKnowledgeGraph() {
        try {
            const response = await fetch('http://localhost:3000/api/v1/knowledge-graph');
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
            const response = await fetch('http://localhost:3000/api/v1/risk-assessment');
            const data = await response.json();

            this.updateOverviewData(data);
        } catch (error) {
            console.error('Failed to load risk assessment:', error);
        }
    }

    async loadCoverageData() {
        try {
            const response = await fetch('http://localhost:3000/api/v1/coverage');
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
            const response = await fetch(`http://localhost:3000/api/v1/issues?type=${type}`);
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
            case 'obsolete':
                html = this.renderObsoleteCode(data.obsolete_code || []);
                break;
            case 'dependencies':
                html = this.renderDependencyIssues(data.dangerous_dependencies || []);
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
        // Don't load data if no project has been started
        if (!this.projectStarted) {
            console.log(`Project not started yet, skipping data load for ${view} view`);
            return;
        }

        switch (view) {
            case 'issues':
                this.loadIssuesData('technical-debt');
                break;
            case 'coverage':
                this.loadCoverageData();
                break;
            case 'graph':
                this.loadKnowledgeGraph();
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

    saveSettings() {
        const scanInterval = document.getElementById('scan-interval').value;
        const remediationThreshold = document.getElementById('remediation-threshold').value;
        const remediationProvider = document.getElementById('remediation-provider').value;

        // Send settings to server
        fetch('http://localhost:3000/api/v1/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                scan_interval: parseInt(scanInterval),
                remediation_threshold: parseInt(remediationThreshold),
                remediation_provider: remediationProvider
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

    switchConnectionTab(tab) {
        // Remove active class from all tabs and panels
        document.querySelectorAll('.connection-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.connection-panel').forEach(p => p.classList.remove('active'));

        // Add active class to selected tab and panel
        document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
        document.getElementById(`${tab}-connection`).classList.add('active');
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
            const response = await fetch('http://localhost:3000/api/v1/projects', {
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

            // Refresh projects list
            this.loadProjects();
        } catch (error) {
            console.error('Failed to connect local project:', error);
            this.showNotification(error.message, 'error');
        }
    }

    async authenticateGitHub() {
        try {
            // Open GitHub OAuth popup or redirect
            const authWindow = window.open(
                'http://localhost:3000/auth/github',
                'GitHub Authentication',
                'width=600,height=700,scrollbars=yes,resizable=yes'
            );

            // Listen for authentication completion
            const checkAuth = setInterval(() => {
                if (authWindow.closed) {
                    clearInterval(checkAuth);
                    this.checkGitHubAuthStatus();
                }
            }, 1000);

        } catch (error) {
            console.error('GitHub authentication error:', error);
            this.showNotification('Failed to start GitHub authentication', 'error');
        }
    }

    async checkGitHubAuthStatus() {
        try {
            const response = await fetch('http://localhost:3000/api/v1/auth/github/status');
            const authData = await response.json();

            if (authData.authenticated) {
                this.githubAuthenticated = true;
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
        const authStatus = document.getElementById('github-auth-status');
        const authBtn = document.querySelector('.auth-btn');
        const connectBtn = document.querySelector('.github-connect-btn');

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
        const owner = document.getElementById('github-owner').value;
        const repo = document.getElementById('github-repo').value;
        const connectBtn = document.querySelector('.github-connect-btn');

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
            const response = await fetch('http://localhost:3000/api/v1/projects', {
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

            // Refresh projects list
            this.loadProjects();
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

// Note: Folder browse buttons use inline onclick handlers to maintain user activation context
// for the File System Access API. Event delegation would break this requirement.
