// ArchGuardian Dashboard JavaScript

class ArchGuardianDashboard {
    constructor() {
        this.currentView = 'overview';
        this.network = null;
        this.riskChart = null;
        this.coverageChart = null;
        this.coverageDetailsChart = null;

        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupWebSocket();
        this.loadInitialData();
        this.setupCharts();
        this.loadProjects(); // Load projects on initial load
        this.setupGraph();
    }

    setupNavigation() {
        const navBtns = document.querySelectorAll('.nav-btn');
        navBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const view = e.target.dataset.view;
                this.switchView(view);
            });
        });

        // Setup issues tabs
        const tabBtns = document.querySelectorAll('.tab-btn');
        tabBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tab = e.target.dataset.tab;
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
        this.ws = new WebSocket(`ws://localhost:8080/ws`);

        this.ws.onopen = () => {
            console.log('Connected to ArchGuardian WebSocket');
        };

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWebSocketMessage(data);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
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
                <button class="start-scan-btn" onclick="window.dashboard.startScan('${p.id}')" ${p.status === 'scanning' ? 'disabled' : ''}>
                    ${p.status === 'scanning' ? 'Scanning...' : 'Start Scan'}
                </button>
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
        this.showNotification(`Starting scan for project...`, 'info');
        await fetch(`http://localhost:3000/api/v1/projects/${projectId}/scan`, { method: 'POST' });
        // The UI will be updated via WebSocket events, but we can also force a refresh
        setTimeout(() => this.loadProjects(), 1000);
    }

    async loadKnowledgeGraph() {
        try {
            const response = await fetch('http://localhost:7080/api/v1/knowledge-graph');
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
            const response = await fetch('http://localhost:7080/api/v1/risk-assessment');
            const data = await response.json();

            this.updateOverviewData(data);
        } catch (error) {
            console.error('Failed to load risk assessment:', error);
        }
    }

    async loadCoverageData() {
        try {
            const response = await fetch('http://localhost:7080/api/v1/coverage');
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
                shape: node.type === 'process' ? 'square' : 'circle'
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

    refreshGraph() {
        this.loadKnowledgeGraph();
    }

    async loadIssuesData(type) {
        try {
            const response = await fetch(`http://localhost:7080/api/v1/issues?type=${type}`);
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
        fetch('http://localhost:7080/api/v1/settings', {
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
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }

    .low-risk { color: #10b981 !important; }
    .medium-risk { color: #f59e0b !important; }
    .high-risk { color: #ef4444 !important; }

    .severity-critical { background: #fee2e2; color: #991b1b; }
    .severity-high { background: #fef3c7; color: #92400e; }
    .severity-medium { background: #dbeafe; color: #1e40af; }
    .severity-low { background: #dcfce7; color: #166534; }

    .safety-safe { background: #dcfce7; color: #166534; }
    .safety-risky { background: #fef3c7; color: #92400e; }

    .status-active { background: #dcfce7; color: #166534; }
    .status-deprecated { background: #fef3c7; color: #92400e; }
    .status-abandoned { background: #fee2e2; color: #991b1b; }

    .no-issues {
        text-align: center;
        color: #10b981;
        font-size: 1.125rem;
        padding: 2rem;
    }

    .error {
        text-align: center;
        color: #ef4444;
        font-size: 1.125rem;
        padding: 2rem;
    }

    .projects-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 1.5rem;
    }

    .project-card, .add-project-card {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 0.5rem;
        padding: 1.5rem;
    }

    .project-path {
        font-size: 0.8rem;
        color: #6b7280;
        word-break: break-all;
        margin-bottom: 1rem;
    }

    .project-status .status-idle { color: #6b7280; }
    .project-status .status-scanning { color: #2563eb; }

    .start-scan-btn {
        width: 100%;
        margin-top: 1rem;
    }

    .issue-item {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 1rem;
    }

    .issue-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.5rem;
    }

    .issue-id, .issue-package {
        font-weight: 600;
        color: #2563eb;
    }

    .issue-severity, .issue-safety, .issue-maintenance {
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        font-weight: 500;
        text-transform: uppercase;
    }

    .issue-description {
        margin-bottom: 0.5rem;
        color: #4b5563;
    }

    .issue-location, .issue-package, .issue-cvss, .issue-effort,
    .issue-references, .issue-versions, .issue-issues {
        font-size: 0.875rem;
        color: #6b7280;
        margin-bottom: 0.25rem;
    }
`;

document.head.appendChild(style);
