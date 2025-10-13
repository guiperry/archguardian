# Welcome to the ArchGuardian Wiki!

ArchGuardian is an AI-powered code guardian designed to provide deep visibility into your software architecture, proactively detect risks, and automatically remediate issues. It acts as a continuous, autonomous security and quality engineer for your codebase.

## What is ArchGuardian?

At its core, ArchGuardian is a sophisticated Go application that performs a multi-faceted analysis of a software project. It combines:

*   **Deep System Scanning**: It analyzes everything from static source code and dependencies to the live runtime environment.
*   **Knowledge Graph Construction**: It builds a comprehensive model of your system, understanding the relationships between files, libraries, APIs, and runtime processes.
*   **AI-Powered Inference**: It uses a multi-model AI engine to diagnose complex risks, including technical debt, security vulnerabilities, and dangerous dependencies.
*   **Automated Remediation**: It can automatically generate and apply fixes for identified issues, creating new branches with proposed changes.
*   **Real-time Monitoring & Dashboard**: It provides a web-based dashboard for real-time log streaming, system metrics, and visualization of your project's architecture and health.

## Core Features

### 1. Comprehensive Scanning Engine
The scanner is the heart of ArchGuardian. It performs a multi-phase scan to build a complete picture of your project:
- **Static Code Analysis**: Parses source files (Go, JavaScript, Python, etc.) using ASTs and regex to understand code structure.
- **Dependency Scanning**: Analyzes `go.mod`, `package.json`, and `requirements.txt` to identify third-party libraries.
- **Runtime Inspection**: Uses `gopsutil` to inspect running processes, network connections, and system resource usage.
- **Test Coverage Analysis**: Executes test suites for Go, Node.js, and Python projects to measure code coverage.
- **API & Database Discovery**: Identifies API endpoints and database models within the codebase.

### 2. AI-Driven Risk Diagnosis
ArchGuardian doesn't just find simple anti-patterns. It uses a powerful, multi-provider AI Inference Engine (supporting models from Gemini, Anthropic, Cerebras, and more) to:
- **Infer Relationships**: Understands how different parts of your system connect to each other.
- **Analyze Risks**: Identifies subtle and complex issues related to security, technical debt, and code quality.
- **Generate Remediation Plans**: Uses an AI orchestrator to plan, execute, and verify code fixes.

### 3. Automated Remediation
When risks are identified, the Remediator can take action:
- **Creates a Git Branch**: Isolates all automated changes in a new branch (e.g., `archguardian-fixes-YYYYMMDD-HHMMSS`).
- **Applies Fixes**: Can update dependencies, apply AI-generated code patches, or even remove obsolete files.
- **Commits and Pushes**: Commits the changes with a detailed message and pushes the branch to the remote repository, ready for your review.

### 4. Authentication & Security
The API and dashboard are secured with a robust authentication system:
- **GitHub OAuth2**: Allows users to log in securely with their GitHub accounts.
- **JWT & Session Management**: Protects API endpoints using JSON Web Tokens and secure session cookies.
- **Security Middleware**: Includes rate limiting, security headers (CSP, HSTS), and CORS policies to protect the server.

### 5. Configuration Management
ArchGuardian is highly configurable:
- **Environment-based Settings**: Supports different configurations for `development`, `production`, and `testing` environments.
- **Hot Reloading**: Settings can be updated via the API and applied on-the-fly without a server restart for many parameters.
- **Secrets Management**: Encrypts and securely stores sensitive information like API keys.

## Getting Started

1.  **Configuration**:
    - Start by creating a `.env` file in the root of the project.
    - At a minimum, you will need to configure your `PROJECT_PATH` and at least one AI provider API key (e.g., `GEMINI_API_KEY`).
    - For auto-remediation, you'll also need a `GITHUB_TOKEN`.

2.  **Running the Application**:
    - Build and run the `main.go` file.
    ```bash
    go run main.go
    ```

3.  **Accessing the Dashboard**:
    - Open your browser and navigate to `http://localhost:3000`.
    - You will see the real-time log output and can log in via GitHub to access the full dashboard features.

4.  **Triggering a Scan**:
    - The application runs scans on a periodic schedule (configurable via `SCAN_INTERVAL_HOURS`).
    - You can also trigger a manual scan by sending a POST request to the `/api/v1/scan/start` endpoint after authenticating.

