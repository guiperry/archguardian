# ArchGuardian API Documentation

**Version:** 1.0.0  
**Base URL:** `http://localhost:3000`  
**OpenAPI Version:** 3.0.1

---

## Overview

The ArchGuardian API provides comprehensive endpoints for code scanning, security analysis, project management, and AI-powered remediation. All services are consolidated on **port 3000** for simplified deployment.

### Authentication

Most endpoints require JWT Bearer token authentication:

```
Authorization: Bearer <your-jwt-token>
```

### Response Format

All API responses follow a consistent JSON format:

```json
{
  "status": "ok|error",
  "message": "Human-readable message",
  "data": { /* Response data */ }
}
```

---

## Table of Contents

- [Health & Status](#health--status)
- [Project Management](#project-management)
- [Scanning & Analysis](#scanning--analysis)
- [Knowledge Graph](#knowledge-graph)
- [Issues & Coverage](#issues--coverage)
- [Settings](#settings)
- [Monitoring & Metrics](#monitoring--metrics)
- [Backup & Restore](#backup--restore)
- [Search](#search)

---

## Health & Status

### GET /health

Returns the health status of the ArchGuardian service.

**Authentication:** None required

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

---

## Project Management

### GET /api/v1/projects

Returns a list of all configured projects.

**Authentication:** Optional

**Response:**
```json
[
  {
    "id": "proj-123",
    "name": "My Project",
    "path": "/path/to/project",
    "status": "idle|scanning|error",
    "lastScan": "2024-01-15T10:30:00Z",
    "issueCount": 42,
    "createdAt": "2024-01-01T00:00:00Z"
  }
]
```

**Status Values:**
- `idle` - Project is not currently being scanned
- `scanning` - Scan is in progress
- `error` - Last scan encountered an error

---

### POST /api/v1/projects

Creates a new project for monitoring.

**Authentication:** Required

**Request Body:**
```json
{
  "name": "Project Name",
  "path": "/absolute/path/to/project"
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "Project created successfully",
  "data": {
    "id": "proj-123",
    "name": "Project Name",
    "path": "/absolute/path/to/project",
    "createdAt": "2024-01-15T10:30:00Z"
  }
}
```

**Status Codes:**
- `201` - Project created successfully
- `400` - Invalid request data
- `409` - Project already exists

---

### GET /api/v1/projects/{id}

Returns details for a specific project.

**Authentication:** Optional

**Parameters:**
- `id` (path, required) - Project ID

**Response:**
```json
{
  "id": "proj-123",
  "name": "My Project",
  "path": "/path/to/project",
  "status": "idle",
  "lastScan": "2024-01-15T10:30:00Z",
  "issueCount": 42,
  "createdAt": "2024-01-01T00:00:00Z",
  "metadata": {
    "language": "go",
    "framework": "gin",
    "totalFiles": 150,
    "linesOfCode": 12500
  }
}
```

**Status Codes:**
- `200` - Success
- `404` - Project not found

---

### DELETE /api/v1/projects/{id}

Deletes a project from monitoring.

**Authentication:** Required

**Parameters:**
- `id` (path, required) - Project ID

**Response:**
```json
{
  "status": "ok",
  "message": "Project deleted successfully"
}
```

**Status Codes:**
- `200` - Project deleted successfully
- `404` - Project not found

---

### POST /api/v1/projects/{id}/scan

Triggers a scan for a specific project.

**Authentication:** Required

**Parameters:**
- `id` (path, required) - Project ID

**Response:**
```json
{
  "status": "ok",
  "message": "Scan started successfully",
  "data": {
    "scanId": "scan-456",
    "projectId": "proj-123",
    "startedAt": "2024-01-15T10:30:00Z"
  }
}
```

**Status Codes:**
- `200` - Scan started successfully
- `404` - Project not found
- `503` - Scan already in progress

---

## Scanning & Analysis

### POST /api/v1/scan/start

Triggers a new comprehensive security and code quality scan.

**Authentication:** Required

**Request Body (Optional):**
```json
{
  "projectPath": "/path/to/project",
  "options": {
    "includeTests": true,
    "deepScan": false,
    "skipDependencies": false
  }
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "Scan triggered successfully",
  "data": {
    "scanId": "scan-456",
    "estimatedDuration": "2-5 minutes"
  }
}
```

**Status Codes:**
- `200` - Scan started successfully
- `503` - Scan already in progress

---

## Knowledge Graph

### GET /api/v1/knowledge-graph

Returns the current knowledge graph data showing code relationships and dependencies.

**Authentication:** Required

**Query Parameters:**
- `projectId` (optional) - Filter by project ID
- `depth` (optional, default: 3) - Maximum relationship depth
- `nodeType` (optional) - Filter by node type (file, function, class, etc.)

**Response:**
```json
{
  "nodes": [
    {
      "id": "node-1",
      "label": "main.go",
      "type": "file",
      "group": "source",
      "metadata": {
        "path": "/path/to/main.go",
        "linesOfCode": 250,
        "complexity": 15
      }
    }
  ],
  "edges": [
    {
      "from": "node-1",
      "to": "node-2",
      "label": "imports",
      "arrows": "to",
      "strength": 0.8
    }
  ],
  "metadata": {
    "totalNodes": 150,
    "totalEdges": 320,
    "generatedAt": "2024-01-15T10:30:00Z"
  }
}
```

**Node Types:**
- `file` - Source code file
- `function` - Function or method
- `class` - Class or struct
- `package` - Package or module
- `database` - Database table or model
- `api` - API endpoint

---

## Issues & Coverage

### GET /api/v1/issues

Returns security issues, technical debt, and other code quality problems.

**Authentication:** Required

**Query Parameters:**
- `type` (optional) - Filter by issue type
  - `technical-debt` - Code quality issues
  - `security` - Security vulnerabilities
  - `obsolete` - Deprecated or unused code
  - `dependencies` - Dependency risks
- `severity` (optional) - Filter by severity (critical, high, medium, low)
- `status` (optional) - Filter by status (open, resolved, ignored)
- `projectId` (optional) - Filter by project ID

**Response:**
```json
{
  "issues": [
    {
      "id": "issue-789",
      "type": "security",
      "severity": "high",
      "title": "SQL Injection Vulnerability",
      "description": "Unsanitized user input in SQL query",
      "location": {
        "file": "/path/to/file.go",
        "line": 42,
        "column": 15
      },
      "detectedAt": "2024-01-15T10:30:00Z",
      "status": "open",
      "codeSnippet": "db.Query(\"SELECT * FROM users WHERE id = \" + userId)"
    }
  ],
  "summary": {
    "total": 42,
    "critical": 2,
    "high": 8,
    "medium": 20,
    "low": 12
  }
}
```

**Issue Types:**
- `technical-debt` - Code smells, complexity, duplication
- `security` - SQL injection, XSS, insecure crypto, etc.
- `obsolete` - Unused code, deprecated APIs
- `dependencies` - Outdated or vulnerable dependencies

---

### GET /api/v1/coverage

Returns test coverage metrics for the scanned codebase.

**Authentication:** Required

**Query Parameters:**
- `projectId` (optional) - Filter by project ID

**Response:**
```json
{
  "overall_coverage": 78.5,
  "lines_covered": 9420,
  "total_lines": 12000,
  "test_files": 45,
  "language": "go",
  "by_package": [
    {
      "package": "internal/scanner",
      "coverage": 85.2,
      "lines_covered": 1200,
      "total_lines": 1408
    }
  ],
  "uncovered_files": [
    {
      "file": "/path/to/file.go",
      "coverage": 0,
      "reason": "No tests found"
    }
  ],
  "generatedAt": "2024-01-15T10:30:00Z"
}
```

---

## Settings

### GET /api/v1/settings

Returns current ArchGuardian configuration settings.

**Authentication:** Required

**Response:**
```json
{
  "ai": {
    "provider": "gemini",
    "model": "gemini-2.5-flash",
    "enabled": true
  },
  "scanning": {
    "autoScan": false,
    "scanInterval": "24h",
    "includeTests": true,
    "maxFileSize": 1048576
  },
  "notifications": {
    "enabled": true,
    "channels": ["email", "webhook"]
  },
  "integrations": {
    "github": {
      "enabled": true,
      "autoCreateIssues": false
    }
  }
}
```

---

### POST /api/v1/settings

Updates ArchGuardian configuration settings.

**Authentication:** Required

**Request Body:**
```json
{
  "ai": {
    "provider": "gemini",
    "model": "gemini-2.5-flash"
  },
  "scanning": {
    "autoScan": true,
    "scanInterval": "12h"
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Settings updated successfully",
  "updatedFields": ["ai.provider", "scanning.autoScan"]
}
```

---

## Monitoring & Metrics

### GET /api/v1/integrations/status

Returns the health status of all external integrations.

**Authentication:** Optional

**Response:**
```json
{
  "github": {
    "connected": true,
    "status": "healthy",
    "message": "Connected to GitHub API",
    "lastCheck": "2024-01-15T10:30:00Z"
  },
  "kafka": {
    "connected": false,
    "status": "disconnected",
    "message": "Kafka integration disabled"
  },
  "chromadb": {
    "connected": false,
    "status": "disconnected",
    "message": "Using embedded Chromem-go"
  },
  "data_engine": {
    "connected": true,
    "status": "healthy",
    "message": "Data engine operational"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Status Values:**
- `healthy` - Integration is working correctly
- `error` - Integration encountered an error
- `disconnected` - Integration is not configured or disabled

---

### GET /api/v1/metrics

Returns real-time system performance metrics.

**Authentication:** Optional

**Response:**
```json
{
  "cpu": 45.2,
  "memory": 62.8,
  "disk": 35.5,
  "network": {
    "in": 1024000,
    "out": 512000
  },
  "processes": 156,
  "uptime": 86400,
  "goroutines": 42,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Metrics:**
- `cpu` - CPU usage percentage (0-100)
- `memory` - Memory usage percentage (0-100)
- `disk` - Disk usage percentage (0-100)
- `network.in` - Bytes received
- `network.out` - Bytes sent
- `processes` - Number of running processes
- `uptime` - System uptime in seconds
- `goroutines` - Number of active goroutines

---

## Backup & Restore

### POST /api/v1/backup

Creates a backup of the ArchGuardian database.

**Authentication:** Required

**Request Body (Optional):**
```json
{
  "encryption_key": "your-32-byte-encryption-key-here"
}
```

**Response:**
```json
{
  "success": true,
  "backup_path": "/path/to/backup/archguardian-backup-20240115-103000.db",
  "timestamp": "2024-01-15T10:30:00Z",
  "encrypted": true,
  "size_bytes": 10485760,
  "collections": [
    "projects",
    "knowledge-graphs",
    "security-issues",
    "test-coverage"
  ]
}
```

---

### GET /api/v1/backup

Returns a list of available database backups.

**Authentication:** Required

**Response:**
```json
{
  "backups": [
    {
      "filename": "archguardian-backup-20240115-103000.db",
      "path": "/path/to/backup/archguardian-backup-20240115-103000.db",
      "size": 10485760,
      "modified": "2024-01-15T10:30:00Z",
      "encrypted": true
    }
  ],
  "total": 5,
  "directory": "/path/to/backup"
}
```

---

## Search

### GET /api/v1/search

Performs natural language semantic search across stored data.

**Authentication:** Required

**Query Parameters:**
- `q` (required) - Search query
- `collection` (optional, default: "knowledge-graphs") - Collection to search
  - `knowledge-graphs` - Search architecture data
  - `security-issues` - Search security issues
  - `test-coverage` - Search coverage data
  - `projects` - Search projects
- `limit` (optional, default: 5, max: 20) - Maximum number of results

**Example Request:**
```
GET /api/v1/search?q=SQL+injection+vulnerabilities&collection=security-issues&limit=10
```

**Response:**
```json
{
  "query": "SQL injection vulnerabilities",
  "collection": "security-issues",
  "total": 3,
  "results": [
    {
      "id": "issue-789",
      "score": 0.95,
      "content": {
        "type": "security",
        "title": "SQL Injection Vulnerability",
        "file": "/path/to/file.go",
        "line": 42
      }
    }
  ],
  "executionTime": "45ms"
}
```

---

## WebSocket API

### WS /ws

Real-time event streaming via WebSocket.

**Authentication:** Optional (via query parameter `?token=<jwt-token>`)

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:3000/ws?token=your-jwt-token');
```

**Event Types:**

#### Scan Progress
```json
{
  "type": "scan_progress",
  "data": {
    "scanId": "scan-456",
    "progress": 45,
    "currentFile": "/path/to/file.go",
    "filesScanned": 45,
    "totalFiles": 100
  }
}
```

#### Scan Complete
```json
{
  "type": "scan_complete",
  "data": {
    "scanId": "scan-456",
    "duration": "2m 15s",
    "issuesFound": 42,
    "filesScanned": 100
  }
}
```

#### New Issue Detected
```json
{
  "type": "issue_detected",
  "data": {
    "issueId": "issue-789",
    "type": "security",
    "severity": "high",
    "title": "SQL Injection Vulnerability"
  }
}
```

#### System Metrics Update
```json
{
  "type": "metrics_update",
  "data": {
    "cpu": 45.2,
    "memory": 62.8,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

## Error Responses

All error responses follow this format:

```json
{
  "status": "error",
  "message": "Human-readable error message",
  "code": "ERROR_CODE",
  "details": {
    "field": "Additional error details"
  }
}
```

**Common Error Codes:**

| Code | Status | Description |
|------|--------|-------------|
| `INVALID_REQUEST` | 400 | Invalid request data |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `SCAN_IN_PROGRESS` | 503 | Scan already running |
| `INTERNAL_ERROR` | 500 | Internal server error |

---

## Rate Limiting

API endpoints are rate-limited to prevent abuse:

- **Anonymous requests:** 100 requests per hour
- **Authenticated requests:** 1000 requests per hour

Rate limit headers are included in all responses:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1705318200
```

---

## Versioning

The API uses URL-based versioning. The current version is `v1`.

Future versions will be available at:
- `/api/v2/...`
- `/api/v3/...`

Version 1 will be maintained for at least 12 months after a new version is released.

---

## Support

For API support and questions:
- **Email:** support@archguardian.dev
- **GitHub Issues:** https://github.com/guiperry/archguardian/issues
- **Documentation:** https://github.com/guiperry/archguardian/wiki

---

## Changelog

### Version 1.0.0 (2024-01-15)
- Initial API release
- Project management endpoints
- Scanning and analysis endpoints
- Knowledge graph API
- Issues and coverage endpoints
- Settings management
- Monitoring and metrics
- Backup and restore
- Semantic search
- WebSocket real-time updates