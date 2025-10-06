#!/usr/bin/env node
/**
 * ArchGuardian Log Ingestion Client
 *
 * A Node.js client for sending logs to ArchGuardian's log ingestion API.
 *
 * Usage:
 *   node log_ingestion_client.js --help
 *
 * Examples:
 *   # Send a single log
 *   node log_ingestion_client.js single --level ERROR --message "Database connection failed" --service user-api --component database
 *
 *   # Send batch logs from file
 *   node log_ingestion_client.js batch --file logs.json
 *
 *   # Health check
 *   node log_ingestion_client.js health
 *
 *   # Monitor file and send logs
 *   node log_ingestion_client.js tail --file /var/log/app.log --service my-app
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

class ArchGuardianClient {
    /**
     * Client for ArchGuardian Log Ingestion API.
     * @param {string} baseUrl - Base URL of the ArchGuardian API
     * @param {number} timeout - Request timeout in milliseconds
     */
    constructor(baseUrl = 'http://localhost:3000/api/v1', timeout = 10000) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.timeout = timeout;
    }

    /**
     * Send a single log message.
     * @param {Object} logData - Log message data
     * @returns {Promise<Object>} API response
     */
    async sendLog(logData) {
        const url = `${this.baseUrl}/logs`;

        // Ensure timestamp is set
        if (!logData.timestamp) {
            logData.timestamp = new Date().toISOString();
        }

        console.debug(`Sending log to ${url}:`, logData);

        const response = await this._makeRequest('POST', url, logData);
        return response;
    }

    /**
     * Send multiple log messages in batch.
     * @param {Array<Object>} logs - List of log message data
     * @returns {Promise<Object>} API response
     */
    async sendBatchLogs(logs) {
        const url = `${this.baseUrl}/logs/batch`;

        // Ensure timestamps are set
        logs.forEach(log => {
            if (!log.timestamp) {
                log.timestamp = new Date().toISOString();
            }
        });

        const payload = { logs };

        console.debug(`Sending batch of ${logs.length} logs to ${url}`);

        const response = await this._makeRequest('POST', url, payload);
        return response;
    }

    /**
     * Perform a health check on the log ingestion service.
     * @returns {Promise<Object>} Health check response
     */
    async healthCheck() {
        const url = `${this.baseUrl}/logs/health`;
        const response = await this._makeRequest('GET', url);
        return response;
    }

    /**
     * Tail a log file and send logs to ArchGuardian.
     * @param {string} filePath - Path to the log file
     * @param {string} service - Service name
     * @param {string} component - Component name
     * @param {string} level - Default log level
     * @param {boolean} follow - Whether to follow the file for new lines
     */
    async tailFile(filePath, service, component = 'app', level = 'INFO', follow = true) {
        if (!fs.existsSync(filePath)) {
            throw new Error(`Log file not found: ${filePath}`);
        }

        console.log(`Tailing log file: ${filePath}`);

        const watcher = fs.watch(filePath, { persistent: follow });

        // Read existing content first
        const existingContent = fs.readFileSync(filePath, 'utf8');
        const lines = existingContent.split('\n').filter(line => line.trim());

        if (lines.length > 0 && !follow) {
            // Send existing content in batch
            const logs = lines.map(line => ({
                level,
                message: line,
                service,
                component,
            }));

            try {
                const result = await this.sendBatchLogs(logs);
                console.log(`Sent ${result.processed}/${result.total} logs from file`);
            } catch (error) {
                console.error(`Failed to send logs from file: ${error.message}`);
            }
            return;
        }

        if (!follow) {
            return;
        }

        // Follow mode - watch for new lines
        let lastSize = fs.statSync(filePath).size;

        watcher.on('change', async (eventType) => {
            if (eventType === 'change') {
                try {
                    const stats = fs.statSync(filePath);
                    if (stats.size > lastSize) {
                        // File has grown, read new content
                        const stream = fs.createReadStream(filePath, {
                            start: lastSize,
                            encoding: 'utf8'
                        });

                        let newContent = '';
                        stream.on('data', chunk => {
                            newContent += chunk;
                        });

                        stream.on('end', async () => {
                            const newLines = newContent.split('\n').filter(line => line.trim());
                            lastSize = stats.size;

                            for (const line of newLines) {
                                try {
                                    await this.sendLog({
                                        level,
                                        message: line,
                                        service,
                                        component,
                                    });
                                    console.debug(`Sent log: ${line.substring(0, 100)}...`);
                                } catch (error) {
                                    console.error(`Failed to send log line: ${error.message}`);
                                }
                            }
                        });
                    }
                } catch (error) {
                    console.error(`Error reading file: ${error.message}`);
                }
            }
        });

        watcher.on('error', error => {
            console.error(`File watcher error: ${error.message}`);
        });

        console.log('File watcher started. Press Ctrl+C to stop.');

        // Keep the process alive
        process.on('SIGINT', () => {
            console.log('\nStopping file watcher...');
            watcher.close();
            process.exit(0);
        });
    }

    /**
     * Make an HTTP request.
     * @private
     * @param {string} method - HTTP method
     * @param {string} url - Request URL
     * @param {Object} data - Request data (for POST)
     * @returns {Promise<Object>} Response data
     */
    _makeRequest(method, url, data = null) {
        return new Promise((resolve, reject) => {
            const urlObj = new URL(url);
            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port,
                path: urlObj.pathname + urlObj.search,
                method,
                headers: {
                    'Content-Type': 'application/json',
                },
                timeout: this.timeout,
            };

            const req = (urlObj.protocol === 'https:' ? https : http).request(options, (res) => {
                let body = '';

                res.on('data', chunk => {
                    body += chunk;
                });

                res.on('end', () => {
                    try {
                        if (res.statusCode >= 200 && res.statusCode < 300) {
                            const responseData = body ? JSON.parse(body) : {};
                            resolve(responseData);
                        } else {
                            const error = new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`);
                            error.statusCode = res.statusCode;
                            error.responseBody = body;
                            reject(error);
                        }
                    } catch (error) {
                        reject(new Error(`Failed to parse response: ${error.message}`));
                    }
                });
            });

            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            if (data && (method === 'POST' || method === 'PUT')) {
                const jsonData = JSON.stringify(data);
                req.write(jsonData);
            }

            req.end();
        });
    }
}

/**
 * Create a structured error log message.
 * @param {string} service - Service name
 * @param {string} component - Component name
 * @param {string} message - Error message
 * @param {string} errorType - Type of error
 * @param {string} errorCode - Error code (optional)
 * @param {string} stackTrace - Stack trace (optional)
 * @param {Object} metadata - Additional metadata (optional)
 * @returns {Object} Structured log message
 */
function createErrorLog(service, component, message, errorType, errorCode = null, stackTrace = null, metadata = null) {
    const logData = {
        level: 'ERROR',
        message,
        service,
        component,
        error: {
            type: errorType,
        }
    };

    if (errorCode) {
        logData.error.code = errorCode;
    }
    if (stackTrace) {
        logData.error.stack = stackTrace;
    }
    if (metadata) {
        logData.metadata = metadata;
    }

    return logData;
}

/**
 * Parse command line arguments.
 */
function parseArgs() {
    const args = process.argv.slice(2);
    const parsed = {
        command: null,
        options: {}
    };

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];

        if (arg.startsWith('--')) {
            const key = arg.slice(2);
            const value = args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true;
            parsed.options[key] = value;
            if (value !== true) i++;
        } else if (!parsed.command) {
            parsed.command = arg;
        }
    }

    return parsed;
}

/**
 * Main CLI entry point.
 */
async function main() {
    const { command, options } = parseArgs();

    if (!command || options.help) {
        printHelp();
        return 0;
    }

    const client = new ArchGuardianClient(options.url);

    try {
        switch (command) {
            case 'single':
                if (!options.message || !options.service) {
                    console.error('Error: --message and --service are required for single command');
                    return 1;
                }

                const logData = {
                    level: options.level || 'INFO',
                    message: options.message,
                    service: options.service,
                    component: options.component || 'app',
                };

                if (options.traceId) logData.trace_id = options.traceId;
                if (options.spanId) logData.span_id = options.spanId;
                if (options.metadata) {
                    try {
                        logData.metadata = JSON.parse(options.metadata);
                    } catch (e) {
                        console.error(`Error parsing metadata JSON: ${e.message}`);
                        return 1;
                    }
                }

                const result = await client.sendLog(logData);
                console.log('✅ Log sent successfully:', result);
                break;

            case 'batch':
                if (!options.file) {
                    console.error('Error: --file is required for batch command');
                    return 1;
                }

                const fileContent = fs.readFileSync(options.file, 'utf8');
                const data = JSON.parse(fileContent);

                if (!data.logs || !Array.isArray(data.logs)) {
                    console.error('Error: JSON file must contain a "logs" array');
                    return 1;
                }

                const batchResult = await client.sendBatchLogs(data.logs);
                console.log(`✅ Batch sent: ${batchResult.processed}/${batchResult.total} logs processed`);
                break;

            case 'tail':
                if (!options.file || !options.service) {
                    console.error('Error: --file and --service are required for tail command');
                    return 1;
                }

                const follow = !options.noFollow;
                await client.tailFile(
                    options.file,
                    options.service,
                    options.component || 'app',
                    options.level || 'INFO',
                    follow
                );
                break;

            case 'health':
                const healthResult = await client.healthCheck();
                console.log('✅ Service health:', healthResult);
                break;

            default:
                console.error(`Unknown command: ${command}`);
                printHelp();
                return 1;
        }
    } catch (error) {
        console.error(`❌ Error: ${error.message}`);
        return 1;
    }

    return 0;
}

/**
 * Print help information.
 */
function printHelp() {
    console.log(`
ArchGuardian Log Ingestion Client

Usage:
  node log_ingestion_client.js <command> [options]

Commands:
  single    Send a single log message
  batch     Send batch logs from file
  tail      Tail a log file and send logs
  health    Check service health

Options:
  --url <url>           ArchGuardian API base URL (default: http://localhost:3000/api/v1)
  --help                Show this help message

Single command options:
  --level <level>       Log level (DEBUG, INFO, WARN, ERROR, FATAL)
  --message <message>   Log message (required)
  --service <service>   Service name (required)
  --component <comp>    Component name (default: app)
  --traceId <id>        Trace ID
  --spanId <id>         Span ID
  --metadata <json>    JSON metadata string

Batch command options:
  --file <file>         JSON file containing logs array (required)

Tail command options:
  --file <file>         Log file to tail (required)
  --service <service>   Service name (required)
  --component <comp>    Component name (default: app)
  --level <level>       Default log level (default: INFO)
  --noFollow           Read entire file once instead of following

Examples:
  # Send a single log
  node log_ingestion_client.js single --level ERROR --message "Database connection failed" --service user-api --component database

  # Send batch logs from file
  node log_ingestion_client.js batch --file logs.json

  # Health check
  node log_ingestion_client.js health

  # Monitor file and send logs
  node log_ingestion_client.js tail --file /var/log/app.log --service my-app
`);
}

// Run the CLI if this file is executed directly
if (require.main === module) {
    main().then(code => {
        process.exit(code);
    }).catch(error => {
        console.error('Unexpected error:', error);
        process.exit(1);
    });
}

module.exports = {
    ArchGuardianClient,
    createErrorLog,
};
