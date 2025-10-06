#!/usr/bin/env python3
"""
ArchGuardian Log Ingestion Client

A Python client for sending logs to ArchGuardian's log ingestion API.

Usage:
    python log_ingestion_client.py --help

Examples:
    # Send a single log
    python log_ingestion_client.py --single --level ERROR --message "Database connection failed" --service user-api --component database

    # Send batch logs from file
    python log_ingestion_client.py --batch --file logs.json

    # Health check
    python log_ingestion_client.py --health

    # Monitor file and send logs
    python log_ingestion_client.py --tail /var/log/app.log --service my-app
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ArchGuardianClient:
    """Client for ArchGuardian Log Ingestion API."""

    def __init__(self, base_url: str = "http://localhost:3000/api/v1", timeout: int = 10):
        """
        Initialize the client.

        Args:
            base_url: Base URL of the ArchGuardian API
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout

        # Configure session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def send_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a single log message.

        Args:
            log_data: Log message data

        Returns:
            API response

        Raises:
            requests.RequestException: If the request fails
        """
        url = f"{self.base_url}/logs"

        # Ensure timestamp is set
        if 'timestamp' not in log_data:
            log_data['timestamp'] = datetime.utcnow().isoformat() + 'Z'

        self.logger.debug(f"Sending log to {url}: {log_data}")

        response = self.session.post(
            url,
            json=log_data,
            timeout=self.timeout,
            headers={'Content-Type': 'application/json'}
        )

        response.raise_for_status()
        return response.json()

    def send_batch_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Send multiple log messages in batch.

        Args:
            logs: List of log message data

        Returns:
            API response

        Raises:
            requests.RequestException: If the request fails
        """
        url = f"{self.base_url}/logs/batch"

        # Ensure timestamps are set
        for log in logs:
            if 'timestamp' not in log:
                log['timestamp'] = datetime.utcnow().isoformat() + 'Z'

        payload = {"logs": logs}

        self.logger.debug(f"Sending batch of {len(logs)} logs to {url}")

        response = self.session.post(
            url,
            json=payload,
            timeout=self.timeout,
            headers={'Content-Type': 'application/json'}
        )

        response.raise_for_status()
        return response.json()

    def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check on the log ingestion service.

        Returns:
            Health check response

        Raises:
            requests.RequestException: If the request fails
        """
        url = f"{self.base_url}/logs/health"

        response = self.session.get(url, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def tail_file(self, file_path: Path, service: str, component: str = "app",
                  level: str = "INFO", follow: bool = True) -> None:
        """
        Tail a log file and send logs to ArchGuardian.

        Args:
            file_path: Path to the log file
            service: Service name
            component: Component name
            level: Default log level
            follow: Whether to follow the file for new lines
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        self.logger.info(f"Tailing log file: {file_path}")

        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            if not follow:
                # Read entire file
                lines = f.readlines()
                logs = []
                for line in lines:
                    line = line.strip()
                    if line:
                        logs.append({
                            'level': level,
                            'message': line,
                            'service': service,
                            'component': component,
                        })

                if logs:
                    try:
                        result = self.send_batch_logs(logs)
                        self.logger.info(f"Sent {result['processed']}/{result['total']} logs from file")
                    except Exception as e:
                        self.logger.error(f"Failed to send logs from file: {e}")
                return

            # Follow mode - read new lines as they come
            f.seek(0, 2)  # Go to end of file

            try:
                while True:
                    line = f.readline()
                    if line:
                        line = line.strip()
                        if line:
                            try:
                                self.send_log({
                                    'level': level,
                                    'message': line,
                                    'service': service,
                                    'component': component,
                                })
                                self.logger.debug(f"Sent log: {line[:100]}...")
                            except Exception as e:
                                self.logger.error(f"Failed to send log line: {e}")
                    else:
                        time.sleep(0.1)  # Small delay to avoid busy waiting
            except KeyboardInterrupt:
                self.logger.info("Stopped tailing log file")


def create_error_log(service: str, component: str, message: str,
                    error_type: str, error_code: str = None,
                    stack_trace: str = None, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Create a structured error log message.

    Args:
        service: Service name
        component: Component name
        message: Error message
        error_type: Type of error
        error_code: Error code (optional)
        stack_trace: Stack trace (optional)
        metadata: Additional metadata (optional)

    Returns:
        Structured log message
    """
    log_data = {
        'level': 'ERROR',
        'message': message,
        'service': service,
        'component': component,
        'error': {
            'type': error_type,
        }
    }

    if error_code:
        log_data['error']['code'] = error_code
    if stack_trace:
        log_data['error']['stack'] = stack_trace
    if metadata:
        log_data['metadata'] = metadata

    return log_data


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ArchGuardian Log Ingestion Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('--url', default='http://localhost:3000/api/v1',
                       help='ArchGuardian API base URL')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Single log command
    single_parser = subparsers.add_parser('single', help='Send a single log message')
    single_parser.add_argument('--level', default='INFO',
                              choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'],
                              help='Log level')
    single_parser.add_argument('--message', '-m', required=True,
                              help='Log message')
    single_parser.add_argument('--service', '-s', required=True,
                              help='Service name')
    single_parser.add_argument('--component', '-c', default='app',
                              help='Component name')
    single_parser.add_argument('--trace-id', help='Trace ID')
    single_parser.add_argument('--span-id', help='Span ID')
    single_parser.add_argument('--metadata', help='JSON metadata string')

    # Batch log command
    batch_parser = subparsers.add_parser('batch', help='Send batch logs from file')
    batch_parser.add_argument('--file', '-f', required=True, type=Path,
                             help='JSON file containing logs array')

    # Tail command
    tail_parser = subparsers.add_parser('tail', help='Tail a log file and send logs')
    tail_parser.add_argument('--file', '-f', required=True, type=Path,
                            help='Log file to tail')
    tail_parser.add_argument('--service', '-s', required=True,
                            help='Service name')
    tail_parser.add_argument('--component', '-c', default='app',
                            help='Component name')
    tail_parser.add_argument('--level', default='INFO',
                            choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'],
                            help='Default log level')
    tail_parser.add_argument('--no-follow', action='store_true',
                            help='Read entire file once instead of following')

    # Health check command
    subparsers.add_parser('health', help='Check service health')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create client
    client = ArchGuardianClient(args.url)

    try:
        if args.command == 'single':
            # Parse metadata if provided
            metadata = None
            if args.metadata:
                try:
                    metadata = json.loads(args.metadata)
                except json.JSONDecodeError as e:
                    print(f"Error parsing metadata JSON: {e}", file=sys.stderr)
                    return 1

            log_data = {
                'level': args.level,
                'message': args.message,
                'service': args.service,
                'component': args.component,
            }

            if args.trace_id:
                log_data['trace_id'] = args.trace_id
            if args.span_id:
                log_data['span_id'] = args.span_id
            if metadata:
                log_data['metadata'] = metadata

            result = client.send_log(log_data)
            print(f"✅ Log sent successfully: {result}")

        elif args.command == 'batch':
            # Load logs from file
            with open(args.file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if 'logs' not in data:
                print("Error: JSON file must contain a 'logs' array", file=sys.stderr)
                return 1

            logs = data['logs']
            result = client.send_batch_logs(logs)
            print(f"✅ Batch sent: {result['processed']}/{result['total']} logs processed")

        elif args.command == 'tail':
            follow = not args.no_follow
            client.tail_file(args.file, args.service, args.component, args.level, follow)

        elif args.command == 'health':
            result = client.health_check()
            print(f"✅ Service health: {result}")

    except KeyboardInterrupt:
        print("\n👋 Interrupted by user")
        return 0
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
