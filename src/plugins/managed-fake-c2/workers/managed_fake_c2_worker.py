"""
managed_fake_c2_worker.py — Fake C2 server worker.

Spins up a configurable HTTP/HTTPS server that responds to predefined
endpoints, optionally executes a .NET sample, and captures all inbound
requests for analysis.

Action: start_fake_c2
"""

import json
import sys
import os
import ssl
import hashlib
import threading
import time
import subprocess
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Globals for request capture
# ---------------------------------------------------------------------------
_captured_requests: List[Dict[str, Any]] = []
_capture_lock = threading.Lock()
_endpoint_config: Dict[str, Dict[str, Any]] = {}
_default_response: str = '{"status":"ok"}'
_capture_enabled: bool = True


# ---------------------------------------------------------------------------
# Fake C2 HTTP handler
# ---------------------------------------------------------------------------

class FakeC2Handler(BaseHTTPRequestHandler):
    """HTTP request handler that records all requests and serves configured responses."""

    def log_message(self, fmt, *args):
        """Suppress default stderr logging."""
        pass

    def _handle_request(self, method: str):
        # Read body if present
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        # Capture the request
        if _capture_enabled:
            entry = {
                'timestamp': time.time(),
                'method': method,
                'path': self.path,
                'headers': dict(self.headers),
                'body_size': len(body),
                'body_preview': body[:1024].decode('utf-8', errors='replace') if body else None,
                'body_sha256': hashlib.sha256(body).hexdigest() if body else None,
                'client_address': f'{self.client_address[0]}:{self.client_address[1]}',
            }
            with _capture_lock:
                _captured_requests.append(entry)

        # Find matching endpoint
        endpoint = None
        for path_pattern, cfg in _endpoint_config.items():
            if self.path == path_pattern or self.path.startswith(path_pattern + '/'):
                endpoint_method = cfg.get('method', 'ANY')
                if endpoint_method == 'ANY' or endpoint_method == method:
                    endpoint = cfg
                    break

        if endpoint:
            # Configured response
            delay_ms = endpoint.get('delay_ms', 0)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
            status = endpoint.get('status_code', 200)
            response_body = endpoint.get('response_body', _default_response)
            content_type = endpoint.get('content_type', 'application/json')
        else:
            # Default response
            status = 200
            response_body = _default_response
            content_type = 'application/json'

        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(response_body.encode('utf-8'))))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(response_body.encode('utf-8'))

    def do_GET(self):
        self._handle_request('GET')

    def do_POST(self):
        self._handle_request('POST')

    def do_PUT(self):
        self._handle_request('PUT')

    def do_DELETE(self):
        self._handle_request('DELETE')

    def do_HEAD(self):
        self._handle_request('HEAD')

    def do_OPTIONS(self):
        self._handle_request('OPTIONS')

    def do_PATCH(self):
        self._handle_request('PATCH')


# ---------------------------------------------------------------------------
# TLS certificate generation
# ---------------------------------------------------------------------------

def _generate_self_signed_cert(cert_path: str, key_path: str):
    """Generate a self-signed TLS certificate using openssl."""
    try:
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', key_path, '-out', cert_path,
            '-days', '1', '-nodes',
            '-subj', '/CN=localhost',
        ], capture_output=True, check=True, timeout=30)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        # If openssl is not available, try Python's ssl module as fallback
        # In Docker containers, openssl is usually available
        raise RuntimeError('openssl is required for TLS certificate generation')


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------

def handle_start_fake_c2(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle the start_fake_c2 action."""
    global _endpoint_config, _default_response, _capture_enabled, _captured_requests

    file_path = request.get('file_path', '')
    endpoints = request.get('endpoints', [])
    listen_port = request.get('listen_port', 8443)
    use_tls = request.get('use_tls', False)
    capture_requests = request.get('capture_requests', True)
    default_response = request.get('default_response', '{"status":"ok"}')
    timeout_seconds = min(request.get('timeout_seconds', 120), 300)
    auto_run_sample = request.get('auto_run_sample', False)
    dns_redirect = request.get('dns_redirect', [])

    if not os.path.isfile(file_path):
        return {'ok': False, 'error': f'File not found: {file_path}'}

    # Reset state
    _captured_requests = []
    _capture_enabled = capture_requests
    _default_response = default_response

    # Build endpoint config
    _endpoint_config = {}
    for ep in endpoints:
        path = ep.get('path', '/')
        _endpoint_config[path] = {
            'method': ep.get('method', 'ANY'),
            'status_code': ep.get('status_code', 200),
            'response_body': ep.get('response_body', default_response),
            'content_type': ep.get('content_type', 'application/json'),
            'delay_ms': ep.get('delay_ms', 0),
        }

    # Start HTTP(S) server
    server = HTTPServer(('127.0.0.1', listen_port), FakeC2Handler)

    if use_tls:
        # Create temporary cert
        tmp_dir = tempfile.mkdtemp(prefix='fake_c2_')
        cert_path = os.path.join(tmp_dir, 'cert.pem')
        key_path = os.path.join(tmp_dir, 'key.pem')
        try:
            _generate_self_signed_cert(cert_path, key_path)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
        except Exception as e:
            return {'ok': False, 'error': f'TLS setup failed: {e}'}

    # Write DNS redirect hosts entries (informational only)
    dns_info = []
    for domain in dns_redirect:
        dns_info.append({'domain': domain, 'target': '127.0.0.1', 'note': 'Add to /etc/hosts manually or via iptables'})

    # Run server in background thread
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    sample_result = None
    try:
        if auto_run_sample:
            # Try to run the sample (mono or dotnet)
            try:
                proc = subprocess.run(
                    ['dotnet', file_path],
                    capture_output=True,
                    timeout=timeout_seconds,
                    cwd=os.path.dirname(file_path),
                    env={**os.environ, 'DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER': '0'},
                )
                sample_result = {
                    'exit_code': proc.returncode,
                    'stdout_preview': proc.stdout[:2048].decode('utf-8', errors='replace'),
                    'stderr_preview': proc.stderr[:2048].decode('utf-8', errors='replace'),
                }
            except subprocess.TimeoutExpired:
                sample_result = {'exit_code': -1, 'error': 'Sample execution timed out'}
            except FileNotFoundError:
                # Try mono
                try:
                    proc = subprocess.run(
                        ['mono', file_path],
                        capture_output=True,
                        timeout=timeout_seconds,
                        cwd=os.path.dirname(file_path),
                    )
                    sample_result = {
                        'exit_code': proc.returncode,
                        'stdout_preview': proc.stdout[:2048].decode('utf-8', errors='replace'),
                        'stderr_preview': proc.stderr[:2048].decode('utf-8', errors='replace'),
                    }
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    sample_result = {'exit_code': -1, 'error': f'Could not run sample: {e}'}
        else:
            # Wait for timeout to collect requests
            time.sleep(min(timeout_seconds, 5))

    finally:
        server.shutdown()

    # Collect results
    with _capture_lock:
        captured = list(_captured_requests)

    protocol = 'https' if use_tls else 'http'
    return {
        'ok': True,
        'data': {
            'listen_address': f'{protocol}://127.0.0.1:{listen_port}',
            'endpoints_configured': len(_endpoint_config),
            'tls_enabled': use_tls,
            'dns_redirect': dns_info,
            'total_requests_captured': len(captured),
            'requests': captured,
            'sample_execution': sample_result,
            'timeout_seconds': timeout_seconds,
        },
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

ACTIONS = {
    'start_fake_c2': handle_start_fake_c2,
}


def main():
    raw = sys.stdin.readline()
    if not raw.strip():
        json.dump({'ok': False, 'error': 'Empty input'}, sys.stdout)
        sys.stdout.flush()
        sys.exit(1)

    try:
        request = json.loads(raw)
    except json.JSONDecodeError as e:
        json.dump({'ok': False, 'error': f'Invalid JSON: {e}'}, sys.stdout)
        sys.stdout.flush()
        sys.exit(1)

    action = request.get('action', '')
    handler = ACTIONS.get(action)
    if not handler:
        json.dump({'ok': False, 'error': f'Unknown action: {action}'}, sys.stdout)
        sys.stdout.flush()
        sys.exit(1)

    try:
        result = handler(request)
    except Exception as e:
        result = {'ok': False, 'error': f'{action} failed: {e}'}

    json.dump(result, sys.stdout)
    sys.stdout.flush()


if __name__ == '__main__':
    main()
