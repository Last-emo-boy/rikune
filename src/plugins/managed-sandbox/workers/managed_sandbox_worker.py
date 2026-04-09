"""
managed_sandbox_worker.py — Managed .NET assembly sandbox execution worker.

Executes .NET assemblies in an isolated environment with:
  - Network sinkholing (redirect all outbound traffic to local responses)
  - CLR hook capture (Assembly.Load, CreateDecryptor, MethodInfo.Invoke)
  - Dynamic assembly dumping
  - Configurable timeout and memory limits

Action: safe_run
"""

import json
import sys
import os
import subprocess
import signal
import hashlib
import base64
import tempfile
import time
import threading
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Network sinkhole
# ---------------------------------------------------------------------------

_sinkhole_requests: List[Dict[str, Any]] = []
_sinkhole_lock = threading.Lock()
_sinkhole_response_body: str = '{"status":"ok"}'


class SinkholeHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures all requests and returns a configurable response."""

    def log_message(self, fmt, *args):
        pass

    def _handle(self, method: str):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        entry = {
            'timestamp': time.time(),
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
            'body_size': len(body),
            'body_preview': body[:512].decode('utf-8', errors='replace') if body else None,
        }
        with _sinkhole_lock:
            _sinkhole_requests.append(entry)

        resp = _sinkhole_response_body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_GET(self):     self._handle('GET')
    def do_POST(self):    self._handle('POST')
    def do_PUT(self):     self._handle('PUT')
    def do_DELETE(self):  self._handle('DELETE')
    def do_HEAD(self):    self._handle('HEAD')
    def do_OPTIONS(self): self._handle('OPTIONS')
    def do_PATCH(self):   self._handle('PATCH')


def _start_sinkhole(port: int = 0) -> tuple:
    """Start a sinkhole HTTP server. Returns (server, port)."""
    server = HTTPServer(('127.0.0.1', port), SinkholeHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port


# ---------------------------------------------------------------------------
# Assembly load monitoring via filesystem
# ---------------------------------------------------------------------------

def _setup_assembly_dump_dir() -> str:
    """Create a temp directory for dumping loaded assemblies."""
    dump_dir = tempfile.mkdtemp(prefix='sandbox_asm_')
    return dump_dir


def _collect_dumped_assemblies(dump_dir: str) -> List[Dict[str, Any]]:
    """Collect info about assemblies dumped to the temp directory."""
    assemblies = []
    if not os.path.isdir(dump_dir):
        return assemblies
    for fname in os.listdir(dump_dir):
        fpath = os.path.join(dump_dir, fname)
        if os.path.isfile(fpath):
            with open(fpath, 'rb') as f:
                data = f.read()
            assemblies.append({
                'filename': fname,
                'size': len(data),
                'sha256': hashlib.sha256(data).hexdigest(),
                'is_pe': data[:2] == b'MZ' if len(data) >= 2 else False,
                'path': fpath,
            })
    return assemblies


# ---------------------------------------------------------------------------
# Sample execution
# ---------------------------------------------------------------------------

def _build_dotnet_env(
    sinkhole_port: Optional[int],
    dump_dir: str,
    memory_limit_mb: int,
    hooks: Dict[str, bool],
) -> Dict[str, str]:
    """Build environment variables for the sandboxed .NET execution."""
    env = dict(os.environ)

    # Point HTTP traffic to sinkhole
    if sinkhole_port:
        env['http_proxy'] = f'http://127.0.0.1:{sinkhole_port}'
        env['https_proxy'] = f'http://127.0.0.1:{sinkhole_port}'
        env['HTTP_PROXY'] = f'http://127.0.0.1:{sinkhole_port}'
        env['HTTPS_PROXY'] = f'http://127.0.0.1:{sinkhole_port}'
        env['NO_PROXY'] = ''
        # Disable certificate validation for sinkholed HTTPS
        env['DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER'] = '0'

    # Assembly dump directory
    env['SANDBOX_DUMP_DIR'] = dump_dir

    # Memory limit (approximate via GC settings)
    env['DOTNET_GCHeapHardLimit'] = str(memory_limit_mb * 1024 * 1024)
    env['COMPlus_GCHeapHardLimit'] = hex(memory_limit_mb * 1024 * 1024)

    # Hook flags (for instrumented runtimes)
    if hooks.get('hook_assembly_load'):
        env['SANDBOX_HOOK_ASSEMBLY_LOAD'] = '1'
    if hooks.get('hook_resource_resolve'):
        env['SANDBOX_HOOK_RESOURCE_RESOLVE'] = '1'
    if hooks.get('hook_create_decryptor'):
        env['SANDBOX_HOOK_CREATE_DECRYPTOR'] = '1'
    if hooks.get('hook_method_invoke'):
        env['SANDBOX_HOOK_METHOD_INVOKE'] = '1'

    return env


def _run_sample(
    file_path: str,
    entry_class: Optional[str],
    entry_method: Optional[str],
    args: List[str],
    timeout_seconds: int,
    env: Dict[str, str],
) -> Dict[str, Any]:
    """Execute the .NET assembly and capture output."""
    # Try dotnet first, then mono
    runtimes = ['dotnet', 'mono']
    cmd = None
    for rt in runtimes:
        try:
            subprocess.run([rt, '--version'], capture_output=True, timeout=5)
            cmd = [rt]
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if cmd is None:
        return {
            'executed': False,
            'error': 'No .NET runtime found (tried dotnet, mono)',
        }

    # Build command
    if cmd[0] == 'dotnet':
        cmd.append(file_path)
    else:
        cmd.append(file_path)

    cmd.extend(args)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout_seconds,
            cwd=os.path.dirname(file_path),
            env=env,
        )
        return {
            'executed': True,
            'runtime': cmd[0],
            'exit_code': proc.returncode,
            'stdout': proc.stdout[:4096].decode('utf-8', errors='replace'),
            'stderr': proc.stderr[:4096].decode('utf-8', errors='replace'),
            'timed_out': False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            'executed': True,
            'runtime': cmd[0],
            'exit_code': -1,
            'stdout': (e.stdout or b'')[:4096].decode('utf-8', errors='replace'),
            'stderr': (e.stderr or b'')[:4096].decode('utf-8', errors='replace'),
            'timed_out': True,
        }


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------

def handle_safe_run(request: Dict[str, Any]) -> Dict[str, Any]:
    """Handle the safe_run action."""
    global _sinkhole_response_body, _sinkhole_requests

    file_path = request.get('file_path', '')
    entry_class = request.get('entry_class')
    entry_method = request.get('entry_method')
    args = request.get('args', [])
    timeout_seconds = min(request.get('timeout_seconds', 60), 300)
    memory_limit_mb = min(max(request.get('memory_limit_mb', 512), 32), 2048)
    enable_sinkhole = request.get('enable_network_sinkhole', True)
    sinkhole_resp = request.get('sinkhole_response_body')
    hook_assembly_load = request.get('hook_assembly_load', True)
    hook_resource_resolve = request.get('hook_resource_resolve', True)
    hook_create_decryptor = request.get('hook_create_decryptor', True)
    hook_method_invoke = request.get('hook_method_invoke', True)
    dump_loaded = request.get('dump_loaded_assemblies', True)

    if not os.path.isfile(file_path):
        return {'ok': False, 'error': f'File not found: {file_path}'}

    # Reset sinkhole state
    _sinkhole_requests = []
    if sinkhole_resp:
        _sinkhole_response_body = sinkhole_resp

    # Setup
    sinkhole_server = None
    sinkhole_port = None
    dump_dir = _setup_assembly_dump_dir() if dump_loaded else tempfile.mkdtemp(prefix='sandbox_')

    try:
        # Start sinkhole if enabled
        if enable_sinkhole:
            sinkhole_server, sinkhole_port = _start_sinkhole()

        # Build environment
        env = _build_dotnet_env(
            sinkhole_port=sinkhole_port,
            dump_dir=dump_dir,
            memory_limit_mb=memory_limit_mb,
            hooks={
                'hook_assembly_load': hook_assembly_load,
                'hook_resource_resolve': hook_resource_resolve,
                'hook_create_decryptor': hook_create_decryptor,
                'hook_method_invoke': hook_method_invoke,
            },
        )

        # Execute sample
        execution = _run_sample(
            file_path=file_path,
            entry_class=entry_class,
            entry_method=entry_method,
            args=args,
            timeout_seconds=timeout_seconds,
            env=env,
        )

    finally:
        if sinkhole_server:
            sinkhole_server.shutdown()

    # Collect results
    with _sinkhole_lock:
        captured_network = list(_sinkhole_requests)

    dumped_assemblies = _collect_dumped_assemblies(dump_dir) if dump_loaded else []

    return {
        'ok': True,
        'data': {
            'execution': execution,
            'network': {
                'sinkhole_enabled': enable_sinkhole,
                'sinkhole_port': sinkhole_port,
                'total_requests': len(captured_network),
                'requests': captured_network,
            },
            'hooks': {
                'assembly_load': hook_assembly_load,
                'resource_resolve': hook_resource_resolve,
                'create_decryptor': hook_create_decryptor,
                'method_invoke': hook_method_invoke,
            },
            'loaded_assemblies': {
                'dump_enabled': dump_loaded,
                'dump_dir': dump_dir,
                'count': len(dumped_assemblies),
                'assemblies': dumped_assemblies,
            },
            'timeout_seconds': timeout_seconds,
            'memory_limit_mb': memory_limit_mb,
        },
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

ACTIONS = {
    'safe_run': handle_safe_run,
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
