"""
Frida Worker - Dynamic instrumentation using Frida

Implements process spawn and attach primitives for runtime API tracing.
Communicates with Node.js via stdin/stdout JSON.
"""

import sys
import json
import os
import time
import subprocess
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from dataclasses import dataclass

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    frida = None


@dataclass
class SampleInfo:
    """Sample information"""
    sample_id: str
    path: str


@dataclass
class PolicyContext:
    """Policy context"""
    allow_dynamic: bool
    allow_network: bool


@dataclass
class WorkerContext:
    """Worker context"""
    request_time_utc: str
    policy: PolicyContext
    versions: Dict[str, str]


@dataclass
class WorkerRequest:
    """Worker request"""
    job_id: str
    tool: str
    sample: SampleInfo
    args: Dict[str, Any]
    context: WorkerContext


@dataclass
class ArtifactRef:
    """Artifact reference"""
    id: str
    type: str
    path: str
    sha256: str
    mime: Optional[str] = None


@dataclass
class WorkerResponse:
    """Worker response"""
    job_id: str
    ok: bool
    warnings: List[str]
    errors: List[str]
    data: Dict[str, Any]
    artifacts: List[ArtifactRef]
    metrics: Dict[str, Any]


class FridaWorker:
    """Frida dynamic instrumentation worker"""

    def __init__(self):
        self._device: Optional[Any] = None
        self._session: Optional[Any] = None
        self._script: Optional[Any] = None
        self._trace_data: List[Dict[str, Any]] = []
        self._start_time: Optional[float] = None

    def _get_frida_version(self) -> Optional[str]:
        """Get Frida version string"""
        if not FRIDA_AVAILABLE:
            return None
        try:
            return getattr(frida, "__version__", None)
        except Exception:
            return None

    def _get_device(self) -> Any:
        """Get Frida USB device"""
        if self._device is not None:
            return self._device

        if not FRIDA_AVAILABLE:
            raise RuntimeError("Frida is not installed")

        self._device = frida.get_local_device()
        return self._device

    def probe_frida(self) -> Dict[str, Any]:
        """Probe Frida availability and return status"""
        result = {
            "available": FRIDA_AVAILABLE,
            "version": self._get_frida_version(),
            "spawn_available": False,
            "attach_available": False,
            "error": None,
        }

        if not FRIDA_AVAILABLE:
            result["error"] = "Frida package not installed. Run: pip install frida"
            return result

        try:
            # Check if spawn and attach are available
            result["spawn_available"] = hasattr(frida, "spawn")
            result["attach_available"] = hasattr(frida, "attach")

            # Try to get device
            self._get_device()

        except Exception as e:
            result["error"] = f"Frida probe failed: {str(e)}"

        return result

    def spawn_and_instrument(
        self,
        target_path: str,
        script_content: Optional[str] = None,
        args: Optional[List[str]] = None,
        timeout_sec: int = 30,
    ) -> Dict[str, Any]:
        """
        Spawn a process and instrument it with Frida.

        Args:
            target_path: Path to the executable to spawn
            script_content: Optional Frida JavaScript script to inject
            args: Optional command-line arguments
            timeout_sec: Execution timeout in seconds

        Returns:
            Dict with session info and trace data
        """
        if not FRIDA_AVAILABLE:
            return {
                "ok": False,
                "error": "Frida not installed",
                "pid": None,
                "session_id": None,
            }

        self._start_time = time.time()
        self._trace_data = []

        try:
            device = self._get_device()

            # Spawn the target process
            pid = device.spawn([target_path] + (args or []))

            # Attach to the spawned process
            session = device.attach(pid)

            self._session = session

            # Enable child gating if needed
            session.enable_child_gating()

            # Create and load script
            script_id = f"session_{pid}_{int(time.time())}"

            if script_content:
                script = session.create_script(script_content)

                # Set up message handler
                def on_message(message, data):
                    self._handle_script_message(message, data)

                script.on("message", on_message)
                script.load()
                self._script = script

            # Resume the process
            device.resume(pid)

            # Wait for completion or timeout
            start_wait = time.time()
            while time.time() - start_wait < timeout_sec:
                try:
                    if not session.is_detached:
                        time.sleep(0.1)
                    else:
                        break
                except Exception:
                    break

            # Unload script and detach
            if self._script:
                self._script.unload()
                self._script = None

            session.detach()
            self._session = None

            elapsed_ms = int((time.time() - self._start_time) * 1000)

            return {
                "ok": True,
                "pid": pid,
                "session_id": script_id,
                "trace_count": len(self._trace_data),
                "traces": self._trace_data[:100],  # Limit returned traces
                "duration_ms": elapsed_ms,
            }

        except Exception as e:
            # Cleanup on error
            if self._script:
                try:
                    self._script.unload()
                except Exception:
                    pass
                self._script = None

            if self._session:
                try:
                    self._session.detach()
                except Exception:
                    pass
                self._session = None

            return {
                "ok": False,
                "error": f"Spawn/instrument failed: {str(e)}",
                "pid": None,
                "session_id": None,
            }

    def attach_and_instrument(
        self,
        pid: int,
        script_content: Optional[str] = None,
        timeout_sec: int = 30,
    ) -> Dict[str, Any]:
        """
        Attach to a running process and instrument it with Frida.

        Args:
            pid: Process ID to attach to
            script_content: Optional Frida JavaScript script to inject
            timeout_sec: Execution timeout in seconds

        Returns:
            Dict with session info and trace data
        """
        if not FRIDA_AVAILABLE:
            return {
                "ok": False,
                "error": "Frida not installed",
                "session_id": None,
            }

        self._start_time = time.time()
        self._trace_data = []

        try:
            device = self._get_device()

            # Attach to the process
            session = device.attach(pid)

            self._session = session

            # Create and load script
            script_id = f"attach_{pid}_{int(time.time())}"

            if script_content:
                script = session.create_script(script_content)

                # Set up message handler
                def on_message(message, data):
                    self._handle_script_message(message, data)

                script.on("message", on_message)
                script.load()
                self._script = script

            # Wait for completion or timeout
            start_wait = time.time()
            while time.time() - start_wait < timeout_sec:
                try:
                    if not session.is_detached:
                        time.sleep(0.1)
                    else:
                        break
                except Exception:
                    break

            # Unload script and detach
            if self._script:
                self._script.unload()
                self._script = None

            session.detach()
            self._session = None

            elapsed_ms = int((time.time() - self._start_time) * 1000)

            return {
                "ok": True,
                "pid": pid,
                "session_id": script_id,
                "trace_count": len(self._trace_data),
                "traces": self._trace_data[:100],
                "duration_ms": elapsed_ms,
            }

        except Exception as e:
            # Cleanup on error
            if self._script:
                try:
                    self._script.unload()
                except Exception:
                    pass
                self._script = None

            if self._session:
                try:
                    self._session.detach()
                except Exception:
                    pass
                self._session = None

            return {
                "ok": False,
                "error": f"Attach/instrument failed: {str(e)}",
                "session_id": None,
            }

    def _handle_script_message(self, message: Dict[str, Any], data: Any) -> None:
        """Handle message from Frida script"""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                payload["_timestamp"] = time.time()
                self._trace_data.append(payload)
        elif message.get("type") == "error":
            error_msg = message.get("stack", message.get("description", "Unknown script error"))
            self._trace_data.append({
                "_type": "error",
                "_timestamp": time.time(),
                "error": str(error_msg),
            })

    def inject_script(
        self,
        pid: int,
        script_content: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Inject a Frida script into a running session.

        Args:
            pid: Process ID
            script_content: Frida JavaScript source
            parameters: Optional parameters to pass to the script

        Returns:
            Dict with script execution result
        """
        if not self._session:
            return {
                "ok": False,
                "error": "No active session. Call spawn_and_instrument or attach_and_instrument first.",
            }

        try:
            # Parameterize script if parameters provided
            if parameters:
                script_with_params = f"""
                const SCRIPT_PARAMS = {json.dumps(parameters)};
                {script_content}
                """
            else:
                script_with_params = script_content

            script = self._session.create_script(script_with_params)

            def on_message(message, data):
                self._handle_script_message(message, data)

            script.on("message", on_message)
            script.load()

            # Give script time to execute
            time.sleep(1)

            script.unload()

            return {
                "ok": True,
                "messages_captured": len(self._trace_data),
            }

        except Exception as e:
            return {
                "ok": False,
                "error": f"Script injection failed: {str(e)}",
            }

    def runtime_instrument(
        self,
        sample_path: str,
        mode: str = "spawn",
        pid: Optional[int] = None,
        script_name: str = "api_trace",
        script_content: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        timeout_sec: int = 30,
        capture_output: bool = True,
    ) -> Dict[str, Any]:
        """
        Main entry point for runtime instrumentation.

        Args:
            sample_path: Path to the sample to instrument
            mode: "spawn" or "attach"
            pid: Process ID (required for attach mode)
            script_name: Name of pre-built script to use
            script_content: Custom script content (overrides script_name)
            parameters: Script parameters
            timeout_sec: Timeout in seconds
            capture_output: Whether to capture trace output

        Returns:
            Dict with instrumentation results
        """
        self._trace_data = []
        self._start_time = time.time()

        # Get built-in script if not provided
        if not script_content:
            script_content = self._get_builtin_script(script_name, parameters)

        if mode == "spawn":
            result = self.spawn_and_instrument(
                target_path=sample_path,
                script_content=script_content,
                timeout_sec=timeout_sec,
            )
        elif mode == "attach":
            if pid is None:
                return {
                    "ok": False,
                    "error": "PID required for attach mode",
                }
            result = self.attach_and_instrument(
                pid=pid,
                script_content=script_content,
                timeout_sec=timeout_sec,
            )
        else:
            return {
                "ok": False,
                "error": f"Unknown mode: {mode}. Use 'spawn' or 'attach'.",
            }

        return result

    def _get_builtin_script(self, name: str, parameters: Optional[Dict[str, Any]] = None) -> str:
        """Get a built-in Frida script by name"""
        params = parameters or {}

        if name == "api_trace":
            modules_filter = params.get("modules", [])
            return self._build_api_trace_script(modules_filter)
        elif name == "string_decoder":
            return self._build_string_decoder_script()
        elif name == "anti_debug_bypass":
            return self._build_anti_debug_bypass_script()
        elif name == "time_bypass":
            return self._build_time_bypass_script(params.get("speed_factor", 100))
        elif name == "evasion_score":
            return self._build_evasion_score_script()
        elif name == "combo_evasion":
            speed = params.get("speed_factor", 100)
            return (
                self._build_anti_debug_bypass_script()
                + "\n"
                + self._build_time_bypass_script(speed)
                + "\n"
                + self._build_evasion_score_script()
            )
        elif name == "crypto_finder":
            return self._build_crypto_finder_script()
        elif name == "file_registry_monitor":
            return self._build_file_registry_monitor_script()
        else:
            return self._build_default_trace_script()

    def _build_default_trace_script(self) -> str:
        """Build default API tracing script"""
        return """
        Interceptor.attach(Module.getExportByName(null, 'LoadLibraryA'), {
            onEnter: function(args) {
                send({
                    type: 'api_call',
                    function: 'LoadLibraryA',
                    args: [args[0].readUtf8String()],
                });
            }
        });

        Interceptor.attach(Module.getExportByName(null, 'GetProcAddress'), {
            onEnter: function(args) {
                send({
                    type: 'api_call',
                    function: 'GetProcAddress',
                    args: [args[1].readUtf8String()],
                });
            }
        });
        """

    def _build_api_trace_script(self, modules: List[str]) -> str:
        """Build API tracing script with module filter"""
        modules_json = json.dumps(modules)
        return f"""
        const targetModules = {modules_json};

        function shouldTrace(moduleName) {{
            if (targetModules.length === 0) return true;
            return targetModules.some(m => moduleName.toLowerCase().includes(m.toLowerCase()));
        }}

        // Trace common APIs
        const apis = [
            'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress',
            'CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile',
            'RegOpenKeyExA', 'RegOpenKeyExW', 'RegQueryValueExA', 'RegQueryValueExW',
            'CreateProcessA', 'CreateProcessW', 'ShellExecuteA', 'ShellExecuteW',
            'InternetOpenA', 'InternetOpenW', 'HttpSendRequestA', 'HttpSendRequestW',
            'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread',
        ];

        apis.forEach(apiName => {{
            const addr = Module.findExportByName(null, apiName);
            if (addr) {{
                Interceptor.attach(addr, {{
                    onEnter: function(args) {{
                        const moduleName = Process.findModuleByAddress(this.returnAddress)?.name || 'unknown';
                        if (shouldTrace(moduleName)) {{
                            send({{
                                type: 'api_call',
                                function: apiName,
                                module: moduleName,
                                timestamp: Date.now(),
                            }});
                        }}
                    }}
                }});
            }}
        }});
        """

    def _build_string_decoder_script(self) -> str:
        """Build string decoder script"""
        return """
        // Intercept string-related APIs to capture decrypted strings
        const stringApis = ['lstrlenA', 'lstrlenW', 'strcpy', 'strncpy', 'wcsncpy'];

        stringApis.forEach(api => {{
            const addr = Module.findExportByName('kernel32.dll', api) ||
                         Module.findExportByName('ntdll.dll', api);
            if (addr) {{
                Interceptor.attach(addr, {{
                    onEnter: function(args) {{
                        try {{
                            const str = args[0].readUtf8String();
                            if (str && str.length > 3) {{
                                send({{
                                    type: 'string_access',
                                    function: api,
                                    value: str.substring(0, 100),
                                }});
                            }}
                        }} catch (e) {{}}
                    }}
                }});
            }}
        }});
        """

    def _build_anti_debug_bypass_script(self) -> str:
        """Build anti-debug bypass script"""
        return """
        // Neutralize common anti-debug checks
        const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
        if (IsDebuggerPresent) {
            Interceptor.attach(IsDebuggerPresent, {
                onLeave: function(retval) {
                    retval.replace(0);
                }
            });
        }

        const CheckRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
        if (CheckRemoteDebuggerPresent) {
            Interceptor.attach(CheckRemoteDebuggerPresent, {
                onEnter: function(args) {
                    this.pbDebuggerPresent = args[1];
                },
                onLeave: function(retval) {
                    retval.replace(0);
                    if (this.pbDebuggerPresent) {
                        Memory.writeU32(this.pbDebuggerPresent, 0);
                    }
                }
            });
        }

        // NtQueryInformationProcess comprehensive patching
        const NtQueryInformationProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
        if (NtQueryInformationProcess) {
            Interceptor.attach(NtQueryInformationProcess, {
                onEnter: function(args) {
                    this.processInformationClass = args[1].toInt32();
                    this.processInformation = args[2];
                },
                onLeave: function(retval) {
                    var patched = false;
                    if (this.processInformationClass === 7 && this.processInformation) {
                        Memory.writeU32(this.processInformation, 0); // ProcessDebugPort
                        patched = true;
                    }
                    if (this.processInformationClass === 0x1F && this.processInformation) {
                        Memory.writeU32(this.processInformation, 1); // ProcessDebugFlags (1 = no debugger)
                        patched = true;
                    }
                    if (this.processInformationClass === 0 && this.processInformation) {
                        Memory.writeU8(this.processInformation.add(0x02), 0); // ProcessBasicInformation.BeingDebugged
                        patched = true;
                    }
                    if (patched) retval.replace(0);
                }
            });
        }

        const NtSetInformationThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
        if (NtSetInformationThread) {
            Interceptor.attach(NtSetInformationThread, {
                onLeave: function(retval) {
                    retval.replace(0);
                }
            });
        }

        const NtClose = Module.findExportByName('ntdll.dll', 'NtClose');
        if (NtClose) {
            Interceptor.attach(NtClose, {
                onLeave: function(retval) {
                    if (retval.toInt32() === -1073741816) {
                        retval.replace(0);
                    }
                }
            });
        }

        const OutputDebugStringA = Module.findExportByName('kernel32.dll', 'OutputDebugStringA');
        if (OutputDebugStringA) {
            Interceptor.attach(OutputDebugStringA, {
                onLeave: function(retval) {
                    retval.replace(0);
                }
            });
        }
        """

    def _build_time_bypass_script(self, speed_factor: int = 100) -> str:
        """Build time-acceleration bypass script to defeat sleep loops."""
        return f"""
        var speedFactor = {speed_factor};
        var startReal = Date.now();
        var startFake = Date.now();
        function getFakeTick() {{
            var elapsedReal = Date.now() - startReal;
            return startFake + (elapsedReal * speedFactor);
        }}

        var GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
        if (GetTickCount) {{
            Interceptor.attach(GetTickCount, {{
                onLeave: function(retval) {{
                    retval.replace(getFakeTick() % 0xFFFFFFFF);
                }}
            }});
        }}

        var GetTickCount64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');
        if (GetTickCount64) {{
            Interceptor.attach(GetTickCount64, {{
                onLeave: function(retval) {{
                    var fake = getFakeTick();
                    retval.replace(ptr(fake.toString()));
                }}
            }});
        }}

        var timeGetTime = Module.findExportByName('winmm.dll', 'timeGetTime');
        if (timeGetTime) {{
            Interceptor.attach(timeGetTime, {{
                onLeave: function(retval) {{
                    retval.replace(getFakeTick() % 0xFFFFFFFF);
                }}
            }});
        }}

        var QueryPerformanceCounter = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
        if (QueryPerformanceCounter) {{
            Interceptor.attach(QueryPerformanceCounter, {{
                onEnter: function(args) {{
                    this.lpPerformanceCount = args[0];
                }},
                onLeave: function(retval) {{
                    if (this.lpPerformanceCount) {{
                        Memory.writeU64(this.lpPerformanceCount, getFakeTick() * 10000);
                    }}
                    retval.replace(0);
                }}
            }});
        }}

        var Sleep = Module.findExportByName('kernel32.dll', 'Sleep');
        if (Sleep) {{
            Interceptor.attach(Sleep, {{
                onEnter: function(args) {{
                    var originalMs = args[0].toUInt32();
                    var reducedMs = Math.max(1, Math.floor(originalMs / speedFactor));
                    args[0] = ptr(reducedMs);
                    send({{ type: 'time_bypass', api: 'Sleep', original_ms: originalMs, reduced_ms: reducedMs }});
                }}
            }});
        }}

        var NtDelayExecution = Module.findExportByName('ntdll.dll', 'NtDelayExecution');
        if (NtDelayExecution) {{
            Interceptor.attach(NtDelayExecution, {{
                onEnter: function(args) {{
                    var pLi = args[1];
                    if (pLi) {{
                        var interval = Memory.readS64(pLi);
                        var reduced = Math.max(-1, Math.floor(interval / speedFactor));
                        Memory.writeS64(pLi, reduced);
                        send({{ type: 'time_bypass', api: 'NtDelayExecution', original_interval: interval.toString(), reduced_interval: reduced.toString() }});
                    }}
                }}
            }});
        }}
        """

    def _build_evasion_score_script(self) -> str:
        """Build script that counts anti-debug/anti-vm API calls for scoring."""
        return """
        var evasionCounters = {};
        function countApi(module, name) {
            var addr = Module.findExportByName(module, name);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function() {
                        evasionCounters[name] = (evasionCounters[name] || 0) + 1;
                    }
                });
            }
        }

        var antiDebugApis = ['IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess',
                             'NtSetInformationThread','NtClose','OutputDebugStringA','OutputDebugStringW'];
        var antiVmApis = ['IsProcessorFeaturePresent','GetSystemFirmwareTable','CheckTokenMembership',
                          'EnumWindows','GetCursorPos','GetTickCount','GetTickCount64','QueryPerformanceCounter',
                          'GetAdaptersInfo','WNetGetProviderNameA'];

        antiDebugApis.forEach(function(name) { countApi('kernel32.dll', name) || countApi('ntdll.dll', name); });
        antiVmApis.forEach(function(name) { countApi('kernel32.dll', name) || countApi('user32.dll', name) || countApi('advapi32.dll', name) || countApi('iphlpapi.dll', name) || countApi('mpr.dll', name); });

        send({ type: 'evasion_hooks_installed', apis: antiDebugApis.concat(antiVmApis) });
        """

    def _build_crypto_finder_script(self) -> str:
        """Build cryptographic API finder script"""
        return """
        // Detect cryptographic API usage
        const cryptoApis = [
            'CryptAcquireContextA', 'CryptAcquireContextW',
            'CryptEncrypt', 'CryptDecrypt',
            'CryptGenKey', 'CryptImportKey', 'CryptExportKey',
            'BCryptEncrypt', 'BCryptDecrypt',
            'BCryptGenerateSymmetricKey',
            'AES_set_encrypt_key', 'AES_set_decrypt_key', 'AES_encrypt', 'AES_decrypt',
        ];

        cryptoApis.forEach(api => {{
            const addr = Module.findExportByName(null, api);
            if (addr) {{
                Interceptor.attach(addr, {{
                    onEnter: function(args) {{
                        send({{
                            type: 'crypto_api',
                            function: api,
                            module: Process.findModuleByAddress(this.returnAddress)?.name || 'unknown',
                        }});
                    }}
                }});
            }}
        }});
        """

    def _build_file_registry_monitor_script(self) -> str:
        """Build file and registry monitoring script"""
        return """
        // Monitor file and registry operations
        const fileApis = ['CreateFileA', 'CreateFileW', 'DeleteFileA', 'DeleteFileW'];
        const regApis = ['RegOpenKeyExA', 'RegOpenKeyExW', 'RegSetValueExA', 'RegSetValueExW'];

        [...fileApis, ...regApis].forEach(api => {{
            const addr = Module.findExportByName('kernel32.dll', api) ||
                         Module.findExportByName('advapi32.dll', api);
            if (addr) {{
                Interceptor.attach(addr, {{
                    onEnter: function(args) {{
                        send({{
                            type: 'io_operation',
                            function: api,
                            timestamp: Date.now(),
                        }});
                    }}
                }});
            }}
        }});
        """

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming worker request"""
        try:
            tool = request.get("tool")
            args = request.get("args", {})
            sample_path = request.get("sample", {}).get("path", "")

            if tool == "frida.probe":
                result = self.probe_frida()
                return self._build_response(request.get("job_id"), True, result)

            elif tool == "frida.runtime.instrument":
                mode = args.get("mode", "spawn")
                pid = args.get("pid")
                script_name = args.get("script_name", "api_trace")
                script_content = args.get("script_content")
                parameters = args.get("parameters")
                timeout_sec = args.get("timeout_sec", 30)

                result = self.runtime_instrument(
                    sample_path=sample_path,
                    mode=mode,
                    pid=pid,
                    script_name=script_name,
                    script_content=script_content,
                    parameters=parameters,
                    timeout_sec=timeout_sec,
                )

                return self._build_response(request.get("job_id"), result.get("ok", False), result)

            elif tool == "frida.script.inject":
                pid = args.get("pid")
                script_content = args.get("script_content", "")
                parameters = args.get("parameters")

                # First attach if not already attached
                if not self._session:
                    attach_result = self.attach_and_instrument(pid, "", 5)
                    if not attach_result.get("ok"):
                        return self._build_response(
                            request.get("job_id"),
                            False,
                            {"error": attach_result.get("error")},
                        )

                result = self.inject_script(pid, script_content, parameters)
                return self._build_response(request.get("job_id"), result.get("ok", False), result)

            elif tool == "frida.trace.capture":
                return self._build_response(
                    request.get("job_id"),
                    True,
                    {
                        "traces": self._trace_data,
                        "count": len(self._trace_data),
                    },
                )

            else:
                return self._build_response(
                    request.get("job_id"),
                    False,
                    {"error": f"Unknown tool: {tool}"},
                )

        except Exception as e:
            return self._build_response(
                request.get("job_id"),
                False,
                {"error": f"Worker error: {str(e)}"},
            )

    def _build_response(
        self,
        job_id: str,
        ok: bool,
        data: Dict[str, Any],
        warnings: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Build worker response"""
        return {
            "job_id": job_id,
            "ok": ok,
            "warnings": warnings or [],
            "errors": errors or [],
            "data": data,
            "artifacts": [],
            "metrics": {
                "elapsed_ms": int((time.time() - (self._start_time or time.time())) * 1000),
                "tool": "frida.worker",
            },
        }


def main():
    """Main entry point"""
    worker = FridaWorker()

    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            response = worker.handle_request(request)
            print(json.dumps(response), flush=True)
        except json.JSONDecodeError as e:
            error_response = {
                "job_id": "unknown",
                "ok": False,
                "warnings": [],
                "errors": [f"Invalid JSON input: {str(e)}"],
                "data": {},
                "artifacts": [],
                "metrics": {},
            }
            print(json.dumps(error_response), flush=True)
        except Exception as e:
            error_response = {
                "job_id": "unknown",
                "ok": False,
                "warnings": [],
                "errors": [f"Worker error: {str(e)}"],
                "data": {},
                "artifacts": [],
                "metrics": {},
            }
            print(json.dumps(error_response), flush=True)


if __name__ == "__main__":
    main()
