/**
 * API Trace Script for Frida
 *
 * Traces common Windows API calls including:
 * - Module loading (LoadLibraryA/W)
 * - Function resolution (GetProcAddress)
 * - File operations (CreateFileA/W, ReadFile, WriteFile)
 * - Registry operations (RegOpenKeyExA/W, RegQueryValueExA/W)
 * - Process creation (CreateProcessA/W, ShellExecuteA/W)
 * - Network operations (InternetOpenA/W, HttpSendRequestA/W)
 * - Memory operations (VirtualAlloc, VirtualProtect)
 * - Code injection (CreateRemoteThread)
 *
 * Usage parameters (optional):
 *   - modules: Array of module name filters (e.g., ["kernel32", "ntdll"])
 *   - apis: Array of specific API names to trace
 */

(function() {
    // Default configuration
    const config = {
        modules: typeof SCRIPT_PARAMS !== 'undefined' ? SCRIPT_PARAMS.modules : [],
        apis: typeof SCRIPT_PARAMS !== 'undefined' ? SCRIPT_PARAMS.apis : null
    };

    // Helper to check if module should be traced
    function shouldTraceModule(moduleName) {
        if (config.modules.length === 0) return true;
        return config.modules.some(m =>
            moduleName.toLowerCase().includes(m.toLowerCase())
        );
    }

    // Helper to check if API should be traced
    function shouldTraceApi(apiName) {
        if (!config.apis) return true;
        return config.apis.some(api =>
            apiName.toLowerCase().includes(api.toLowerCase())
        );
    }

    // Comprehensive API list for malware analysis
    const trackedApis = [
        // Module loading
        'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
        'GetProcAddress', 'GetModuleHandleA', 'GetModuleHandleW',

        // File operations
        'CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile',
        'DeleteFileA', 'DeleteFileW', 'CopyFileA', 'CopyFileW',
        'MoveFileA', 'MoveFileW', 'FindFirstFileA', 'FindFirstFileW',
        'GetFileAttributesA', 'GetFileAttributesW',

        // Registry operations
        'RegOpenKeyExA', 'RegOpenKeyExW', 'RegQueryValueExA', 'RegQueryValueExW',
        'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegCreateKeyExW',
        'RegDeleteKeyA', 'RegDeleteKeyW', 'RegEnumKeyExA', 'RegEnumKeyExW',

        // Process operations
        'CreateProcessA', 'CreateProcessW', 'OpenProcess',
        'TerminateProcess', 'ExitProcess', 'GetCurrentProcess',
        'ShellExecuteA', 'ShellExecuteW', 'WinExec',

        // Thread operations
        'CreateThread', 'CreateRemoteThread', 'CreateRemoteThreadEx',
        'SuspendThread', 'ResumeThread', 'TerminateThread',

        // Memory operations
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualFree', 'VirtualFreeEx',
        'VirtualProtect', 'VirtualProtectEx', 'ReadProcessMemory', 'WriteProcessMemory',

        // Network operations
        'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
        'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW',
        'HttpReadData', 'InternetReadFile', 'InternetCloseHandle',
        'WSAStartup', 'socket', 'connect', 'send', 'recv',

        // Crypto operations
        'CryptAcquireContextA', 'CryptAcquireContextW',
        'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
        'CryptImportKey', 'CryptExportKey', 'CryptHashData',
        'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenerateSymmetricKey',

        // Anti-analysis detection
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'OutputDebugStringA', 'OutputDebugStringW',
        'GetTickCount', 'QueryPerformanceCounter', 'NtQuerySystemTime',
    ];

    let apiCallCount = 0;
    const moduleCache = new Map();

    trackedApis.forEach(apiName => {
        if (!shouldTraceApi(apiName)) return;

        const addr = Module.findExportByName(null, apiName);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                apiCallCount++;

                // Get calling module
                const returnAddr = this.returnAddress;
                let moduleName = 'unknown';
                try {
                    const mod = Process.findModuleByAddress(returnAddr);
                    if (mod) {
                        moduleName = mod.name;
                        moduleCache.set(moduleName, mod.path);
                    }
                } catch (e) {}

                // Skip if module filtered out
                if (!shouldTraceModule(moduleName)) {
                    return;
                }

                // Build argument summary based on API
                let argSummary = [];
                try {
                    switch (apiName) {
                        // Module loading APIs
                        case 'LoadLibraryA':
                        case 'LoadLibraryW':
                            argSummary = [apiName.includes('W') ? args[0].readUtf16String() : args[0].readUtf8String()];
                            break;
                        case 'GetProcAddress':
                            argSummary = [args[1].readUtf8String()];
                            break;

                        // File APIs
                        case 'CreateFileA':
                        case 'CreateFileW':
                            argSummary = [apiName.includes('W') ? args[0].readUtf16String() : args[0].readUtf8String()];
                            break;
                        case 'DeleteFileA':
                        case 'DeleteFileW':
                            argSummary = [apiName.includes('W') ? args[0].readUtf16String() : args[0].readUtf8String()];
                            break;

                        // Registry APIs
                        case 'RegOpenKeyExA':
                        case 'RegOpenKeyExW':
                        case 'RegQueryValueExA':
                        case 'RegQueryValueExW':
                            argSummary = [apiName.includes('W') ? args[1].readUtf16String() : args[1].readUtf8String()];
                            break;

                        // Process APIs
                        case 'CreateProcessA':
                        case 'CreateProcessW':
                            argSummary = [apiName.includes('W') ? args[1].readUtf16String() : args[1].readUtf8String()];
                            break;
                        case 'ShellExecuteA':
                        case 'ShellExecuteW':
                            argSummary = [apiName.includes('W') ? args[3].readUtf16String() : args[3].readUtf8String()];
                            break;

                        // Network APIs
                        case 'InternetOpenA':
                        case 'InternetOpenW':
                            argSummary = [apiName.includes('W') ? args[0].readUtf16String() : args[0].readUtf8String()];
                            break;
                        case 'HttpOpenRequestA':
                        case 'HttpOpenRequestW':
                            argSummary = [
                                apiName.includes('W') ? args[2].readUtf16String() : args[2].readUtf8String(),
                                apiName.includes('W') ? args[3].readUtf16String() : args[3].readUtf8String()
                            ];
                            break;

                        // Memory APIs
                        case 'VirtualAlloc':
                        case 'VirtualAllocEx':
                            argSummary = ['size: ' + args[1].toUInt32(), 'type: ' + args[2].toUInt32(), 'prot: ' + args[3].toUInt32()];
                            break;

                        // Debug detection
                        case 'IsDebuggerPresent':
                        case 'CheckRemoteDebuggerPresent':
                            argSummary = ['[no args]'];
                            break;

                        default:
                            argSummary = ['[...]'];
                    }
                } catch (e) {
                    argSummary = ['[error reading args]'];
                }

                send({
                    type: 'api_call',
                    function: apiName,
                    module: moduleName,
                    args: argSummary,
                    timestamp: Date.now(),
                    thread_id: this.threadId
                });
            },

            onLeave: function(retval) {
                // Log return values for certain APIs
                if (['CreateFileA', 'CreateFileW', 'LoadLibraryA', 'LoadLibraryW',
                     'GetProcAddress', 'VirtualAlloc', 'VirtualAllocEx'].includes(apiName)) {
                    send({
                        type: 'api_return',
                        function: apiName,
                        retval: retval.toString(),
                        timestamp: Date.now()
                    });
                }
            }
        });
    });

    // Send initialization message
    send({
        type: 'init',
        message: 'API Trace script loaded',
        tracked_apis: trackedApis.filter(shouldTraceApi).length,
        module_filter: config.modules,
        api_filter: config.apis
    });

    console.log('[*] API Trace script loaded - monitoring ' + trackedApis.filter(shouldTraceApi).length + ' APIs');
})();
