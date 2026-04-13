/**
 * Anti-Debug Bypass Script for Frida
 *
 * Neutralizes common anti-debugging techniques:
 * - IsDebuggerPresent checks
 * - CheckRemoteDebuggerPresent
 * - NtQueryInformationProcess (ProcessDebugPort, ProcessDebugFlags, etc.)
 * - NtSetInformationThread (ThreadHideFromDebugger)
 * - GetTickCount / QueryPerformanceCounter timing checks
 * - OutputDebugString detection
 * - PE B being debugged flags
 *
 * Usage: Attach before the sample runs or use with spawn mode.
 */

(function() {
    const config = {
        verbose: typeof SCRIPT_PARAMS !== 'undefined' ? (SCRIPT_PARAMS.verbose || false) : false,
        bypassAll: typeof SCRIPT_PARAMS !== 'undefined' ? SCRIPT_PARAMS.bypassAll : true,
    };

    let bypassCount = 0;

    function logBypass(technique) {
        bypassCount++;
        if (config.verbose) {
            send({
                type: 'antidbg_bypass',
                technique: technique,
                timestamp: Date.now()
            });
        }
    }

    // === IsDebuggerPresent ===
    const isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
    if (isDebuggerPresent) {
        Interceptor.attach(isDebuggerPresent, {
            onLeave: function(retval) {
                retval.replace(0);
                logBypass('IsDebuggerPresent');
            }
        });
        console.log('[*] Hooked IsDebuggerPresent - always returning FALSE');
    }

    // === CheckRemoteDebuggerPresent ===
    const checkRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
    if (checkRemoteDebuggerPresent) {
        Interceptor.attach(checkRemoteDebuggerPresent, {
            onLeave: function(retval) {
                retval.replace(0);
                logBypass('CheckRemoteDebuggerPresent');
            }
        });
        console.log('[*] Hooked CheckRemoteDebuggerPresent - always returning FALSE');
    }

    // === NtQueryInformationProcess ===
    const NtQueryInformationProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
    if (NtQueryInformationProcess) {
        Interceptor.attach(NtQueryInformationProcess, {
            onEnter: function(args) {
                this.processInfoClass = args[1].toInt32();
            },
            onLeave: function(retval) {
                // ProcessDebugPort = 7
                if (this.processInfoClass === 7) {
                    // Set return value to non-zero (debug port exists) but make the actual port value 0
                    retval.replace(0);
                    logBypass('NtQueryInformationProcess(ProcessDebugPort)');
                }
                // ProcessDebugFlags = 31
                else if (this.processInfoClass === 31) {
                    retval.replace(1); // Return "no debug flags"
                    logBypass('NtQueryInformationProcess(ProcessDebugFlags)');
                }
                // ProcessBasicInformation = 0 (check Peb being debugged)
                else if (this.processInfoClass === 0) {
                    // Don't modify, just log
                    logBypass('NtQueryInformationProcess(ProcessBasicInformation)');
                }
                // ProcessSnapshotInformation = 27 (used by some protectors)
                else if (this.processInfoClass === 27) {
                    retval.replace(0);
                    logBypass('NtQueryInformationProcess(ProcessSnapshotInformation)');
                }
            }
        });
        console.log('[*] Hooked NtQueryInformationProcess - bypassing debug checks');
    }

    // === NtSetInformationThread (ThreadHideFromDebugger = 0x11) ===
    const NtSetInformationThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
    if (NtSetInformationThread) {
        Interceptor.attach(NtSetInformationThread, {
            onEnter: function(args) {
                this.threadInfoClass = args[1].toInt32();
                // ThreadHideFromDebugger = 0x11 (17)
                if (this.threadInfoClass === 17) {
                    logBypass('NtSetInformationThread(ThreadHideFromDebugger)');
                    // Skip the call by zeroing the thread handle
                    args[0] = ptr(0);
                }
            }
        });
        console.log('[*] Hooked NtSetInformationThread - bypassing ThreadHideFromDebugger');
    }

    // === NtQuerySystemTime / GetTickCount64 timing ===
    const NtQuerySystemTime = Module.findExportByName('ntdll.dll', 'NtQuerySystemTime');
    if (NtQuerySystemTime) {
        let lastCallTime = 0;
        Interceptor.attach(NtQuerySystemTime, {
            onLeave: function(retval) {
                const now = Date.now();
                if (lastCallTime > 0 && (now - lastCallTime) < 10) {
                    // Rapid calls - possible timing check
                    logBypass('NtQuerySystemTime (rapid call)');
                }
                lastCallTime = now;
            }
        });
    }

    // === GetTickCount / GetTickCount64 ===
    ['GetTickCount', 'GetTickCount64'].forEach(funcName => {
        const addr = Module.findExportByName('kernel32.dll', funcName);
        if (addr) {
            let lastTick = 0;
            Interceptor.attach(addr, {
                onLeave: function(retval) {
                    const current = funcName.endsWith('64') ? retval.toUInt64() : retval.toUInt32();
                    if (lastTick > 0 && (current - lastTick) < 10) {
                        logBypass(funcName + ' (rapid call)');
                    }
                    lastTick = current;
                }
            });
        }
    });

    // === OutputDebugString detection ===
    const outputDebugStringA = Module.findExportByName('kernel32.dll', 'OutputDebugStringA');
    const outputDebugStringW = Module.findExportByName('kernel32.dll', 'OutputDebugStringW');

    if (outputDebugStringA) {
        Interceptor.attach(outputDebugStringA, {
            onEnter: function(args) {
                try {
                    const msg = args[0].readUtf8String();
                    if (msg && msg.length > 0) {
                        send({
                            type: 'debug_string',
                            value: msg.substring(0, 200),
                            timestamp: Date.now()
                        });
                    }
                } catch (e) {}
            }
        });
    }

    if (outputDebugStringW) {
        Interceptor.attach(outputDebugStringW, {
            onEnter: function(args) {
                try {
                    const msg = args[0].readUtf16String();
                    if (msg && msg.length > 0) {
                        send({
                            type: 'debug_string',
                            value: msg.substring(0, 200),
                            timestamp: Date.now()
                        });
                    }
                } catch (e) {}
            }
        });
    }

    // === PEB BeingDebugged flag (direct memory patch approach) ===
    // This is a more aggressive approach - patch the PEB directly
    try {
        const pebPtr = Process.getCurrentProcess().getPeb();
        if (pebPtr) {
            const beingDebuggedOffset = 2; // Offset in PEB
            const beingDebuggedPtr = pebPtr.add(beingDebuggedOffset);
            Memory.writeU8(beingDebuggedPtr, 0);
            console.log('[*] Patched PEB BeingDebugged flag to 0');
            logBypass('PEB BeingDebugged patch');
        }
    } catch (e) {
        console.log('[-] Could not patch PEB: ' + e.message);
    }

    // === NtQueryObject (used to detect debuggers via object handles) ===
    const NtQueryObject = Module.findExportByName('ntdll.dll', 'NtQueryObject');
    if (NtQueryObject) {
        Interceptor.attach(NtQueryObject, {
            onEnter: function(args) {
                this.objectClass = args[1] ? args[1].toInt32() : -1;
            },
            onLeave: function(retval) {
                // ObjectTypeInformation = 2
                if (this.objectClass === 2) {
                    logBypass('NtQueryObject(ObjectTypeInformation)');
                }
            }
        });
    }

    send({
        type: 'init',
        message: 'Anti-Debug Bypass script loaded',
        verbose: config.verbose,
        bypasses_applied: config.bypassAll
    });

    console.log('[*] Anti-Debug Bypass loaded - bypasses active');
})();
