/**
 * File & Registry Monitor Script for Frida
 *
 * Tracks file system and registry operations:
 * - File creation, deletion, read, write
 * - Directory operations
 * - Registry key open, query, set, delete
 * - Named pipe operations
 *
 * Useful for detecting persistence mechanisms, data exfiltration,
 * and system reconnaissance.
 */

(function() {
    const config = {
        trackContent: typeof SCRIPT_PARAMS !== 'undefined' ? (SCRIPT_PARAMS.trackContent || false) : false,
        maxDataSize: typeof SCRIPT_PARAMS !== 'undefined' ? (SCRIPT_PARAMS.maxDataSize || 256) : 256,
        filePatterns: typeof SCRIPT_PARAMS !== 'undefined' ? (SCRIPT_PARAMS.filePatterns || []) : [],
        regPatterns: typeof SCRIPT_PARAMS !== 'undefined' ? (SCRIPT_PARAMS.regPatterns || []) : [],
    };

    let operationCount = 0;
    const fileHandles = new Map();
    const regHandles = new Map();

    function shouldTrackPath(path, patterns) {
        if (patterns.length === 0) return true;
        return patterns.some(p => path.toLowerCase().includes(p.toLowerCase()));
    }

    function sendOperation(type, func, details) {
        operationCount++;
        send({
            type: type,
            function: func,
            ...details,
            timestamp: Date.now(),
            thread_id: this.threadId
        });
    }

    // Helper to get module name
    function getModuleName(returnAddr) {
        try {
            const mod = Process.findModuleByAddress(returnAddr);
            return mod ? mod.name : 'unknown';
        } catch (e) {
            return 'unknown';
        }
    }

    // === File Operations ===

    // CreateFileA/W - track file opens/creates
    ['CreateFileA', 'CreateFileW'].forEach(funcName => {
        const addr = Module.findExportByName('kernel32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');

        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.fileName = isWide ? args[0].readUtf16String() : args[0].readUtf8String();
                this.desiredAccess = args[1].toUInt32();
                this.shareMode = args[2].toUInt32();
                this.creationDisposition = args[3].toUInt32();
            },
            onLeave: function(retval) {
                if (!shouldTrackPath(this.fileName, config.filePatterns)) return;

                const HANDLE_FLAG = 0x80000000;
                const isStdHandle = (retval.toUInt32() & HANDLE_FLAG) !== 0;
                if (!isStdHandle && !retval.isNull()) {
                    fileHandles.set(retval.toString(), this.fileName);
                }

                // Decode access flags
                const accessFlags = [];
                if (this.desiredAccess & 0x80000000) accessFlags.push('GENERIC_READ');
                if (this.desiredAccess & 0x40000000) accessFlags.push('GENERIC_WRITE');
                if (this.desiredAccess & 0x10000000) accessFlags.push('GENERIC_EXECUTE');
                if (this.desiredAccess & 0x20000000) accessFlags.push('GENERIC_ALL');

                // Decode creation disposition
                const createDisp = {
                    1: 'CREATE_NEW',
                    2: 'CREATE_ALWAYS',
                    3: 'OPEN_EXISTING',
                    4: 'OPEN_ALWAYS',
                    5: 'TRUNCATE_EXISTING'
                };

                sendOperation('file_create', funcName, {
                    path: this.fileName,
                    access: accessFlags.join(' | '),
                    creation: createDisp[this.creationDisposition] || 'UNKNOWN',
                    handle: retval.toString(),
                    module: getModuleName(this.returnAddress)
                });
            }
        });
    });

    // ReadFile
    const readFileAddr = Module.findExportByName('kernel32.dll', 'ReadFile');
    if (readFileAddr) {
        Interceptor.attach(readFileAddr, {
            onEnter: function(args) {
                this.hFile = args[0].toString();
                this.bytesToRead = args[3].readU32();
            },
            onLeave: function(retval) {
                if (!retval.toUInt32()) return;

                const fileName = fileHandles.get(this.hFile) || 'unknown';
                if (!shouldTrackPath(fileName, config.filePatterns)) return;

                sendOperation('file_read', 'ReadFile', {
                    path: fileName,
                    handle: this.hFile,
                    bytes_read: retval.toUInt32()
                });
            }
        });
    }

    // WriteFile
    const writeFileAddr = Module.findExportByName('kernel32.dll', 'WriteFile');
    if (writeFileAddr) {
        Interceptor.attach(writeFileAddr, {
            onEnter: function(args) {
                this.hFile = args[0].toString();
                this.bytesToWrite = args[3].readU32();
                if (config.trackContent && args[1] && this.bytesToWrite <= config.maxDataSize) {
                    try {
                        this.writeData = args[1].readByteArray(this.bytesToWrite);
                    } catch (e) {}
                }
            },
            onLeave: function(retval) {
                if (!retval.toUInt32()) return;

                const fileName = fileHandles.get(this.hFile) || 'unknown';
                if (!shouldTrackPath(fileName, config.filePatterns)) return;

                const details = {
                    path: fileName,
                    handle: this.hFile,
                    bytes_written: retval.toUInt32()
                };

                if (this.writeData && config.trackContent) {
                    details.data_preview = Array.from(new Uint8Array(this.writeData))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                }

                sendOperation('file_write', 'WriteFile', details);
            }
        });
    }

    // DeleteFileA/W
    ['DeleteFileA', 'DeleteFileW'].forEach(funcName => {
        const addr = Module.findExportByName('kernel32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.fileName = isWide ? args[0].readUtf16String() : args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (!shouldTrackPath(this.fileName, config.filePatterns)) return;

                sendOperation('file_delete', funcName, {
                    path: this.fileName,
                    success: retval.toUInt32() !== 0,
                    module: getModuleName(this.returnAddress)
                });
            }
        });
    });

    // CopyFileA/W
    ['CopyFileA', 'CopyFileW'].forEach(funcName => {
        const addr = Module.findExportByName('kernel32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.srcFile = isWide ? args[0].readUtf16String() : args[0].readUtf8String();
                this.dstFile = isWide ? args[1].readUtf16String() : args[1].readUtf8String();
            },
            onLeave: function(retval) {
                if (!shouldTrackPath(this.srcFile, config.filePatterns) &&
                    !shouldTrackPath(this.dstFile, config.filePatterns)) return;

                sendOperation('file_copy', funcName, {
                    source: this.srcFile,
                    destination: this.dstFile,
                    success: retval.toUInt32() !== 0,
                    module: getModuleName(this.returnAddress)
                });
            }
        });
    });

    // MoveFileA/W
    ['MoveFileA', 'MoveFileW'].forEach(funcName => {
        const addr = Module.findExportByName('kernel32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.srcFile = isWide ? args[0].readUtf16String() : args[0].readUtf8String();
                this.dstFile = isWide ? args[1].readUtf16String() : args[1].readUtf8String();
            },
            onLeave: function(retval) {
                if (!shouldTrackPath(this.srcFile, config.filePatterns) &&
                    !shouldTrackPath(this.dstFile, config.filePatterns)) return;

                sendOperation('file_move', funcName, {
                    source: this.srcFile,
                    destination: this.dstFile,
                    success: retval.toUInt32() !== 0,
                    module: getModuleName(this.returnAddress)
                });
            }
        });
    });

    // === Registry Operations ===

    // RegOpenKeyExA/W
    ['RegOpenKeyExA', 'RegOpenKeyExW'].forEach(funcName => {
        const addr = Module.findExportByName('advapi32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.hKey = args[0].toString();
                this.subKey = isWide ? args[1].readUtf16String() : args[1].readUtf8String();
                this.samDesired = args[4].toUInt32();
            },
            onLeave: function(retval) {
                if (!shouldTrackPath(this.subKey, config.regPatterns)) return;

                const hKeyResult = retval.toString();
                if (!retval.isNull()) {
                    regHandles.set(hKeyResult, this.subKey);
                }

                const accessFlags = [];
                if (this.samDesired & 0x0001) accessFlags.push('KEY_QUERY_VALUE');
                if (this.samDesired & 0x0002) accessFlags.push('KEY_SET_VALUE');
                if (this.samDesired & 0x0004) accessFlags.push('KEY_CREATE_SUB_KEY');
                if (this.samDesired & 0x0008) accessFlags.push('KEY_ENUMERATE_SUB_KEYS');
                if (this.samDesired & 0x0010) accessFlags.push('KEY_NOTIFY');
                if (this.samDesired & 0x0020) accessFlags.push('KEY_CREATE_LINK');
                if (this.samDesired & 0x00040000) accessFlags.push('KEY_READ');
                if (this.samDesired & 0x00020000) accessFlags.push('KEY_WRITE');
                if (this.samDesired & 0x000f001f) accessFlags.push('KEY_ALL_ACCESS');

                sendOperation('reg_open', funcName, {
                    key: this.subKey,
                    access: accessFlags.join(' | '),
                    handle: hKeyResult,
                    module: getModuleName(this.returnAddress)
                });
            }
        });
    });

    // RegQueryValueExA/W
    ['RegQueryValueExA', 'RegQueryValueExW'].forEach(funcName => {
        const addr = Module.findExportByName('advapi32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.hKey = args[0].toString();
                this.valueName = args[1] ? (isWide ? args[1].readUtf16String() : args[1].readUtf8String()) : '';
            },
            onLeave: function(retval) {
                if (!shouldTrackPath(this.valueName, config.regPatterns)) return;

                const keyPath = regHandles.get(this.hKey) || this.hKey;

                sendOperation('reg_query', funcName, {
                    key: keyPath,
                    value: this.valueName,
                    result: retval.toUInt32() === 0 ? 'SUCCESS' : 'FAILED',
                    module: getModuleName(this.returnAddress)
                });
            }
        });
    });

    // RegSetValueExA/W
    ['RegSetValueExA', 'RegSetValueExW'].forEach(funcName => {
        const addr = Module.findExportByName('advapi32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.hKey = args[0].toString();
                this.valueName = args[1] ? (isWide ? args[1].readUtf16String() : args[1].readUtf8String()) : '';
                this.dataType = args[2].toUInt32();
                this.dataSize = args[4].toUInt32();
            },
            onLeave: function(retval) {
                if (!shouldTrackPath(this.valueName, config.regPatterns)) return;

                const keyPath = regHandles.get(this.hKey) || this.hKey;

                const typeNames = {
                    1: 'REG_SZ',
                    2: 'REG_EXPAND_SZ',
                    3: 'REG_BINARY',
                    4: 'REG_DWORD',
                    5: 'REG_DWORD_BE',
                    6: 'REG_LINK',
                    7: 'REG_MULTI_SZ',
                    8: 'REG_RESOURCE_LIST',
                    9: 'REG_FULL_RESOURCE_DESCRIPTOR',
                    10: 'REG_RESOURCE_REQUIREMENTS_LIST',
                    11: 'REG_QWORD'
                };

                sendOperation('reg_set', funcName, {
                    key: keyPath,
                    value: this.valueName,
                    type: typeNames[this.dataType] || 'UNKNOWN(' + this.dataType + ')',
                    size: this.dataSize,
                    result: retval.toUInt32() === 0 ? 'SUCCESS' : 'FAILED',
                    module: getModuleName(this.returnAddress)
                });
            }
        });
    });

    // RegCreateKeyExA/W
    ['RegCreateKeyExA', 'RegCreateKeyExW'].forEach(funcName => {
        const addr = Module.findExportByName('advapi32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.hKey = args[0].toString();
                this.subKey = isWide ? args[1].readUtf16String() : args[1].readUtf8String();
            },
            onLeave: function(retval) {
                if (!shouldTrackPath(this.subKey, config.regPatterns)) return;

                const keyPath = regHandles.get(this.hKey) || this.hKey;
                const fullPath = keyPath + '\\' + this.subKey;

                const hKeyResult = retval.toString();
                if (!retval.isNull()) {
                    regHandles.set(hKeyResult, fullPath);
                }

                sendOperation('reg_create', funcName, {
                    key: fullPath,
                    handle: hKeyResult,
                    result: retval.toUInt32() === 0 ? 'SUCCESS' : 'FAILED',
                    module: getModuleName(this.returnAddress)
                });
            }
        });
    });

    // RegDeleteKeyA/W
    ['RegDeleteKeyA', 'RegDeleteKeyW'].forEach(funcName => {
        const addr = Module.findExportByName('advapi32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.hKey = args[0].toString();
                this.subKey = isWide ? args[1].readUtf16String() : args[1].readUtf8String();
            },
            onLeave: function(retval) {
                if (!shouldTrackPath(this.subKey, config.regPatterns)) return;

                const keyPath = regHandles.get(this.hKey) || this.hKey;

                sendOperation('reg_delete', funcName, {
                    key: keyPath + '\\' + this.subKey,
                    result: retval.toUInt32() === 0 ? 'SUCCESS' : 'FAILED',
                    module: getModuleName(this.returnAddress)
                });
            }
        });
    });

    // Initialization
    send({
        type: 'init',
        message: 'File & Registry Monitor script loaded',
        track_content: config.trackContent,
        max_data_size: config.maxDataSize,
        file_patterns: config.filePatterns,
        reg_patterns: config.regPatterns
    });

    console.log('[*] File & Registry Monitor loaded - tracking I/O operations');
})();
