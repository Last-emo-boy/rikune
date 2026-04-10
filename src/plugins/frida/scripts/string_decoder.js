/**
 * String Decoder Script for Frida
 *
 * Captures decrypted/decoded strings at runtime by intercepting:
 * - String copy operations (strcpy, strncpy, wcscpy, etc.)
 * - String length calculations (strlen, lstrlen, etc.)
 * - String comparison (strcmp, strncmp, etc.)
 * - Memory operations that may involve strings (memcpy, memmove)
 * - Format string operations (sprintf, printf, etc.)
 *
 * Useful for detecting unpacked strings from packed/obfuscated malware.
 */

(function() {
    const config = {
        minStringLength: typeof SCRIPT_PARAMS !== 'undefined' ? (SCRIPT_PARAMS.minLength || 4) : 4,
        captureAll: typeof SCRIPT_PARAMS !== 'undefined' ? SCRIPT_PARAMS.captureAll : false,
    };

    let stringCount = 0;
    const seenStrings = new Set();

    // Helper to validate and dedupe strings
    function isValidString(str) {
        if (!str || str.length < config.minStringLength) return false;
        if (seenStrings.has(str)) return false;

        // Check for printable characters
        const printable = /^[\x20-\x7E\u0080-\uFFFF]+$/;
        if (!printable.test(str)) return false;

        // Limit length
        if (str.length > 500) return false;

        seenStrings.add(str);
        return true;
    }

    function sendString(source, func, str, encoding = 'utf8') {
        stringCount++;
        send({
            type: 'string_detected',
            source: source,
            function: func,
            value: str.substring(0, 200),
            length: str.length,
            encoding: encoding,
            timestamp: Date.now()
        });
    }

    // String length functions - capture on entry
    const lengthFunctions = [
        { name: 'strlen', dll: 'msvcrt.dll', wide: false },
        { name: 'lstrlenA', dll: 'kernel32.dll', wide: false },
        { name: 'lstrlenW', dll: 'kernel32.dll', wide: true },
        { name: 'wcslen', dll: 'msvcrt.dll', wide: true },
    ];

    lengthFunctions.forEach(func => {
        const addr = Module.findExportByName(func.dll, func.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    const str = func.wide ? args[0].readUtf16String() : args[0].readUtf8String();
                    if (isValidString(str)) {
                        sendString('length', func.name, str, func.wide ? 'utf16' : 'utf8');
                    }
                } catch (e) {}
            }
        });
    });

    // String copy functions - capture destination string on return
    const copyFunctions = [
        { name: 'strcpy', dll: 'msvcrt.dll', wide: false },
        { name: 'strncpy', dll: 'msvcrt.dll', wide: false },
        { name: 'wcscpy', dll: 'msvcrt.dll', wide: true },
        { name: 'wcsncpy', dll: 'msvcrt.dll', wide: true },
        { name: 'strcat', dll: 'msvcrt.dll', wide: false },
        { name: 'strncat', dll: 'msvcrt.dll', wide: false },
    ];

    copyFunctions.forEach(func => {
        const addr = Module.findExportByName(func.dll, func.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onLeave: function(retval) {
                try {
                    const str = func.wide ? retval.readUtf16String() : retval.readUtf8String();
                    if (isValidString(str)) {
                        sendString('copy', func.name, str, func.wide ? 'utf16' : 'utf8');
                    }
                } catch (e) {}
            }
        });
    });

    // String comparison functions
    const compareFunctions = [
        { name: 'strcmp', dll: 'msvcrt.dll', wide: false },
        { name: 'strncmp', dll: 'msvcrt.dll', wide: false },
        { name: 'wcscmp', dll: 'msvcrt.dll', wide: true },
        { name: 'wcsncmp', dll: 'msvcrt.dll', wide: true },
        { name: '_stricmp', dll: 'msvcrt.dll', wide: false },
        { name: '_wcsicmp', dll: 'msvcrt.dll', wide: true },
    ];

    compareFunctions.forEach(func => {
        const addr = Module.findExportByName(func.dll, func.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    const str1 = func.wide ? args[0].readUtf16String() : args[0].readUtf8String();
                    const str2 = func.wide ? args[1].readUtf16String() : args[1].readUtf8String();
                    if (isValidString(str1)) {
                        sendString('compare_arg1', func.name, str1, func.wide ? 'utf16' : 'utf8');
                    }
                    if (isValidString(str2)) {
                        sendString('compare_arg2', func.name, str2, func.wide ? 'utf16' : 'utf8');
                    }
                } catch (e) {}
            }
        });
    });

    // Format string functions
    const formatFunctions = [
        { name: 'sprintf', dll: 'msvcrt.dll' },
        { name: 'swprintf', dll: 'msvcrt.dll', wide: true },
        { name: 'snprintf', dll: 'msvcrt.dll' },
        { name: '_snprintf', dll: 'msvcrt.dll' },
    ];

    formatFunctions.forEach(func => {
        const addr = Module.findExportByName(func.dll, func.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onLeave: function(retval) {
                try {
                    const str = func.wide ? retval.readUtf16String() : retval.readUtf8String();
                    if (isValidString(str)) {
                        sendString('format_result', func.name, str, func.wide ? 'utf16' : 'utf8');
                    }
                } catch (e) {}
            }
        });
    });

    // Memory functions that might contain strings
    const memFunctions = [
        { name: 'memcpy', dll: 'msvcrt.dll' },
        { name: 'memmove', dll: 'msvcrt.dll' },
        { name: 'memset', dll: 'msvcrt.dll' },
    ];

    memFunctions.forEach(func => {
        const addr = Module.findExportByName(func.dll, func.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                // Only capture if size is reasonable for a string
                const size = args[2].toUInt32();
                if (size < config.minStringLength || size > 1024) return;

                try {
                    const ptr = args[1]; // Source pointer
                    const str = ptr.readUtf8String(size);
                    if (isValidString(str)) {
                        sendString('memory_op', func.name, str, 'utf8');
                    }
                } catch (e) {}
            }
        });
    });

    // OutputDebugString - often used for string debugging
    ['OutputDebugStringA', 'OutputDebugStringW'].forEach(funcName => {
        const addr = Module.findExportByName('kernel32.dll', funcName);
        if (!addr) return;

        const isWide = funcName.endsWith('W');
        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    const str = isWide ? args[0].readUtf16String() : args[0].readUtf8String();
                    if (isValidString(str)) {
                        sendString('debug_output', funcName, str, isWide ? 'utf16' : 'utf8');
                    }
                } catch (e) {}
            }
        });
    });

    send({
        type: 'init',
        message: 'String Decoder script loaded',
        min_length: config.minStringLength,
        capture_all: config.captureAll
    });

    console.log('[*] String Decoder loaded - capturing strings (min length: ' + config.minStringLength + ')');
})();
