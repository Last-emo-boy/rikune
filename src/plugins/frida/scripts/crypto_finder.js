/**
 * Crypto Finder Script for Frida
 *
 * Detects cryptographic API usage including:
 * - Windows CryptoAPI (CryptoAPI)
 * - BCrypt (CNG - Cryptography Next Generation)
 * - OpenSSL functions
 * - Custom crypto implementations (AES, RC4, etc.)
 * - Hashing functions (MD5, SHA1, SHA256, etc.)
 * - Random number generation
 *
 * Useful for identifying ransomware, info stealers, and C2 encryption.
 */

(function() {
    const config = {
        trackData: typeof SCRIPT_PARAMS !== 'undefined' ? (SCRIPT_PARAMS.trackData || false) : false,
        modules: typeof SCRIPT_PARAMS !== 'undefined' ? (SCRIPT_PARAMS.modules || []) : [],
    };

    let cryptoCallCount = 0;
    const cryptoOperations = [];

    function shouldTraceModule(moduleName) {
        if (config.modules.length === 0) return true;
        return config.modules.some(m => moduleName.toLowerCase().includes(m.toLowerCase()));
    }

    function sendCryptoEvent(category, func, module, args) {
        cryptoCallCount++;
        send({
            type: 'crypto_operation',
            category: category,
            function: func,
            module: module,
            args: args,
            timestamp: Date.now(),
            thread_id: this.threadId
        });
    }

    // Helper to get module name from return address
    function getModuleName(returnAddr) {
        try {
            const mod = Process.findModuleByAddress(returnAddr);
            return mod ? mod.name : 'unknown';
        } catch (e) {
            return 'unknown';
        }
    }

    // === Windows CryptoAPI ===
    const cryptoApiFunctions = [
        // Context acquisition
        { name: 'CryptAcquireContextA', dll: 'advapi32.dll', category: 'context', wide: false },
        { name: 'CryptAcquireContextW', dll: 'advapi32.dll', category: 'context', wide: true },
        { name: 'CryptReleaseContext', dll: 'advapi32.dll', category: 'context' },

        // Key operations
        { name: 'CryptGenKey', dll: 'advapi32.dll', category: 'key' },
        { name: 'CryptImportKey', dll: 'advapi32.dll', category: 'key' },
        { name: 'CryptExportKey', dll: 'advapi32.dll', category: 'key' },
        { name: 'CryptDestroyKey', dll: 'advapi32.dll', category: 'key' },
        { name: 'CryptDuplicateKey', dll: 'advapi32.dll', category: 'key' },
        { name: 'CryptGetKeyParam', dll: 'advapi32.dll', category: 'key' },
        { name: 'CryptSetKeyParam', dll: 'advapi32.dll', category: 'key' },

        // Encryption/Decryption
        { name: 'CryptEncrypt', dll: 'advapi32.dll', category: 'encrypt' },
        { name: 'CryptDecrypt', dll: 'advapi32.dll', category: 'decrypt' },

        // Hashing
        { name: 'CryptCreateHash', dll: 'advapi32.dll', category: 'hash' },
        { name: 'CryptHashData', dll: 'advapi32.dll', category: 'hash' },
        { name: 'CryptHashSessionKey', dll: 'advapi32.dll', category: 'hash' },
        { name: 'CryptGetHashParam', dll: 'advapi32.dll', category: 'hash' },
        { name: 'CryptDestroyHash', dll: 'advapi32.dll', category: 'hash' },

        // Certificate
        { name: 'CryptVerifySignatureA', dll: 'advapi32.dll', category: 'verify', wide: false },
        { name: 'CryptVerifySignatureW', dll: 'advapi32.dll', category: 'verify', wide: true },
        { name: 'CryptSignHashA', dll: 'advapi32.dll', category: 'sign', wide: false },
        { name: 'CryptSignHashW', dll: 'advapi32.dll', category: 'sign', wide: true },
    ];

    cryptoApiFunctions.forEach(func => {
        const addr = Module.findExportByName(func.dll, func.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                const moduleName = getModuleName(this.returnAddress);
                if (!shouldTraceModule(moduleName)) return;

                let argSummary = [];
                try {
                    switch (func.category) {
                        case 'context':
                            if (func.name.includes('Acquire')) {
                                argSummary = [func.wide ? args[0].readUtf16String() : (args[0].isNull() ? 'NULL' : args[0].readUtf8String())];
                            }
                            break;
                        case 'encrypt':
                        case 'decrypt':
                            argSummary = ['hKey: ' + args[0], 'data_len: ' + args[3].readU32()];
                            break;
                        case 'hash':
                            if (func.name.includes('HashData')) {
                                argSummary = ['data_len: ' + args[2].toUInt32()];
                            }
                            break;
                    }
                } catch (e) {
                    argSummary = ['[...]'];
                }

                sendCryptoEvent(func.category, func.name, moduleName, argSummary);
            }
        });
    });

    // === BCrypt (CNG) ===
    const bcryptFunctions = [
        { name: 'BCryptOpenAlgorithmProvider', dll: 'bcrypt.dll', category: 'context' },
        { name: 'BCryptCloseAlgorithmProvider', dll: 'bcrypt.dll', category: 'context' },
        { name: 'BCryptGenerateSymmetricKey', dll: 'bcrypt.dll', category: 'key' },
        { name: 'BCryptGenerateKeyPair', dll: 'bcrypt.dll', category: 'key' },
        { name: 'BCryptEncrypt', dll: 'bcrypt.dll', category: 'encrypt' },
        { name: 'BCryptDecrypt', dll: 'bcrypt.dll', category: 'decrypt' },
        { name: 'BCryptHash', dll: 'bcrypt.dll', category: 'hash' },
        { name: 'BCryptCreateHash', dll: 'bcrypt.dll', category: 'hash' },
        { name: 'BCryptDestroyHash', dll: 'bcrypt.dll', category: 'hash' },
        { name: 'BCryptHashData', dll: 'bcrypt.dll', category: 'hash' },
        { name: 'BCryptHashFinish', dll: 'bcrypt.dll', category: 'hash' },
        { name: 'BCryptSignHash', dll: 'bcrypt.dll', category: 'sign' },
        { name: 'BCryptVerifySignature', dll: 'bcrypt.dll', category: 'verify' },
        { name: 'BCryptGenRandom', dll: 'bcrypt.dll', category: 'random' },
    ];

    bcryptFunctions.forEach(func => {
        const addr = Module.findExportByName(func.dll, func.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                const moduleName = getModuleName(this.returnAddress);
                if (!shouldTraceModule(moduleName)) return;

                let argSummary = [];
                try {
                    if (func.name.includes('Encrypt') || func.name.includes('Decrypt')) {
                        argSummary = ['hKey: ' + args[0], 'data_len: ' + args[5].toUInt32()];
                    } else if (func.name.includes('GenRandom')) {
                        argSummary = ['cbBuffer: ' + args[1].toUInt32()];
                    }
                } catch (e) {
                    argSummary = ['[...]'];
                }

                sendCryptoEvent(func.category, func.name, moduleName, argSummary);
            }
        });
    });

    // === OpenSSL (common functions) ===
    const opensslFunctions = [
        { name: 'EVP_EncryptInit', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'EVP_EncryptUpdate', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'EVP_EncryptFinal', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'EVP_DecryptInit', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'EVP_DecryptUpdate', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'EVP_DecryptFinal', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'EVP_MD5', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'EVP_SHA1', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'EVP_SHA256', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'AES_set_encrypt_key', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'AES_set_decrypt_key', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'AES_encrypt', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'AES_decrypt', dll: 'libcrypto.dll', category: 'openssl' },
        { name: 'RC4', dll: 'libcrypto.dll', category: 'openssl' },
    ];

    opensslFunctions.forEach(func => {
        const addr = Module.findExportByName(func.dll, func.name);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                const moduleName = getModuleName(this.returnAddress);
                if (!shouldTraceModule(moduleName)) return;

                sendCryptoEvent(func.category, func.name, moduleName, ['[...]']);
            }
        });
    });

    // === RtlRandom / RtlRandomEx ===
    const rtlRandom = Module.findExportByName('ntdll.dll', 'RtlRandomEx');
    if (rtlRandom) {
        Interceptor.attach(rtlRandom, {
            onLeave: function(retval) {
                sendCryptoEvent('random', 'RtlRandomEx', 'ntdll.dll', ['result: ' + retval.toUInt32()]);
            }
        });
    }

    // Summary on exit
    send({
        type: 'init',
        message: 'Crypto Finder script loaded',
        track_data: config.trackData,
        modules_filter: config.modules
    });

    console.log('[*] Crypto Finder loaded - monitoring cryptographic operations');
})();
