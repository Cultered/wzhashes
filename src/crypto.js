/**
 * Cryptographic Implementation using libsodium-wrappers-sumo
 * Ed25519 key generation and SHA256 hashing
 */

import sodium from 'libsodium-wrappers-sumo';

// =====================================================
// Initialize libsodium
// =====================================================

let sodiumReady = false;

export async function initCrypto() {
    await sodium.ready;
    sodiumReady = true;
    console.log('libsodium initialized successfully');
    return true;
}

export function isReady() {
    return sodiumReady;
}

// =====================================================
// SHA-256 using libsodium
// =====================================================

export const SHA256 = {
    hash: function(message) {
        if (!sodiumReady) {
            throw new Error('Sodium not ready');
        }
        return sodium.crypto_hash_sha256(message);
    }
};

// =====================================================
// Ed25519 using libsodium
// =====================================================

export const Ed25519 = {
    generateKeypair: function() {
        if (!sodiumReady) {
            throw new Error('Sodium not ready');
        }
        const keypair = sodium.crypto_sign_keypair();
        return {
            publicKey: keypair.publicKey,
            privateKey: keypair.privateKey
        };
    }
};

// =====================================================
// Base64 Encoding/Decoding (matching Python implementation)
// =====================================================

export const Base64 = {
    alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    
    encode: function(data) {
        const result = [];
        const len = data.length;
        
        // Process each 3-byte block
        for (let n = 0; n < Math.floor(len / 3); n++) {
            const block = (data[n * 3] << 16) | (data[n * 3 + 1] << 8) | data[n * 3 + 2];
            for (let i = 0; i < 4; i++) {
                const val = (block >> (6 * (3 - i))) & 0x3F;
                result.push(this.alphabet[val]);
            }
        }
        
        // Handle remaining bytes (padding)
        const remaining = len % 3;
        if (remaining > 0) {
            let block = data[Math.floor(len / 3) * 3] << 16;
            if (remaining === 2) {
                block |= data[Math.floor(len / 3) * 3 + 1] << 8;
            }
            
            for (let i = 0; i < remaining + 1; i++) {
                const val = (block >> (6 * (3 - i))) & 0x3F;
                result.push(this.alphabet[val]);
            }
            
            for (let i = 0; i < 3 - remaining; i++) {
                result.push("=");
            }
        }
        
        return result.join("");
    },
    
    decode: function(string) {
        const bytes = new Uint8Array(Math.floor(string.length / 4) * 3);
        
        for (let n = 0; n < Math.floor(string.length / 4); n++) {
            let block = 0;
            
            for (let i = 0; i < 4; i++) {
                const ch = string[i + n * 4];
                let val;
                
                if (ch >= 'A' && ch <= 'Z') {
                    val = ch.charCodeAt(0) - 'A'.charCodeAt(0);
                } else if (ch >= 'a' && ch <= 'z') {
                    val = ch.charCodeAt(0) - 'a'.charCodeAt(0) + 26;
                } else if (ch >= '0' && ch <= '9') {
                    val = ch.charCodeAt(0) - '0'.charCodeAt(0) + 52;
                } else if (ch === '+') {
                    val = 62;
                } else if (ch === '/') {
                    val = 63;
                } else {
                    val = 0;
                }
                
                block |= val << (6 * (3 - i));
            }
            
            bytes[0 + n * 3] = (block >> 16) & 0xFF;
            bytes[1 + n * 3] = (block >> 8) & 0xFF;
            bytes[2 + n * 3] = block & 0xFF;
        }
        
        // Handle padding
        let trimLength = bytes.length;
        if (string.length >= 4) {
            if (string[Math.floor(string.length / 4) * 4 - 2] === '=') {
                trimLength -= 2;
            } else if (string[Math.floor(string.length / 4) * 4 - 1] === '=') {
                trimLength -= 1;
            }
        }
        
        return bytes.slice(0, trimLength);
    }
};

// =====================================================
// Utility Functions
// =====================================================

export function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

export function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

// =====================================================
// EcKey Class (mirrors Python implementation)
// =====================================================

export class EcKey {
    static PUBLICKEYBYTES = 32;
    static SECRETKEYBYTES = 64;
    
    constructor(publicKey = null, privateKey = null) {
        this.publicKey = publicKey || new Uint8Array(0);
        this.privateKey = privateKey || new Uint8Array(0);
    }
    
    clear() {
        this.publicKey = new Uint8Array(0);
        this.privateKey = new Uint8Array(0);
    }
    
    empty() {
        return this.publicKey.length === 0;
    }
    
    hasPrivate() {
        return this.privateKey.length === EcKey.SECRETKEYBYTES;
    }
    
    toBytes(privacy) {
        if (this.empty()) {
            console.warn("WARNING: No key");
            return new Uint8Array(0);
        }
        
        if (this.publicKey.length !== EcKey.PUBLICKEYBYTES) {
            console.error(`ERROR: Invalid public key size: ${this.publicKey.length}`);
            return new Uint8Array(0);
        }
        
        if (privacy === 'public') {
            return this.publicKey;
        } else if (privacy === 'private') {
            if (this.privateKey.length !== EcKey.SECRETKEYBYTES) {
                console.error("ERROR: Failed to create external representation of private key");
                return new Uint8Array(0);
            }
            return this.privateKey;
        } else {
            console.error("FATAL: Unsupported privacy level");
            return new Uint8Array(0);
        }
    }
    
    publicHashString(truncateToLength = 0) {
        const keyBytes = this.toBytes('public');
        if (keyBytes.length === 0) {
            return "";
        }
        
        const hash = SHA256.hash(keyBytes);
        let shaStr = bytesToHex(hash);
        
        if (truncateToLength > 0 && truncateToLength < shaStr.length) {
            return shaStr.substring(0, truncateToLength);
        }
        
        return shaStr;
    }
    
    publicKeyHexString(truncateToLength = 0) {
        const keyBytes = this.toBytes('public');
        if (keyBytes.length === 0) {
            return "";
        }
        
        let hexStr = bytesToHex(keyBytes);
        
        if (truncateToLength > 0 && truncateToLength < hexStr.length) {
            return hexStr.substring(0, truncateToLength);
        }
        
        return hexStr;
    }
}
