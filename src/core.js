// src/core.js
import 'react-native-get-random-values';
import { Buffer } from 'buffer';
import AsyncStorage from '@react-native-async-storage/async-storage';
import AesGcmCrypto from 'react-native-aes-gcm-crypto';
import argon2 from 'argon2-wasm';

const NAMESPACE = '@securekv:v1:';

// ---------------- Utils ----------------
function u8ToBase64(u8) {
    return Buffer.from(u8).toString('base64');
}

function hexToBase64(hex) {
    return Buffer.from(hex, 'hex').toString('base64');
}

function base64ToHex(b64) {
    return Buffer.from(b64, 'base64').toString('hex');
}

function newRandomBytes(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return a;
}

// Derive encryption key using Argon2
async function deriveKeyArgon2(passphrase, saltB64, opts = {}) {
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be a non-empty string for key derivation');
    }

    const {
        time = 2,
        mem = 65536,
        parallelism = 1,
        hashLen = 32,
        type = argon2.ArgonType.Argon2id
    } = opts;

    const res = await argon2.hash({
        pass: passphrase,
        salt: saltB64,
        time,
        mem,
        hashLen,
        type
    });

    return hexToBase64(res.hashHex);
}

// ---------------- API ----------------

// Encrypt value and store
export async function encryptAndStore(itemKey, plainString, passphrase, options = {}) {
    if (!itemKey || typeof itemKey !== 'string') {
        throw new Error('itemKey must be a non-empty string');
    }
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be provided to encrypt data');
    }

    const salt = newRandomBytes(16);
    const saltB64 = u8ToBase64(salt);

    const kdfParams = options.kdfParams || { time: 2, mem: 65536, parallelism: 1, hashLen: 32 };
    const keyB64 = await deriveKeyArgon2(passphrase, saltB64, kdfParams);

    const enc = await AesGcmCrypto.encrypt(plainString, false, keyB64);

    const payload = {
        version: 'v1',
        alg: 'AES-256-GCM',
        kdf: 'argon2-wasm',
        kdfParams,
        salt: saltB64,
        iv: enc.iv,
        tag: enc.tag,
        ct: enc.content
    };

    await AsyncStorage.setItem(`${NAMESPACE}${itemKey}`, JSON.stringify(payload));
}

// Retrieve and decrypt (requires passphrase)
export async function getAndDecrypt(itemKey, passphrase) {
    if (!itemKey || typeof itemKey !== 'string') {
        throw new Error('itemKey must be a non-empty string');
    }
    if (!passphrase || typeof passphrase !== 'string') {
        // STRICT: refuse to return any ciphertext if passphrase not supplied
        throw new Error('passphrase is required to decrypt item');
    }

    const raw = await AsyncStorage.getItem(`${NAMESPACE}${itemKey}`);
    if (!raw) return null;

    const payload = JSON.parse(raw);
    const { salt, kdfParams, iv, tag, ct } = payload;

    if (!salt || !ct) {
        throw new Error('Stored item is malformed');
    }

    const keyB64 = await deriveKeyArgon2(passphrase, salt, kdfParams);

    try {
        // AesGcmCrypto.decrypt(ct, key, iv, tag, isBinary?) has different signatures between libs;
        // our earlier usage was AesGcmCrypto.decrypt(ct, keyB64, iv, tag, false)
        // Some versions of the library use (ct, false, key) etc. If your AES lib signature differs,
        // update call accordingly.
        const plain = await AesGcmCrypto.decrypt(ct, keyB64, iv, tag, false);
        return plain;
    } catch (err) {
        // Do not leak details — generic error message is better
        throw new Error('Decryption failed — wrong passphrase or tampered data');
    }
}

// Remove one item
export async function removeItem(itemKey) {
    if (!itemKey || typeof itemKey !== 'string') {
        throw new Error('itemKey must be a non-empty string');
    }
    await AsyncStorage.removeItem(`${NAMESPACE}${itemKey}`);
}

// Clear all SecureKV items
export async function clearAll() {
    const keys = await AsyncStorage.getAllKeys();
    const secureKeys = keys.filter(k => k.startsWith(NAMESPACE));
    if (secureKeys.length > 0) {
        await AsyncStorage.multiRemove(secureKeys);
    }
}

// Create verification blob (for checking passphrase correctness)
// This stores an encrypted known-string under __verify__, and requires passphrase to decrypt.
export async function createVerifyBlob(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be provided to create verify blob');
    }
    await encryptAndStore('__verify__', 'ok', passphrase);
}

// Verify passphrase by trying to decrypt the verify blob.
// Returns true if passphrase can decrypt, false otherwise.
export async function verifyPassphrase(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase is required to verify');
    }

    const raw = await AsyncStorage.getItem(`${NAMESPACE}__verify__`);
    if (!raw) return false;

    const payload = JSON.parse(raw);
    const { salt, kdfParams, iv, tag, ct } = payload;

    const keyB64 = await deriveKeyArgon2(passphrase, salt, kdfParams || {});
    try {
        await AesGcmCrypto.decrypt(ct, keyB64, iv, tag, false);
        return true;
    } catch {
        return false;
    }
}
