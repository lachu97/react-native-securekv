// src/core.js
import 'react-native-get-random-values';
import { Buffer } from 'buffer';
import AsyncStorage from '@react-native-async-storage/async-storage';
import SimpleCrypto from 'react-native-simple-crypto';
import argon2 from 'react-native-argon2';

const NAMESPACE = '@securekv:v1:';

// ---------------- Utils ----------------
function u8ToBase64(u8) {
    return Buffer.from(u8).toString('base64');
}

function base64ToU8(b64) {
    return Uint8Array.from(Buffer.from(b64, 'base64'));
}

function newRandomBytes(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return a;
}

// ---------------- KDF (Argon2) ----------------
async function deriveKeyArgon2(passphrase, saltB64, opts = {}) {
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be a non-empty string for key derivation');
    }

    const { time = 2, mem = 65536, parallelism = 1, hashLen = 32, mode = 'argon2id' } = opts;

    try {
        const saltU8 = base64ToU8(saltB64);

        const res = await argon2(passphrase, saltU8, {
            iterations: time,
            memory: mem,
            parallelism,
            hashLength: hashLen,
            mode,
        });

        // Convert hex string to Uint8Array for AES key
        return Uint8Array.from(Buffer.from(res.rawHash, 'hex'));
    } catch (err) {
        console.error('Argon2 key derivation failed:', err);
        throw new Error('Key derivation failed');
    }
}

// ---------------- API ----------------
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
    const keyU8 = await deriveKeyArgon2(passphrase, saltB64, kdfParams);

    const iv = newRandomBytes(12); // AES-GCM nonce
    const cipher = await SimpleCrypto.AES.encrypt(plainString, keyU8, iv);

    const payload = {
        version: 'v1',
        alg: 'AES-256-GCM',
        kdf: 'react-native-argon2',
        kdfParams,
        salt: saltB64,
        iv: u8ToBase64(iv),
        ct: u8ToBase64(cipher),
    };

    await AsyncStorage.setItem(`${NAMESPACE}${itemKey}`, JSON.stringify(payload));
}

export async function getAndDecrypt(itemKey, passphrase) {
    if (!itemKey || typeof itemKey !== 'string') {
        throw new Error('itemKey must be a non-empty string');
    }
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase is required to decrypt item');
    }

    const raw = await AsyncStorage.getItem(`${NAMESPACE}${itemKey}`);
    if (!raw) return null;

    const payload = JSON.parse(raw);
    const { salt, kdfParams, iv, ct } = payload;

    if (!salt || !ct || !iv) {
        throw new Error('Stored item is malformed');
    }

    const keyU8 = await deriveKeyArgon2(passphrase, salt, kdfParams);
    const ivU8 = base64ToU8(iv);
    const cipherU8 = base64ToU8(ct);

    try {
        const decrypted = await SimpleCrypto.AES.decrypt(cipherU8, keyU8, ivU8);
        return decrypted;
    } catch {
        throw new Error('Decryption failed — wrong passphrase or tampered data');
    }
}

export async function removeItem(itemKey) {
    if (!itemKey || typeof itemKey !== 'string') {
        throw new Error('itemKey must be a non-empty string');
    }
    await AsyncStorage.removeItem(`${NAMESPACE}${itemKey}`);
}

export async function clearAll() {
    const keys = await AsyncStorage.getAllKeys();
    const secureKeys = keys.filter(k => k.startsWith(NAMESPACE));
    if (secureKeys.length > 0) {
        await AsyncStorage.multiRemove(secureKeys);
    }
}

export async function createVerifyBlob(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be provided to create verify blob');
    }
    await encryptAndStore('__verify__', 'ok', passphrase);
}

export async function verifyPassphrase(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase is required to verify');
    }

    const raw = await AsyncStorage.getItem(`${NAMESPACE}__verify__`);
    if (!raw) return false;

    const payload = JSON.parse(raw);
    const { salt, kdfParams, iv, ct } = payload;

    try {
        const keyU8 = await deriveKeyArgon2(passphrase, salt, kdfParams);
        const ivU8 = base64ToU8(iv);
        const ctU8 = base64ToU8(ct);
        await SimpleCrypto.AES.decrypt(ctU8, keyU8, ivU8);
        return true;
    } catch {
        return false;
    }
}
