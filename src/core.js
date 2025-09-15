// src/core.js
import 'react-native-get-random-values';
import { Buffer } from 'buffer';
import AsyncStorage from '@react-native-async-storage/async-storage';
import AesGcmCrypto from 'react-native-aes-gcm-crypto';
import Argon2 from "react-native-argon2";

const NAMESPACE = '@securekv:v1:';

// ---------------- Utils ----------------
function u8ToBase64(u8) {
    return Buffer.from(u8).toString('base64');
}

function newRandomBytes(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return a;
}

// Derive encryption key using Argon2
async function deriveKeyArgon2(passphrase, saltB64, opts = {}) {
    if (!passphrase || typeof passphrase !== "string") {
        throw new Error("passphrase must be a non-empty string for key derivation");
    }

    const {
        time = 2,
        mem = 65536,
        parallelism = 1,
        hashLen = 32,
    } = opts;

    try {
        const res = await Argon2.hash({
            password: passphrase,
            salt: saltB64,
            iterations: time,
            memory: mem,
            parallelism,
            hashLength: hashLen,
        });

        // base64 string, suitable for AES key
        return res.rawHash;
    } catch (err) {
        console.error("Argon2 key derivation failed:", err);
        throw err;
    }
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
        kdf: 'react-native-argon2',   // 🔥 updated
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
        const plain = await AesGcmCrypto.decrypt(ct, keyB64, iv, tag, false);
        return plain;
    } catch {
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

// Create verification blob
export async function createVerifyBlob(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be provided to create verify blob');
    }
    await encryptAndStore('__verify__', 'ok', passphrase);
}

// Verify passphrase
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
