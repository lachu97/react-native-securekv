// src/core.js
import 'react-native-get-random-values';
import { Buffer } from 'buffer';
import AsyncStorage from '@react-native-async-storage/async-storage';
import RNSimpleCrypto from 'react-native-simple-crypto';
import argon2 from 'react-native-argon2';

const NAMESPACE = '@securekv:v1:';

// ---------- Utils ----------
function u8ToBase64(u8) {
    return Buffer.from(u8).toString('base64');
}

function base64ToU8(b64) {
    return Uint8Array.from(Buffer.from(b64, 'base64'));
}

function newRandomBytes(length) {
    const arr = new Uint8Array(length);
    crypto.getRandomValues(arr);
    return arr;
}

// ---------- Key Derivation ----------
async function deriveKeyArgon2(passphrase, saltB64, opts = {}) {
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be a non-empty string');
    }

    const saltU8 = base64ToU8(saltB64);

    const { time = 2, mem = 65536, parallelism = 1, hashLen = 32, mode = 'argon2id' } = opts;

    try {
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

// ---------- API ----------

// Encrypt and store a value
export async function encryptAndStore(itemKey, plainText, passphrase, options = {}) {
    if (!itemKey || typeof itemKey !== 'string') throw new Error('itemKey must be a string');
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase required');

    const salt = newRandomBytes(16);
    const saltB64 = u8ToBase64(salt);

    const kdfParams = options.kdfParams || { time: 2, mem: 65536, parallelism: 1, hashLen: 32 };
    const aesKey = await deriveKeyArgon2(passphrase, saltB64, kdfParams);

    const iv = newRandomBytes(12); // AES-GCM standard IV length
    const cipher = await RNSimpleCrypto.AES.encrypt(plainText, aesKey, iv);

    const payload = {
        version: 'v1',
        alg: 'AES-256-GCM',
        kdf: 'argon2',
        kdfParams,
        salt: saltB64,
        iv: u8ToBase64(iv),
        ct: u8ToBase64(cipher),
    };

    await AsyncStorage.setItem(`${NAMESPACE}${itemKey}`, JSON.stringify(payload));
}

// Retrieve and decrypt a value
export async function getAndDecrypt(itemKey, passphrase) {
    if (!itemKey || typeof itemKey !== 'string') throw new Error('itemKey must be a string');
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase required');

    const raw = await AsyncStorage.getItem(`${NAMESPACE}${itemKey}`);
    if (!raw) return null;

    const { salt, kdfParams, iv, ct } = JSON.parse(raw);
    if (!salt || !ct || !iv) throw new Error('Stored item is malformed');

    const aesKey = await deriveKeyArgon2(passphrase, salt, kdfParams);

    try {
        const decrypted = await RNSimpleCrypto.AES.decrypt(base64ToU8(ct), aesKey, base64ToU8(iv));
        return decrypted;
    } catch {
        throw new Error('Decryption failed — wrong passphrase or tampered data');
    }
}

// Remove one item
export async function removeItem(itemKey) {
    if (!itemKey || typeof itemKey !== 'string') throw new Error('itemKey must be a string');
    await AsyncStorage.removeItem(`${NAMESPACE}${itemKey}`);
}

// Clear all SecureKV items
export async function clearAll() {
    const keys = await AsyncStorage.getAllKeys();
    const secureKeys = keys.filter(k => k.startsWith(NAMESPACE));
    if (secureKeys.length > 0) await AsyncStorage.multiRemove(secureKeys);
}

// Create verify blob
export async function createVerifyBlob(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase required');
    await encryptAndStore('__verify__', 'ok', passphrase);
}

// Verify passphrase
export async function verifyPassphrase(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase required');

    const raw = await AsyncStorage.getItem(`${NAMESPACE}__verify__`);
    if (!raw) return false;

    const { salt, kdfParams, iv, ct } = JSON.parse(raw);
    const aesKey = await deriveKeyArgon2(passphrase, salt, kdfParams || {});

    try {
        await RNSimpleCrypto.AES.decrypt(base64ToU8(ct), aesKey, base64ToU8(iv));
        return true;
    } catch {
        return false;
    }
}
