// src/core.js
import 'react-native-get-random-values';
import { Buffer } from 'buffer';
import AsyncStorage from '@react-native-async-storage/async-storage';
import argon2 from 'react-native-argon2';
import RNSimpleCrypto from 'react-native-simple-crypto';

const NAMESPACE = '@securekv:v1:';

// ---------------- Utils ----------------
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

// ---------------- Argon2 Key Derivation ----------------
async function deriveKeyArgon2(passphrase, saltB64, opts = {}) {
    const { time = 2, mem = 65536, parallelism = 1, hashLen = 32, type = 'argon2id' } = opts;

    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be a non-empty string');
    }

    try {
        // argon2(pass, salt, config) returns hex string
        const derivedKeyHex = await argon2(passphrase, saltB64, {
            iterations: time,
            memory: mem,
            parallelism,
            hashLength: hashLen,
            type,
        });

        // convert hex -> base64 (for AES-GCM key)
        return Buffer.from(derivedKeyHex, 'hex').toString('base64');
    } catch (err) {
        console.error('Argon2 key derivation failed:', err);
        throw err;
    }
}

// ---------------- AES-GCM Encryption ----------------
async function aesGcmEncrypt(plaintext, keyB64) {
    const keyU8 = base64ToU8(keyB64);
    const iv = newRandomBytes(12); // 96-bit nonce
    const textU8 = Buffer.from(plaintext, 'utf8');

    const cipherBuffer = await RNSimpleCrypto.AES.encrypt(
        textU8,
        keyU8,
        iv
    );

    return {
        iv: u8ToBase64(iv),
        ct: u8ToBase64(cipherBuffer),
    };
}

async function aesGcmDecrypt(ctB64, keyB64, ivB64) {
    const keyU8 = base64ToU8(keyB64);
    const ivU8 = base64ToU8(ivB64);
    const ctU8 = base64ToU8(ctB64);

    const decryptedU8 = await RNSimpleCrypto.AES.decrypt(ctU8, keyU8, ivU8);
    return Buffer.from(decryptedU8).toString('utf8');
}

// ---------------- API ----------------

// Encrypt & store a value
export async function encryptAndStore(itemKey, plainString, passphrase, options = {}) {
    if (!itemKey || typeof itemKey !== 'string') throw new Error('itemKey must be a non-empty string');
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase must be provided');

    const salt = newRandomBytes(16);
    const saltB64 = u8ToBase64(salt);

    const kdfParams = options.kdfParams || { time: 2, mem: 65536, parallelism: 1, hashLen: 32 };
    const keyB64 = await deriveKeyArgon2(passphrase, saltB64, kdfParams);

    const enc = await aesGcmEncrypt(plainString, keyB64);

    const payload = {
        version: 'v1',
        alg: 'AES-256-GCM',
        kdf: 'react-native-argon2',
        kdfParams,
        salt: saltB64,
        iv: enc.iv,
        ct: enc.ct,
    };

    await AsyncStorage.setItem(`${NAMESPACE}${itemKey}`, JSON.stringify(payload));
}

// Retrieve & decrypt a value
export async function getAndDecrypt(itemKey, passphrase) {
    if (!itemKey || typeof itemKey !== 'string') throw new Error('itemKey must be a non-empty string');
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase is required');

    const raw = await AsyncStorage.getItem(`${NAMESPACE}${itemKey}`);
    if (!raw) return null;

    const payload = JSON.parse(raw);
    const { salt, kdfParams, iv, ct } = payload;

    if (!salt || !ct) throw new Error('Stored item is malformed');

    const keyB64 = await deriveKeyArgon2(passphrase, salt, kdfParams);
    try {
        return await aesGcmDecrypt(ct, keyB64, iv);
    } catch {
        throw new Error('Decryption failed — wrong passphrase or tampered data');
    }
}

// Remove single item
export async function removeItem(itemKey) {
    if (!itemKey || typeof itemKey !== 'string') throw new Error('itemKey must be a non-empty string');
    await AsyncStorage.removeItem(`${NAMESPACE}${itemKey}`);
}

// Clear all SecureKV items
export async function clearAll() {
    const keys = await AsyncStorage.getAllKeys();
    const secureKeys = keys.filter(k => k.startsWith(NAMESPACE));
    if (secureKeys.length) await AsyncStorage.multiRemove(secureKeys);
}

// Create verify blob
export async function createVerifyBlob(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase must be provided');
    await encryptAndStore('__verify__', 'ok', passphrase);
}

// Verify passphrase
export async function verifyPassphrase(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase is required');

    const raw = await AsyncStorage.getItem(`${NAMESPACE}__verify__`);
    if (!raw) return false;

    const { salt, kdfParams, iv, ct } = JSON.parse(raw);
    const keyB64 = await deriveKeyArgon2(passphrase, salt, kdfParams || {});

    try {
        await aesGcmDecrypt(ct, keyB64, iv);
        return true;
    } catch {
        return false;
    }
}
