// src/core.js
import 'react-native-get-random-values';
import { Buffer } from 'buffer';
import AsyncStorage from '@react-native-async-storage/async-storage';
import SimpleCrypto from 'react-native-simple-crypto';

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

// ---------------- KDF ----------------
async function deriveKey(passphrase, saltB64, iterations = 100000, keyLen = 32) {
    const saltU8 = base64ToU8(saltB64);
    return await SimpleCrypto.PBKDF2.hash(passphrase, saltU8, iterations, keyLen);
}

// ---------------- API ----------------

// Encrypt and store a value securely
export async function encryptAndStore(itemKey, plainText, passphrase) {
    if (!itemKey || typeof itemKey !== 'string') throw new Error('itemKey must be a non-empty string');
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase must be provided');

    const salt = newRandomBytes(16);
    const saltB64 = u8ToBase64(salt);
    const key = await deriveKey(passphrase, saltB64);

    const iv = newRandomBytes(12); // AES-GCM standard IV length
    const cipherU8 = await SimpleCrypto.AES.encrypt(plainText, key, iv);

    const payload = {
        salt: saltB64,
        iv: u8ToBase64(iv),
        ct: u8ToBase64(cipherU8),
    };

    await AsyncStorage.setItem(`${NAMESPACE}${itemKey}`, JSON.stringify(payload));
}

// Retrieve and decrypt a value (requires passphrase)
export async function getAndDecrypt(itemKey, passphrase) {
    if (!itemKey || typeof itemKey !== 'string') throw new Error('itemKey must be a non-empty string');
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase is required');

    const raw = await AsyncStorage.getItem(`${NAMESPACE}${itemKey}`);
    if (!raw) return null;

    const { salt, iv, ct } = JSON.parse(raw);
    if (!salt || !iv || !ct) throw new Error('Stored item is malformed');

    const key = await deriveKey(passphrase, salt);
    try {
        const decryptedU8 = await SimpleCrypto.AES.decrypt(base64ToU8(ct), key, base64ToU8(iv));
        return Buffer.from(decryptedU8).toString();
    } catch {
        throw new Error('Decryption failed — wrong passphrase or tampered data');
    }
}

// Remove a single item
export async function removeItem(itemKey) {
    if (!itemKey || typeof itemKey !== 'string') throw new Error('itemKey must be a non-empty string');
    await AsyncStorage.removeItem(`${NAMESPACE}${itemKey}`);
}

// Clear all stored SecureKV items
export async function clearAll() {
    const keys = await AsyncStorage.getAllKeys();
    const secureKeys = keys.filter(k => k.startsWith(NAMESPACE));
    if (secureKeys.length > 0) {
        await AsyncStorage.multiRemove(secureKeys);
    }
}

// Create verification blob (used to verify passphrase)
export async function createVerifyBlob(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase must be provided');
    await encryptAndStore('__verify__', 'ok', passphrase);
}

// Verify passphrase correctness
export async function verifyPassphrase(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') throw new Error('passphrase is required');

    const raw = await AsyncStorage.getItem(`${NAMESPACE}__verify__`);
    if (!raw) return false;

    const { salt, iv, ct } = JSON.parse(raw);
    if (!salt || !iv || !ct) return false;

    try {
        const key = await deriveKey(passphrase, salt);
        await SimpleCrypto.AES.decrypt(base64ToU8(ct), key, base64ToU8(iv));
        return true;
    } catch {
        return false;
    }
}
