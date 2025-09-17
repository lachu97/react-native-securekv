// src/core.js
import 'react-native-get-random-values';
import AsyncStorage from '@react-native-async-storage/async-storage';
import SimpleCrypto from 'react-native-simple-crypto';

const NAMESPACE = '@securekv:v1:';

// ---------------- API ----------------

// Encrypt and store a value securely
export async function encryptAndStore(itemKey, plainText, passphrase) {
    if (!itemKey || typeof itemKey !== 'string') {
        throw new Error('itemKey must be a non-empty string');
    }
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be provided');
    }

    // generate salt and iv using utils.randomBytes
    const saltBuf = await SimpleCrypto.utils.randomBytes(16);
    const saltB64 = SimpleCrypto.utils.convertArrayBufferToBase64(saltBuf);

    // derive key using PBKDF2.hash(password: string, salt: ArrayBuffer, iterations: number, keyLength: number, hash: string)
    const keyBuf = await SimpleCrypto.PBKDF2.hash(
        passphrase,
        saltBuf,
        100000,
        32,
        'SHA256',
    );

    const ivBuf = await SimpleCrypto.utils.randomBytes(16);

    // convert plaintext to ArrayBuffer
    const plainBuf = SimpleCrypto.utils.convertUtf8ToArrayBuffer(plainText);

    // encrypt
    const cipherBuf = await SimpleCrypto.AES.encrypt(plainBuf, keyBuf, ivBuf);

    const payload = {
        salt: saltB64,
        iv: SimpleCrypto.utils.convertArrayBufferToBase64(ivBuf),
        ct: SimpleCrypto.utils.convertArrayBufferToBase64(cipherBuf),
    };

    await AsyncStorage.setItem(`${NAMESPACE}${itemKey}`, JSON.stringify(payload));
}

// Retrieve and decrypt a value (requires passphrase)
export async function getAndDecrypt(itemKey, passphrase) {
    if (!itemKey || typeof itemKey !== 'string') {
        throw new Error('itemKey must be a non-empty string');
    }
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase is required');
    }

    const raw = await AsyncStorage.getItem(`${NAMESPACE}${itemKey}`);
    if (!raw) {
        return null;
    }

    const {salt, iv, ct} = JSON.parse(raw);
    if (!salt || !iv || !ct) {
        throw new Error('Stored item is malformed');
    }

    // convert salt, iv, ct from Base64 to ArrayBuffer
    const saltBuf = SimpleCrypto.utils.convertBase64ToArrayBuffer(salt);
    const ivBuf = SimpleCrypto.utils.convertBase64ToArrayBuffer(iv);
    const ctBuf = SimpleCrypto.utils.convertBase64ToArrayBuffer(ct);

    const keyBuf = await SimpleCrypto.PBKDF2.hash(
        passphrase,
        saltBuf,
        100000,
        32,
        'SHA256',
    );

    try {
        const decryptedBuf = await SimpleCrypto.AES.decrypt(ctBuf, keyBuf, ivBuf);
        const decryptedText =
            SimpleCrypto.utils.convertArrayBufferToUtf8(decryptedBuf);
        return decryptedText;
    } catch {
        throw new Error('Decryption failed — wrong passphrase or tampered data');
    }
}

// Remove a single item
export async function removeItem(itemKey) {
    if (!itemKey || typeof itemKey !== 'string') {
        throw new Error('itemKey must be a non-empty string');
    }

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
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase must be provided');
    }

    // store a tiny value under __verify__
    await encryptAndStore('__verify__', 'ok', passphrase);
}

// Verify passphrase correctness
export async function verifyPassphrase(passphrase) {
    if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('passphrase is required');
    }

    const raw = await AsyncStorage.getItem(`${NAMESPACE}__verify__`);
    if (!raw) {
        return false;
    }

    const {salt, iv, ct} = JSON.parse(raw);
    if (!salt || !iv || !ct) {
        return false;
    }

    try {
        // convert salt, iv, ct back to ArrayBuffer
        const saltBuf = SimpleCrypto.utils.convertBase64ToArrayBuffer(salt);
        const ivBuf = SimpleCrypto.utils.convertBase64ToArrayBuffer(iv);
        const ctBuf = SimpleCrypto.utils.convertBase64ToArrayBuffer(ct);

        // derive key again
        const keyBuf = await SimpleCrypto.PBKDF2.hash(
            passphrase,
            saltBuf,
            100000,
            32,
            'SHA256',
        );

        // try decrypting
        await SimpleCrypto.AES.decrypt(ctBuf, keyBuf, ivBuf);
        return true;
    } catch {
        return false;
    }
}
