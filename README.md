# 📦 react-native-securekv

**Secure key-value storage for React Native apps**  
Built on **PBKDF2-SHA256** key derivation and **AES-256-GCM** encryption 
Unlike `AsyncStorage`, all values are encrypted and can only be decrypted with the correct passphrase.  
If the passphrase is lost, the data is unrecoverable.

---

## ✨ Features
🔑 Strong PBKDF2-SHA256 key derivation (configurable iterations, salt).

🔒 AES-256-GCM encryption with authentication (detects tampering).

🚫 Passphrase required for both encryption and decryption — no accidental leaks.

🧹 Utilities to remove or clear stored items.

✅ Passphrase verification helper.

⚡ Drop-in for React Native apps (iOS + Android).

---

## 📦 Installation

```sh
# with npm
npm install react-native-securekv

# with yarn
yarn add react-native-securekv
```
## 📦 Peer dependencies
```shell
# with npm
# required peer deps
npm install react-native-get-random-values @react-native-async-storage/async-storage react-native-simple-crypto

# with yarn
# required peer deps
yarn add react-native-get-random-values @react-native-async-storage/async-storage react-native-simple-crypto

```
## 📖 Usage
```javascript

import SecureKV from "react-native-securekv";

async function demo() {
    const passphrase = "myStrongPassword123"; // ideally from secure storage/env

    // Save a value securely
    await SecureKV.setItem("userToken", "abc123", passphrase);

    // Retrieve the value (will decrypt using passphrase)
    const value = await SecureKV.getItem("userToken", passphrase);
    console.log("Decrypted value:", value);

    // Remove a value
    await SecureKV.removeItem("userToken");

    // Clear all values (⚠️ irreversible)
    await SecureKV.clear();

    // Verify passphrase correctness
    await SecureKV.createVerifyBlob(passphrase); // call once to set verification value
    const ok = await SecureKV.verify(passphrase);
    console.log("Password match?", ok);
}



```
## 🔑 API

`setItem(key, value, passphrase, options?)`

Encrypts value using passphrase and stores it in SecureKV.

`getItem(key, passphrase)`

Retrieves and decrypts the value. Returns null if the key does not exist.

`removeItem(key)`

Removes a stored item.

`clear()`

Clears all stored secure items.

`createVerifyBlob(passphrase)`

Stores a hidden encrypted “ok” marker for passphrase validation.

`verify(passphrase)`

Checks if a stored item can be decrypted with the given passphrase.

## ⚙️ Options

You can pass custom KDF (Argon2) parameters in setItem:
```javascript
await SecureKV.setItem("secret", "value", passphrase, {
  kdfParams: { time: 3, mem: 131072, parallelism: 2, hashLen: 32 }
});

```
## 📌 Notes

1.Always store passphrases securely. If the wrong passphrase is provided, decryption will fail.

2.This library is designed for React Native only.

3.AES-GCM provides both encryption and integrity protection.

4.Supports Typescript

## 📜 License

MIT © 2025
