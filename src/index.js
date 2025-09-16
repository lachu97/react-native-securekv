// src/index.js
import * as core from './core.js';

const SecureKV = {
    // note: all APIs that decrypt require a passphrase parameter
    setItem: async (key, value, passphrase, options = {}) => {
        return core.encryptAndStore(key, value, passphrase, options);
    },

    getItem: async (key, passphrase) => {
        return core.getAndDecrypt(key, passphrase);
    },

    removeItem: async (key) => {
        return core.removeItem(key);
    },

    clear: async () => {
        return core.clearAll();
    },

    // verify whether a passphrase is valid (returns boolean)
    verify: async (passphrase) => {
        return core.verifyPassphrase(passphrase);
    },

    // convenience: create verification blob (call at setup if you want)
    createVerifyBlob: async (passphrase) => {
        return core.createVerifyBlob(passphrase);
    }
};

export default SecureKV;
