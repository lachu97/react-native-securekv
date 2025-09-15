import SecureKV from "../types";

async function demo() {
    try {
        // Store this in env file and import it for more security.
        const passphrase = "myStrongPassword123";

        // Save a value securely
        await SecureKV.setItem("userToken", "abc123", passphrase);

        // Retrieve the value (will decrypt using passphrase)
        const value = await SecureKV.getItem("userToken", passphrase);
        console.log("Decrypted value:", value);

        // Remove a value
        await SecureKV.removeItem("userToken");

        // Clear all values (⚠️ irreversible)
        await SecureKV.clear();

        // Verify passphrase against stored value
        const ok = await SecureKV.verify("userToken", passphrase);
        console.log("Password match?", ok);
    } catch (e) {
        console.error(e)
    }

}
demo()
