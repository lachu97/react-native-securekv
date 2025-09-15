export function encryptAndStore(itemKey: any, plainText: any, passphrase: any): Promise<void>;
export function getAndDecrypt(itemKey: any, passphrase: any): Promise<string | null>;
export function removeItem(itemKey: any): Promise<void>;
export function clearAll(): Promise<void>;
export function createVerifyBlob(passphrase: any): Promise<void>;
export function verifyPassphrase(passphrase: any): Promise<boolean>;
