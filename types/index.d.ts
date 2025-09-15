export default SecureKV;
declare namespace SecureKV {
    function setItem(key: any, value: any, passphrase: any, options?: {}): Promise<void>;
    function getItem(key: any, passphrase: any): Promise<ArrayBuffer | null>;
    function removeItem(key: any): Promise<void>;
    function clear(): Promise<void>;
    function verify(passphrase: any): Promise<boolean>;
    function createVerifyBlob(passphrase: any): Promise<void>;
}
