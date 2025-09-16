declare module "react-native-securekv" {
    export interface KdfParams {
        time?: number;
        mem?: number;
        parallelism?: number;
        hashLen?: number;
    }

    export interface SetItemOptions {
        kdfParams?: KdfParams;
    }

    export interface SecureKV {
        setItem(
            key: string,
            value: string,
            passphrase: string,
            options?: SetItemOptions
        ): Promise<void>;

        getItem(
            key: string,
            passphrase: string
        ): Promise<string | null>;

        removeItem(key: string): Promise<void>;

        clear(): Promise<void>;

        verify(passphrase: string): Promise<boolean>;

        createVerifyBlob(passphrase: string): Promise<void>;
    }

    const SecureKV: SecureKV;
    export default SecureKV;
}
