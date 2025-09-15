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

    export function setItem(
        key: string,
        value: string,
        passphrase: string,
        options?: SetItemOptions
    ): Promise<void>;

    export function getItem(
        key: string,
        passphrase: string
    ): Promise<string | null>;

    export function removeItem(key: string): Promise<void>;

    export function clear(): Promise<void>;

    export function verify(
        key: string,
        passphrase: string
    ): Promise<boolean>;
}
