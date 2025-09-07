type StoredVC = {
    id: string;
    type: string[];
    jwt: string;
    createdAt: string;
};
export declare class EncryptedWallet {
    private passphrase;
    private state;
    constructor(passphrase: string);
    exportEncrypted(): {
        iv: string;
        data: string;
        tag: string;
    };
    importEncrypted(payload: {
        iv: string;
        data: string;
        tag: string;
    }): void;
    storeVC(vcJwt: string, type: string[]): string;
    getVCsByType(typeName: string): StoredVC[];
}
export {};
