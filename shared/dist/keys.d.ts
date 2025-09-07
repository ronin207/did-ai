import type { JWK } from 'jose';
export type Ed25519KeyPair = {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
};
export declare function generateEd25519KeyPair(seed?: Uint8Array): Ed25519KeyPair;
export declare function toPublicJwkEd25519(publicKey: Uint8Array): JWK;
export declare function toPrivateJwkEd25519(privateKey: Uint8Array): JWK;
export declare function jwkThumbprintSha256(jwk: JWK): Promise<string>;
export declare function signEd25519(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
export declare function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
export declare function sha256Bytes(data: Uint8Array): Uint8Array;
