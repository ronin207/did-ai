import { toPublicJwkEd25519 } from './keys.js';
export declare function didKeyFromPublicKeyEd25519(publicKey: Uint8Array): string;
export type DidDocument = {
    id: string;
    verificationMethod: Array<{
        id: string;
        type: 'Ed25519VerificationKey2020';
        controller: string;
        publicKeyJwk: ReturnType<typeof toPublicJwkEd25519>;
    }>;
    assertionMethod: string[];
    authentication: string[];
};
export declare function buildDidKeyDocument(pubKey: Uint8Array): DidDocument;
