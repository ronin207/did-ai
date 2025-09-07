import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { calculateJwkThumbprint } from 'jose';
export function generateEd25519KeyPair(seed) {
    let privateKey;
    if (seed) {
        if (!(seed instanceof Uint8Array))
            throw new TypeError('seed must be Uint8Array');
        if (seed.length !== 32)
            throw new Error('seed must be 32 bytes for Ed25519');
        privateKey = new Uint8Array(seed);
    }
    else {
        privateKey = ed25519.utils.randomPrivateKey();
    }
    const publicKey = ed25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
}
export function toPublicJwkEd25519(publicKey) {
    if (publicKey.length !== 32)
        throw new Error('publicKey must be 32 bytes');
    return {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(publicKey).toString('base64url'),
    };
}
export function toPrivateJwkEd25519(privateKey) {
    if (privateKey.length !== 32)
        throw new Error('privateKey must be 32 bytes');
    const publicKey = ed25519.getPublicKey(privateKey);
    return {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(publicKey).toString('base64url'),
        d: Buffer.from(privateKey).toString('base64url'),
    };
}
export async function jwkThumbprintSha256(jwk) {
    // RFC 7638 JWK Thumbprint (base64url, no padding) using SHA-256
    return calculateJwkThumbprint(jwk, 'sha256');
}
export function signEd25519(message, privateKey) {
    if (privateKey.length !== 32)
        throw new Error('privateKey must be 32 bytes');
    return ed25519.sign(message, privateKey);
}
export function verifyEd25519(signature, message, publicKey) {
    if (publicKey.length !== 32)
        throw new Error('publicKey must be 32 bytes');
    return ed25519.verify(signature, message, publicKey);
}
export function sha256Bytes(data) {
    return sha256(data);
}
