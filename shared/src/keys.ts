import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import type { JWK } from 'jose';
import { calculateJwkThumbprint } from 'jose';

export type Ed25519KeyPair = {
  privateKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
};

export function generateEd25519KeyPair(seed?: Uint8Array): Ed25519KeyPair {
  let privateKey: Uint8Array;
  if (seed) {
    if (!(seed instanceof Uint8Array)) throw new TypeError('seed must be Uint8Array');
    if (seed.length !== 32) throw new Error('seed must be 32 bytes for Ed25519');
    privateKey = new Uint8Array(seed);
  } else {
    privateKey = ed25519.utils.randomPrivateKey();
  }
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function toPublicJwkEd25519(publicKey: Uint8Array): JWK {
  if (publicKey.length !== 32) throw new Error('publicKey must be 32 bytes');
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(publicKey).toString('base64url'),
  } satisfies JWK;
}

export function toPrivateJwkEd25519(privateKey: Uint8Array): JWK {
  if (privateKey.length !== 32) throw new Error('privateKey must be 32 bytes');
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(publicKey).toString('base64url'),
    d: Buffer.from(privateKey).toString('base64url'),
  } satisfies JWK;
}

export async function jwkThumbprintSha256(jwk: JWK): Promise<string> {
  // RFC 7638 JWK Thumbprint (base64url, no padding) using SHA-256
  return calculateJwkThumbprint(jwk, 'sha256');
}

export function signEd25519(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) throw new Error('privateKey must be 32 bytes');
  return ed25519.sign(message, privateKey);
}

export function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (publicKey.length !== 32) throw new Error('publicKey must be 32 bytes');
  return ed25519.verify(signature, message, publicKey);
}

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}
