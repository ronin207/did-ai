import { describe, it, expect } from 'vitest';
import {
  generateEd25519KeyPair,
  signEd25519,
  verifyEd25519,
  toPublicJwkEd25519,
  toPrivateJwkEd25519,
  jwkThumbprintSha256,
} from '../dist/keys.js';
import { buildDidKeyDocument, didKeyFromPublicKeyEd25519 } from '../dist/did.js';

function u8(n: number): Uint8Array {
  const a = new Uint8Array(32);
  a.fill(n & 0xff);
  return a;
}

describe('Ed25519 keys + did:key', () => {
  it('generates, signs, verifies, and derives DID', async () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    const msg = crypto.getRandomValues(new Uint8Array(128));
    const sig = signEd25519(msg, privateKey);
    expect(verifyEd25519(sig, msg, publicKey)).toBe(true);

    const did = didKeyFromPublicKeyEd25519(publicKey);
    expect(did.startsWith('did:key:z')).toBe(true);

    const doc = buildDidKeyDocument(publicKey);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod[0].publicKeyJwk.kty).toBe('OKP');
  });

  it('creates stable JWK thumbprints for same key', async () => {
    const { privateKey, publicKey } = generateEd25519KeyPair(u8(7));
    const jwkPub = toPublicJwkEd25519(publicKey);
    const jwkPriv = toPrivateJwkEd25519(privateKey);
    const t1 = await jwkThumbprintSha256(jwkPub);
    const t2 = await jwkThumbprintSha256({ kty: jwkPriv.kty, crv: jwkPriv.crv, x: jwkPriv.x! });
    expect(t1).toBe(t2);
  });

  it('fails verify on tampered message', () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    const msg = new Uint8Array([1,2,3,4]);
    const sig = signEd25519(msg, privateKey);
    const bad = new Uint8Array(msg);
    bad[0] ^= 0xff;
    expect(verifyEd25519(sig, bad, publicKey)).toBe(false);
  });

  it('fuzz multiple random messages', () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    for (let i=0; i<100; i++) {
      const len = 1 + Math.floor(Math.random()*1024);
      const msg = crypto.getRandomValues(new Uint8Array(len));
      const sig = signEd25519(msg, privateKey);
      expect(verifyEd25519(sig, msg, publicKey)).toBe(true);
    }
  });
});
