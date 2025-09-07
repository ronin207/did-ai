import { toPublicJwkEd25519, type Ed25519KeyPair } from './keys.js';

// did:key for Ed25519 uses multicodec 0xED (0xED01 as varint) prefixed to raw 32-byte pubkey, then base58btc (multibase 'z')
// Reference: https://w3c-ccg.github.io/did-method-key/

import bs58 from 'bs58';

function varintEd25519Header(): Uint8Array {
  // 0xED 0x01 in little-endian varint encoding
  return new Uint8Array([0xED, 0x01]);
}

export function didKeyFromPublicKeyEd25519(publicKey: Uint8Array): string {
  const header = varintEd25519Header();
  const bytes = new Uint8Array(header.length + publicKey.length);
  bytes.set(header, 0);
  bytes.set(publicKey, header.length);
  const mb = 'z' + bs58.encode(bytes);
  return `did:key:${mb}`;
}

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

export function buildDidKeyDocument(pubKey: Uint8Array): DidDocument {
  const did = didKeyFromPublicKeyEd25519(pubKey);
  const vmId = `${did}#keys-1`;
  return {
    id: did,
    verificationMethod: [
      {
        id: vmId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyJwk: toPublicJwkEd25519(pubKey),
      },
    ],
    assertionMethod: [vmId],
    authentication: [vmId],
  };
}
