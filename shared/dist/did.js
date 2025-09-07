import { toPublicJwkEd25519 } from './keys.js';
// did:key for Ed25519 uses multicodec 0xED (0xED01 as varint) prefixed to raw 32-byte pubkey, then base58btc (multibase 'z')
// Reference: https://w3c-ccg.github.io/did-method-key/
import bs58 from 'bs58';
function varintEd25519Header() {
    // 0xED 0x01 in little-endian varint encoding
    return new Uint8Array([0xED, 0x01]);
}
export function didKeyFromPublicKeyEd25519(publicKey) {
    const header = varintEd25519Header();
    const bytes = new Uint8Array(header.length + publicKey.length);
    bytes.set(header, 0);
    bytes.set(publicKey, header.length);
    const mb = 'z' + bs58.encode(bytes);
    return `did:key:${mb}`;
}
export function buildDidKeyDocument(pubKey) {
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
