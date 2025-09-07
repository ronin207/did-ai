import { describe, it, expect } from 'vitest';
import { EncryptedWallet } from '../src/wallet';

function fakeJwt(payload: object) {
  return [
    Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' }), 'utf8').toString('base64url'),
    Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url'),
    ''
  ].join('.');
}

describe('EncryptedWallet', () => {
  it('stores, exports, imports, and queries by type', () => {
    const w1 = new EncryptedWallet('changeit');
    const id1 = w1.storeVC(fakeJwt({ a: 1 }), ['VerifiableCredential', 'PermissionCredential']);
    const id2 = w1.storeVC(fakeJwt({ b: 2 }), ['VerifiableCredential', 'AgentCredential']);

    const dump = w1.exportEncrypted();
    const w2 = new EncryptedWallet('changeit');
    w2.importEncrypted(dump);

    const pcs = w2.getVCsByType('PermissionCredential');
    expect(pcs.length).toBe(1);
    expect(pcs[0].id).toBe(id1);

    const acs = w2.getVCsByType('AgentCredential');
    expect(acs.length).toBe(1);
    expect(acs[0].id).toBe(id2);
  });

  it('rejects tampered ciphertext', () => {
    const w1 = new EncryptedWallet('changeit');
    w1.storeVC(fakeJwt({ x: 'y' }), ['VerifiableCredential']);
    const dump = w1.exportEncrypted();
    // tamper with data
    const tampered = { ...dump, data: dump.data.slice(0, -2) + 'AA' };
    const w2 = new EncryptedWallet('changeit');
    expect(() => w2.importEncrypted(tampered)).toThrow();
  });

  it('fails to decrypt with wrong passphrase', () => {
    const w1 = new EncryptedWallet('right-pass');
    w1.storeVC(fakeJwt({ ok: true }), ['VerifiableCredential']);
    const dump = w1.exportEncrypted();
    const w2 = new EncryptedWallet('wrong-pass');
    expect(() => w2.importEncrypted(dump)).toThrow();
  });
});
