import { randomUUID, randomBytes, createCipheriv, createDecipheriv } from 'crypto';

type StoredVC = {
  id: string;
  type: string[];
  jwt: string;
  createdAt: string;
};

type WalletState = {
  v: 1;
  items: StoredVC[];
};

function deriveKey(passphrase: string): Buffer {
  // Simple derivation for demo: use SubtleCrypto in browser or scrypt in prod.
  // Here: SHA-256(passphrase) truncated to 32 bytes (NOT for prod use).
  const hash = createHash('sha256').update(passphrase).digest();
  return hash.subarray(0, 32);
}

import { createHash } from 'crypto';

export class EncryptedWallet {
  private state: WalletState = { v: 1, items: [] };
  constructor(private passphrase: string) {}

  exportEncrypted(): { iv: string; data: string; tag: string } {
    const iv = randomBytes(12);
    const key = deriveKey(this.passphrase);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const plaintext = Buffer.from(JSON.stringify(this.state), 'utf8');
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      iv: iv.toString('base64url'),
      data: enc.toString('base64url'),
      tag: tag.toString('base64url')
    };
  }

  importEncrypted(payload: { iv: string; data: string; tag: string }) {
    const iv = Buffer.from(payload.iv, 'base64url');
    const key = deriveKey(this.passphrase);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(Buffer.from(payload.tag, 'base64url'));
    const dec = Buffer.concat([
      decipher.update(Buffer.from(payload.data, 'base64url')),
      decipher.final(),
    ]);
    const obj: WalletState = JSON.parse(dec.toString('utf8'));
    if (!obj || obj.v !== 1 || !Array.isArray(obj.items)) throw new Error('invalid wallet payload');
    this.state = obj;
  }

  storeVC(vcJwt: string, type: string[]): string {
    const id = randomUUID();
    this.state.items.push({ id, type, jwt: vcJwt, createdAt: new Date().toISOString() });
    return id;
  }

  getVCsByType(typeName: string): StoredVC[] {
    return this.state.items.filter(i => i.type.includes(typeName));
  }
}
