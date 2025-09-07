import { randomUUID, randomBytes, createCipheriv, createDecipheriv } from 'crypto';
function deriveKey(passphrase) {
    // Simple derivation for demo: use SubtleCrypto in browser or scrypt in prod.
    // Here: SHA-256(passphrase) truncated to 32 bytes (NOT for prod use).
    const hash = createHash('sha256').update(passphrase).digest();
    return hash.subarray(0, 32);
}
import { createHash } from 'crypto';
export class EncryptedWallet {
    passphrase;
    state = { v: 1, items: [] };
    constructor(passphrase) {
        this.passphrase = passphrase;
    }
    exportEncrypted() {
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
    importEncrypted(payload) {
        const iv = Buffer.from(payload.iv, 'base64url');
        const key = deriveKey(this.passphrase);
        const decipher = createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(Buffer.from(payload.tag, 'base64url'));
        const dec = Buffer.concat([
            decipher.update(Buffer.from(payload.data, 'base64url')),
            decipher.final(),
        ]);
        const obj = JSON.parse(dec.toString('utf8'));
        if (!obj || obj.v !== 1 || !Array.isArray(obj.items))
            throw new Error('invalid wallet payload');
        this.state = obj;
    }
    storeVC(vcJwt, type) {
        const id = randomUUID();
        this.state.items.push({ id, type, jwt: vcJwt, createdAt: new Date().toISOString() });
        return id;
    }
    getVCsByType(typeName) {
        return this.state.items.filter(i => i.type.includes(typeName));
    }
}
