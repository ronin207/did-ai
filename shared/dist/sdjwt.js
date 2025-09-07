import { createHash, randomBytes } from 'crypto';
function b64u(buf) { return Buffer.from(buf).toString('base64url'); }
export function makeDisclosure(name, value, salt) {
    const s = salt ?? randomBytes(16);
    const arr = [b64u(s), name, value];
    const json = Buffer.from(JSON.stringify(arr), 'utf8');
    return b64u(json);
}
export function digestDisclosure(disclosure) {
    const bytes = Buffer.from(disclosure, 'base64url');
    const digest = createHash('sha256').update(bytes).digest();
    return b64u(digest);
}
export function parseDisclosure(disclosure) {
    const bytes = Buffer.from(disclosure, 'base64url');
    const arr = JSON.parse(bytes.toString('utf8'));
    if (!Array.isArray(arr) || arr.length !== 3)
        throw new Error('invalid disclosure');
    return { saltB64u: arr[0], name: arr[1], value: arr[2] };
}
