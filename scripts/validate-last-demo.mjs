// Validate last demo artifacts: VC signature, SD-JWT digests, status list, and access token claims
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { importJWK, jwtVerify } from 'jose';

const art = JSON.parse(await readFile('.last-demo.json', 'utf8'));

function b64u(buf) { return Buffer.from(buf).toString('base64url'); }

function parseDisclosure(disclosure) {
  const bytes = Buffer.from(disclosure, 'base64url');
  const arr = JSON.parse(bytes.toString('utf8'));
  if (!Array.isArray(arr) || arr.length !== 3) throw new Error('invalid disclosure');
  return { saltB64u: arr[0], name: arr[1], value: arr[2] };
}

function digestDisclosure(disclosure) {
  const bytes = Buffer.from(disclosure, 'base64url');
  const digest = createHash('sha256').update(bytes).digest();
  return b64u(digest);
}

async function main() {
  // 1) Use stored JWKS to verify VC
  const jwk = (art.jwks && art.jwks.keys && art.jwks.keys[0]) || null;
  if (!jwk) throw new Error('missing jwks in artifact');
  const { payload } = await jwtVerify(art.vc, await importJWK(jwk, 'EdDSA'), { issuer: undefined, audience: undefined });
  const vc = payload.vc;
  if (!vc?.credentialSubject?._sd) throw new Error('vc missing _sd');

  // 2) SD-JWT: recompute digests and match
  const [discScope, discAud] = art.disclosures;
  const recomputed = [digestDisclosure(discScope), digestDisclosure(discAud)];
  const digests = vc.credentialSubject._sd;
  if (digests[0] !== recomputed[0] || digests[1] !== recomputed[1]) throw new Error('sd mismatch');

  // 3) Status list: ensure not revoked (use snapshot)
  const sl = art.statusList;
  if (!sl) throw new Error('missing statusList snapshot');
  const bits = Buffer.from(sl.bits_b64u, 'base64url');
  const idx = Number(vc.credentialStatus.statusListIndex);
  if (bits[idx] === 1) throw new Error('credential revoked');

  // 4) Access token: verify structure (HMAC key is private, so just decode and assert required claims)
  const tok = JSON.parse(Buffer.from(art.access_token.split('.')[1], 'base64url').toString('utf8'));
  const reqClaims = ['sub', 'scope', 'aud', 'cnf', 'iat', 'iss', 'exp'];
  for (const k of reqClaims) if (!(k in tok)) throw new Error(`token missing ${k}`);

  const scope = parseDisclosure(art.disclosures[0]).value;
  const aud = parseDisclosure(art.disclosures[1]).value;
  console.log('[VALIDATE] OK');
  console.log('[VALIDATE] vc.subject', payload.sub);
  console.log('[VALIDATE] vc.scope', scope);
  console.log('[VALIDATE] vc.aud', aud);
}

main().catch((e) => { console.error('[VALIDATE] FAIL:', e.message || e); process.exitCode = 1; });
