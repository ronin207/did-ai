import Fastify from 'fastify';
import cors from '@fastify/cors';
import { importJWK, jwtVerify, SignJWT, calculateJwkThumbprint } from 'jose';
import { appendFile, readFile } from 'fs/promises';
import { createHash, randomUUID } from 'crypto';

const RS_ISS = process.env.RS_ISS || 'https://api.calendar.local.test';
const ISSUER_BASE = process.env.ISSUER_BASE || 'http://127.0.0.1:4001';
const REQUIRED_SCOPE = process.env.REQUIRED_SCOPE || 'calendar.read:public';
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS || '120');

// In-memory stores for demo
type NonceInfo = { exp: number; corrId: string };
const nonces = new Map<string, NonceInfo>(); // nonce -> info
const usedJti = new Map<string, number>(); // jti -> expTs
const statusCache = new Map<string, { etag?: string; body: any; fetchedAt: number }>();

// RS HMAC secret for access tokens (demo)
import { randomBytes } from 'crypto';
const rsSecret = randomBytes(32);

type IssuerClient = {
  getJson: (path: string) => Promise<any>;
  getWithMeta?: (
    path: string,
    headers?: Record<string, string>
  ) => Promise<{ body: any; headers: Record<string, any>; status?: number }>;
};

export function buildServer(
  issuerBase = ISSUER_BASE,
  issuerClient?: IssuerClient
) {
  const app = Fastify({ logger: false });
  app.register(cors, { origin: true });

  // Periodic TTL cleanup for in-memory caches
  function sweep() {
    const now = Math.floor(Date.now() / 1000);
    for (const [k, info] of nonces.entries()) {
      if (info.exp < now) nonces.delete(k);
    }
    for (const [k, exp] of usedJti.entries()) {
      if (exp < now) usedJti.delete(k);
    }
  }
  const sweepHandle: NodeJS.Timeout = setInterval(sweep, 60_000);
  app.addHook('onClose', async () => clearInterval(sweepHandle));

  async function audit(event: string, data: Record<string, any>) {
    const entry = { ts: new Date().toISOString(), event, ...data };
    await appendFile('verifier-audit.log', JSON.stringify(entry) + '\n');
  }

  app.get('/protected/resource', async (req, reply) => {
    // If no Authorization header, return OID4VP challenge
    const auth = req.headers['authorization'];
    const dpop = req.headers['dpop'];
    if (!auth) {
      const nonce = Math.random().toString(36).slice(2);
      const corrId = (req.headers['x-correlation-id'] as string) || randomUUID();
      nonces.set(nonce, { exp: Math.floor(Date.now()/1000) + 300, corrId });
      return reply.header('x-correlation-id', corrId).code(401).send({
        nonce,
        aud: RS_ISS,
        presentation_definition: { id: 'perm-vp-1', input_descriptors: [{ id: 'permcred', format: { jwt_vc: {} } }] },
      });
    }

    // Validate DPoP-bound token
    if (!auth.toLowerCase().startsWith('dpop ')) {
      return reply.code(401).send({ error: 'invalid scheme' });
    }
    const token = auth.slice(5).trim();
    // Verify token signature and claims
    let payload: any;
    try {
      const { payload: p } = await jwtVerify(token, rsSecret, { issuer: RS_ISS, audience: RS_ISS });
      payload = p;
    } catch (e) {
      return reply.code(401).send({ error: 'invalid token' });
    }
    if (payload.scope !== REQUIRED_SCOPE) return reply.code(403).send({ error: 'scope' });
    const cnfJkt = payload?.cnf?.jkt;
    if (!cnfJkt) return reply.code(401).send({ error: 'missing cnf' });

    // Validate DPoP proof
    if (!dpop || typeof dpop !== 'string') return reply.code(401).send({ error: 'missing DPoP' });
    try {
      const segments = dpop.split('.');
      const header = JSON.parse(Buffer.from(segments[0], 'base64url').toString('utf8'));
      if (!header || header.typ !== 'dpop+jwt' || !header.jwk) return reply.code(401).send({ error: 'bad DPoP header' });
      const jwk = header.jwk;
      // Thumbprint must match cnf.jkt
      const jkt = await (await import('jose')).calculateJwkThumbprint(jwk, 'sha256');
      if (jkt !== cnfJkt) return reply.code(401).send({ error: 'cnf mismatch' });

      // Verify DPoP signature and claims
      const { payload: dpopPayload } = await jwtVerify(dpop, await importJWK(jwk));
      const htm = dpopPayload['htm'];
      const htu = dpopPayload['htu'];
      const iat = dpopPayload['iat'];
      const jti = dpopPayload['jti'];
      const expectedHtu = `${RS_ISS}/protected/resource`;
      if (htm !== 'GET' || htu !== expectedHtu) return reply.code(401).send({ error: 'htu/htm' });
      const now = Math.floor(Date.now() / 1000);
      if (typeof iat !== 'number' || Math.abs(now - iat) > 120) return reply.code(401).send({ error: 'iat' });
      if (!jti || typeof jti !== 'string') return reply.code(401).send({ error: 'jti' });
      // Replay cache
      const seen = usedJti.get(jti);
      if (seen && seen > now) return reply.code(401).send({ error: 'replay' });
      usedJti.set(jti, now + 300);
    } catch (e) {
      return reply.code(401).send({ error: 'invalid DPoP' });
    }

  console.log('[VERIFIER] resource_ok');
  return reply.code(200).send({ ok: true, data: [1, 2, 3] });
  });

  app.post('/present', async (req, reply) => {
  const body = req.body as any;
    const { vp_token, state, disclosures, presentation_submission } = body || {};
    if (!vp_token || !state) return reply.code(400).send({ error: 'vp_token and state required' });
    const nInfo = nonces.get(state);
    const nowTs = Math.floor(Date.now()/1000);
    if (!nInfo || nInfo.exp < nowTs) {
      await audit('presentation_failed', { reason: 'invalid_nonce', correlationId: req.headers['x-correlation-id'] });
      return reply.code(401).send({ error: 'invalid nonce' });
    }
    // Minimal OID4VP check for presentation_submission shape
    if (!presentation_submission || typeof presentation_submission !== 'object') {
  await audit('presentation_failed', { reason: 'missing_presentation_submission', correlationId: nInfo.corrId });
      return reply.code(400).send({ error: 'missing presentation_submission' });
    }
    // Validate presentation_submission fields match our challenge
    try {
      const { definition_id, descriptor_map } = presentation_submission as any;
      if (definition_id !== 'perm-vp-1' || !Array.isArray(descriptor_map) || descriptor_map.length === 0) {
        throw new Error('bad ps');
      }
      const d0 = descriptor_map[0];
      if (d0.id !== 'permcred' || d0.format !== 'jwt_vc' || d0.path !== '$.vp_token') {
        throw new Error('bad descriptor');
      }
    } catch {
      await audit('presentation_failed', { reason: 'invalid_presentation_submission', correlationId: nInfo.corrId });
      return reply.code(400).send({ error: 'invalid presentation_submission' });
    }

    // Fetch Issuer JWKS
    const jwks: any = issuerClient
      ? await issuerClient.getJson('/.well-known/jwks.json')
      : await (await fetch(`${issuerBase}/.well-known/jwks.json`)).json();
  const jwk = jwks.keys[0];

    // Verify VC JWT (vp_token MVP = VC for simplicity)
    const { payload, protectedHeader } = await jwtVerify(vp_token, await importJWK(jwk, 'EdDSA'), {
      audience: undefined, // VC may not have aud claim; check inside vc
      issuer: undefined,
    });

    const vc = (payload as any).vc;
    if (!vc?.credentialSubject?._sd || !Array.isArray(vc.credentialSubject._sd)) {
  await audit('presentation_failed', { reason: 'invalid_vc', correlationId: nInfo.corrId });
      return reply.code(400).send({ error: 'invalid VC' });
    }
    // Reconstruct scope/aud from disclosures and compare to _sd digests
    if (!Array.isArray(disclosures)) {
  await audit('presentation_failed', { reason: 'missing_disclosures', correlationId: nInfo.corrId });
      return reply.code(400).send({ error: 'missing disclosures' });
    }
    const [discScope, discAud] = disclosures;
    const { name: nameScope, value: valScope } = (await import('@did-ai/shared')).parseDisclosure(discScope);
    const { name: nameAud, value: valAud } = (await import('@did-ai/shared')).parseDisclosure(discAud);
    const digests = vc.credentialSubject._sd as string[];
    const recomputed = [(await import('@did-ai/shared')).digestDisclosure(discScope), (await import('@did-ai/shared')).digestDisclosure(discAud)];
    if (nameScope !== 'scope' || nameAud !== 'aud' || digests[0] !== recomputed[0] || digests[1] !== recomputed[1]) {
  await audit('presentation_failed', { reason: 'sd_mismatch', correlationId: nInfo.corrId });
      return reply.code(400).send({ error: 'sd mismatch' });
    }
    if (valScope !== REQUIRED_SCOPE) {
  await audit('presentation_failed', { reason: 'scope_mismatch', scope: vc.credentialSubject.scope, correlationId: nInfo.corrId });
      return reply.code(403).send({ error: 'scope mismatch' });
    }
    if (valAud !== RS_ISS) {
  await audit('presentation_failed', { reason: 'aud_mismatch', aud: vc.credentialSubject.aud, correlationId: nInfo.corrId });
      return reply.code(403).send({ error: 'aud mismatch' });
    }

    // Status check
    const status = vc.credentialStatus;
    if (!status?.statusListCredential || !status?.statusListIndex) {
  await audit('presentation_failed', { reason: 'missing_status', correlationId: nInfo.corrId });
      return reply.code(400).send({ error: 'missing status info' });
    }
    // Status list fetch with cache (ETag/TTL)
    const listPath: string = status.statusListCredential;
    let sl: any | undefined;
    const cached = statusCache.get(listPath);
    if (issuerClient) {
      if (issuerClient.getWithMeta) {
        const { body, headers, status } = await issuerClient.getWithMeta(listPath, cached?.etag ? { 'If-None-Match': cached.etag } : undefined);
        const etag = headers['etag'] as string | undefined;
        if (status === 304 && cached) {
          sl = cached.body;
        } else {
          sl = body;
          statusCache.set(listPath, { etag, body, fetchedAt: Date.now() });
        }
      } else {
        // With injected client (tests), always fetch fresh to reflect immediate toggles
        sl = await issuerClient.getJson(listPath);
        statusCache.set(listPath, { body: sl, fetchedAt: Date.now() });
      }
    } else {
      const headers: Record<string, string> = {};
      if (cached?.etag) headers['If-None-Match'] = cached.etag;
      const res = await fetch(`${issuerBase}${listPath}`, { headers } as any);
      if (res.status === 304 && cached) {
        sl = cached.body;
      } else {
        const fetched = await res.json();
        sl = fetched;
        const etag = res.headers.get('etag') || undefined;
        statusCache.set(listPath, { etag, body: fetched, fetchedAt: Date.now() });
      }
    }
  const bits = Buffer.from(sl.bits_b64u, 'base64url');
    const idx = Number(status.statusListIndex);
    if (bits[idx] === 1) {
      await audit('presentation_failed', { reason: 'revoked', statusIndex: idx, correlationId: nInfo.corrId });
      return reply.code(403).send({ error: 'revoked' });
    }

    // Issue DPoP-bound access token (cnf.jkt)
    const cnfJkt = body?.cnfJkt;
    if (!cnfJkt) {
      await audit('presentation_failed', { reason: 'missing_cnf', correlationId: nInfo.corrId });
      return reply.code(400).send({ error: 'cnfJkt required' });
    }

  const now = Math.floor(Date.now() / 1000);
  const exp = now + TOKEN_TTL_SECONDS;
    const access = await new SignJWT({
      sub: (payload as any).sub,
  scope: valScope,
      aud: RS_ISS,
      cnf: { jkt: cnfJkt },
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuedAt(now)
      .setIssuer(RS_ISS)
      .setExpirationTime(exp)
      .sign(rsSecret);
  // Invalidate nonce after successful presentation
  nonces.delete(state);

    await audit('authorization_grant', {
      agentDid: (payload as any).sub,
      issuerDid: (payload as any).iss,
      scope: undefined, // logged below via valScope
      aud: RS_ISS,
      exp,
      statusIndex: idx,
      decision: 'allow',
      requestHash: createHash('sha256').update(vp_token).digest('base64url'),
      correlationId: nInfo.corrId,
    });
    console.log('[VERIFIER] authorization_grant', {
      agentDid: (payload as any).sub,
      scope: valScope,
      aud: RS_ISS,
      exp,
      statusIndex: idx,
      correlationId: nInfo.corrId,
    });

    return reply.send({ access_token: access, token_type: 'DPoP', expires_in: TOKEN_TTL_SECONDS });
  });

  app.get('/audit', async (_req, reply) => {
    try {
      const txt = await readFile('verifier-audit.log', 'utf8').catch(() => '');
      const lines = txt.trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
      return reply.send({ events: lines.slice(-500) });
    } catch (e) {
      return reply.code(500).send({ error: 'audit_read_failed' });
    }
  });

  return app;
}

if (import.meta.main) {
  const app = buildServer();
  const port = Number(process.env.PORT || 4002);
  app.listen({ port, host: '127.0.0.1' }).then(() => {
    console.log(`Verifier/RS listening on http://127.0.0.1:${port}`);
  });
}
