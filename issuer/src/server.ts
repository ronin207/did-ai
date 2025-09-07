import Fastify from 'fastify';
import cors from '@fastify/cors';
import { SignJWT, importJWK, JWTPayload, JWK } from 'jose';
import { toPublicJwkEd25519, generateEd25519KeyPair, makeDisclosure, digestDisclosure } from '@did-ai/shared';
import { appendFile, readFile } from 'fs/promises';
import { randomUUID } from 'crypto';

// Simple in-memory status list using a BitSet-like array of booleans.
const statusLists: Record<string, { purpose: 'revocation'; bits: Uint8Array }> = {};

function getOrCreateStatusList(id: string, size = 10000) {
  if (!statusLists[id]) statusLists[id] = { purpose: 'revocation', bits: new Uint8Array(size) };
  return statusLists[id];
}

// In-memory issuer signing key (Ed25519) for demo.
const issuerDid = process.env.ISSUER_DID || 'did:web:issuer.local.test';
const issuerKeypair = generateEd25519KeyPair();
const issuerKid = 'issuer-ed25519-1';
const issuerPrivJwk: JWK = { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(issuerKeypair.publicKey).toString('base64url'), d: Buffer.from(issuerKeypair.privateKey).toString('base64url'), kid: issuerKid };
const issuerPubJwk: JWK = { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(issuerKeypair.publicKey).toString('base64url'), kid: issuerKid };

export function buildServer() {
  const app = Fastify({ logger: false });
  app.register(cors, { origin: true });

  async function audit(event: string, data: Record<string, any>) {
    const entry = {
      ts: new Date().toISOString(),
      event,
      ...data,
    };
    await appendFile('issuer-audit.log', JSON.stringify(entry) + '\n');
  }

  app.post('/oid4vci/issue', async (req, reply) => {
    const body = req.body as any;
    const { agentDid, proof, requestedClaims } = body || {};

    if (!agentDid || typeof agentDid !== 'string') {
      return reply.code(400).send({ error: 'agentDid required' });
    }
    // MVP: skip full DID-auth verification; accept presence only for demo.
    if (!proof || typeof proof !== 'object') {
      return reply.code(400).send({ error: 'proof required' });
    }

    const statusListId = 'perm-v1';
    const status = getOrCreateStatusList(statusListId);

    // Allocate a free index (find first zero bit)
    let index = -1;
    for (let i = 0; i < status.bits.length; i++) {
      if (status.bits[i] === 0) { index = i; break; }
    }
    if (index === -1) return reply.code(503).send({ error: 'no status slots' });

  const now = Math.floor(Date.now() / 1000);
  const exp = typeof requestedClaims?.exp === 'number' ? requestedClaims.exp : now + 600; // 10m
  const scope = requestedClaims?.scope || 'calendar.read:public';
  const aud = requestedClaims?.aud || 'https://api.calendar.local.test';

  const corr = req.headers['x-correlation-id'] || randomUUID();
  // SD-JWT like: place claim digests in _sd and return disclosures alongside
  const discScope = makeDisclosure('scope', scope);
  const discAud = makeDisclosure('aud', aud);
  const _sd = [digestDisclosure(discScope), digestDisclosure(discAud)];

  const vcPayload: JWTPayload = {
      iss: issuerDid,
      sub: agentDid,
      nbf: now - 60,
      exp,
      type: ['VerifiableCredential', 'PermissionCredential'],
      vc: {
    credentialSubject: { _sd },
        credentialStatus: {
          type: 'BitstringStatusListEntry',
          statusListCredential: `/status/lists/${statusListId}`,
          statusListIndex: String(index),
          statusPurpose: status.purpose,
        },
        issuanceDate: new Date(now * 1000).toISOString(),
        expirationDate: new Date(exp * 1000).toISOString(),
      },
    } as any;

    const prv = await importJWK(issuerPrivJwk, 'EdDSA');
    const jwt = await new SignJWT(vcPayload)
      .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+sd-jwt', kid: issuerKid })
      .setIssuedAt(now)
      .setIssuer(issuerDid)
      .setSubject(agentDid)
      .setExpirationTime(exp)
      .sign(prv);

    await audit('issue_vc', {
      correlationId: corr,
      agentDid,
      issuerDid,
  scope,
  aud,
      statusListId,
      statusIndex: index,
      exp: vcPayload.exp,
    });
    console.log('[ISSUER] issue_vc', {
      correlationId: corr,
      agentDid,
      scope,
      aud,
      statusListId,
      statusIndex: index,
      exp
    });
  return reply.send({ vc: jwt, disclosures: [discScope, discAud], status: { listId: statusListId, index } });
  });

  app.get('/status/lists/:listId', async (req, reply) => {
    const { listId } = req.params as any;
    const list = getOrCreateStatusList(listId);
    // Represent as a compact base64url bitstring
    const bytes = Buffer.from(list.bits);
    const etag = `W/"${bytes.length}-${bytes.subarray(0, 8).toString('base64url')}"`;
    const inm = (req.headers['if-none-match'] as string) || '';
    if (inm && inm === etag) {
      return reply.header('ETag', etag).code(304).send();
    }
    return reply
      .header('Cache-Control', 'public, max-age=60')
      .header('ETag', etag)
      .send({ id: listId, purpose: list.purpose, bits_b64u: bytes.toString('base64url') });
  });

  app.get('/.well-known/jwks.json', async (_req, reply) => {
    return reply.send({ keys: [issuerPubJwk] });
  });

  app.post('/status/lists/:listId/toggle', async (req, reply) => {
    const { listId } = req.params as any;
    const { index, revoked } = req.body as any;
    const list = getOrCreateStatusList(listId);
    if (typeof index !== 'number' || index < 0 || index >= list.bits.length) {
      return reply.code(400).send({ error: 'invalid index' });
    }
  list.bits[index] = revoked ? 1 : 0;
  await audit('status_toggle', { listId, index, revoked: !!revoked });
  console.log('[ISSUER] status_toggle', { listId, index, revoked: !!revoked });
    return reply.send({ ok: true, index, revoked: !!revoked });
  });

  app.get('/audit', async (_req, reply) => {
    try {
      const txt = await readFile('issuer-audit.log', 'utf8').catch(() => '');
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
  const port = Number(process.env.PORT || 4001);
  app.listen({ port, host: '127.0.0.1' }).then(() => {
    console.log(`Issuer listening on http://127.0.0.1:${port}`);
  });
}
