import { describe, it, expect } from 'vitest';
import { buildServer as buildIssuer } from '../../issuer/src/server';
import { buildServer as buildRS } from '../src/server';
import { SignJWT, calculateJwkThumbprint, importJWK, type JWK } from 'jose';
import { randomBytes, randomUUID } from 'crypto';

async function issueVC(app: any, agentDid: string) {
  const res = await app.inject({ method: 'POST', url: '/oid4vci/issue', payload: { agentDid, proof: { type: 'did-auth', jws: 'x' }, requestedClaims: { scope: 'calendar.read:public', aud: 'https://api.calendar.local.test' } } });
  return res.json();
}

describe('Verifier/RS OID4VP + token mint', () => {
  it('challenges, verifies VC, and returns a DPoP-bound token', async () => {
    const issuer = buildIssuer();
    const client = {
      getJson: async (path: string) => {
        const res = await issuer.inject({ method: 'GET', url: path });
        return res.json();
      },
      getWithMeta: async (path: string, headers?: Record<string, string>) => {
        const res = await issuer.inject({ method: 'GET', url: path, headers });
        return { body: res.json(), headers: res.headers as any, status: res.statusCode } as any;
      }
    };
    const rs = buildRS('http://issuer.local.test', client);

    const agentDid = 'did:key:test-agent';
  const { vc, disclosures } = await issueVC(issuer, agentDid);

    const challenge = await rs.inject({ method: 'GET', url: '/protected/resource' });
    expect(challenge.statusCode).toBe(401);
    const { nonce } = challenge.json();

  const res = await rs.inject({ method: 'POST', url: '/present', payload: { vp_token: vc, disclosures, state: nonce, cnfJkt: 'dummy-thumb', presentation_submission: { id: 'ps1', definition_id: 'perm-vp-1', descriptor_map: [{ id: 'permcred', format: 'jwt_vc', path: '$.vp_token' }] } } });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.access_token).toBeDefined();
    expect(body.token_type).toBe('DPoP');
  });

  it('rejects missing presentation_submission with 400', async () => {
    const issuer = buildIssuer();
  const client = { getJson: async (path: string) => (await issuer.inject({ method: 'GET', url: path })).json(), getWithMeta: async (path: string, headers?: Record<string, string>) => { const r = await issuer.inject({ method: 'GET', url: path, headers }); return { body: r.json(), headers: r.headers as any, status: r.statusCode } as any; } };
    const rs = buildRS('http://issuer.local.test', client);

    const agentDid = 'did:key:test-agent';
    const { vc, disclosures } = await issueVC(issuer, agentDid);
    const challenge = await rs.inject({ method: 'GET', url: '/protected/resource' });
    const { nonce } = challenge.json();
    const res = await rs.inject({ method: 'POST', url: '/present', payload: { vp_token: vc, disclosures, state: nonce, cnfJkt: 'x' } });
    expect(res.statusCode).toBe(400);
  });

  it('rejects invalid presentation_submission shape with 400', async () => {
    const issuer = buildIssuer();
  const client = { getJson: async (path: string) => (await issuer.inject({ method: 'GET', url: path })).json(), getWithMeta: async (path: string, headers?: Record<string, string>) => { const r = await issuer.inject({ method: 'GET', url: path, headers }); return { body: r.json(), headers: r.headers as any, status: r.statusCode } as any; } };
    const rs = buildRS('http://issuer.local.test', client);

    const agentDid = 'did:key:test-agent';
    const { vc, disclosures } = await issueVC(issuer, agentDid);
    const challenge = await rs.inject({ method: 'GET', url: '/protected/resource' });
    const { nonce } = challenge.json();
    const badPs = { id: 'ps1', definition_id: 'wrong', descriptor_map: [{ id: 'x', format: 'jwt_vc', path: '$.foo' }] };
    const res = await rs.inject({ method: 'POST', url: '/present', payload: { vp_token: vc, disclosures, state: nonce, cnfJkt: 'x', presentation_submission: badPs } });
    expect(res.statusCode).toBe(400);
  });

  it('rejects invalid nonce, aud/scope mismatch, and revoked status', async () => {
    const issuer = buildIssuer();
  const client = { getJson: async (path: string) => (await issuer.inject({ method: 'GET', url: path })).json(), getWithMeta: async (path: string, headers?: Record<string, string>) => { const r = await issuer.inject({ method: 'GET', url: path, headers }); return { body: r.json(), headers: r.headers as any, status: r.statusCode } as any; } };
    const rs = buildRS('http://issuer.local.test', client);

    const agentDid = 'did:key:test-agent';
  const { vc, disclosures, status } = await issueVC(issuer, agentDid);

    // Invalid nonce
  const badNonce = await rs.inject({ method: 'POST', url: '/present', payload: { vp_token: vc, disclosures, state: 'nope', cnfJkt: 'x', presentation_submission: { id: 'ps1', definition_id: 'perm-vp-1', descriptor_map: [{ id: 'permcred', format: 'jwt_vc', path: '$.vp_token' }] } } });
    expect(badNonce.statusCode).toBe(401);

    // Valid nonce but wrong aud: simulate by issuing a VC with different aud
    const res2 = await issuer.inject({ method: 'POST', url: '/oid4vci/issue', payload: { agentDid, proof: { type: 'did-auth', jws: 'x' }, requestedClaims: { scope: 'calendar.read:public', aud: 'https://wrong.example' } } });
  const { vc: vcWrongAud, disclosures: discWrongAud } = res2.json();
    const ch = await rs.inject({ method: 'GET', url: '/protected/resource' });
    const { nonce } = ch.json();
  const wrongAud = await rs.inject({ method: 'POST', url: '/present', payload: { vp_token: vcWrongAud, disclosures: discWrongAud, state: nonce, cnfJkt: 'x', presentation_submission: { id: 'ps1', definition_id: 'perm-vp-1', descriptor_map: [{ id: 'permcred', format: 'jwt_vc', path: '$.vp_token' }] } } });
    expect(wrongAud.statusCode).toBe(403);

    // Scope mismatch
    const res3 = await issuer.inject({ method: 'POST', url: '/oid4vci/issue', payload: { agentDid, proof: { type: 'did-auth', jws: 'x' }, requestedClaims: { scope: 'calendar.write', aud: process.env.RS_ISS || 'https://api.calendar.local.test' } } });
  const { vc: vcWrongScope, disclosures: discWrongScope } = res3.json();
    const ch2 = await rs.inject({ method: 'GET', url: '/protected/resource' });
    const { nonce: n2 } = ch2.json();
  const wrongScope = await rs.inject({ method: 'POST', url: '/present', payload: { vp_token: vcWrongScope, disclosures: discWrongScope, state: n2, cnfJkt: 'x', presentation_submission: { id: 'ps1', definition_id: 'perm-vp-1', descriptor_map: [{ id: 'permcred', format: 'jwt_vc', path: '$.vp_token' }] } } });
    expect(wrongScope.statusCode).toBe(403);

    // Revoked status
    // Toggle the bit to revoked and try again
    await issuer.inject({ method: 'POST', url: `/status/lists/${status.listId}/toggle`, payload: { index: status.index, revoked: true } });
    const ch3 = await rs.inject({ method: 'GET', url: '/protected/resource' });
    const { nonce: n3 } = ch3.json();
  const revoked = await rs.inject({ method: 'POST', url: '/present', payload: { vp_token: vc, disclosures, state: n3, cnfJkt: 'x', presentation_submission: { id: 'ps1', definition_id: 'perm-vp-1', descriptor_map: [{ id: 'permcred', format: 'jwt_vc', path: '$.vp_token' }] } } });
    expect(revoked.statusCode).toBe(403);
  });

  it('enforces DPoP on resource access (happy path + negatives)', async () => {
    const issuer = buildIssuer();
    const client = { getJson: async (path: string) => (await issuer.inject({ method: 'GET', url: path })).json() };
    const rs = buildRS('http://issuer.local.test', client);

    // Issue vc and mint token
    const agentDid = 'did:key:test-agent';
  const { vc, disclosures } = await issueVC(issuer, agentDid);
    const challenge = await rs.inject({ method: 'GET', url: '/protected/resource' });
    const { nonce } = challenge.json();
    // Prepare a symmetric JWK for DPoP and compute its thumbprint
    const symKey: JWK = { kty: 'oct', k: Buffer.from(randomBytes(32)).toString('base64url') };
    const jkt = await calculateJwkThumbprint(symKey, 'sha256');
  const tokenRes = await rs.inject({ method: 'POST', url: '/present', payload: { vp_token: vc, disclosures, state: nonce, cnfJkt: jkt, presentation_submission: { id: 'ps1', definition_id: 'perm-vp-1', descriptor_map: [{ id: 'permcred', format: 'jwt_vc', path: '$.vp_token' }] } } });
    const { access_token } = tokenRes.json();

    // Missing DPoP -> 401
    const r1 = await rs.inject({ method: 'GET', url: '/protected/resource', headers: { Authorization: `DPoP ${access_token}` } });
    expect(r1.statusCode).toBe(401);

    // Happy path DPoP -> 200
    const htu = `${process.env.RS_ISS || 'https://api.calendar.local.test'}/protected/resource`;
    const goodDpop = await new SignJWT({ htm: 'GET', htu, jti: randomUUID(), iat: Math.floor(Date.now()/1000) })
      .setProtectedHeader({ alg: 'HS256', typ: 'dpop+jwt', jwk: symKey })
      .sign(Buffer.from(symKey.k!, 'base64url'));
    const rOk = await rs.inject({ method: 'GET', url: '/protected/resource', headers: { Authorization: `DPoP ${access_token}`, DPoP: goodDpop } });
    expect(rOk.statusCode).toBe(200);

    // Wrong htu/htm -> 401
    const badDpop = await new SignJWT({ htm: 'POST', htu, jti: randomUUID(), iat: Math.floor(Date.now()/1000) })
      .setProtectedHeader({ alg: 'HS256', typ: 'dpop+jwt', jwk: symKey })
      .sign(Buffer.from(symKey.k!, 'base64url'));
    const r2 = await rs.inject({ method: 'GET', url: '/protected/resource', headers: { Authorization: `DPoP ${access_token}`, DPoP: badDpop } });
    expect(r2.statusCode).toBe(401);

    // Replay jti -> 401
    const jti = randomUUID();
    const replayDpop = await new SignJWT({ htm: 'GET', htu, jti, iat: Math.floor(Date.now()/1000) })
      .setProtectedHeader({ alg: 'HS256', typ: 'dpop+jwt', jwk: symKey })
      .sign(Buffer.from(symKey.k!, 'base64url'));
    const r3a = await rs.inject({ method: 'GET', url: '/protected/resource', headers: { Authorization: `DPoP ${access_token}`, DPoP: replayDpop } });
    expect(r3a.statusCode).toBe(200);
    const r3b = await rs.inject({ method: 'GET', url: '/protected/resource', headers: { Authorization: `DPoP ${access_token}`, DPoP: replayDpop } });
    expect(r3b.statusCode).toBe(401);
  });
});
