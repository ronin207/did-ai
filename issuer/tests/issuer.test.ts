import { describe, it, expect } from 'vitest';
import { buildServer } from '../src/server';
import { randomUUID } from 'crypto';

function didKey(agent: string) { return agent; }

describe('Issuer OID4VCI + Status List', () => {
  it('issues a PermissionCredential and serves status list', async () => {
    const app = buildServer();
    const agentDid = `did:key:agent-${randomUUID()}`;
    const res = await app.inject({
      method: 'POST',
      url: '/oid4vci/issue',
      payload: { agentDid, proof: { type: 'did-auth', jws: 'x' }, requestedClaims: { scope: 'calendar.read:public' } },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.vc).toBeDefined();
    expect(body.status.index).toBeGreaterThanOrEqual(0);

    const sl = await app.inject({ method: 'GET', url: `/status/lists/${body.status.listId}` });
    expect(sl.statusCode).toBe(200);
    const list = sl.json();
    expect(list.id).toBe(body.status.listId);
    expect(typeof list.bits_b64u).toBe('string');
  });

  it('toggles revocation bits dynamically across indices', async () => {
    const app = buildServer();
    const agentDid = `did:key:agent-${randomUUID()}`;
    const first = await app.inject({ method: 'POST', url: '/oid4vci/issue', payload: { agentDid, proof: { type: 'did-auth', jws: 'x' }, requestedClaims: {} } });
    const { status } = first.json();

    for (let i = 0; i < 5; i++) {
      const toggled = await app.inject({ method: 'POST', url: `/status/lists/${status.listId}/toggle`, payload: { index: status.index, revoked: i % 2 === 0 } });
      expect(toggled.statusCode).toBe(200);
      const s = toggled.json();
      expect(s.index).toBe(status.index);
      expect(typeof s.revoked).toBe('boolean');
    }
  });

  it('returns 304 when ETag matches via If-None-Match', async () => {
    const app = buildServer();
    const agentDid = `did:key:agent-${randomUUID()}`;
    const res = await app.inject({ method: 'POST', url: '/oid4vci/issue', payload: { agentDid, proof: { type: 'did-auth', jws: 'x' }, requestedClaims: {} } });
    const { status } = res.json();
    const first = await app.inject({ method: 'GET', url: `/status/lists/${status.listId}` });
    const etag = first.headers['etag'];
    expect(etag).toBeDefined();
    const second = await app.inject({ method: 'GET', url: `/status/lists/${status.listId}`, headers: { 'If-None-Match': etag as string } });
    expect(second.statusCode).toBe(304);
  });
});
