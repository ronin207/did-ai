// Full demo: Issue VC -> Challenge -> Present -> Call resource with DPoP
// This script will spawn the issuer and verifier servers on custom ports,
// then run the end-to-end flow and exit.

import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { SignJWT, calculateJwkThumbprint } from 'jose';

const ISSUER_PORT = 4005;
const VERIFIER_PORT = 4006;
const ISSUER = `http://127.0.0.1:${ISSUER_PORT}`;
const VERIFIER = `http://127.0.0.1:${VERIFIER_PORT}`;

async function json(url, init) {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function log(step, data) {
  console.log(`[DEMO] ${step}`, data);
}

// Simple DPoP key (P-256) for the demo
async function genDpopJwk() {
  const { generateKeyPair } = await import('node:crypto');
  return new Promise((resolve, reject) => {
    generateKeyPair('ec', { namedCurve: 'P-256' }, (err, pub, priv) => {
      if (err) return reject(err);
      resolve({ pub, priv });
    });
  });
}

async function jwkFromKey(key) {
  const { exportJWK } = await import('jose');
  return exportJWK(key);
}

async function dpopProof(priv, jwk, htm, htu) {
  const iat = Math.floor(Date.now() / 1000);
  const jti = randomUUID();
  return new SignJWT({ htm, htu, iat, jti })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk })
    .sign(priv);
}

async function main() {
  // Spawn servers on custom ports
  const issuer = spawn('node', ['issuer/dist/server.js'], {
    env: { ...process.env, PORT: String(ISSUER_PORT) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  issuer.stdout.on('data', (d) => process.stdout.write(`[ISSUER] ${d}`));
  issuer.stderr.on('data', (d) => process.stderr.write(`[ISSUER-ERR] ${d}`));
  const verifier = spawn('node', ['verifier-rs/dist/server.js'], {
    env: { ...process.env, PORT: String(VERIFIER_PORT), ISSUER_BASE: ISSUER },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  verifier.stdout.on('data', (d) => process.stdout.write(`[VERIFIER] ${d}`));
  verifier.stderr.on('data', (d) => process.stderr.write(`[VERIFIER-ERR] ${d}`));

  // Wait for servers to come up by probing known endpoints
  const waitFor = async (url, timeoutMs = 5000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const res = await fetch(url);
        if (res.ok || res.status === 304) return;
      } catch {}
      await sleep(150);
    }
    throw new Error(`Timeout waiting for ${url}`);
  };
  await waitFor(`${ISSUER}/.well-known/jwks.json`);
  await waitFor(`${VERIFIER}/audit`);

  // 1) Issue VC
  const correlationId = randomUUID();
  const agentDid = 'did:key:test-agent';
  const issueRes = await json(`${ISSUER}/oid4vci/issue`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-correlation-id': correlationId },
    body: JSON.stringify({ agentDid, proof: { dummy: true } })
  });
  log('issued', { correlationId, status: issueRes.status, disclosures: issueRes.disclosures.length });
  // Fetch JWKS and status list snapshot for offline validation
  const jwks = await json(`${ISSUER}/.well-known/jwks.json`);
  const statusList = await json(`${ISSUER}${issueRes.status ? `/status/lists/${issueRes.status.listId}` : ''}`).catch(() => null);
  const artifact = {
    issuer: ISSUER,
    verifier: VERIFIER,
    correlationId,
    agentDid,
    vc: issueRes.vc,
    disclosures: issueRes.disclosures,
    status: issueRes.status,
    jwks,
    statusList
  };
  await writeFile('.last-demo.json', JSON.stringify(artifact, null, 2));

  // 2) Challenge
  const challengeRes = await fetch(`${VERIFIER}/protected/resource`);
  const corr = challengeRes.headers.get('x-correlation-id');
  const challenge = await challengeRes.json();
  log('challenge', { corrId: corr, nonce: challenge.nonce, aud: challenge.aud });

  // 3) Present
  // Generate a DPoP JWK and send thumbprint to verifier
  const { pub, priv } = await genDpopJwk();
  const { exportJWK } = await import('jose');
  const pubJwk = await exportJWK(pub);
  const jkt = await calculateJwkThumbprint(pubJwk, 'sha256');

  const presentRes = await json(`${VERIFIER}/present`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-correlation-id': corr },
    body: JSON.stringify({
      vp_token: issueRes.vc,
      state: challenge.nonce,
      disclosures: issueRes.disclosures,
      presentation_submission: {
        id: 'ps-1',
        definition_id: 'perm-vp-1',
        descriptor_map: [{ id: 'permcred', format: 'jwt_vc', path: '$.vp_token' }]
      },
      cnfJkt: jkt
    })
  });
  log('presented', { token_type: presentRes.token_type, expires_in: presentRes.expires_in });
  artifact.access_token = presentRes.access_token;
  artifact.token_type = presentRes.token_type;
  artifact.expires_in = presentRes.expires_in;
  await writeFile('.last-demo.json', JSON.stringify(artifact, null, 2));

  // 4) Call resource with DPoP
  const access = presentRes.access_token;
  const htu = 'https://api.calendar.local.test/protected/resource';
  const proof = await dpopProof(priv, pubJwk, 'GET', htu);
  const rsRes = await json(`${VERIFIER}/protected/resource`, {
    headers: { Authorization: `DPoP ${access}`, DPoP: proof }
  });
  log('resource', rsRes);
  artifact.resource = rsRes;
  await writeFile('.last-demo.json', JSON.stringify(artifact, null, 2));

  // Cleanup
  issuer.kill('SIGINT');
  verifier.kill('SIGINT');
}

main().catch((e) => {
  console.error('[DEMO] error', e);
  process.exitCode = 1;
});
