import { useEffect, useMemo, useState } from 'react'
import { SignJWT, calculateJwkThumbprint, type JWK } from 'jose'

const ISSUER = import.meta.env.VITE_ISSUER_BASE || 'http://127.0.0.1:4001'
const VERIFIER = import.meta.env.VITE_VERIFIER_BASE || 'http://127.0.0.1:4002'

type AuditEvent = { ts: string; event: string; [k: string]: any }

export default function App() {
  const [issuerAudit, setIssuerAudit] = useState<AuditEvent[]>([])
  const [verifierAudit, setVerifierAudit] = useState<AuditEvent[]>([])
  const [agentDid, setAgentDid] = useState<string>(() => localStorage.getItem('agentDid') || 'did:key:test-agent')
  const [vc, setVc] = useState<string>(() => localStorage.getItem('vc') || '')
  const [disclosures, setDisclosures] = useState<string[]>(() => JSON.parse(localStorage.getItem('disclosures') || '[]'))
  const [status, setStatus] = useState<{ listId: string; index: number } | null>(() => JSON.parse(localStorage.getItem('status') || 'null'))
  const [token, setToken] = useState<string>(() => localStorage.getItem('token') || '')
  const [symKey, setSymKey] = useState<JWK | null>(() => JSON.parse(localStorage.getItem('symKey') || 'null'))
  const [nonce, setNonce] = useState<string>('')
  const [result, setResult] = useState<any>(null)
  const [issuerUp, setIssuerUp] = useState<boolean>(false)
  const [verifierUp, setVerifierUp] = useState<boolean>(false)
  const [msg, setMsg] = useState<string>('')
  const [running, setRunning] = useState<boolean>(false)

  useEffect(() => { const poll = async () => {
    try {
      const r = await fetch(`${ISSUER}/audit`)
      setIssuerUp(r.ok)
      const ia = r.ok ? await r.json() : { events: [] }
      setIssuerAudit(ia.events || [])
    } catch { setIssuerUp(false) }
    try {
      const r = await fetch(`${VERIFIER}/audit`)
      setVerifierUp(r.ok)
      const va = r.ok ? await r.json() : { events: [] }
      setVerifierAudit(va.events || [])
    } catch { setVerifierUp(false) }
  }; poll(); const i = setInterval(poll, 3000); return () => clearInterval(i) }, [])

  useEffect(() => { localStorage.setItem('agentDid', agentDid) }, [agentDid])
  useEffect(() => { localStorage.setItem('vc', vc) }, [vc])
  useEffect(() => { localStorage.setItem('disclosures', JSON.stringify(disclosures)) }, [disclosures])
  useEffect(() => { localStorage.setItem('status', JSON.stringify(status)) }, [status])
  useEffect(() => { localStorage.setItem('token', token) }, [token])
  useEffect(() => { localStorage.setItem('symKey', JSON.stringify(symKey)) }, [symKey])

  async function issue() {
    setMsg('Issuing VC...')
    try {
      const res = await fetch(`${ISSUER}/oid4vci/issue`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentDid, proof: { type: 'did-auth', jws: 'x' }, requestedClaims: { scope: 'calendar.read:public', aud: 'https://api.calendar.local.test' } }) })
      if (!res.ok) throw new Error(`Issuer responded ${res.status}`)
      const body = await res.json()
      setVc(body.vc); setDisclosures(body.disclosures); setStatus(body.status); setMsg('VC issued')
    } catch (e:any) { setMsg(`Issue failed: ${e.message||e}`) }
  }

  async function toggleRevoked(revoked: boolean) {
    if (!status) return
    setMsg(revoked ? 'Revoking...' : 'Unrevoking...')
    try {
      const r = await fetch(`${ISSUER}/status/lists/${status.listId}/toggle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ index: status.index, revoked }) })
      if (!r.ok) throw new Error(`Toggle failed ${r.status}`)
      setMsg(revoked ? 'Revoked' : 'Unrevoked')
    } catch (e:any) { setMsg(`Toggle failed: ${e.message||e}`) }
  }

  async function challenge() {
    setMsg('Requesting challenge...')
    try {
      const ch = await fetch(`${VERIFIER}/protected/resource`)
      const data = await ch.json()
      if (!data?.nonce) throw new Error('No nonce returned')
      setNonce(data.nonce); setMsg('Challenge received')
    } catch (e:any) { setMsg(`Challenge failed: ${e.message||e}`) }
  }

  function toB64u(bytes: Uint8Array) {
    const b64 = btoa(String.fromCharCode(...bytes))
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }
  function fromB64u(b64u: string) {
    const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice((2 - (b64u.length * 3) % 4) % 4)
    const bin = atob(b64)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    return bytes
  }

  async function present() {
    if (!vc || !disclosures?.length || !nonce) return
    // create a symmetric JWK and compute thumbprint
  const k: JWK = symKey || { kty: 'oct', k: toB64u(crypto.getRandomValues(new Uint8Array(32))) }
    if (!symKey) setSymKey(k)
    const jkt = await calculateJwkThumbprint(k, 'sha256')
    const ps = { id: 'ps1', definition_id: 'perm-vp-1', descriptor_map: [{ id: 'permcred', format: 'jwt_vc', path: '$.vp_token' }] }
    setMsg('Presenting VC...')
    try {
      const res = await fetch(`${VERIFIER}/present`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ vp_token: vc, disclosures, state: nonce, cnfJkt: jkt, presentation_submission: ps }) })
      const body = await res.json()
      if (!res.ok) throw new Error(body?.error || `Verifier responded ${res.status}`)
      setToken(body.access_token || ''); setMsg('Token minted')
    } catch (e:any) { setMsg(`Present failed: ${e.message||e}`) }
  }

  async function callResource() {
    if (!token || !symKey) return
    const htu = `https://api.calendar.local.test/protected/resource`
    setMsg('Calling resource...')
    const dpop = await new SignJWT({ htm: 'GET', htu, jti: crypto.randomUUID(), iat: Math.floor(Date.now()/1000) })
      .setProtectedHeader({ alg: 'HS256', typ: 'dpop+jwt', jwk: symKey as any })
      .sign(fromB64u((symKey as any).k))
    try {
      const res = await fetch(`${VERIFIER}/protected/resource`, { headers: { Authorization: `DPoP ${token}`, DPoP: dpop } })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(body?.error || `RS responded ${res.status}`)
      setResult(body); setMsg('Resource call OK')
    } catch (e:any) { setMsg(`Resource call failed: ${e.message||e}`) }
  }

  async function runFullDemo() {
    if (running) return
    setRunning(true)
    setMsg('Running full demo...')
    try {
      await issue()
      await challenge()
      await present()
      await callResource()
      setMsg('Full demo complete')
    } catch (e:any) {
      setMsg(`Full demo failed: ${e?.message || e}`)
    } finally {
      setRunning(false)
    }
  }

  return (
    <div style={{ fontFamily: 'system-ui', padding: 16, display: 'grid', gap: 12 }}>
      <h1>DID-AI Dashboard</h1>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <input value={agentDid} onChange={e => setAgentDid(e.target.value)} style={{ width: 380 }} />
        <button onClick={issue}>Issue VC</button>
        <button onClick={() => toggleRevoked(true)} disabled={!status}>Revoke</button>
        <button onClick={() => toggleRevoked(false)} disabled={!status}>Unrevoke</button>
        <button onClick={challenge}>Start Challenge</button>
        <button onClick={present} disabled={!vc || !disclosures?.length || !nonce}>Present</button>
        <button onClick={callResource} disabled={!token || !symKey}>Call Resource</button>
        <button onClick={runFullDemo} disabled={!issuerUp || !verifierUp || running}>
          {running ? 'Running…' : 'Run Full Demo'}
        </button>
        <span style={{ marginLeft: 12, fontSize: 12, opacity: 0.8 }}>
          Issuer: <b style={{ color: issuerUp ? 'green' : 'red' }}>{issuerUp ? 'UP' : 'DOWN'}</b> · Verifier: <b style={{ color: verifierUp ? 'green' : 'red' }}>{verifierUp ? 'UP' : 'DOWN'}</b>
        </span>
      </div>
      {msg && <div style={{ padding: 8, background: '#fff3cd', border: '1px solid #ffe69c' }}>{msg}</div>}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <section>
          <h3>Issuer Audit</h3>
          <pre style={{ background: '#f6f8fa', padding: 8, maxHeight: 240, overflow: 'auto' }}>{JSON.stringify(issuerAudit.slice(-40), null, 2)}</pre>
        </section>
        <section>
          <h3>Verifier Audit</h3>
          <pre style={{ background: '#f6f8fa', padding: 8, maxHeight: 240, overflow: 'auto' }}>{JSON.stringify(verifierAudit.slice(-40), null, 2)}</pre>
        </section>
      </div>
      <section>
        <h3>State</h3>
        <pre style={{ background: '#fafafa', padding: 8, maxHeight: 300, overflow: 'auto' }}>{JSON.stringify({ vc: !!vc, disclosures, status, nonce, token, symKey, result }, null, 2)}</pre>
      </section>
    </div>
  )
}
