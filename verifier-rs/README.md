# Verifier & Resource Server (RS)

This service exposes:
- GET /protected/resource: Returns an OID4VP challenge (nonce, presentation_definition) when unauthenticated. Requires a DPoP-bound access token when authenticated.
- POST /present: Accepts a vp_token (VC JWT), SD-JWT disclosures, and presentation_submission. Verifies issuer JWKS, selective disclosure digests, revocation via Status List, and issues a DPoP-bound access token.

Highlights
- OID4VP: Requires presentation_submission aligned with the challenge.
- SD-JWT Selective Disclosure: Digests validated against `_sd` claim.
- Revocation: Bitstring Status List with ETag caching.
- DPoP: Validates htm/htu, iat skew, cnf.jkt thumbprint, and replay jti cache.
- Audit: JSONL in `verifier-audit.log` with correlationId.

Dev
- Tests use an injected Issuer client (Fastify inject) to avoid network.
- Nonces and jti replay cache use TTL with a periodic sweep.

Env
- RS_ISS: Issuer/audience for RS tokens (default https://api.calendar.local.test)
- REQUIRED_SCOPE: Required scope (default calendar.read:public)
- TOKEN_TTL_SECONDS: Access token lifetime (default 120)
