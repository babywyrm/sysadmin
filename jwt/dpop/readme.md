
```
Legend:
  AT   = Access Token (JWT)
  PJWT = DPoP Proof JWT (signed w/ client's private key)
  jkt  = JWK thumbprint (hash of client's public key)
  ath  = hash of the access token (binds proof to token)
  RS   = Resource Server (your Spring API)
  AS   = Authorization Server (optional in your demo; real OAuth flow)

──────────────────────────────────────────────────────────────────────────────
1) CLIENT CREATES A KEYPAIR (Proof-of-possession key)
──────────────────────────────────────────────────────────────────────────────
      ┌───────────────────────┐
      │ Client / Workload     │
      │ (pod / app / script)  │
      └───────────┬───────────┘
                  │
                  │  Generate asymmetric keypair (EC/RSA)
                  │  Keep private key secret
                  │
                  v
      ┌────────────────────────────────────────────────────────---───┐
      │ Public key is shared via JWK (goes into DPoP proof header)   │
      │ Private key never leaves the client                          │
      └──────────────────────────────────────────────────────────---─┘

──────────────────────────────────────────────────────────────────────────────
2) (OPTIONAL) CLIENT GETS AN ACCESS TOKEN THAT IS "BOUND" TO THAT KEY
   (This is where OAuth AS typically binds token -> key via cnf.jkt)
──────────────────────────────────────────────────────────────────────────────
      Client                                 AS (OAuth)
      ┌───────────────┐                      ┌──────────────────────────┐
      │ Private Key   │                      │ Authorization Server     │
      │ + Public JWK  │                      │ (issues access tokens)   │
      └───────┬───────┘                      └───────────┬──────────────┘
              │                                         │
              │  POST /token                            │
              │  DPoP: PJWT (htm=POST, htu=/token, ...)  │
              ├────────────────────────────────────────►│
              │                                         │
              │                            Validate PJWT signature
              │                            Extract public JWK
              │                            Compute jkt (thumbprint)
              │                                         │
              │  <- AT (JWT) includes: cnf: { jkt: ... } │
              │  token_type may be "DPoP"                │
              ◄──────────────────────────────────────────┤

      NOTE: In your demo, you minted AT locally with cnf.jkt to show binding.

──────────────────────────────────────────────────────────────────────────────
3) CLIENT CALLS RESOURCE SERVER WITH *BOTH* AT + DPoP PROOF
   (AT proves authorization, PJWT proves possession of the key)
──────────────────────────────────────────────────────────────────────────────
      Client (has AT + private key)                      RS (API)
      ┌──────────────────────────┐                      ┌─────────────────────┐
      │ Authorization: DPoP AT   │                      │ Resource Server     │
      │ DPoP: PJWT               │                      │ (Spring API)        │
      └───────────┬──────────────┘                      └───────────┬─────────┘
                  │                                         (1) Validate AT
                  │                                         - signature
                  │                                         - exp/iat
                  │                                         - scopes, etc.
                  │                                         - read cnf.jkt
                  │
                  │  GET /api/hello                          (2) Validate PJWT
                  │  Authorization: DPoP <AT>                - typ=dpop+jwt
                  │  DPoP: <PJWT>                            - jwk present
                  ├────────────────────────────────────────► - signature verifies
                  │                                           with jwk public key
                  │                                           - claims:
                  │                                             htm == GET
                  │                                             htu == URL
                  │                                             iat fresh
                  │                                             jti unique
                  │                                           - ath matches AT
                  │
                  │                                        (3) Bind checks
                  │                                           jkt(from PJWT jwk)
                  │                                           == cnf.jkt(in AT)
                  │
                  │                                        (4) Replay protection
                  │                                           reject reused jti
                  │
                  │  200 OK (authorized + proven) / 401       │
                  ◄───────────────────────────────────────────┘

──────────────────────────────────────────────────────────────────────────────
WHY THIS STOPS TOKEN THEFT
──────────────────────────────────────────────────────────────────────────────
Attacker steals AT only:

      Attacker                               RS
      ┌──────────────────────────┐          ┌───────────────────────────┐
      │ Authorization: DPoP AT   │          │ Needs DPoP proof signed by │
      │ (no private key!)        │          │ the key bound to cnf.jkt   │
      └───────────┬──────────────┘          └───────────┬───────────────┘
                  ├────────────────────────►            │
                  │                                     │  FAIL:
                  │                                     │  - can't sign PJWT
                  │                                     │  - ath/jkt checks fail
                  │                                     │
                  ◄────────────────────────            401 Unauthorized

Replay attacker reuses old proof (same jti):

      RS rejects because jti already seen (anti-replay cache).

──────────────────────────────────────────────────────────────────────────────
WHAT YOUR DEMO IMPLEMENTS (Spring API)
──────────────────────────────────────────────────────────────────────────────
  ✔ Accepts Authorization: DPoP <AT>
  ✔ Validates AT (HS256 in your demo)
  ✔ Validates DPoP proof:
      - typ / jwk / signature
      - htm / htu / iat / jti
      - ath == hash(AT)
  ✔ Enforces cnf.jkt == proof key jkt
  ✔ Rejects replay (jti cache)
