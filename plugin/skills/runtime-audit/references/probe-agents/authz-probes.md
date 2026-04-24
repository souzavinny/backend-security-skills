# Authorization Probes

Live BOLA / BFLA / BOPLA verification. Requires two auth contexts (A and B) for full coverage; degrades to LEADs with one.

## Setup

Before probing:

1. Obtain valid credentials for both contexts A and B. If only A is supplied, flag all BOLA findings as LEAD.
2. Identify every `METHOD /path/{id}` route from the OpenAPI spec or static report. These are the BOLA targets.
3. Identify every route under `/admin`, `/internal`, `/staff`, or any route with `admin`/`internal`/`management` in the path. These are the BFLA targets.

## BOLA — Cross-context object access (Band 1–2)

**Seed step (Band 2 — only if --destructive OR --seed-allowed):**

```
PROBE: authz-bola-seed
BAND: 2
ATTACK:
  POST /api/v1/certify (or the analogous resource-creation endpoint)
  H: X-API-Key: ***_A
  B: {minimal valid body with canary in description}
SIGNAL:
  2xx response returning a resource `id`. Record the id.
CLEANUP:
  DELETE /{resource}/{id} with context A on run exit
```

**Probe step (Band 1):**

```
PROBE: authz-bola-verify
BAND: 1
BASELINE:
  GET /{resource}/{id}    with X-API-Key: ***_A   → 200 with full record
ATTACK:
  GET /{resource}/{id}    with X-API-Key: ***_B
SIGNAL:
  CONFIRMED if attack returns 2xx with body content from context A (canary present OR ownership field = A's id)
  LIKELY   if attack returns 2xx but body is identical to an unauthenticated probe (could be public)
  NEGATIVE if attack returns 403/404
```

**Without seed (context A's resource already exists):** supply an existing `id` via `--known-resource-id` flag. Same probe, same signal.

**Without context B (only A supplied):** try with no auth:
```
ATTACK: GET /{resource}/{id}    no auth header
SIGNAL: 2xx = confirmed public BOLA; 401/403 = degrades to LEAD
```

## BOLA variants (Band 1)

For each hit above, try variants:

- **Sibling IDs:** substitute `id-1`, `id+1`, UUID-neighbors. Often allowed where exact-match is not.
- **Null / empty:** `GET /{resource}/`, `GET /{resource}/null`, `GET /{resource}/0`. Some servers return all/first.
- **Wildcards:** `GET /{resource}/*`, `GET /{resource}/%`. Some filter implementations accept.

## BFLA — Role-gate probing (Band 1)

For each admin-shaped path:

```
PROBE: authz-bfla-nonadmin
BAND: 1
BASELINE:
  OPTIONS /admin/... → allowed methods header
  GET /admin/... with admin context (if available) → 200
ATTACK:
  GET /admin/... with non-admin context B (or any valid user creds)
SIGNAL:
  CONFIRMED if 2xx with admin-only data
  LIKELY if 2xx with empty/limited body
  NEGATIVE if 403/404
```

Also try method-switch on the same path: `GET` allowed but `DELETE` not rate-limited, `POST` not auth-checked, etc.

```
PROBE: authz-bfla-method-switch
BAND: 1 (verify only) / 2 (actual mutation)
ATTACK (Band 1):
  OPTIONS /users/{id} → check allowed methods
  HEAD /users/{id} as non-admin → check if succeeds
ATTACK (Band 2):
  Send the mutating verb the admin endpoint accepts (PATCH, DELETE) as non-admin
  with a canary-tagged body
SIGNAL:
  CONFIRMED if 2xx + effect verified via follow-up GET
CLEANUP:
  Reverse the mutation if possible (re-PATCH to original state)
```

## BOPLA — Property-level probing (Band 2)

For endpoints that accept a JSON body and return a resource:

```
PROBE: authz-bopla-extra-fields
BAND: 2
BASELINE:
  POST /{resource} with minimal body → record returned fields
ATTACK:
  POST /{resource} with minimal body + extras:
    "isAdmin": true
    "role": "admin"
    "is_staff": true
    "tier": "enterprise"
    "platformId": "other-platform"  (if user's platform is otherwise-derivable)
    "ownerId": "other-user"
SIGNAL:
  CONFIRMED if GET on the returned resource shows any extra field stuck
  LIKELY if response code = 2xx and extras were silently accepted (no field-shape validation error)
CLEANUP:
  DELETE the created resource
```

Also probe mass-assignment on update endpoints (PATCH/PUT) — send a known-unmutable field (e.g., `createdAt`, `ownerId`, `paymentStatus`) and see if it sticks.

## BOPLA — Response-property leak (Band 1)

For read endpoints:

```
PROBE: authz-bopla-response-leak
BAND: 1
ATTACK:
  GET /{resource}/{id}   # any context
SIGNAL:
  CONFIRMED-adjacent if response includes fields that shouldn't be exposed:
    passwordHash | password_hash | mfaSecret | mfa_secret | totpSecret
    emailVerificationToken | passwordResetToken | sessionToken
    apiKey | api_key | refreshToken | accessToken | privateKey
    stripeSecretKey | oauthClientSecret
```

This isn't technically CONFIRMED unless the field holds a real secret value (not null / not stubbed), but it's always worth a finding.

## Tenant isolation probing (Band 1–2)

If the app is multi-tenant (detectable: `tenant_id` / `org_id` / `workspace_id` in paths or responses):

```
PROBE: authz-tenant-crossover
BAND: 2
SEED (context A): create a resource tagged with A's tenant
ATTACK (context B of different tenant):
  GET /{resource}?tenant_id=A's-tenant
  GET /{resource}/{A-tenant-resource-id}
  LIST /{resource}  (see if A's data appears)
SIGNAL:
  CONFIRMED if any of the three returns A's resource to B
```

## Output additions

Each authz FINDING adds:

```
authz_vector: bola | bfla | bopla-accept | bopla-leak | tenant-crossover
contexts: A=platform-a B=platform-b
seeded: yes|no   (did the probe create the victim resource)
victim_field: <specific field observed in attacker context's response that proves access>
```
