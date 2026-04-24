# Attack Vectors (Python Backend APIs)

Pattern library organized by OWASP API Security Top 10 (2023) + Python-specific vectors. Each entry: shape, sink/source, concrete exploit, safe form. Grep patterns are POSIX ERE.

---

## API1:2023 — Broken Object Level Authorization (BOLA)

**1.1 Raw-ID find without ownership filter**
- Shape: `Model.objects.get(id=id)`, `find_one({"_id": id})`, `session.get(Model, id)`
- Exploit: enumerate IDs, read any user's resource
- Safe: `.filter(id=id, user=request.user)`, `find_one({"_id": id, "user_id": u.id})`

**1.2 DRF default queryset**
- Shape: `queryset = Model.objects.all()` in a `ModelViewSet` without `get_queryset` override
- Exploit: any authenticated user lists/retrieves any object
- Safe: override `get_queryset` to filter by `self.request.user`

**1.3 Trusted client-supplied `user_id`**
- Shape: `Payment(user_id=body.user_id, amount=body.amount)`
- Exploit: create resources for other users
- Safe: derive scope from session

**1.4 Prefetch / select_related leaks joined data**
- Shape: outer model scoped to user, inner not
- Exploit: joined query leaks cross-tenant rows

---

## API2:2023 — Broken Authentication

**2.1 JWT `algorithms` not specified**
- Shape: `jwt.decode(token, key)` (2-arg)
- Exploit: `alg:none`, HS256-with-RSA-public-key

**2.2 JWT audience / issuer not validated**
- Shape: verify without `audience`/`issuer`
- Exploit: token from sibling service accepted

**2.3 `verify_signature=False`**
- Shape: options dict disables verification
- Exploit: any token accepted

**2.4 Password compared with `==` / fast hash**
- Shape: `hashlib.md5(pwd)`, `hash == provided`
- Exploit: timing attack / rainbow table

**2.5 Django `SECRET_KEY` hardcoded**
- Shape: literal in `settings.py` committed
- Exploit: session forgery, password-reset forgery

**2.6 Reset token from `random` / `uuid4`**
- Shape: non-secrets-module RNG
- Exploit: predict tokens

**2.7 MFA client-settable**
- Shape: `request.POST["mfa_passed"]` trusted
- Exploit: skip MFA

---

## API3:2023 — Broken Object Property Level Authorization (BOPLA)

**3.1 DRF `fields = "__all__"`**
- Shape: ModelSerializer exposes every column
- Exploit: leaks `password_hash`, `is_staff`, PII
- Safe: explicit field list; separate read/write serializers

**3.2 pydantic `extra="allow"`**
- Shape: `model_config = ConfigDict(extra="allow")`
- Exploit: client-set unexpected fields pass through

**3.3 Mass assignment**
- Shape: `.update(**request.POST.dict())`, `User.objects.filter(id=u.id).update(**body.dict())`
- Exploit: set `is_staff=True`, `tenant_id=...`

**3.4 FastAPI missing `response_model`**
- Shape: route returns a model directly with all fields
- Exploit: leaks secret fields

---

## API4:2023 — Unrestricted Resource Consumption

**4.1 Missing rate limit on amplification endpoints**
- `/login`, `/password-reset`, `/verify-phone`, `/signup`
- Exploit: credential stuffing, SMS pump, enumeration

**4.2 Client-controlled `limit` / `page_size`**
- Shape: `int(request.GET["limit"])` passed to slice
- Exploit: `?limit=1000000`

**4.3 Unbounded body / upload**
- Shape: no `DATA_UPLOAD_MAX_MEMORY_SIZE` (Django) / `MAX_CONTENT_LENGTH` (Flask) / size check (FastAPI)

**4.4 ReDoS**
- Shape: `re.compile(user_pattern)`, catastrophic regex applied to input

**4.5 Sync crypto in async handler**
- Shape: `bcrypt.hashpw(...)` in a `async def` FastAPI handler
- Exploit: event-loop stall under concurrency

**4.6 YAML anchor bomb**
- Shape: `yaml.safe_load(body)` with no size cap
- Exploit: exponential expansion on reference

**4.7 XML billion-laughs**
- Shape: `xml.etree` on untrusted XML; no `defusedxml`

---

## API5:2023 — Broken Function Level Authorization (BFLA)

**5.1 DRF `AllowAny` on mutating view**
- Shape: `permission_classes = [AllowAny]` on POST/PATCH/DELETE
- Exploit: anyone mutates

**5.2 HTTP method confusion**
- Shape: GET gated by decorator, DELETE not
- Exploit: delete without permission

**5.3 `@csrf_exempt` on sensitive views**
- Shape: Django view decorated to skip CSRF
- Exploit: cross-site request

**5.4 Django admin URLconf exposed publicly**
- Shape: `path("admin/", admin.site.urls)` with default creds seeded
- Exploit: browse to admin

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**6.1 Bulk checkout / limited-edition race**

**6.2 Referral / coupon farming**

**6.3 Workflow step skip**

**6.4 Captcha on signup but not login/reset**

---

## API7:2023 — SSRF

**7.1 User-URL fetch**
- Shape: `requests.get(body.url)`, `urlopen(body.url)`, `httpx.get(body.url)`
- Exploit: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

**7.2 Headless browser user-goto**
- Shape: `await page.goto(body.url)` (Playwright / Pyppeteer)

**7.3 URL parsing differential**
- Shape: `urlparse(x).hostname` allowlist check, but connector resolves differently
- Exploit: `http://allowed@169.254.169.254/`, IPv6, decimal IPs

**7.4 File / gopher schemes**
- Shape: older `urllib` followed `file://`
- Exploit: LFI via SSRF

**7.5 `requests` follows redirects by default**
- Shape: no `allow_redirects=False`
- Exploit: 302 → metadata endpoint after allowlist passes

---

## API8:2023 — Security Misconfiguration

**8.1 CORS reflects origin with credentials**
- Shape: `allow_origins=["*"], allow_credentials=True`

**8.2 Django `DEBUG=True` in prod**
- Shape: settings loaded without env override
- Exploit: traceback page leaks SECRET_KEY, env, DB

**8.3 Flask `debug=True` / Werkzeug debugger exposed**
- Shape: `app.run(debug=True)` or `FLASK_DEBUG=1` in prod
- Exploit: Werkzeug PIN → RCE

**8.4 `ALLOWED_HOSTS = ['*']`**
- Shape: Django wildcard host
- Exploit: Host header attacks, cache poisoning

**8.5 Missing cookie flags**
- Shape: `SESSION_COOKIE_SECURE=False`, missing `HttpOnly`

**8.6 `manage.py check --deploy` findings**
- Any `W` or `E` flag from Django's deploy checklist

**8.7 `verify=False` on HTTPS client**
- Shape: `requests.get(url, verify=False)`
- Exploit: MITM

**8.8 Hardcoded `SECRET_KEY`**
- Shape: literal value in committed settings
- Exploit: session forgery

---

## API9:2023 — Improper Inventory Management

**9.1 `/v1/` live after `/v2/` deploy**

**9.2 `/internal/` URL conf included publicly**

**9.3 Django Debug Toolbar in production**

**9.4 Swagger UI in production without auth on internal endpoints**

**9.5 Management endpoints in production URL conf**

---

## API10:2023 — Unsafe Consumption of APIs

**10.1 Trusting 3rd-party webhook fields without verify + re-fetch**

**10.2 Reflecting 3rd-party HTML into email**

**10.3 OIDC role claim trusted without issuer validation**

---

## Python-specific add-ons

**P.1 `pickle.loads` on untrusted input**
- RCE. Never.

**P.2 `yaml.load` without `SafeLoader`**
- RCE via Python object instantiation

**P.3 `eval` / `exec` on user input**
- RCE

**P.4 `subprocess(..., shell=True)` with interpolation**
- Command injection

**P.5 `os.system` / `os.popen` with user input**
- Command injection

**P.6 `render_template_string(user_input)`**
- SSTI → RCE

**P.7 `lxml.etree` with external entities**
- XXE → file read / SSRF

**P.8 `tarfile.extractall` without `filter='data'` (Py 3.12+)**
- Tar slip

**P.9 `zipfile.extractall` without path check**
- Zip slip

**P.10 Django `.extra()` / `.raw()` with f-strings**
- SQL injection

**P.11 SQLAlchemy `text(f"...")`**
- SQL injection

**P.12 `random.*` for security tokens**
- Predictable

**P.13 pydantic `extra="allow"`**
- Mass assignment

**P.14 DRF `fields = "__all__"`**
- Excessive exposure

**P.15 `@csrf_exempt` + session auth**
- CSRF

**P.16 Celery task accepting user args that end in shell/SQL**
- Command / SQL injection via task queue

---

## Grep cheat-sheet

```
jwt\.decode\([^,)]+,[^,)]+\)                # missing algorithms
algorithms.*['"]none['"]                    # alg:none
verify_signature.*False                     # disabled verify
hashlib\.(md5|sha1)\(                       # weak hash
random\.(random|randint|choice|sample)      # weak RNG for secrets
uuid\.uuid4\(\)                             # if used as secret
subprocess.*shell\s*=\s*True                # shell exec
os\.(system|popen)\(                        # shell exec
\.(extra|raw)\(.*f['"]                      # Django raw SQL
text\(f['"]                                 # SQLAlchemy f-string
cursor\.execute\(f['"]                      # DB-API f-string
render_template_string\(                    # SSTI
pickle\.loads\(                             # unpickle
yaml\.load\([^,)]+\)$                       # yaml without SafeLoader
yaml\.load\(.*Loader=yaml\.(Unsafe|)Loader  # yaml unsafe loader
eval\(|exec\(                               # eval/exec
lxml\..*resolve_entities\s*=\s*True         # XXE
verify\s*=\s*False                          # TLS off
DEBUG\s*=\s*True                            # debug on
ALLOWED_HOSTS\s*=\s*\[['"]?\*              # wildcard host
SECRET_KEY\s*=\s*['"][A-Za-z0-9+/=]{10,}    # hardcoded
fields\s*=\s*['"]__all__['"]                # DRF __all__
ConfigDict\(extra=['"]allow['"]             # pydantic permissive
@csrf_exempt                                # CSRF bypass
requests\.(get|post).*verify\s*=\s*False    # TLS bypass
fetch\(request\.                            # SSRF
tarfile\..*extractall\(                     # tar slip (check filter)
zipfile.*extractall\(                       # zip slip
```
