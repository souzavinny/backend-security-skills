---
repo_url: https://github.com/stamparm/DSVW
repo_ref: master
---

# Ground Truth — Damn Small Vulnerable Web (DSVW)

Source: Miroslav Stampar's single-file Python vulnerable web app demonstrating a broad set of OWASP bugs in a minimal surface. Upstream: [stamparm/DSVW](https://github.com/stamparm/DSVW).

## Findings

FINDING | id: H-1 | severity: High | file: dsvw.py | function: (sqlite handler) | bug_class: sql-injection
description: Login and query endpoints concatenate user parameters into SQL, exposing classical SQLi including authentication bypass via `' OR '1'='1`.

FINDING | id: H-2 | severity: High | file: dsvw.py | function: (xpath handler) | bug_class: xpath-injection
description: The XPath handler injects user input into an XPath query, allowing authentication bypass and data extraction.

FINDING | id: H-3 | severity: High | file: dsvw.py | function: (xxe handler) | bug_class: xxe
description: The XXE endpoint parses user XML with external entity resolution, leaking local files and enabling SSRF.

FINDING | id: H-4 | severity: High | file: dsvw.py | function: (eval handler) | bug_class: code-injection
description: The eval endpoint passes user input directly to Python `eval()`, yielding RCE.

FINDING | id: H-5 | severity: High | file: dsvw.py | function: (command handler) | bug_class: command-injection
description: The command handler uses `os.system` / `subprocess` with string-interpolated user input, giving RCE.

FINDING | id: H-6 | severity: High | file: dsvw.py | function: (ssrf handler) | bug_class: ssrf
description: The SSRF endpoint fetches any URL supplied by the caller, with no allowlist or private-IP block, reaching cloud metadata and internal services.

FINDING | id: M-1 | severity: Medium | file: dsvw.py | function: (open-redirect handler) | bug_class: open-redirect
description: Redirect endpoint forwards to any user-supplied URL without allowlist, enabling phishing.

FINDING | id: M-2 | severity: Medium | file: dsvw.py | function: (html handler) | bug_class: reflected-xss
description: User-supplied content is reflected unescaped into the response HTML, yielding reflected XSS.

FINDING | id: M-3 | severity: Medium | file: dsvw.py | function: (path-traversal handler) | bug_class: directory-traversal
description: File viewer concatenates the filename into an `open()` call, allowing `../`-based access to arbitrary local files.

FINDING | id: M-4 | severity: Medium | file: dsvw.py | function: (login) | bug_class: missing-rate-limit
description: No rate limiting or lockout on the login endpoint, enabling credential brute-force.

FINDING | id: M-5 | severity: Medium | file: dsvw.py | function: (session handler) | bug_class: weak-session
description: Sessions are signed with a weak hardcoded secret and lack secure/httponly flags, enabling session forgery and theft.
