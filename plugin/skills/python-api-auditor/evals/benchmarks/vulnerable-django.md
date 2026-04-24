---
repo_url: https://github.com/nVisium/django.nV
repo_ref: master
scope_dir: taskManager
---

# Ground Truth — django.nV

Source: nVisium's intentionally vulnerable Django app covering the OWASP Top 10 in the Django context. Upstream: [nVisium/django.nV](https://github.com/nVisium/django.nV).

## Findings

FINDING | id: H-1 | severity: High | file: taskManager/views.py | function: upload | bug_class: unrestricted-file-upload
description: File upload writes any uploaded file to a web-served directory with no type or extension restriction, enabling arbitrary file upload including executable scripts.

FINDING | id: H-2 | severity: High | file: taskManager/views.py | function: search | bug_class: sql-injection
description: search builds a raw SQL query using string interpolation of the search term, allowing UNION-based extraction.

FINDING | id: H-3 | severity: High | file: taskManager/views.py | function: index | bug_class: stored-xss
description: Task descriptions are rendered with `|safe` (autoescape off) in the template, allowing stored XSS via user-submitted HTML.

FINDING | id: H-4 | severity: High | file: taskManager/views.py | function: forgotPassword | bug_class: predictable-reset-token
description: Password reset emails a predictable token derived from weak randomness and leaves it valid indefinitely, enabling account takeover.

FINDING | id: H-5 | severity: High | file: taskManager/views.py | function: taskDetail | bug_class: bola
description: taskDetail returns any task by ID without checking ownership, letting any authenticated user read any other user's task.

FINDING | id: M-1 | severity: Medium | file: taskManager/settings.py | function: (config) | bug_class: security-misconfig
description: Settings ship with DEBUG=True, a hardcoded SECRET_KEY, ALLOWED_HOSTS=['*'], and missing secure cookie flags, exposing SECRET_KEY via debug pages and enabling session forgery.

FINDING | id: M-2 | severity: Medium | file: taskManager/views.py | function: login | bug_class: missing-rate-limit
description: Login endpoint has no rate limit or account lockout, enabling credential stuffing.

FINDING | id: M-3 | severity: Medium | file: taskManager/views.py | function: register | bug_class: mass-assignment
description: Registration mass-assigns from the POST body into the user model, letting the client set is_staff/is_superuser.

FINDING | id: M-4 | severity: Medium | file: taskManager/views.py | function: delete | bug_class: bfla
description: Delete view is accessible by any authenticated user rather than the owner/admin only, enabling cross-user deletion.

FINDING | id: M-5 | severity: Medium | file: taskManager/views.py | function: (redirect handlers) | bug_class: open-redirect
description: Post-login / post-logout redirects honor a `next` parameter without allowlist validation, enabling phishing pivots.

FINDING | id: M-6 | severity: Medium | file: taskManager/views.py | function: (csrf exemptions) | bug_class: missing-csrf
description: Sensitive state-changing views use @csrf_exempt despite using Django cookie sessions, opening CSRF vectors.
