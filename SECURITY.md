# Security Policy

## Reporting vulnerabilities

If you discover a vulnerability in these skills (e.g. a prompt-injection payload
that causes the auditor to produce unsafe output, or a code-injection in the
eval runner scripts), please email the maintainer privately rather than opening
a public issue.

## Scope

These skills read source code from repos they are pointed at. They do not
execute that source code. If a target repo contains malicious code designed to
exfiltrate secrets via the LLM context window (indirect prompt injection), the
LLM — not this skill — is the vector. Keep sensitive credentials out of repos
you audit.

## Disclaimer

These skills produce AI-generated security findings. AI analysis cannot verify
the complete absence of vulnerabilities. Professional security reviews and bug
bounty programs remain the authoritative bar for production systems.
