# Transcripts

HTTP request/response transcripts from runtime audits are written to a per-run subfolder:

```
{YYYYMMDD-HHMMSS}/
├── 001-probe-name.http
├── 002-probe-name.http
└── ...
```

Each `.http` file contains the request + response for one probe, for reproduction and evidence attachment.

Transcript folders are git-ignored. Keep this README committed so the directory exists.
