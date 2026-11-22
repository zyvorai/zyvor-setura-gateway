# Security policy

Please report suspected vulnerabilities privately to **sales@zyvor.dev** with the subject "Zyvor Setura security". Do not open a public issue for a vulnerability. Include the version (`setura version`), what you observed, and steps to reproduce. We aim to acknowledge reports within three business days.

## Scope notes

- Setura reads cluster state through your existing `kubectl` credentials and never writes to the cluster. `publish` runs `kubectl port-forward` bound to `127.0.0.1`.
- Probes bypass HTTP proxy environment variables and use Go's TLS trust configuration; `--ca` replaces the system trust store for that one request.
- The optional `ai` command only talks to Ollama on `127.0.0.1` and treats report contents as untrusted data.
