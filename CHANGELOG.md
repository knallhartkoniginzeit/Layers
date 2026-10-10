# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure with full CLI and library surfaces
- `layers diagnose` command for evidence-backed API failure diagnosis
- `layers probe` command for running individual probes
- `layers explain` command for human-readable explanations
- `layers testbed` command for local scenario testing
- `layers eval` command for batch accuracy evaluation

### Probes
- **request_lint** – validates method/body/Content-Type consistency
- **dns** – resolves hostname via dnspython, detects NXDOMAIN / timeout
- **tcp** – raw socket connect to detect port closed / filtered
- **tls** – full TLS handshake with cert chain, hostname, and expiry checks
- **proxy_env** – reads HTTP_PROXY / HTTPS_PROXY env vars for misconfiguration
- **gateway_fingerprint** – detects HTML error pages, CDN headers, fixed timeouts
- **credentials** – opt-in read-vs-write probe to distinguish key vs. permission errors
- **provider_status** – checks Statuspage API for open provider incidents
- **completion** – determines if a timed-out write actually committed

### Engine
- Rule-based hypothesis evaluation with Dempster-Shafer-style confidence update
- Evidence weighted by `strength` and penalised by contradictions
- `ConfidenceBand`: HIGH / MED / LOW / INCONCLUSIVE thresholds

### Recovery
- Safe `RecoveryAction` for every hypothesis kind
- `patches.py` – Python code patches shown as reviewable diffs (never auto-applied)
- `retry_policy.py` – exponential-backoff-aware retry guidance
- `idempotency.py` – idempotency key detection to guard non-safe retries

### Provider Packs
- **serpapi** – SerpApi-specific probes and rules (quota, invalid engine, CAPTCHA)
- **openai_compat** – OpenAI-compatible API probes and rules (model not found, context window)
- Pack registry for autodiscovery

### Ingest
- curl command string parser (inline and `-v` verbose output)
- HAR (HTTP Archive) file and entry parser
- Python exception traceback parser (requests, httpx, urllib3)
- Raw HTTP response parser (status line + headers + body)
- Credential redaction for all ingest paths

### Report
- Rich-coloured terminal output with evidence table
- Markdown output for PR comments and CI summaries
- JSON output for agent loops and tooling integration
- `explain.py` – honesty guard that refuses unsupported claims

### Safety
- Probe method allowlist (`ALLOWED_PROBE_METHODS = {"GET", "HEAD"}`)
- Per-run probe budget tracker (max N probes per host)
- Replay guard (opt-in only via `--allow-replay`)
- Credential redaction invariants validated at import time

### Testbed
- Local Docker Compose environment with toy FastAPI server and nginx
- 20 hand-crafted failure scenarios (S01–S20) in YAML
- `testbed/run.py` – runs all scenarios through layers and reports accuracy

### Eval
- `eval/run_eval.py` – batch evaluator against scenario YAML files
- `eval/baseline.py` – minimal rule-of-thumb baseline for accuracy comparison

### Docs
- `docs/safety.md` – safety guarantees and threat model
- `docs/limits.md` – documented limits and known edge cases
- `docs/writing-a-pack.md` – guide for creating new provider packs

## [0.1.0] - TBD

Initial public release.
