# Safety Rules
`layers` is designed to run safely against failing, degraded, or production APIs. It enforces five strict safety invariants in code.

# 1. Read-Only Probes
- All probes issued by `layers` are strictly read-only: HTTP `GET` and `HEAD`, or transport-layer handshakes (`DNS`, `TCP`, `TLS`).
- HTTP `POST`, `PUT`, `PATCH`, and `DELETE` requests are prohibited at the probe runner layer.
- Attempting to dispatch a mutating probe immediately raises a `SafetyViolation`.
# 2. No Blind Replay of Non-Idempotent Requests
- A failed non-idempotent request (e.g. `POST /orders`, `POST /payments`) is never replayed by default.
- Even with `--allow-replay`, only idempotent requests (`GET`, `PUT`, `DELETE`, or requests carrying an explicit `Idempotency-Key`) may be retried.
- If an operation's completion status is `UNKNOWN`, the tool issues `check_then_retry`, directing the developer to inspect the target system first before reissuing the write.
# 3. Pre-Ingest Secret Redaction
- Redaction happens before parsing or probing takes place.
- Tokens, API keys, basic authentication credentials in URLs, cookies, Bearer tokens, and sensitive query parameters (`api_key`, `secret`, `token`) are sanitized with `[REDACTED]`.
- The optional LLM explanation generator receives **only** sanitized findings and layer summaries; raw dictionary structures and body blobs are excluded.
# 4. Probe Budget & Per-Host Rate Limits
- To prevent exacerbating problems on a failing or throttled endpoint, `layers` enforces:
  - `--max-probes` limit (default: 20 per diagnosis).
  - Strict per-host concurrency and rate limit (maximum 3 probes to any single host per run).
- When a budget limit is reached, remaining probes are cleanly marked as `skipped` with the reason recorded in the diagnosis output.
# 5. Explicit Consent for Credential Verification
- Probes that test credentials using the actual API key require explicit opt-in via `--probe-auth`.
- Without `--probe-auth`, credential verification probes are skipped and recorded in `probes_skipped`.
# 6. Scoped Claims & Honesty
- Output reports explicitly contain `probes_skipped` and `limits`.
- The tool never claims certainty it cannot prove with captured evidence.
