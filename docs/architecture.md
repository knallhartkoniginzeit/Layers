# layers-Architecture
 input (curl / HAR / exception / raw / FailureCase)
            │
            ▼
   ┌─────────────────┐
   │ 1. Ingest       │  parse → FailureCase (redacted)
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │ 2. Pack Select  │  URL-matched or explicit provider pack
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │ 3. Probe Runner │  layered probes, safety-gated, budget-tracked
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │ 4. Rule Engine  │  evidence → weighted hypotheses
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │ 5. Recovery     │  top hypothesis → safe RecoveryAction + patch
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │ 6. Report       │  terminal / markdown / JSON
   └─────────────────┘
# 1. Ingest (`layers/ingest/`)
Converts any input format into a `FailureCase`:
| Module | Input |
|--------|-------|
| `curl.py` | `curl -X POST …` command or `curl -v` verbose output |
| `har.py` | HAR (HTTP Archive) entry or full `.har` file |
| `exception.py` | Python exception traceback (requests, httpx, urllib3) |
| `raw.py` | Raw pasted HTTP response (status + headers + body) |
All ingest paths run through `ingest/redact.py` which calls `safety.redact_all()`.
# 2. Provider Packs (`layers/packs/`)
Packs are plugins that teach layers about a specific API:
packs/
├── base.py        # ProviderPack protocol
├── registry.py    # autodiscovery by URL pattern
├── serpapi/       # SerpApi: quota, engine validity, CAPTCHA
└── openai_compat/ # OpenAI-compatible: model not found, context window
Each pack provides:
- Additional **probes** specific to the provider
- Additional **rules** that fire on provider-specific signals
- A `pack.yaml` with metadata and URL patterns for autodiscovery
# 3. Probe Runner (`layers/runner.py`)
Runs probes in **layered order** (cheapest → most expensive):
1. `request_lint` – zero-cost, no I/O
2. `proxy_env` – reads env vars only
3. `dns` – DNS resolution (100ms)
4. `tcp` – raw socket connect (timeout-bounded)
5. `tls` – TLS handshake (timeout-bounded)
6. `gateway_fingerprint` – static analysis of response
7. `provider_status` – HTTP to status page (opt-in)
8. `credentials` – authenticated GET (opt-in, `--probe-auth`)
9. `completion` – idempotent read-back (opt-in, `--allow-replay`)
10. Pack probes – provider-specific (loaded last)
Short-circuiting: if a network probe shows the host is unreachable (DNS/TCP), downstream probes are skipped.
Safety gate: every network probe calls `safety.check_probe_allowed()` before I/O.
# 4. Rule Engine (`layers/engine/`)
engine/
├── hypotheses.py  # RuleEngine: applies rules, scores hypotheses
├── confidence.py  # Dempster-Shafer-style belief update
└── rules/
    ├── network.py     # dns_failure, connection_refused, tls_error
    ├── gateway.py     # gateway_timeout, gateway_rate_limit
    ├── auth.py        # key_expired, key_invalid, missing_permission
    ├── rate_limit.py  # provider_rate_limit, gateway_rate_limit
    ├── provider.py    # provider_error, provider_incident
    └── timeout.py     # read_timeout, write_committed
Rules fire on evidence and update hypothesis confidence:
- Supporting evidence: `confidence += strength × (1 - confidence)` (belief accumulation)
- Contradicting evidence: `confidence *= (1 - strength)` (belief discount)
# 5. Recovery (`layers/recovery/`)
recovery/
├── actions.py       # action_for_hypothesis(): maps hypothesis → RecoveryAction
├── retry_policy.py  # safe backoff parameters for RETRY_WITH_BACKOFF
├── idempotency.py   # detects idempotency key headers
└── patches.py       # Python code patches shown as diffs (never auto-applied)
Every `RecoveryAction` has:
- `kind`: one of `retry_with_backoff`, `do_not_retry`, `check_then_retry`, `fix_request`, `fix_credentials`, `wait`, `escalate`
- `safe`: `True` only if the action cannot cause duplicate state mutations
- `explanation`: human-readable rationale
- `patch`: optional unified diff for the suggested code change
# 6. Report (`layers/report/`)
report/
├── terminal.py   # Rich-coloured interactive output
├── markdown.py   # PR comment / CI summary format
├── json_out.py   # Machine-readable for agents / CI
└── explain.py    # Honesty guard: refuses unsupported claims
# Key Data Models (`layers/schemas.py`)
FailureCase  # normalised, redacted API failure
Evidence  # one finding from one probe
Hypothesis  # candidate explanation with confidence score
RecoveryAction  # safe, reviewable recovery step
Diagnosis  # complete output: case + top + alternatives + action
ProbeResult  # raw output of a single probe
# Safety Model
See [docs/safety.md](safety.md) for the full threat model.
Key invariants:
- No write-method network probes ever (only GET/HEAD allowed)
- Replay guard off by default
- Auth probes off by default
- Per-host probe budget prevents excessive requests
- All inputs redacted before any probe or report
# Provider Pack Interface
See [docs/writing-a-pack.md](writing-a-pack.md) for the full guide.
```python
class MyPack(ProviderPack):
    name = "myprovider"
    url_patterns = [r"api\.myprovider\.com"]

    def probes(self) -> list[Probe]:
        return [MyCustomProbe()]

    def rules(self) -> list[Rule]:
        return MY_RULES
```
