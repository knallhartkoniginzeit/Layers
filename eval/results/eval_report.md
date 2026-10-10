# layers Evaluation Benchmark (N=20 scenarios)

This evaluation benchmarks `layers` against a naive status-code and keyword classifier baseline across 20 fault-injected scenarios.

## Summary Metrics

| Metric | Status-Code Baseline | layers | Delta / Notes |
| :--- | :---: | :---: | :---: |
| **Layer-attribution accuracy** | 70.0% (14/20) | **100.0%** (20/20) | **+30.0%** |
| **Cause accuracy** | 25.0% (5/20) | **75.0%** (15/20) | **+50.0%** |
| **Safe-action rate** | 80.0% | **100.0%** | Prevents blind retry on non-idempotent writes |
| **Completion-verdict accuracy** | 30.0% | **65.0%** | Avoids false NOT_COMPLETED defaults |
| **Calibration (HIGH band)** | N/A | **100.0%** | 20/20 high-confidence cases correct |
| **False-certainty count** | Unbounded | **0** | Zero false high-confidence claims |
| **Probes used per diagnosis** | 0.0 | **5.8** | Layered short-circuiting limits cost |

## Per-Scenario Breakdown

| Scenario | Expected Layer | Baseline Layer | layers Layer | Safe Advice (Base / fs) | Completion (Base / fs) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `S01_expired_key` | `credentials` | `credentials` (PASS) | `credentials` (PASS) | `True` / `True` | `NOT_COMPLETED` / `NOT_APPLICABLE` |
| `S02_invalid_key` | `credentials` | `credentials` (PASS) | `credentials` (PASS) | `True` / `True` | `NOT_COMPLETED` / `NOT_APPLICABLE` |
| `S03_missing_scope_read_ok_write_403` | `credentials` | `credentials` (PASS) | `credentials` (PASS) | `True` / `True` | `NOT_COMPLETED` / `NOT_COMPLETED` |
| `S04_key_valid_quota_exhausted` | `credentials` | `provider` (FAIL) | `credentials` (PASS) | `True` / `True` | `NOT_COMPLETED` / `NOT_APPLICABLE` |
| `S05_malformed_json` | `request` | `request` (PASS) | `request` (PASS) | `True` / `True` | `NOT_COMPLETED` / `UNKNOWN` |
| `S06_wrong_content_type` | `request` | `request` (PASS) | `request` (PASS) | `True` / `True` | `NOT_COMPLETED` / `UNKNOWN` |
| `S07_missing_required_field` | `request` | `request` (PASS) | `request` (PASS) | `True` / `True` | `NOT_COMPLETED` / `UNKNOWN` |
| `S08_dns_failure` | `network` | `network` (PASS) | `network` (PASS) | `True` / `True` | `NOT_COMPLETED` / `UNKNOWN` |
| `S09_connection_refused` | `network` | `network` (PASS) | `network` (PASS) | `True` / `True` | `NOT_COMPLETED` / `UNKNOWN` |
| `S10_tls_expired` | `network` | `network` (PASS) | `network` (PASS) | `True` / `True` | `NOT_COMPLETED` / `UNKNOWN` |
| `S11_tls_hostname_mismatch` | `network` | `network` (PASS) | `network` (PASS) | `True` / `True` | `NOT_COMPLETED` / `UNKNOWN` |
| `S12_bad_proxy_env` | `network` | `network` (PASS) | `network` (PASS) | `True` / `True` | `NOT_COMPLETED` / `NOT_APPLICABLE` |
| `S13_html_502_nginx` | `gateway` | `provider` (FAIL) | `gateway` (PASS) | `True` / `True` | `NOT_COMPLETED` / `NOT_APPLICABLE` |
| `S14_proxy_timeout_fixed_duration` | `gateway` | `provider` (FAIL) | `gateway` (PASS) | `False` / `True` | `NOT_COMPLETED` / `UNKNOWN` |
| `S15_gateway_429_with_retry_after` | `gateway` | `provider` (FAIL) | `gateway` (PASS) | `True` / `True` | `NOT_COMPLETED` / `NOT_APPLICABLE` |
| `S16_provider_429_no_gateway_headers` | `provider` | `provider` (PASS) | `provider` (PASS) | `False` / `True` | `NOT_COMPLETED` / `NOT_COMPLETED` |
| `S17_provider_500_internal_error` | `provider` | `provider` (PASS) | `provider` (PASS) | `True` / `True` | `NOT_COMPLETED` / `NOT_COMPLETED` |
| `S18_provider_incident_open` | `provider` | `provider` (PASS) | `provider` (PASS) | `True` / `True` | `NOT_COMPLETED` / `NOT_APPLICABLE` |
| `S19_timeout_write_committed` | `gateway` | `provider` (FAIL) | `gateway` (PASS) | `False` / `True` | `NOT_COMPLETED` / `COMPLETED` |
| `S20_timeout_write_not_committed` | `gateway` | `provider` (FAIL) | `gateway` (PASS) | `False` / `True` | `NOT_COMPLETED` / `UNKNOWN` |