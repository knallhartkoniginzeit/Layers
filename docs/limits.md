# Limits & Boundaries
`layers` operates from the perspective of an external API consumer. It never guesses or claims beyond what is observered and obtained from the evidence.
# 1. Client-Side Visibility Horizon
- `layers` inspects what the client observes: outgoing requests, incoming response status/headers/bodies, timing measurements, and active transport handshakes (DNS, TCP, TLS).
- It does not have access to:
  - Upstream backend application logs
  - Internal database commit logs
  - Firewall or load balancer packet captures (PCAP)
  - Microservice mesh distributed traces (unless exposed in response headers)
# 2. Gateway Fingerprint Heuristics
- Gateway detection relies on characteristic signatures:
  - HTML error documents served on JSON APIs
  - Well-known edge server headers (`Server: nginx`, `CF-Ray`, `Via: varnish`)
  - Response elapsed times clustering near standard timeout cutoffs (10s, 15s, 30s, 60s, 90s, 100s, 120s)
- Edge cases: A bespoke internal proxy that mimics JSON schemas or strips `Server`/`Via` headers cannot be uniquely fingerprinted without internal knowledge.
# 3. Operation Completion Asymmetry
- For non-idempotent operations (such as `POST /orders`), the network may drop after the server processed the database transaction.
- Without a provider-specific readback API (or a persistent idempotency key), the completion verdict remains honestly `UNKNOWN`.
- `layers` will never guess `NOT_COMPLETED` when state cannot be confirmed.
# 4. Provider Pack Constraints
- Provider packs only add intelligence for documented public endpoints:
  -SerpApi: Can check account quota and search archive. If a query times out before a `search_id` is assigned, the Search Archive cannot be queried without an ID. The pack reports `UNKNOWN` honestly.
  - openAI-compatible: Distinguishes gateway 429 from provider 429 based on response body structure and edge headers.
# 5. Confidence Bands and Inconclusive Verdicts
- Below 0.35 confidence, verdicts are flagged as `INCONCLUSIVE`.
- Missing probes and lack of evidence reduce confidence rather than letting the engine make unfounded assumptions.