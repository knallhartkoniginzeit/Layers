# layers

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

CLI and library that diagnoses failed API calls by probing request, network, gateway, credentials, provider, and completion layers.

## Architecture

```
 input (curl / HAR / exception / raw)
            │
            ▼
    ┌───────────────┐
    │ Ingest        │  parse and redact FailureCase
    └───────┬───────┘
            ▼
    ┌───────────────┐
    │ Probe runner  │  request → network → gateway → credentials → provider → completion
    └───────┬───────┘
            │ Evidence[]
            ▼
    ┌───────────────┐
    │ Rule engine   │  evidence → ranked Hypotheses (layer, cause, confidence)
    └───────┬───────┘
            ▼
    ┌───────────────┐
    │ Recovery      │  Hypothesis → safe Action (retry / do-not-retry / patch)
    └───────┬───────┘
            ▼
    ┌───────────────┐
    │ Report        │  terminal, JSON, Markdown
    └───────────────┘
```

## Installation

```bash
pip install layers
```

Development:
```bash
git clone https://github.com/layers/layers.git
cd layers
pip install -e ".[dev]"
```

## Usage

### CLI

Diagnose a curl command:
```bash
layers diagnose "curl -X POST https://api.example.com/orders -d '{\"broken\": }'" --curl
```

Diagnose from stdin:
```bash
curl -v https://api.example.com/endpoint 2>&1 | layers diagnose - --curl
```

Diagnose a HAR file:
```bash
layers diagnose search_failure.har --har --provider serpapi
```

Diagnose an exception traceback with JSON output:
```bash
python app.py 2> error.log
layers diagnose error.log --exception --json
```

Run a probe in isolation:
```bash
layers probe dns https://api.example.com/
layers probe tls https://expired.badssl.com/
layers probe gateway https://api.example.com/
```

### Python Library

```python
from layers import diagnose
from layers.schemas import ActionKind

diagnosis = diagnose(
    "curl -X POST https://api.example.com/orders -d '{\"item\": 1}'",
    input_type="curl",
)

print(diagnosis.top.layer.value)
print(diagnosis.top.cause)
print(diagnosis.top.confidence)
print(diagnosis.action.kind.value)

if diagnosis.action.kind == ActionKind.CHECK_THEN_RETRY:
    print("Do not blindly retry: verify transaction state first.")
```

## Provider Packs

Provider packs add provider-specific error mappings, probes, and rules:
- `serpapi`: Host matching for `serpapi.com`, error mappings, quota separation, search archive completion checks.
- `openai_compat`: OpenAI, Groq, Together, and OpenRouter endpoints; gateway vs provider 429 classification.

```bash
layers packs list
layers packs show serpapi
```

## Safety Guarantees

- Read-only probes: only HTTP GET, HEAD, and transport handshakes are performed.
- Replay guard: non-idempotent write requests are never replayed by default.
- Redaction: secrets and authorization tokens are redacted before probing.
- Probe budget: max 20 probes per run with per-host throttling.

## License

MIT © 2024 layers contributors.
