import pytest

from layers.safety import (
    ProbeBudget,
    SafetyViolation,
    assert_probe_method_allowed,
    assert_replay_allowed,
)


def test_probe_method_allowed():
    assert_probe_method_allowed("GET")
    assert_probe_method_allowed("HEAD")
    assert_probe_method_allowed("get")


def test_probe_method_forbidden_rejected():
    with pytest.raises(SafetyViolation, match="Only GET and HEAD are permitted"):
        assert_probe_method_allowed("POST")

    with pytest.raises(SafetyViolation, match="Only GET and HEAD are permitted"):
        assert_probe_method_allowed("PUT")

    with pytest.raises(SafetyViolation, match="Only GET and HEAD are permitted"):
        assert_probe_method_allowed("DELETE")


def test_probe_budget_limit():
    budget = ProbeBudget(max_probes=3)
    budget.consume("p1")
    budget.consume("p2")
    budget.consume("p3")
    assert budget.remaining == 0

    with pytest.raises(SafetyViolation, match="Probe budget exhausted"):
        budget.consume("p4")


def test_per_host_rate_limit():
    budget = ProbeBudget(max_probes=10)
    host = "api.example.com"
    budget.consume("p1", host=host)
    budget.consume("p2", host=host)
    budget.consume("p3", host=host)

    with pytest.raises(SafetyViolation, match="Per-host rate limit reached"):
        budget.consume("p4", host=host)


def test_replay_guard_non_idempotent():
    from layers.config import settings

    settings.probe.allow_replay = False
    with pytest.raises(SafetyViolation, match="Replay of the original request is disabled"):
        assert_replay_allowed(idempotent=True)

    settings.probe.allow_replay = True
    with pytest.raises(
        SafetyViolation, match="Replay refused: the original call was non-idempotent"
    ):
        assert_replay_allowed(idempotent=False)

    settings.probe.allow_replay = False
