"""Scope-guard behavior: the agent only handles SOC triage requests."""
from soc_agent.agent import is_in_scope, sanitize


def test_security_query_is_in_scope():
    ok, reason = is_in_scope("Triage security alert for host WS5")
    assert ok is True
    assert reason == ""


def test_event_payload_always_in_scope():
    # Scheduled triage passes an event payload -- never rejected.
    ok, _ = is_in_scope("", event_payload={"host_ip": "WS5"})
    assert ok is True


def test_offtopic_query_is_rejected_with_explanation():
    ok, reason = is_in_scope("write me a poem about the ocean")
    assert ok is False
    assert "SOC" in reason or "scope" in reason.lower()


def test_empty_query_is_rejected():
    ok, _ = is_in_scope("   ")
    assert ok is False


def test_sanitize_strips_nonprintable_and_truncates():
    dirty = "alert\x00\x1b[31m" + "A" * 500
    clean = sanitize(dirty, max_chars=64)
    assert len(clean) <= 64
    assert all(32 <= ord(ch) < 127 for ch in clean)
    assert clean.startswith("alert")
