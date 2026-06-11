"""Escalation-gate decisioning in classify_and_ticket().

The gate (aligned with the deployed databricks_src/03_soc_agent_live.py):

    escalate = z > 1.5 AND (confidence > 0.7 OR tactic == MANUAL_REVIEW)

- escalated:      anomalous host + confident classification  -> incident written
- manual_review:  anomalous host + LLM could not classify    -> incident written
- dismissed:      quiet host (z <= 1.5), regardless of confidence -> no write
"""
from typing import Any, Dict

import pytest

from soc_agent.agent import classify_and_ticket
from soc_agent.config import Settings


class FakeLLM:
    """Duck-typed stand-in returning a fixed classification."""

    def __init__(self, classification: Dict[str, Any]):
        self._classification = classification

    def classify_json(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return dict(self._classification)


def run_gate(z: float, conf: float, tactic: str = "Execution") -> Dict[str, Any]:
    settings = Settings()  # mock_mode=True default; z gate 1.5, conf gate 0.7
    llm = FakeLLM({
        "tactic": tactic,
        "technique_id": "T1059",
        "severity": "HIGH",
        "confidence": conf,
    })
    context = {"host_ip": "WS5", "z_score": z, "event_payload": {"user_id": "u1"}}
    return classify_and_ticket(context, llm=llm, settings=settings)


def test_anomalous_and_confident_escalates():
    res = run_gate(z=2.0, conf=0.9)
    assert res["decision"] == "escalated"
    assert res["written"] is True
    assert res["incident"] is not None


def test_anomalous_but_unclassifiable_goes_to_manual_review():
    res = run_gate(z=2.0, conf=0.0, tactic="MANUAL_REVIEW")
    assert res["decision"] == "manual_review"
    assert res["written"] is True


def test_anomalous_low_confidence_is_dismissed():
    res = run_gate(z=2.0, conf=0.3)
    assert res["decision"] == "dismissed"
    assert res["written"] is False
    assert res["incident"] is None


def test_quiet_host_dismissed_despite_high_confidence():
    res = run_gate(z=0.5, conf=0.99)
    assert res["decision"] == "dismissed"
    assert res["written"] is False


def test_quiet_host_manual_review_does_not_create_noise():
    # MANUAL_REVIEW only escalates INSIDE an anomaly -- a quiet host must not
    # generate tickets just because the LLM was uncertain.
    res = run_gate(z=0.0, conf=0.0, tactic="MANUAL_REVIEW")
    assert res["decision"] == "dismissed"
    assert res["written"] is False


@pytest.mark.parametrize("z", [1.5, 1.0, 0.0])
def test_gate_boundary_is_strictly_greater_than(z):
    res = run_gate(z=z, conf=0.95)
    assert res["decision"] == "dismissed"


def test_threshold_is_env_configurable(monkeypatch):
    settings = Settings(anomaly_z_threshold=3.0)
    llm = FakeLLM({"tactic": "Execution", "technique_id": "T1059",
                   "severity": "HIGH", "confidence": 0.9})
    res = classify_and_ticket({"host_ip": "WS5", "z_score": 2.0}, llm=llm, settings=settings)
    assert res["decision"] == "dismissed"
