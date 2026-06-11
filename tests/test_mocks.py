"""Mock fixtures are deterministic and shaped like the live UC/API responses."""
from soc_agent import mocks


def test_mock_score_anomaly_shape():
    rows = mocks.mock_score_anomaly("WS5", 60)
    assert isinstance(rows, list) and rows
    top = rows[0]
    assert "host_ip" in top and "z_score" in top
    assert isinstance(float(top["z_score"]), float)


def test_mock_virustotal_shape():
    d = mocks.mock_virustotal("WS5")
    assert isinstance(d, dict) and d


def test_mock_shodan_shape():
    d = mocks.mock_shodan("FILESRV1")
    assert isinstance(d, dict) and d


def test_mock_nvd_returns_cve_list():
    out = mocks.mock_nvd("powershell")
    assert isinstance(out, list)
