from app.services.llm_service import llm_status
from app.services.virustotal_service import vt_status


def test_health_metadata_does_not_expose_openai_key_fragment(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "unit-test-openai-key-never-return-this")
    status = llm_status()
    assert status["configured"] is True
    assert "api_key" not in status
    assert "secret" not in repr(status)


def test_health_metadata_does_not_expose_virustotal_key_fragment(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test-secret-value-that-should-never-be-returned")
    status = vt_status()
    assert status["configured"] is True
    assert "api_key" not in status
    assert "secret" not in repr(status)
