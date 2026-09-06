from types import SimpleNamespace

import yaml

from app.services.export_service import build_attack_navigator_layer
from app.services.mitre_service import map_mitre
from app.services.rule_service import generate_sigma_rules


def test_registry_run_key_maps_to_current_subtechnique(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    mappings = map_mitre("The malware established persistence using a registry run key.")
    assert any(item["technique_id"] == "T1547.001" for item in mappings)
    assert all(item["technique_id"] != "T1060" for item in mappings)


def test_fallback_sigma_rule_is_valid_yaml():
    rules = generate_sigma_rules(
        [{"ioc_type": "ipv4", "value": "8.8.8.8"}],
        [{"technique_id": "T1071", "technique_name": "Application Layer Protocol"}],
        report_text="",
    )
    assert len(rules) == 1
    parsed = yaml.safe_load(rules[0]["rule_content"])
    assert parsed["detection"]["condition"] == "selection"
    assert parsed["detection"]["selection"]["DestinationIp"] == ["8.8.8.8"]


def test_navigator_export_uses_current_versions():
    report = SimpleNamespace(title="Example", filename="example.pdf")
    mapping = SimpleNamespace(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        evidence="PowerShell executed a script.",
        confidence="high",
    )
    layer = build_attack_navigator_layer(report, [mapping])
    assert layer["versions"] == {"attack": "19.1", "navigator": "5.3.2", "layer": "4.5"}
