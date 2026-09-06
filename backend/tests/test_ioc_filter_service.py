from app.services.ioc_filter_service import filter_iocs, should_keep_ioc


def test_private_ipv4_is_filtered():
    keep, reason = should_keep_ioc({"ioc_type": "ipv4", "value": "192.168.1.10"})
    assert keep is False
    assert "non-public" in reason


def test_public_ipv4_is_kept():
    keep, reason = should_keep_ioc({"ioc_type": "ipv4", "value": "8.8.8.8"})
    assert keep is True
    assert reason == ""


def test_reference_domain_and_duplicates_are_removed():
    kept, removed = filter_iocs(
        [
            {"ioc_type": "domain", "value": "attack.mitre.org"},
            {"ioc_type": "domain", "value": "evil.example.net"},
            {"ioc_type": "domain", "value": "evil.example.net"},
        ]
    )
    assert [item["value"] for item in kept] == ["evil.example.net"]
    assert len(removed) == 2
