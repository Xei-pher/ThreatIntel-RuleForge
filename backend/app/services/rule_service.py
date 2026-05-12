import yaml
from typing import Dict, List
from datetime import date


def generate_sigma_rules(iocs: List[Dict], mitre: List[Dict]) -> List[Dict]:
    rules = []
    grouped = {}
    for ioc in iocs:
        grouped.setdefault(ioc["ioc_type"], []).append(ioc["value"])

    mitre_tags = [f"attack.{m['technique_id'].lower()}" for m in mitre[:5]]

    for ioc_type, values in grouped.items():
        if ioc_type not in {"domain", "url", "ipv4", "sha256", "sha1", "md5", "windows_path", "registry_key"}:
            continue
        field = {
            "domain": "DestinationHostname",
            "url": "url.original",
            "ipv4": "DestinationIp",
            "sha256": "file.hash.sha256",
            "sha1": "file.hash.sha1",
            "md5": "file.hash.md5",
            "windows_path": "Image",
            "registry_key": "TargetObject",
        }[ioc_type]
        title = f"Threat Report IOC Match - {ioc_type.upper()}"
        sigma = {
            "title": title,
            "id": f"ruleforge-{ioc_type}-{date.today().isoformat()}",
            "status": "experimental",
            "description": f"Detects {ioc_type} indicators extracted from an uploaded threat report.",
            "author": "ThreatIntel RuleForge",
            "date": date.today().isoformat(),
            "references": ["Uploaded threat report"],
            "tags": mitre_tags or ["attack.discovery"],
            "logsource": {"product": "windows" if ioc_type in {"windows_path", "registry_key"} else "proxy"},
            "detection": {
                "selection": {field: values[:50]},
                "condition": "selection",
            },
            "falsepositives": ["Legitimate access to previously reported infrastructure", "Shared hosting or sinkholed infrastructure"],
            "level": "medium",
        }
        rules.append({
            "rule_type": "sigma",
            "title": title,
            "description": sigma["description"],
            "severity": "medium",
            "mitre_technique": ",".join([m["technique_id"] for m in mitre[:3]]) if mitre else None,
            "rule_content": yaml.safe_dump(sigma, sort_keys=False),
            "status": "draft",
        })
    return rules
