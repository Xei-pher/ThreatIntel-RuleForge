from pathlib import Path
import csv
import yaml
from zipfile import ZipFile

EXPORT_DIR = Path(__file__).resolve().parents[2] / "storage" / "exports"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)


def export_report(report, iocs, mappings, detections) -> str:
    base = EXPORT_DIR / f"report_{report.id}_export"
    base.mkdir(parents=True, exist_ok=True)

    csv_path = base / "iocs.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value", "confidence", "approved", "context"])
        for ioc in iocs:
            writer.writerow([ioc.ioc_type, ioc.value, ioc.confidence, ioc.is_approved, ioc.source_context])

    mitre_path = base / "mitre_mapping.yaml"
    with mitre_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump([
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "evidence": m.evidence,
                "confidence": m.confidence,
            } for m in mappings
        ], f, sort_keys=False)

    rules_dir = base / "sigma_rules"
    rules_dir.mkdir(exist_ok=True)
    for rule in detections:
        safe_name = "".join(c if c.isalnum() else "_" for c in rule.title.lower())[:80]
        (rules_dir / f"{safe_name}.yml").write_text(rule.rule_content, encoding="utf-8")

    md_path = base / "summary.md"
    md_path.write_text(f"""# Threat Intelligence Extraction Report

## Source

- File: {report.filename}
- Status: {report.processing_status}

## Summary

{report.summary or 'No summary generated.'}

## IOC Count

{len(iocs)} indicators extracted.

## MITRE Techniques

""" + "\n".join([f"- {m.technique_id}: {m.technique_name} ({m.confidence})" for m in mappings]) + "\n\n## Detection Rules\n\n" + "\n".join([f"- {d.title} [{d.severity}]" for d in detections]), encoding="utf-8")

    zip_path = EXPORT_DIR / f"report_{report.id}_export.zip"
    with ZipFile(zip_path, "w") as zipf:
        for file in base.rglob("*"):
            if file.is_file():
                zipf.write(file, file.relative_to(base))
    return str(zip_path)
