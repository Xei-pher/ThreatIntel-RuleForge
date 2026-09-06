# Changelog

All notable project changes will be documented here.

## Unreleased

### Added
- Open-source project metadata, contribution guidance, security policy, CI, dependency review, CodeQL, and Dependabot configuration.
- Backend tests for IOC filtering, upload filename handling, health metadata, and fallback Sigma generation.
- Upload size limits and filename sanitization.

### Changed
- Dependency ranges are reproducible rather than using floating `latest` frontend versions.
- Health endpoints report whether integrations are configured without exposing API-key fragments.
- ATT&CK Registry Run Keys mapping uses `T1547.001`.
- ATT&CK Navigator exports target ATT&CK v19.1, Navigator v5.3.2, and layer format v4.5.
- Report reprocessing preserves previous results until a replacement processing run completes successfully.

### Security
- Removed local secrets, runtime databases, virtual environments, `node_modules`, and generated report data from the release tree.
