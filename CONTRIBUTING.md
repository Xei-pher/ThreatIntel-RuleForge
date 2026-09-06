# Contributing

Thanks for contributing to ThreatIntel RuleForge.

## Before opening a pull request

1. Create a focused branch from `main`.
2. Keep changes scoped; avoid unrelated formatting or generated artifacts.
3. Never commit report PDFs, local databases, `.env` files, API keys, `node_modules`, or virtual environments.
4. Add or update tests for backend behavior changes.
5. Run the backend test suite and frontend production build.

```bash
cd backend
pip install -r requirements-dev.txt
pytest

cd ../frontend
npm ci
npm run build
```

## Detection-engineering changes

For ATT&CK mappings and Sigma logic, include the evidence or rationale behind the change. Prefer behavior-based detections when the source evidence supports them, and document known false-positive tradeoffs.

Generated rules are not automatically trusted. Changes that increase automation should preserve human review and safe fallback behavior.

## Pull requests

A good pull request explains:

- the problem being solved;
- the implementation approach;
- how it was tested;
- any security, privacy, or detection-quality impact.

Small, reviewable pull requests are preferred.
