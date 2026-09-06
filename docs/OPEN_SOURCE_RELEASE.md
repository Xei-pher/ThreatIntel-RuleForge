# Open-source release checklist

Use this checklist before changing the repository visibility to public.

## 1. Rotate credentials

The development archive used during the open-source review contained local OpenAI and VirusTotal credentials in `backend/.env`. The file was not tracked in Git, but the credentials should still be revoked and replaced before publishing or sharing any further archive.

Keep real credentials only in local `.env` files or a secret manager. Commit only the provided `.env.example` files.

## 2. Validate the release candidate

From the repository root:

```bash
cd backend
python -m pip install -r requirements-dev.txt
pytest -q
python -m compileall -q app tests

cd ../frontend
npm ci
npm run build
```

Do not publish until the GitHub Actions CI and CodeQL workflows are green.

## 3. Publish the cleanup through a pull request

Create a branch, commit the open-source preparation, push it, and merge only after checks pass:

```bash
git switch -c open-source-readiness
git add .
git commit -m "chore: prepare project for open source"
git push -u origin open-source-readiness
```

## 4. Configure GitHub security

In **Settings → Security and analysis / Code security and analysis** (wording can vary), enable the public-repository security features available to the project, including Dependabot alerts, secret scanning, push protection, and code scanning.

Enable private vulnerability reporting so researchers have a non-public reporting path.

## 5. Protect `main`

Create a branch ruleset for `main` that:

- requires pull requests before merging;
- requires at least one approval;
- requires conversation resolution;
- requires the backend/frontend CI jobs and CodeQL checks;
- blocks force pushes and branch deletion.

Adjust these requirements if the repository is intentionally maintained by one person, but keep status checks and force-push protection.

## 6. Review visibility side effects

Before changing a private repository to public, review existing Actions logs, issue/PR content, releases, attachments, commit history, and repository metadata. Public visibility can expose historical repository content that was previously visible only to collaborators.

Only then use **Settings → General → Danger Zone → Change repository visibility → Public**.

## 7. Finish the public profile

Suggested repository description:

> Analyst-assisted threat-intelligence report processing that extracts IOCs, maps ATT&CK techniques, and drafts reviewable Sigma detections.

Suggested topics:

`threat-intelligence`, `cybersecurity`, `detection-engineering`, `sigma-rules`, `mitre-attack`, `ioc`, `fastapi`, `react`

Create the first release only after CI passes and the public README renders correctly.
