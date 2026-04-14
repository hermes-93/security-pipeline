# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-04-15

### Added
- Sample Flask application with JWT auth, bcrypt passwords, SHA-256 (no MD5/SHA-1)
- Multi-stage Dockerfile: non-root user UID 1001, HEALTHCHECK, minimal attack surface
- 7-stage Security Pipeline (GitHub Actions):
  1. **Secrets scan** — Gitleaks full-history scan
  2. **SAST** — Semgrep (p/python, p/owasp-top-ten, p/jwt, custom rules) + Bandit
  3. **SCA** — pip-audit (block on CRITICAL) + Safety (warn)
  4. **Container scan** — Hadolint + Trivy image (SARIF) + Trivy filesystem
  5. **Policy check** — Conftest/OPA for Dockerfile and K8s manifests
  6. **SBOM** — Syft CycloneDX JSON, 90-day retention
  7. **Push & Sign** — GHCR push + Cosign keyless signing via Sigstore OIDC
- OPA/Rego policies: Dockerfile rules (no root, no :latest, HEALTHCHECK required)
- OPA/Rego policies: Kubernetes rules (runAsNonRoot, resource limits, no privileged)
- Semgrep custom rules: hardcoded secrets, API keys, MD5/SHA-1, SQL injection, unsafe pickle
- Trivy configuration: `.trivyignore`, `trivy.yaml`
- DAST workflow: OWASP ZAP baseline scan (scheduled weekly)
- Security controls documentation

### Security
- All 7 security scanning stages gate the image push
- Images signed with Cosign keyless (Sigstore OIDC) for supply chain integrity
- SBOM generated with Syft in CycloneDX format
- SARIF results from Semgrep, Bandit, Trivy uploaded to GitHub Security tab
- No hardcoded secrets — all via environment variables with startup validation

### Fixed
- Conftest installation: switched to `go install` for runner compatibility
- Semgrep: replaced deprecated cloud action with `pip install semgrep`
- Trivy SARIF: separated scan (always writes file) from fail check

[Unreleased]: https://github.com/hermes-93/security-pipeline/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/hermes-93/security-pipeline/releases/tag/v1.0.0
