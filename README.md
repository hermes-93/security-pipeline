# security-pipeline

End-to-end DevSecOps pipeline demonstrating security scanning at every stage of the software delivery lifecycle.

## Security controls

| Stage | Tool | What it catches |
|-------|------|-----------------|
| Pre-commit | Gitleaks | Secrets in code |
| SAST | Semgrep | Code vulnerabilities, anti-patterns |
| SAST | Bandit | Python-specific security issues |
| SCA | Safety | Vulnerable Python dependencies |
| SCA | OWASP Dep-Check | CVEs in all dependencies |
| Container | Trivy | OS packages + app deps in image |
| Container | Hadolint | Dockerfile best practices |
| SBOM | Syft | Software Bill of Materials (CycloneDX) |
| Image signing | Cosign | Keyless signing via Sigstore |
| Policy | Conftest + OPA | Dockerfile and K8s manifest policies |
| DAST | OWASP ZAP | Runtime vulnerabilities (scheduled) |

## Pipeline overview

```
push / PR
   │
   ├── secrets-scan     Gitleaks — block on any secret detected
   ├── sast             Semgrep + Bandit — block on HIGH+
   ├── sca              Safety + pip-audit — block on CRITICAL CVE
   ├── container-scan   Build image → Trivy + Hadolint — block on CRITICAL
   ├── policy-check     Conftest/OPA — block on policy violation
   ├── sbom             Syft → CycloneDX JSON artifact
   └── sign             Cosign keyless sign (main branch only)

scheduled (nightly)
   └── dast             ZAP baseline scan against staging URL
```

## Repository structure

```
security-pipeline/
├── app/                    # Demo FastAPI application (scan target)
│   ├── src/main.py
│   ├── Dockerfile
│   └── requirements.txt
├── .github/workflows/
│   ├── security-scan.yml   # Main pipeline (all SAST/SCA/container)
│   └── dast.yml            # Nightly ZAP DAST scan
├── conftest/               # OPA/Conftest policies
│   ├── docker/policy.rego  # Dockerfile policies
│   └── k8s/policy.rego     # Kubernetes manifest policies
├── semgrep/                # Custom Semgrep rules
│   └── custom-rules.yaml
├── trivy/                  # Trivy configuration
│   └── trivy.yaml
├── .pre-commit-config.yaml # Pre-commit hooks (Gitleaks + linting)
└── scripts/
    ├── scan-local.sh       # Run all scans locally
    └── generate-sbom.sh    # Generate SBOM for local image
```

## Quick start

### Run all scans locally

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run full scan suite
./scripts/scan-local.sh
```

### Generate SBOM

```bash
./scripts/generate-sbom.sh app:latest
# Output: sbom.cyclonedx.json
```

### Verify image signature

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/hermes-93/security-pipeline" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/hermes-93/security-pipeline/app:latest
```

## Findings policy

| Severity | SAST | SCA | Container |
|----------|------|-----|-----------|
| CRITICAL | ❌ Block | ❌ Block | ❌ Block |
| HIGH | ❌ Block | ⚠️ Warn | ❌ Block |
| MEDIUM | ⚠️ Warn | ⚠️ Warn | ⚠️ Warn |
| LOW | ✅ Allow | ✅ Allow | ✅ Allow |

## License

MIT
