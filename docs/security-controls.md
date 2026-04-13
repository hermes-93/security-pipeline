# Security Controls Reference

## Defense-in-depth model

```
Developer workstation
  └── pre-commit hooks
        ├── Gitleaks        (secrets)
        ├── Bandit          (Python SAST)
        └── Hadolint        (Dockerfile)

CI pipeline (every push/PR)
  ├── Gitleaks CI          (secrets — full history scan)
  ├── Semgrep              (SAST — OWASP Top 10, JWT, custom rules)
  ├── Bandit               (Python-specific SAST)
  ├── pip-audit            (SCA — PyPI advisory database)
  ├── Safety               (SCA — additional CVE database)
  ├── Trivy image          (container OS + app layer CVEs)
  ├── Trivy fs             (IaC misconfigs, repo secrets)
  ├── Hadolint             (Dockerfile best practices)
  └── Conftest/OPA         (policy-as-code enforcement)

Post-build (main branch only)
  ├── Syft SBOM            (CycloneDX inventory)
  └── Cosign sign          (keyless image signing via Sigstore)

Scheduled (nightly)
  └── OWASP ZAP DAST       (runtime vulnerability discovery)
```

## Tool rationale

| Tool | Category | Why this tool |
|------|----------|---------------|
| Gitleaks | Secrets | High accuracy, low false positive rate, git-aware (scans history) |
| Semgrep | SAST | Language-agnostic, custom rules in YAML, no code upload required |
| Bandit | SAST | Python-specific, understands stdlib security patterns |
| pip-audit | SCA | Official PyPA tool, uses PyPI Advisory Database |
| Safety | SCA | Complementary CVE database coverage |
| Trivy | Container/IaC | Single tool for OS, app libs, secrets, misconfig |
| Hadolint | Dockerfile | Maps to Docker best practices and CIS benchmarks |
| Conftest | Policy | OPA-based, reusable across Dockerfile/K8s/Terraform |
| Syft | SBOM | CycloneDX + SPDX output, integrates with Grype for vuln scan |
| Cosign | Signing | Keyless signing via Sigstore — no key management needed |
| ZAP | DAST | Industry standard, detects runtime vulns missed by SAST |

## Severity thresholds

```
CRITICAL  → Block CI, must fix before merge
HIGH      → Block CI for SAST/container; warn for SCA
MEDIUM    → Warn, tracked in Security tab
LOW       → Informational
```

## SBOM (Software Bill of Materials)

Every image pushed to GHCR gets an attached CycloneDX SBOM. This enables:
- Vulnerability tracking over time (run Grype against archived SBOMs)
- License compliance auditing
- Supply chain transparency

## Image signing (Sigstore/Cosign)

Images pushed from main branch are signed with Cosign keyless signing:
- No private key to manage or rotate
- Signature tied to GitHub Actions OIDC identity
- Verification: `cosign verify --certificate-identity-regexp="..." image`

## Adding a new check

1. Add the tool/step to `.github/workflows/security-scan.yml`
2. Add corresponding pre-commit hook to `.pre-commit-config.yaml`  
3. Update `scripts/scan-local.sh` so developers can run it locally
4. Document threshold/rationale in this file
