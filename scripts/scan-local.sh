#!/usr/bin/env bash
# Run the full security scan suite locally.
# Requires: bandit, pip-audit, semgrep, trivy, conftest, docker

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

pass() { echo -e "${GREEN}  ✅ $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠️  $*${NC}"; }
fail() { echo -e "${RED}  ❌ $*${NC}"; FAILED=1; }
step() { echo -e "\n${BLUE}▶ $*${NC}"; }

FAILED=0
cd "$ROOT"

# ── 1. Secrets scan ───────────────────────────────────────────────────────────
step "Gitleaks — secrets detection"
if command -v gitleaks &>/dev/null; then
    if gitleaks detect --source . --no-banner 2>/dev/null; then
        pass "No secrets detected"
    else
        fail "Secrets detected! Check gitleaks output above."
    fi
else
    warn "gitleaks not installed — skipping (install: https://github.com/gitleaks/gitleaks)"
fi

# ── 2. SAST: Bandit ───────────────────────────────────────────────────────────
step "Bandit — Python SAST"
if command -v bandit &>/dev/null; then
    if bandit -r app/src/ -ll -ii --quiet; then
        pass "No HIGH/CRITICAL Bandit issues"
    else
        fail "Bandit found HIGH/CRITICAL issues"
    fi
else
    warn "bandit not installed — run: pip install bandit[toml]"
fi

# ── 3. SAST: Semgrep ──────────────────────────────────────────────────────────
step "Semgrep — SAST with custom rules"
if command -v semgrep &>/dev/null; then
    if semgrep --config semgrep/custom-rules.yaml app/src/ --quiet; then
        pass "No Semgrep findings"
    else
        warn "Semgrep findings detected (see output above)"
    fi
else
    warn "semgrep not installed — run: pip install semgrep"
fi

# ── 4. SCA: pip-audit ────────────────────────────────────────────────────────
step "pip-audit — dependency vulnerability scan"
if command -v pip-audit &>/dev/null; then
    if pip-audit --requirement app/requirements.txt --strict --quiet; then
        pass "No vulnerable dependencies found"
    else
        fail "Vulnerable dependencies detected"
    fi
else
    warn "pip-audit not installed — run: pip install pip-audit"
fi

# ── 5. Container: Hadolint ────────────────────────────────────────────────────
step "Hadolint — Dockerfile linting"
if command -v hadolint &>/dev/null; then
    if hadolint app/Dockerfile; then
        pass "Dockerfile is clean"
    else
        warn "Hadolint warnings in Dockerfile"
    fi
else
    warn "hadolint not installed — see https://github.com/hadolint/hadolint"
fi

# ── 6. Container: Trivy ──────────────────────────────────────────────────────
step "Trivy — container image scan"
if command -v docker &>/dev/null && command -v trivy &>/dev/null; then
    echo "  Building image..."
    docker build app/ --tag security-pipeline:local --quiet

    if trivy image \
        --config trivy/trivy.yaml \
        --severity CRITICAL,HIGH \
        --exit-code 1 \
        --quiet \
        security-pipeline:local; then
        pass "No CRITICAL/HIGH CVEs in image"
    else
        fail "CRITICAL/HIGH CVEs found in image"
    fi
else
    warn "docker or trivy not installed — skipping container scan"
fi

# ── 7. Policy: Conftest ───────────────────────────────────────────────────────
step "Conftest — OPA policy check"
if command -v conftest &>/dev/null; then
    if conftest test app/Dockerfile --policy conftest/docker/ --namespace docker; then
        pass "Dockerfile passes all policies"
    else
        fail "Dockerfile policy violations found"
    fi
else
    warn "conftest not installed — see https://www.conftest.dev"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}✅ All security checks passed!${NC}"
else
    echo -e "${RED}❌ Some security checks FAILED. Review output above.${NC}"
    exit 1
fi
