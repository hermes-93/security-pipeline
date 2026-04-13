#!/usr/bin/env bash
# Generate a CycloneDX SBOM for a Docker image using Syft.
# Usage: ./scripts/generate-sbom.sh <image:tag>

set -euo pipefail

IMAGE="${1:-security-pipeline:local}"
OUTPUT="${2:-sbom.cyclonedx.json}"

if ! command -v syft &>/dev/null; then
    echo "Installing Syft..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
fi

echo "Generating SBOM for: $IMAGE"
syft "$IMAGE" \
    --output cyclonedx-json="$OUTPUT" \
    --output table

echo "SBOM written to: $OUTPUT"
echo "Component count: $(python3 -c "import json; d=json.load(open('$OUTPUT')); print(len(d.get('components', [])))")"
