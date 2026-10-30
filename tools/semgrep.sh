#!/usr/bin/env bash
# Scans every rule variant with Semgrep's public C# rules and writes one SARIF file per variant.
#
# Usage (from the repository root):
#   git clone --depth 1 https://github.com/semgrep/semgrep-rules /tmp/semgrep-rules
#   tools/semgrep.sh /tmp/semgrep-rules sarif/semgrep
#   dotnet run --project runner -- score --tool Semgrep --input sarif/semgrep
set -euo pipefail

rules_repo=${1:?path to a semgrep-rules checkout}
out=${2:?output folder for SARIF files}
mkdir -p "$out"

echo "semgrep $(semgrep --version), semgrep-rules $(git -C "$rules_repo" rev-parse --short HEAD)"

for dir in rules/R*/; do
  id=$(basename "$dir" | cut -d- -f1)
  for variant in Vulnerable Fixed; do
    semgrep scan \
      --config "$rules_repo/csharp" \
      --sarif --output "$out/$id.$variant.sarif" \
      --metrics=off --disable-version-check --quiet \
      "$dir$variant"
  done
done
