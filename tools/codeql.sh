#!/usr/bin/env bash
# Builds a CodeQL database for every rule variant and analyzes it with the C# security-extended
# suite, writing one SARIF file per variant.
#
# Usage (from the repository root):
#   tools/codeql.sh /path/to/codeql sarif/codeql [tfm]
#   dotnet run --project runner -- score --tool CodeQL --input sarif/codeql
#
# tfm defaults to net10.0. Extra build arguments can be passed in CODEQL_BUILD_ARGS
# (for example CODEQL_BUILD_ARGS=--no-restore when offline).
set -euo pipefail

codeql=${1:?path to the codeql executable}
out=${2:?output folder for SARIF files}
tfm=${3:-net10.0}
suite=codeql/csharp-queries:codeql-suites/csharp-security-extended.qls

mkdir -p "$out"
out=$(realpath "$out")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "codeql $("$codeql" version --format=terse), suite csharp-security-extended, $tfm"

for dir in rules/R*/; do
  id=$(basename "$dir" | cut -d- -f1)
  for variant in Vulnerable Fixed; do
    project=$(realpath "$dir$variant/$id.$variant.csproj")
    db="$work/$id.$variant"
    echo "== $id.$variant"
    "$codeql" database create "$db" \
      --language=csharp \
      --source-root="$dir$variant" \
      --command="dotnet build $project -c Release -f $tfm --no-incremental ${CODEQL_BUILD_ARGS:-}" \
      --overwrite --quiet
    "$codeql" database analyze "$db" "$suite" \
      --format=sarif-latest --output="$out/$id.$variant.sarif" \
      --threads=0 --quiet
  done
done
