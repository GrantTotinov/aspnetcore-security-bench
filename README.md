# When Protections Silently Do Not Apply

**A Benchmark of ASP.NET Core Security Misconfigurations and the Tools That Miss Them**

[![benchmark](https://github.com/GrantTotinov/aspnetcore-security-bench/actions/workflows/benchmark.yml/badge.svg)](https://github.com/GrantTotinov/aspnetcore-security-bench/actions/workflows/benchmark.yml)
[![DOI](https://zenodo.org/badge/1440174108.svg)](https://doi.org/10.5281/zenodo.23822216)

This repository is one study: the report and all the code it describes.

**Report:** [paper/report.pdf](paper/report.pdf) (source: [paper/report.md](paper/report.md))

Four ASP.NET Core misconfigurations each disable a protection at runtime on .NET 8 and .NET 10
without any warning, and the built-in .NET analyzers, Semgrep and CodeQL detect none of them. All
three tools ship a rule for the MVC antiforgery case, yet each misses it.

> **The `Vulnerable` apps are insecure on purpose.** They exist to test detection tools.
> Run them only locally; never deploy them or copy their configuration into a real app.

## The benchmark

Pairs of minimal ASP.NET Core apps, one **vulnerable** and one **fixed**, for security
misconfigurations where a protection silently does not apply. Each pair differs only in the
misconfiguration. A runner starts every app on .NET 8 and .NET 10 and checks the behavior over
loopback HTTP, and evaluates which tools detect the misconfiguration.

**Status:** 4 rules implemented and verified at runtime. Three tools evaluated: the built-in
.NET analyzers, Semgrep and CodeQL. None of them detects any of the four misconfigurations.
More rules and more tools are in progress.

## Rules

| ID | Misconfiguration | Weakness | Effect |
|---|---|---|---|
| [R01](rules/R01-method-override-antiforgery) | Form-field `UseHttpMethodOverride` before `UseAntiforgery()` | CWE-352 | A form POST overridden to DELETE skips antiforgery validation |
| [R02](rules/R02-rate-limiter-before-routing) | `UseRateLimiter()` before `UseRouting()` | CWE-307 | Endpoint-specific rate limits (e.g. on login) are never applied |
| [R03](rules/R03-mvc-missing-antiforgery) | MVC POST action without antiforgery filter | CWE-352 | The action accepts requests without a token |
| [R07](rules/R07-cors-any-origin-credentials) | CORS `SetIsOriginAllowed(_ => true)` + `AllowCredentials()` | CWE-942 | Any website can make credentialed requests and read responses |

Rule IDs follow the draft catalogue, so the numbering has gaps until all rules are implemented.

## Verified runtime behavior

Run on 2026-10-30, Ubuntu 24.04, runtimes 8.0.33 and 10.0.14. Results were identical on both.

| Rule | Vulnerable | Fixed |
|---|---|---|
| R01 | DELETE without token -> 200 | DELETE without token -> 400 |
| R02 | 10 login attempts -> 10x200 | 10 login attempts -> 3x200, 7x429 |
| R03 | POST without token -> 200 | POST without token -> 400 |
| R07 | untrusted origin gets ACAO + credentials | untrusted origin gets no CORS headers |

In every run, legitimate requests still worked in both variants, and no vulnerable app logged a
warning.

## Tool evaluation

A tool detects a rule if it reports a finding on the vulnerable variant that it does not report on
the fixed one.

| Rule | Built-in .NET analyzers | Semgrep | CodeQL |
|---|---|---|---|
| R01 method override vs antiforgery | not detected | not detected | not detected |
| R02 rate limiter before routing | not detected | not detected | not detected |
| R03 MVC without antiforgery | not detected | not detected | not detected |
| R07 CORS any origin + credentials | not detected | not detected | not detected |
| **Detected** | **0 of 4** | **0 of 4** | **0 of 4** |

Versions and settings (run in CI on 2026-10-30):

- **Built-in analyzers:** .NET SDK 10.0.403 with `AnalysisLevel=latest-all` (every CA rule on,
  including the security rules that are off by default), plus the ASP.NET Core analyzers from the
  .NET 8 and .NET 10 targeting packs. Run on both frameworks; the same result locally with SDK 10.0.114.
  The analyzers did run: they reported style and design rules (CA1050, CA1515, CA2007).
- **Semgrep** 1.183.0 with every C# rule from [semgrep-rules](https://github.com/semgrep/semgrep-rules)
  (commit 16b9e6d). Its only finding, `missing-or-broken-authorization` on R03, appears on both
  variants and is unrelated to CSRF: the benchmark apps have no authentication.
- **CodeQL** 2.27.3, C# `security-extended` suite (csharp-queries 1.10.2), database built from the
  .NET 10 build. No findings on any variant.

### Why the CSRF rules stay silent on R03

All three tools have a rule meant for R03, and all three miss it:

- **CA5391** and **CodeQL `cs/web/missing-token-validation`** only report when the project already
  uses an antiforgery attribute somewhere. The CodeQL query states the reason: to avoid false
  positives in projects that mitigate CSRF another way. The effect is that an MVC app with no
  antiforgery protection at all gets no warning from either tool.
  Reproduction: [experiments/ca5391-condition](experiments/ca5391-condition).
- **Semgrep `mvc-missing-antiforgery`** does not match a verb attribute with a route template such
  as `[HttpPost("email")]`, and it reports controllers protected by the global
  `AutoValidateAntiforgeryToken` filter that the ASP.NET Core docs recommend.
  Reproduction: [experiments/semgrep-mvc-antiforgery](experiments/semgrep-mvc-antiforgery).

None of the tools has a rule for R01, R02 or R07.

### Next tools

SonarAnalyzer.CSharp, Security Code Scan, and AI code review.

## Running it

Requires the .NET SDK and the ASP.NET Core 8 and/or 10 runtimes. Missing runtimes are skipped.

```bash
dotnet run --project runner                  # runtime checks on .NET 8 and 10
dotnet run --project runner -- --tfm net10.0 # one framework only
dotnet run --project runner -- analyze       # built-in analyzer evaluation
```

Semgrep and CodeQL (Linux, WSL or macOS; CI runs both on every push):

```bash
git clone --depth 1 https://github.com/semgrep/semgrep-rules /tmp/semgrep-rules
tools/semgrep.sh /tmp/semgrep-rules sarif/semgrep
dotnet run --project runner -- score --tool Semgrep --input sarif/semgrep

tools/codeql.sh /path/to/codeql sarif/codeql net10.0
dotnet run --project runner -- score --tool CodeQL --input sarif/codeql
```

Outputs go to `results/`: `results.md` (runtime), `analyzers.md`, `semgrep.md`, `codeql.md`, each
with a `.json` file, and one log per app in `results/logs/`. The runtime mode exits with code 1 if
any app does not behave as expected. The CI run uploads all results and SARIF files as artifacts.

## Layout

```
paper/
  report.pdf        the report
  report.md         its source text
rules/
  R01-method-override-antiforgery/
    Vulnerable/   Program.cs, R01.Vulnerable.csproj
    Fixed/        Program.cs, R01.Fixed.csproj
    README.md     misconfiguration, fix, expected behavior, references
  R02-..., R03-..., R07-...
experiments/
  ca5391-condition/          why CA5391 (and CodeQL) miss R03
  semgrep-mvc-antiforgery/   why Semgrep misses R03
runner/                      BCL-only console app: runtime checks, analyzer evaluation, SARIF scoring
tools/                       Semgrep and CodeQL scan scripts
results/, sarif/             generated
```

## Method

- Each pair differs only in the misconfiguration. A tool detects a rule if it reports a security
  diagnostic on the vulnerable variant that it does not report on the fixed one; any security
  diagnostic on the fixed variant is a false positive.
- Apps run in the `Production` environment on `127.0.0.1` only. Nothing is tested against live systems.
- Every runtime scenario includes a legitimate request, so a "fix" that simply breaks the feature fails.
- Every app runs on both LTS lines (.NET 8 and .NET 10) and the exact runtime version is recorded.

## Next

1. Remaining rules: minimal API with `DisableAntiforgery()` under cookie auth, `ShortCircuit()` on an
   endpoint with authorization metadata, `AllowAnonymous` overriding `Authorize`, JWT validation
   switched off, weak cookie settings, developer exception page outside Development, forwarded
   headers trusting any proxy.
2. More tools: SonarAnalyzer.CSharp, Security Code Scan, AI code review.
3. Publication: dataset and code on Zenodo, technical report on TechRxiv.

## Author and license

Grant Totinov ([@GrantTotinov](https://github.com/GrantTotinov),
ORCID [0009-0002-8014-409X](https://orcid.org/0009-0002-8014-409X)). MIT license.

The report and the code are archived together on Zenodo as one record:
[10.5281/zenodo.23822216](https://doi.org/10.5281/zenodo.23822216) (all versions). If you use the
study, cite the report: see `CITATION.cff` or "Cite this repository" on GitHub.
