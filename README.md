# ASP.NET Core Security Misconfiguration Benchmark

[![benchmark](https://github.com/GrantTotinov/aspnetcore-security-bench/actions/workflows/benchmark.yml/badge.svg)](https://github.com/GrantTotinov/aspnetcore-security-bench/actions/workflows/benchmark.yml)

> **The `Vulnerable` apps are insecure on purpose.** They exist to test detection tools.
> Run them only locally; never deploy them or copy their configuration into a real app.

Pairs of minimal ASP.NET Core apps, one **vulnerable** and one **fixed**, for security
misconfigurations where a protection silently does not apply. Each pair differs only in the
misconfiguration. A runner starts every app on .NET 8 and .NET 10 and checks the behavior over
loopback HTTP, and evaluates which tools detect the misconfiguration.

**Status:** 4 rules implemented and verified at runtime. Built-in .NET analyzers evaluated.
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

### Built-in .NET and ASP.NET Core analyzers

.NET SDK 10.0.114 with `AnalysisLevel=latest-all` (every CA rule on, including the security
rules that are off by default), plus the ASP.NET Core analyzers from the 8.0.33 and 10.0.14
targeting packs.

| Rule | .NET 8 | .NET 10 |
|---|---|---|
| R01 | not detected | not detected |
| R02 | not detected | not detected |
| R03 | not detected | not detected |
| R07 | not detected | not detected |

**0 of 8** rule/framework pairs detected, 0 false positives. The analyzers did run: they reported
style and design rules (CA1050, CA1515, CA2007) on the same projects.

R03 is the notable miss. CA5391 exists for exactly this case, but it only reports when the project
already uses an antiforgery attribute somewhere, so an MVC app with no antiforgery protection at
all gets no warning. Reproduction: [experiments/ca5391-condition](experiments/ca5391-condition).

### Next tools

CodeQL (C#), Semgrep, SonarAnalyzer.CSharp, Security Code Scan, and AI code review.

## Running it

Requires the .NET SDK and the ASP.NET Core 8 and/or 10 runtimes. Missing runtimes are skipped.

```bash
dotnet run --project runner                  # runtime checks on .NET 8 and 10
dotnet run --project runner -- --tfm net10.0 # one framework only
dotnet run --project runner -- analyze       # built-in analyzer evaluation
```

Outputs go to `results/`: `results.md`/`results.json` (runtime), `analyzers.md`/`analyzers.json`
(analyzers) and one log per app in `results/logs/`. The runtime mode exits with code 1 if any app
does not behave as expected.

## Layout

```
rules/
  R01-method-override-antiforgery/
    Vulnerable/   Program.cs, R01.Vulnerable.csproj
    Fixed/        Program.cs, R01.Fixed.csproj
    README.md     misconfiguration, fix, expected behavior, references
  R02-..., R03-..., R07-...
experiments/
  ca5391-condition/   why CA5391 misses R03
runner/               BCL-only console app: runtime checks and analyzer evaluation
results/              generated
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
2. More tools (see above).
3. Publication: dataset and code on Zenodo, technical report on TechRxiv.

## Author and license

Grant Totinov ([@GrantTotinov](https://github.com/GrantTotinov)). MIT license. If you use the
benchmark, see `CITATION.cff` for how to cite it.
