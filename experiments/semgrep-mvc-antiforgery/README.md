# Why Semgrep's MVC antiforgery rule misses R03

Semgrep's public rule `csharp.dotnet.security.mvc-missing-antiforgery` targets the R03
misconfiguration, but it cannot tell the R03 vulnerable app from the fixed one.

The rule matches a state-changing action written as

```yaml
- pattern: |
    [$HTTPMETHOD]
    public IActionResult $METHOD(...){
        ...
    }
- pattern-not: |
    [ValidateAntiForgeryToken]
    public IActionResult $METHOD(...){
        ...
    }
```

This has two consequences:

1. **Missed:** `[$HTTPMETHOD]` does not match a verb attribute with a route template, such as
   `[HttpPost("email")]`, which is how the R03 action is written. The unprotected action is not reported.
2. **False positive:** the only accepted protection is `[ValidateAntiForgeryToken]` on the method
   itself. A controller protected by a global `AutoValidateAntiforgeryToken` filter (the approach the
   ASP.NET Core docs recommend, and the R03 fix) is still reported.

## Reproduce

```bash
git clone --depth 1 https://github.com/semgrep/semgrep-rules /tmp/semgrep-rules
semgrep scan --metrics=off \
  --config /tmp/semgrep-rules/csharp/dotnet/security/mvc-missing-antiforgery.yaml \
  experiments/semgrep-mvc-antiforgery
```

| File | Protection | Reported | Correct result |
|---|---|---|---|
| `Unprotected.cs` | none, `[HttpPost]` | yes | yes |
| `UnprotectedWithRoute.cs` | none, `[HttpPost("email")]` | **no** | yes |
| `GlobalFilter.cs` | global `AutoValidateAntiforgeryToken` filter | **yes** | no |

Checked on 2026-10-30 with Semgrep 1.183.0 and semgrep-rules commit 16b9e6d.
