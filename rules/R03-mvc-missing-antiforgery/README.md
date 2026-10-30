# R03: MVC controller action without antiforgery validation

**Weakness:** CWE-352 (Cross-Site Request Forgery)

## The misconfiguration

```csharp
builder.Services.AddControllersWithViews();

public class AccountController : Controller
{
    [HttpPost("email")]
    public IActionResult ChangeEmail([FromForm] string email) => ...;
}
```

`AddControllersWithViews()` registers antiforgery services and Razor views generate tokens in
forms, but MVC only validates a token when a filter asks for it. Without
`[ValidateAntiForgeryToken]` on the action (or controller) and without a global
`AutoValidateAntiforgeryToken` filter, the POST accepts requests with no token at all.

This differs from Razor Pages and from minimal APIs that bind forms, which validate by default.
Developers who move between these models can assume MVC does the same.

## The fix

Add `AutoValidateAntiforgeryTokenAttribute` as a global filter, which the ASP.NET Core CSRF
documentation recommends for non-API apps. Per-action `[ValidateAntiForgeryToken]` also works,
but it is easy to forget on a new action, which is exactly this misconfiguration.

## Expected behavior

| Request | Vulnerable | Fixed |
|---|---|---|
| POST `/account/email`, no token | 200 `email changed` | 400 |
| POST `/account/email`, valid token | 200 | 200 |

## Tools

Three tools have a rule for this misconfiguration and none reports the vulnerable variant:

- **CA5391** (built-in, with `AnalysisLevel=latest-all`) and **CodeQL**
  `cs/web/missing-token-validation` only report when the project already uses an antiforgery
  attribute somewhere, so an app with no antiforgery protection at all gets no warning.
  See [experiments/ca5391-condition](../../experiments/ca5391-condition).
- **Semgrep** `mvc-missing-antiforgery` does not match `[HttpPost("email")]` (a verb attribute
  with a route template) and reports the global-filter fix as unprotected.
  See [experiments/semgrep-mvc-antiforgery](../../experiments/semgrep-mvc-antiforgery).

## Threat model note

As in R01, the apps have no authentication and the `SameSite=Lax` default on authentication
cookies limits cross-site POSTs in modern browsers. See the R01 README.

## References

- ASP.NET Core docs, "Prevent Cross-Site Request Forgery (XSRF/CSRF) attacks", sections on
  `AutoValidateAntiforgeryToken` and `AddControllers`:
  https://learn.microsoft.com/aspnet/core/security/anti-request-forgery
- CA5391, "Use antiforgery tokens in ASP.NET Core MVC controllers" (off by default):
  https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca5391
