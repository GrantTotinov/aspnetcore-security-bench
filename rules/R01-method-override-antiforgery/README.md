# R01: Form-field HttpMethodOverride bypasses UseAntiforgery()

**Weakness:** CWE-352 (Cross-Site Request Forgery)

## The misconfiguration

```csharp
app.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = "_method" });
app.UseRouting();
app.UseAntiforgery();

app.MapDelete("/items/{id:int}", (int id, [FromForm] string? note) => ...);
```

`UseAntiforgery()` validates tokens only for POST, PUT and PATCH. The override middleware
rewrites a form POST carrying `_method=DELETE` into a DELETE before routing, so the request
reaches the DELETE endpoint and antiforgery skips it. The endpoint binds a form, so it carries
antiforgery metadata and looks protected, but no token is ever checked.

## The fix

The fixed variant keeps the same pipeline and validates the token explicitly in the endpoint
with `IAntiforgery.IsRequestValidAsync`. This follows the ASP.NET Core CSRF documentation, which
also lists avoiding form-field overrides for endpoints that rely on antiforgery.

## Expected behavior

| Request | Vulnerable | Fixed |
|---|---|---|
| POST `/items/42`, `_method=DELETE`, no token | 200 `deleted 42` | 400 |
| POST `/items`, no token (control) | 400 | 400 |
| POST `/items/42`, `_method=DELETE`, valid token | 200 | 200 |

The control row shows that antiforgery is active in both variants: only the overridden DELETE slips through.

## Threat model note

The apps have no authentication, to stay minimal. In a real app the forged request has to carry
the victim's authentication cookie. ASP.NET Core authentication cookies default to `SameSite=Lax`,
which modern browsers do not send on cross-site POSTs, so real-world exposure is mainly:

- apps whose authentication cookie uses `SameSite=None` (for example for embedding or some SSO flows);
- attackers on a same-site origin, such as a sibling subdomain;
- clients that do not enforce SameSite.

The core problem stays: the developer enabled antiforgery, the endpoint carries antiforgery
metadata, and the token is not checked.

## References

- ASP.NET Core docs, "Prevent Cross-Site Request Forgery (XSRF/CSRF) attacks", section on
  HTTP method limitations and `HttpMethodOverrideMiddleware`:
  https://learn.microsoft.com/aspnet/core/security/anti-request-forgery
- dotnet/aspnetcore PR #66772 and dotnet/AspNetCore.Docs PR #37224
