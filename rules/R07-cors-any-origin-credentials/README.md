# R07: CORS allows any origin with credentials

**Weakness:** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)

## The misconfiguration

```csharp
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy => policy
        .SetIsOriginAllowed(_ => true)
        .AllowCredentials()));
```

ASP.NET Core does not allow `AllowAnyOrigin()` together with `AllowCredentials()`: the app fails
at startup with `InvalidOperationException: The CORS protocol does not allow specifying a
wildcard (any) origin and credentials at the same time` (checked on .NET 10.0.14). An origin
predicate that always returns `true` gets around that check: the middleware echoes every
request's `Origin` back in `Access-Control-Allow-Origin` and adds
`Access-Control-Allow-Credentials: true`. Any website the user visits can then send
credentialed requests to the app and read the responses.

The pattern is common in answers that "fix" the CORS error about wildcard origins and
credentials. The ASP.NET Core CORS documentation names it as insecure.

## The fix

List the trusted origins with `WithOrigins(...)`. If many subdomains are needed, use
`WithOrigins("https://*.example.com").SetIsOriginAllowedToAllowWildcardSubdomains()` rather
than a predicate that accepts everything.

## Expected behavior

CORS is enforced by the browser, so the observable signal is the response headers. The runner
sends requests with an `Origin` header and checks them.

| Request | Vulnerable | Fixed |
|---|---|---|
| GET `/api/me`, `Origin: https://evil.example` | ACAO `https://evil.example`, ACAC `true` | no CORS headers |
| Preflight OPTIONS from `https://evil.example` | allowed | no CORS headers |
| GET `/api/me`, `Origin: https://app.example.com` | ACAO `https://app.example.com`, ACAC `true` | same |

(ACAO = `Access-Control-Allow-Origin`, ACAC = `Access-Control-Allow-Credentials`.)

## References

- ASP.NET Core docs, "Enable Cross-Origin Requests (CORS)", warning on `AllowAnyOrigin`,
  `AllowCredentials` and `SetIsOriginAllowed(_ => true)`:
  https://learn.microsoft.com/aspnet/core/security/cors
