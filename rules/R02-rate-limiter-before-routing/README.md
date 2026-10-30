# R02: UseRateLimiter() before UseRouting() drops endpoint policies

**Weakness:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

## The misconfiguration

```csharp
app.UseRateLimiter();
app.UseRouting();

app.MapPost("/login", ...).RequireRateLimiting("login");
```

Endpoint-specific policies (`RequireRateLimiting`, `[EnableRateLimiting]`) are read from the
selected endpoint. When `UseRateLimiter()` runs before `UseRouting()`, no endpoint has been
selected yet, so the policy is never applied. The app starts normally and logs no warning.

## The fix

Call `UseRouting()` before `UseRateLimiter()`. If the app never calls `UseRouting()` explicitly,
`WebApplication` adds routing at the start of the pipeline and the limiter works; the problem
appears when routing is called explicitly after the limiter, which is common in apps
migrated from the `Startup` pattern.

## Expected behavior

The `login` policy allows 3 requests per minute with no queue.

| Request | Vulnerable | Fixed |
|---|---|---|
| 10 rapid POSTs to `/login` | 10x200 | 3x200, 7x429 |
| First POST to `/login` | 200 | 200 |

## Notes

Global limiters (`RateLimiterOptions.GlobalLimiter`) do not depend on the endpoint and still
work before routing. Only endpoint-specific policies are dropped.

## References

- ASP.NET Core docs, "Rate limiting middleware in ASP.NET Core":
  https://learn.microsoft.com/aspnet/core/performance/rate-limit
- ASP.NET Core docs, "ASP.NET Core middleware", middleware order:
  https://learn.microsoft.com/aspnet/core/fundamentals/middleware/
