// R02 - VULNERABLE
//
// UseRateLimiter() runs before UseRouting(). At that point no endpoint has been
// selected, so the middleware cannot see the endpoint's "login" policy and never
// applies it. There is no exception and no warning: the login endpoint simply
// has no rate limit.

using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("login", limiter =>
    {
        limiter.PermitLimit = 3;
        limiter.Window = TimeSpan.FromMinutes(1);
        limiter.QueueLimit = 0;
    });
});

var app = builder.Build();

app.UseRateLimiter();
app.UseRouting();

app.MapGet("/health", () => Results.Ok(new { runtime = Environment.Version.ToString() }));

// Target: a login endpoint that should allow at most 3 attempts per minute.
app.MapPost("/login", () => Results.Ok(new { ok = false, message = "invalid credentials" }))
   .RequireRateLimiting("login");

app.Run();
