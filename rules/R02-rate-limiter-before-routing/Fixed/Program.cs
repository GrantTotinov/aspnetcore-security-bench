// R02 - FIXED
//
// UseRouting() runs first, so the endpoint is known when UseRateLimiter() runs
// and the endpoint-specific "login" policy is applied.

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

app.UseRouting();
app.UseRateLimiter();

app.MapGet("/health", () => Results.Ok(new { runtime = Environment.Version.ToString() }));

// Target: a login endpoint that should allow at most 3 attempts per minute.
app.MapPost("/login", () => Results.Ok(new { ok = false, message = "invalid credentials" }))
   .RequireRateLimiting("login");

app.Run();
