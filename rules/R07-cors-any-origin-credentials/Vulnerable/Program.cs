// R07 - VULNERABLE
//
// ASP.NET Core refuses AllowAnyOrigin() together with AllowCredentials().
// SetIsOriginAllowed(_ => true) gets around that check: every origin is reflected
// back in Access-Control-Allow-Origin together with Access-Control-Allow-Credentials,
// so any website can make credentialed requests and read the responses.

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy
        .SetIsOriginAllowed(_ => true)
        .AllowCredentials()
        .AllowAnyHeader()
        .AllowAnyMethod());
});

var app = builder.Build();

app.UseCors();

app.MapGet("/health", () => Results.Ok(new { runtime = Environment.Version.ToString() }));

// Target: per-user data that only the app's own frontend should be able to read.
app.MapGet("/api/me", () => Results.Ok(new { user = "alice", email = "alice@example.com" }));

app.Run();
