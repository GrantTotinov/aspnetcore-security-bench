// R07 - FIXED
//
// Credentials are allowed only for an explicit list of trusted origins.

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy
        .WithOrigins("https://app.example.com")
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
