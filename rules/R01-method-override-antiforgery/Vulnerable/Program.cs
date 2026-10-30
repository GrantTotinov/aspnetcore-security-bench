// R01 - VULNERABLE
//
// Form-field HttpMethodOverride runs before routing and antiforgery.
// A cross-site form POST carrying _method=DELETE is routed to the DELETE endpoint,
// and UseAntiforgery() skips it, because it validates only POST, PUT and PATCH.
// The DELETE endpoint binds a form, so it carries antiforgery metadata,
// but nothing actually checks the token.

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();

app.UseHttpMethodOverride(new HttpMethodOverrideOptions { FormFieldName = "_method" });
app.UseRouting();
app.UseAntiforgery();

app.MapGet("/health", () => Results.Ok(new { runtime = Environment.Version.ToString() }));

app.MapGet("/token", (IAntiforgery antiforgery, HttpContext context) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    return Results.Ok(new { field = tokens.FormFieldName, token = tokens.RequestToken });
});

// Control: a plain form POST. Antiforgery protects it as expected.
app.MapPost("/items", ([FromForm] string name) => Results.Ok($"created {name}"));

// Target: a form-bound DELETE, reachable from an HTML form only through the override.
app.MapDelete("/items/{id:int}", (int id, [FromForm] string? note) =>
    Results.Ok($"deleted {id}"));

app.Run();
