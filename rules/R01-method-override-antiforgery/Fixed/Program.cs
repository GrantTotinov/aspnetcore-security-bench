// R01 - FIXED
//
// Same pipeline as the vulnerable variant. The override still turns the POST into
// a DELETE that UseAntiforgery() does not validate, so the DELETE endpoint validates
// the token itself with IAntiforgery, as the ASP.NET Core CSRF docs recommend
// when form-field override has to run first.

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

// Target: the DELETE now checks the token explicitly.
app.MapDelete("/items/{id:int}", async (int id, [FromForm] string? note,
    IAntiforgery antiforgery, HttpContext context) =>
{
    if (!await antiforgery.IsRequestValidAsync(context))
    {
        return Results.BadRequest("antiforgery token missing or invalid");
    }

    return Results.Ok($"deleted {id}");
});

app.Run();
