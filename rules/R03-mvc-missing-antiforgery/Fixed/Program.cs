// R03 - FIXED
//
// Same controller. AutoValidateAntiforgeryToken is added as a global filter, as the
// ASP.NET Core CSRF docs recommend for non-API apps, so every unsafe-method action
// (anything but GET, HEAD, OPTIONS, TRACE) requires a valid token.

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

var app = builder.Build();

app.MapGet("/health", () => Results.Ok(new { runtime = Environment.Version.ToString() }));

app.MapGet("/token", (IAntiforgery antiforgery, HttpContext context) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    return Results.Ok(new { field = tokens.FormFieldName, token = tokens.RequestToken });
});

app.MapControllers();

app.Run();

[Route("account")]
public class AccountController : Controller
{
    // Target: changes the account email from a form post.
    [HttpPost("email")]
    public IActionResult ChangeEmail([FromForm] string email) => Ok($"email changed to {email}");
}
