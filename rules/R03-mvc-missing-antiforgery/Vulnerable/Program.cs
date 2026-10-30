// R03 - VULNERABLE
//
// An MVC controller with a state-changing POST action. Antiforgery services are
// registered (AddControllersWithViews does that), but MVC validates tokens only
// where a filter asks for it: there is no [ValidateAntiForgeryToken] on the action
// and no global AutoValidateAntiforgeryToken filter. Unlike minimal APIs with
// form binding, MVC actions get no automatic antiforgery validation.

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();

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
