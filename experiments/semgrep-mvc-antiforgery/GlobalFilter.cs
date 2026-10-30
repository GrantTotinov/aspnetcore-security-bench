using Microsoft.AspNetCore.Mvc;

// Protected by a global AutoValidateAntiforgeryToken filter, as the ASP.NET Core docs recommend.
// Semgrep still reports the action (false positive).
public static class GlobalFilterSetup
{
    public static void Configure(IServiceCollection services) =>
        services.AddControllersWithViews(options =>
            options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));
}

public class GlobalFilterController : Controller
{
    [HttpPost]
    public IActionResult ChangeEmail([FromForm] string email) => Ok(email);
}
