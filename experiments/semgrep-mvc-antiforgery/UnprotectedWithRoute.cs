using Microsoft.AspNetCore.Mvc;

// No antiforgery protection, verb attribute with a route template. Semgrep does not report it (missed).
public class UnprotectedWithRouteController : Controller
{
    [HttpPost("email")]
    public IActionResult ChangeEmail([FromForm] string email) => Ok(email);
}
