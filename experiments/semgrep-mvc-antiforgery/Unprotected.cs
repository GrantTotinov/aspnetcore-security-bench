using Microsoft.AspNetCore.Mvc;

// No antiforgery protection. Semgrep reports it (correct).
public class UnprotectedController : Controller
{
    [HttpPost]
    public IActionResult ChangeEmail([FromForm] string email) => Ok(email);
}
