using Microsoft.AspNetCore.Mvc;

namespace Demo;

public class ExampleController : Controller
{
    // Unprotected POST. CA5391 reports it only while ProtectedAction below exists.
    [HttpPost]
    public IActionResult PostAction([FromForm] string email) => Ok(email);

    // Delete this action (or its attribute) and rebuild: the CA5391 warning on PostAction disappears,
    // although PostAction is exactly as unprotected as before.
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ProtectedAction([FromForm] string email) => Ok(email);
}
