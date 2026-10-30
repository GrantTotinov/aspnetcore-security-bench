using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

/// <summary>
/// Result of one scenario against one running app.
/// AttackSucceeded: the misconfiguration was observable from outside (the protection did not apply).
/// LegitWorks: a normal, well-formed request still behaves correctly (guards against a "fix" that just breaks the app).
/// </summary>
record Outcome(bool AttackSucceeded, bool LegitWorks, string Attack, string Control, string Legit);

static class Scenarios
{
    /// <summary>
    /// R01: cross-site form POST with _method=DELETE and no antiforgery token.
    /// </summary>
    public static async Task<Outcome> R01(Uri baseUri)
    {
        // The attacker's request: no antiforgery cookie, no token, just a form.
        using var attacker = NewClient(baseUri, cookies: false);

        var attack = await attacker.PostAsync("/items/42", Form(("_method", "DELETE"), ("note", "csrf")));
        var attackBody = await attack.Content.ReadAsStringAsync();
        var attackSucceeded = attack.StatusCode == HttpStatusCode.OK && attackBody.Contains("deleted 42");

        // Control: the same attacker against a plain POST. Antiforgery should reject it in both variants.
        var control = await attacker.PostAsync("/items", Form(("name", "x")));

        // The legitimate user: fetches a token (and cookie) first, then submits the same form.
        using var user = NewClient(baseUri, cookies: true);
        var tokens = await user.GetFromJsonAsync<JsonElement>("/token");
        var field = tokens.GetProperty("field").GetString()!;
        var token = tokens.GetProperty("token").GetString()!;

        var legit = await user.PostAsync("/items/42", Form(("_method", "DELETE"), (field, token)));
        var legitBody = await legit.Content.ReadAsStringAsync();
        var legitWorks = legit.StatusCode == HttpStatusCode.OK && legitBody.Contains("deleted 42");

        return new Outcome(
            attackSucceeded,
            legitWorks,
            Attack: $"POST _method=DELETE, no token -> {(int)attack.StatusCode}",
            Control: $"plain POST, no token -> {(int)control.StatusCode}",
            Legit: $"POST _method=DELETE + valid token -> {(int)legit.StatusCode}");
    }

    /// <summary>
    /// R02: 10 rapid login attempts against an endpoint limited to 3 per minute.
    /// </summary>
    public static async Task<Outcome> R02(Uri baseUri)
    {
        const int attempts = 10;
        using var client = NewClient(baseUri, cookies: false);

        var statuses = new List<int>();
        for (var i = 0; i < attempts; i++)
        {
            using var body = new StringContent("{}", Encoding.UTF8, "application/json");
            var response = await client.PostAsync("/login", body);
            statuses.Add((int)response.StatusCode);
        }

        var allProcessed = statuses.All(s => s == 200);
        var firstProcessed = statuses[0] == 200;

        var summary = string.Join(", ", statuses
            .GroupBy(s => s)
            .OrderBy(g => g.Key)
            .Select(g => $"{g.Count()}x{g.Key}"));

        return new Outcome(
            AttackSucceeded: allProcessed,
            LegitWorks: firstProcessed,
            Attack: $"{attempts} login attempts (limit 3/min) -> {summary}",
            Control: "-",
            Legit: $"first attempt -> {statuses[0]}");
    }

    /// <summary>
    /// R03: cross-site form POST to an MVC action, without an antiforgery token.
    /// </summary>
    public static async Task<Outcome> R03(Uri baseUri)
    {
        using var attacker = NewClient(baseUri, cookies: false);
        var attack = await attacker.PostAsync("/account/email", Form(("email", "attacker@evil.example")));
        var attackBody = await attack.Content.ReadAsStringAsync();
        var attackSucceeded = attack.StatusCode == HttpStatusCode.OK && attackBody.Contains("email changed");

        using var user = NewClient(baseUri, cookies: true);
        var tokens = await user.GetFromJsonAsync<JsonElement>("/token");
        var field = tokens.GetProperty("field").GetString()!;
        var token = tokens.GetProperty("token").GetString()!;

        var legit = await user.PostAsync("/account/email", Form(("email", "alice@example.com"), (field, token)));
        var legitBody = await legit.Content.ReadAsStringAsync();
        var legitWorks = legit.StatusCode == HttpStatusCode.OK && legitBody.Contains("email changed");

        return new Outcome(
            attackSucceeded,
            legitWorks,
            Attack: $"POST /account/email, no token -> {(int)attack.StatusCode}",
            Control: "-",
            Legit: $"POST /account/email + valid token -> {(int)legit.StatusCode}");
    }

    /// <summary>
    /// R07: credentialed CORS from an untrusted origin. CORS is enforced by the browser,
    /// so the check is whether the server grants the untrusted origin read access with credentials.
    /// </summary>
    public static async Task<Outcome> R07(Uri baseUri)
    {
        const string evil = "https://evil.example";
        const string trusted = "https://app.example.com";
        using var client = NewClient(baseUri, cookies: false);

        var attack = await SendWithOrigin(client, HttpMethod.Get, "/api/me", evil);
        var attackSucceeded = Header(attack, "Access-Control-Allow-Origin") == evil
                              && Header(attack, "Access-Control-Allow-Credentials") == "true";

        var preflight = await SendWithOrigin(client, HttpMethod.Options, "/api/me", evil, preflight: true);

        var legit = await SendWithOrigin(client, HttpMethod.Get, "/api/me", trusted);
        var legitWorks = legit.StatusCode == HttpStatusCode.OK
                         && Header(legit, "Access-Control-Allow-Origin") == trusted
                         && Header(legit, "Access-Control-Allow-Credentials") == "true";

        return new Outcome(
            attackSucceeded,
            legitWorks,
            Attack: $"GET from {evil} -> {DescribeCors(attack)}",
            Control: $"preflight from {evil} -> {DescribeCors(preflight)}",
            Legit: $"GET from {trusted} -> {DescribeCors(legit)}");
    }

    static async Task<HttpResponseMessage> SendWithOrigin(HttpClient client, HttpMethod method, string path, string origin, bool preflight = false)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.TryAddWithoutValidation("Origin", origin);
        if (preflight)
        {
            request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "GET");
            request.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "content-type");
        }
        return await client.SendAsync(request);
    }

    static string? Header(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values) ? string.Join(",", values) : null;

    static string DescribeCors(HttpResponseMessage response)
    {
        var acao = Header(response, "Access-Control-Allow-Origin");
        var acac = Header(response, "Access-Control-Allow-Credentials");
        var cors = acao is null ? "no CORS headers" : $"ACAO {acao}{(acac is null ? "" : $", ACAC {acac}")}";
        return $"{(int)response.StatusCode}, {cors}";
    }

    static HttpClient NewClient(Uri baseUri, bool cookies)
    {
        var handler = new HttpClientHandler
        {
            UseCookies = cookies,
            CookieContainer = new CookieContainer(),
            AllowAutoRedirect = false,
        };
        return new HttpClient(handler) { BaseAddress = baseUri, Timeout = TimeSpan.FromSeconds(15) };
    }

    static FormUrlEncodedContent Form(params (string Key, string Value)[] fields) =>
        new(fields.Select(f => new KeyValuePair<string, string>(f.Key, f.Value)));
}
