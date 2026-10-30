// ASP.NET Core security misconfiguration benchmark - runner.
//
// For every rule, starts the Vulnerable and the Fixed app on each target framework,
// runs the rule's scenario over loopback HTTP and checks the outcome:
//   Vulnerable -> the attack succeeds and legitimate requests work
//   Fixed      -> the attack is blocked and legitimate requests still work
//
// Usage (from the repository root):
//   dotnet run --project runner                      runtime checks, .NET 8 and 10
//   dotnet run --project runner -- --tfm net10.0     one framework only
//   dotnet run --project runner -- --no-build        reuse existing builds
//   dotnet run --project runner -- analyze           built-in .NET and ASP.NET Core analyzers
//   add --no-restore to either mode to build without contacting NuGet

using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

var rules = new List<Rule>
{
    new("R01", "method-override-antiforgery", "Form-field HttpMethodOverride bypasses UseAntiforgery()", Scenarios.R01),
    new("R02", "rate-limiter-before-routing", "UseRateLimiter() before UseRouting() drops endpoint policies", Scenarios.R02),
    new("R03", "mvc-missing-antiforgery", "MVC controller action without antiforgery validation", Scenarios.R03),
    new("R07", "cors-any-origin-credentials", "CORS allows any origin with credentials", Scenarios.R07),
};
string[] variants = ["Vulnerable", "Fixed"];

var root = FindRoot();
var noBuild = args.Contains("--no-build");
var noRestore = args.Contains("--no-restore");
var requestedTfms = ArgValue(args, "--tfm")?.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    ?? ["net8.0", "net10.0"];

var installed = InstalledAspNetCoreMajors();
var tfms = new List<string>();
foreach (var tfm in requestedTfms)
{
    if (installed.Contains(MajorOf(tfm))) tfms.Add(tfm);
    else Console.WriteLine($"Skipping {tfm}: no Microsoft.AspNetCore.App {MajorOf(tfm)}.x runtime installed.");
}
if (tfms.Count == 0)
{
    Console.Error.WriteLine("No requested target framework has an installed ASP.NET Core runtime.");
    return 2;
}

var resultsDir = Path.Combine(root, "results");
var logsDir = Path.Combine(resultsDir, "logs");
Directory.CreateDirectory(logsDir);

if (args.Contains("analyze"))
{
    return await AnalyzerEvaluation.RunAsync(root, rules, variants, tfms, noRestore, resultsDir);
}

if (!noBuild)
{
    foreach (var rule in rules)
    foreach (var variant in variants)
    foreach (var tfm in tfms)
    {
        var project = rule.ProjectPath(root, variant);
        Console.WriteLine($"Building {Path.GetFileName(project)} ({tfm})...");
        string[] buildArgs = ["build", project, "-c", "Release", "-f", tfm, "-nologo", "-v", "q"];
        if (noRestore) buildArgs = [.. buildArgs, "--no-restore"];
        var (code, output) = await Proc.RunToEnd("dotnet", buildArgs, root);
        if (code != 0)
        {
            Console.Error.WriteLine(output);
            return 1;
        }
    }
}

var rows = new List<ResultRow>();
foreach (var rule in rules)
foreach (var variant in variants)
foreach (var tfm in tfms)
{
    var name = $"{rule.Id}.{variant}";
    var dll = Path.Combine(Path.GetDirectoryName(rule.ProjectPath(root, variant))!, "bin", "Release", tfm, name + ".dll");
    var logPath = Path.Combine(logsDir, $"{name}.{tfm}.log");
    Console.WriteLine($"Running {name} on {tfm}...");

    ResultRow row;
    try
    {
        await using var app = await RunningApp.StartAsync(dll, logPath);
        var outcome = await rule.Scenario(app.BaseUri);
        var expectedAttack = variant == "Vulnerable";
        var asExpected = outcome.AttackSucceeded == expectedAttack && outcome.LegitWorks;
        row = new ResultRow(rule.Id, variant, tfm, app.Runtime, outcome.Attack, outcome.Control, outcome.Legit,
            outcome.AttackSucceeded, outcome.LegitWorks, asExpected, Error: null);
    }
    catch (Exception ex)
    {
        row = new ResultRow(rule.Id, variant, tfm, "?", "-", "-", "-", false, false, false, ex.Message);
    }
    rows.Add(row);
}

var markdown = RenderMarkdown(rules, rows);
Console.WriteLine();
Console.WriteLine(markdown);

await File.WriteAllTextAsync(Path.Combine(resultsDir, "results.md"), markdown);
await File.WriteAllTextAsync(Path.Combine(resultsDir, "results.json"),
    JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }));

var failures = rows.Count(r => !r.AsExpected);
Console.WriteLine(failures == 0 ? "All variants behaved as expected." : $"{failures} run(s) did not behave as expected.");
return failures == 0 ? 0 : 1;

// ---------------------------------------------------------------------------

static string RenderMarkdown(List<Rule> rules, List<ResultRow> rows)
{
    var sb = new StringBuilder();
    sb.AppendLine($"# Results ({DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC)");
    sb.AppendLine();
    foreach (var rule in rules)
    {
        sb.AppendLine($"## {rule.Id}: {rule.Title}");
        sb.AppendLine();
        sb.AppendLine("| Variant | TFM | Runtime | Attack | Control | Legitimate request | As expected |");
        sb.AppendLine("|---|---|---|---|---|---|---|");
        foreach (var r in rows.Where(r => r.Rule == rule.Id))
        {
            var verdict = r.AsExpected ? "yes" : $"**NO**{(r.Error is null ? "" : $" ({r.Error})")}";
            sb.AppendLine($"| {r.Variant} | {r.Tfm} | {r.Runtime} | {r.Attack} | {r.Control} | {r.Legit} | {verdict} |");
        }
        sb.AppendLine();
    }
    return sb.ToString();
}

static string FindRoot()
{
    for (var dir = new DirectoryInfo(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
    {
        if (Directory.Exists(Path.Combine(dir.FullName, "rules")) && Directory.Exists(Path.Combine(dir.FullName, "runner")))
            return dir.FullName;
    }
    throw new InvalidOperationException("Run the runner from inside the benchmark repository.");
}

static string? ArgValue(string[] args, string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static int MajorOf(string tfm) => int.Parse(tfm["net".Length..].Split('.')[0]);

static HashSet<int> InstalledAspNetCoreMajors()
{
    var psi = new ProcessStartInfo("dotnet", "--list-runtimes") { RedirectStandardOutput = true, UseShellExecute = false };
    using var p = Process.Start(psi)!;
    var output = p.StandardOutput.ReadToEnd();
    p.WaitForExit();
    return output.Split('\n')
        .Where(l => l.StartsWith("Microsoft.AspNetCore.App "))
        .Select(l => int.Parse(l.Split(' ')[1].Split('.')[0]))
        .ToHashSet();
}

record Rule(string Id, string Slug, string Title, Func<Uri, Task<Outcome>> Scenario)
{
    public string ProjectPath(string root, string variant) =>
        Path.Combine(root, "rules", $"{Id}-{Slug}", variant, $"{Id}.{variant}.csproj");
}

static class Proc
{
    public static async Task<(int Code, string Output)> RunToEnd(string file, string[] arguments, string workingDirectory)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = workingDirectory,
        };
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        return (p.ExitCode, await stdout + await stderr);
    }
}

record ResultRow(
    string Rule, string Variant, string Tfm, string Runtime,
    string Attack, string Control, string Legit,
    bool AttackSucceeded, bool LegitWorks, bool AsExpected, string? Error);

/// <summary>An app process listening on a free loopback port, killed on dispose.</summary>
sealed class RunningApp : IAsyncDisposable
{
    readonly Process _process;
    readonly StringBuilder _log;
    readonly string _logPath;

    public Uri BaseUri { get; }
    public string Runtime { get; private set; } = "?";

    RunningApp(Process process, StringBuilder log, string logPath, Uri baseUri)
    {
        _process = process;
        _log = log;
        _logPath = logPath;
        BaseUri = baseUri;
    }

    public static async Task<RunningApp> StartAsync(string dll, string logPath)
    {
        if (!File.Exists(dll)) throw new FileNotFoundException($"Build output not found: {dll}");

        var port = FreePort();
        var psi = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(dll)!,
        };
        psi.ArgumentList.Add(dll);
        psi.ArgumentList.Add("--urls");
        psi.ArgumentList.Add($"http://127.0.0.1:{port}");
        // Production: antiforgery failures return 400 instead of throwing the developer exception page.
        psi.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        psi.Environment["DOTNET_NOLOGO"] = "1";

        var log = new StringBuilder();
        var process = new Process { StartInfo = psi };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) lock (log) log.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (log) log.AppendLine(e.Data); };
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var app = new RunningApp(process, log, logPath, new Uri($"http://127.0.0.1:{port}"));
        await app.WaitUntilHealthyAsync();
        return app;
    }

    async Task WaitUntilHealthyAsync()
    {
        using var client = new HttpClient { BaseAddress = BaseUri, Timeout = TimeSpan.FromSeconds(2) };
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            if (_process.HasExited)
            {
                var exitCode = _process.ExitCode;
                await DisposeAsync();
                throw new InvalidOperationException($"App exited during startup (code {exitCode}); see {_logPath}");
            }
            try
            {
                var health = await client.GetFromJsonAsync<JsonElement>("/health");
                Runtime = health.GetProperty("runtime").GetString() ?? "?";
                return;
            }
            catch (HttpRequestException) { }
            catch (TaskCanceledException) { }
            await Task.Delay(250);
        }
        await DisposeAsync();
        throw new TimeoutException($"App did not become healthy within 30 s; see {_logPath}");
    }

    static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                await _process.WaitForExitAsync();
            }
        }
        catch (InvalidOperationException) { }

        string text;
        lock (_log) text = _log.ToString();
        await File.WriteAllTextAsync(_logPath, text);
        _process.Dispose();
    }
}
