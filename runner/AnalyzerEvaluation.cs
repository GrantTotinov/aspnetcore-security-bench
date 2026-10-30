using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

/// <summary>
/// Builds every variant with all built-in analyzers enabled and records the diagnostics.
///
/// Tools covered: the .NET code analyzers shipped with the SDK (CAxxxx), switched on with
/// AnalysisLevel=latest-all, and the ASP.NET Core analyzers shipped in the targeting pack (ASPxxxx),
/// which are on by default.
///
/// Scoring: the two variants of a rule differ only in the misconfiguration, so
///   - a security diagnostic on the Vulnerable variant that is absent from Fixed = detection
///   - a security diagnostic on the Fixed variant = false positive
/// Non-security diagnostics (style, design, naming) are kept in the JSON but not scored.
/// </summary>
static class AnalyzerEvaluation
{
    static readonly Regex DiagnosticLine = new(
        @"^(?<file>.+?)\((?<line>\d+),(?<col>\d+)\): (?<sev>warning|error) (?<id>[A-Z]+\d+): (?<msg>.*?)(?: \[[^\]]+\])?$",
        RegexOptions.Compiled);

    public static async Task<int> RunAsync(string root, List<Rule> rules, string[] variants, List<string> tfms, bool noRestore, string resultsDir)
    {
        var sdk = (await Proc.RunToEnd("dotnet", ["--version"], root)).Output.Trim();
        var results = new List<AnalysisResult>();

        foreach (var rule in rules)
        foreach (var variant in variants)
        foreach (var tfm in tfms)
        {
            var project = rule.ProjectPath(root, variant);
            Console.WriteLine($"Analyzing {rule.Id}.{variant} ({tfm})...");

            string[] buildArgs =
            [
                "build", project, "-c", "Release", "-f", tfm, "--no-incremental",
                "-nologo", "-v", "q", "-clp:NoSummary",
                "-p:AnalysisLevel=latest-all",
                "-p:TreatWarningsAsErrors=false",
            ];
            if (noRestore) buildArgs = [.. buildArgs, "--no-restore"];

            var (code, output) = await Proc.RunToEnd("dotnet", buildArgs, root);
            if (code != 0)
            {
                Console.Error.WriteLine(output);
                return 1;
            }

            var diagnostics = output
                .Split('\n')
                .Select(l => DiagnosticLine.Match(l.Trim()))
                .Where(m => m.Success)
                .Select(m => new Diagnostic(
                    m.Groups["id"].Value,
                    m.Groups["sev"].Value,
                    Path.GetFileName(m.Groups["file"].Value),
                    int.Parse(m.Groups["line"].Value),
                    m.Groups["msg"].Value.Trim(),
                    IsSecurity(m.Groups["id"].Value)))
                .Where(d => !d.Id.StartsWith("NU") && !d.Id.StartsWith("NETSDK"))
                .DistinctBy(d => (d.Id, d.File, d.Line))
                .OrderBy(d => d.Id)
                .ToList();

            results.Add(new AnalysisResult(rule.Id, variant, tfm, diagnostics));
        }

        var markdown = Render(rules, tfms, results, sdk);
        Console.WriteLine();
        Console.WriteLine(markdown);

        await File.WriteAllTextAsync(Path.Combine(resultsDir, "analyzers.md"), markdown);
        await File.WriteAllTextAsync(Path.Combine(resultsDir, "analyzers.json"),
            JsonSerializer.Serialize(new { sdk, results }, new JsonSerializerOptions { WriteIndented = true }));

        // One compact line, e.g. "Built-in analyzers (SDK 10.0.114): R01/net8.0=no R01/net10.0=no ... | fixed: none".
        var pairs = rules.SelectMany(r => tfms.Select(t => (Rule: r.Id, Tfm: t))).Select(p =>
        {
            var vulnerable = results.Single(r => r.Rule == p.Rule && r.Variant == "Vulnerable" && r.Tfm == p.Tfm);
            var fixedVariant = results.Single(r => r.Rule == p.Rule && r.Variant == "Fixed" && r.Tfm == p.Tfm);
            var fixedIds = fixedVariant.Diagnostics.Where(d => d.Security).Select(d => d.Id).ToHashSet();
            var detected = vulnerable.Diagnostics.Where(d => d.Security && !fixedIds.Contains(d.Id)).Select(d => d.Id).Distinct().ToList();
            return (p.Rule, p.Tfm, detected, fixedIds);
        }).ToList();
        var compact = $"Built-in analyzers (SDK {sdk}): " +
            string.Join(" ", pairs.Select(p => $"{p.Rule}/{p.Tfm}={(p.detected.Count > 0 ? $"yes({string.Join(",", p.detected)})" : "no")}")) +
            " | reported on Fixed: " +
            (pairs.Any(p => p.fixedIds.Count > 0)
                ? string.Join(" ", pairs.Where(p => p.fixedIds.Count > 0).Select(p => $"{p.Rule}/{p.Tfm}({string.Join(",", p.fixedIds)})"))
                : "none");
        await File.WriteAllTextAsync(Path.Combine(resultsDir, "analyzers.summary.txt"), compact + Environment.NewLine);
        return 0;
    }

    /// <summary>
    /// Security category of the .NET code analyzers, plus every ASP.NET Core analyzer
    /// (ASP.NET Core analyzers are few and all framework-usage checks, so none are filtered out).
    /// </summary>
    static bool IsSecurity(string id)
    {
        if (id.StartsWith("ASP")) return true;
        if (!id.StartsWith("CA") || !int.TryParse(id[2..], out var n)) return false;
        return n is 2100 or 2109 or 2119 or 2153
            || n is >= 2300 and <= 2399
            || n is >= 3001 and <= 3012
            || n is 3061 or 3075 or 3076 or 3077 or 3147
            || n is >= 5350 and <= 5405;
    }

    static string Render(List<Rule> rules, List<string> tfms, List<AnalysisResult> results, string sdk)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# Built-in analyzers ({DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC)");
        sb.AppendLine();
        sb.AppendLine($".NET SDK {sdk}, `AnalysisLevel=latest-all`. ASP.NET Core analyzers come from the targeting pack of each TFM.");
        sb.AppendLine();
        sb.AppendLine("| Rule | TFM | Detected in Vulnerable | False positive in Fixed |");
        sb.AppendLine("|---|---|---|---|");

        var detections = 0;
        var falsePositives = 0;
        var pairs = 0;

        foreach (var rule in rules)
        foreach (var tfm in tfms)
        {
            var vulnerable = results.Single(r => r.Rule == rule.Id && r.Variant == "Vulnerable" && r.Tfm == tfm);
            var fixedVariant = results.Single(r => r.Rule == rule.Id && r.Variant == "Fixed" && r.Tfm == tfm);

            var fixedSecurityIds = fixedVariant.Diagnostics.Where(d => d.Security).Select(d => d.Id).ToHashSet();
            var detected = vulnerable.Diagnostics
                .Where(d => d.Security && !fixedSecurityIds.Contains(d.Id))
                .Select(d => d.Id)
                .Distinct()
                .ToList();

            pairs++;
            if (detected.Count > 0) detections++;
            if (fixedSecurityIds.Count > 0) falsePositives++;

            sb.AppendLine($"| {rule.Id} | {tfm} | {(detected.Count > 0 ? "yes: " + string.Join(", ", detected) : "no")} | {(fixedSecurityIds.Count > 0 ? "yes: " + string.Join(", ", fixedSecurityIds) : "no")} |");
        }

        sb.AppendLine();
        sb.AppendLine($"Detected: {detections} of {pairs} rule/TFM pairs. False positives: {falsePositives} of {pairs}.");
        sb.AppendLine();
        sb.AppendLine("Non-security diagnostics (style, design, naming) are listed in `analyzers.json` and not scored.");
        return sb.ToString();
    }
}

record Diagnostic(string Id, string Severity, string File, int Line, string Message, bool Security);

record AnalysisResult(string Rule, string Variant, string Tfm, List<Diagnostic> Diagnostics);
