using System.Text;
using System.Text.Json;

/// <summary>
/// Scores an external tool from SARIF files named &lt;Rule&gt;.&lt;Variant&gt;.sarif in one folder
/// (for example R01.Vulnerable.sarif and R01.Fixed.sarif).
///
/// The two variants of a rule differ only in the misconfiguration, so
///   - a finding on the Vulnerable variant whose rule ID is absent from Fixed = detection
///   - any finding on the Fixed variant is listed as "reported on Fixed"
///     (a false positive for the benchmarked misconfiguration, or an unrelated finding on shared code)
/// </summary>
static class SarifScoring
{
    public static async Task<int> RunAsync(string root, List<Rule> rules, string[] variants, string tool, string inputDir, string resultsDir)
    {
        if (!Directory.Exists(inputDir))
        {
            Console.Error.WriteLine($"Input folder not found: {inputDir}");
            return 2;
        }

        var findings = new Dictionary<(string Rule, string Variant), List<Finding>>();
        string? toolVersion = null;

        foreach (var rule in rules)
        foreach (var variant in variants)
        {
            var path = Path.Combine(inputDir, $"{rule.Id}.{variant}.sarif");
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"Missing SARIF file: {path}");
                return 2;
            }

            using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(path));
            var list = new List<Finding>();
            foreach (var run in doc.RootElement.GetProperty("runs").EnumerateArray())
            {
                toolVersion ??= DriverVersion(run);
                if (!run.TryGetProperty("results", out var results)) continue;
                foreach (var result in results.EnumerateArray())
                {
                    var ruleId = result.TryGetProperty("ruleId", out var id) ? id.GetString() ?? "?" : "?";
                    var message = result.TryGetProperty("message", out var m) && m.TryGetProperty("text", out var t) ? t.GetString() ?? "" : "";
                    var (file, line) = Location(result);
                    list.Add(new Finding(ruleId, file, line, message));
                }
            }
            findings[(rule.Id, variant)] = list.DistinctBy(f => (f.RuleId, f.File, f.Line)).ToList();
        }

        var rows = new List<ScoreRow>();
        foreach (var rule in rules)
        {
            var vulnerable = findings[(rule.Id, "Vulnerable")];
            var fixedVariant = findings[(rule.Id, "Fixed")];
            var fixedIds = fixedVariant.Select(f => f.RuleId).ToHashSet();
            var detected = vulnerable.Select(f => f.RuleId).Where(id => !fixedIds.Contains(id)).Distinct().ToList();
            rows.Add(new ScoreRow(rule.Id, detected, fixedIds.ToList(), vulnerable, fixedVariant));
        }

        var markdown = Render(tool, toolVersion, rules, rows);
        Console.WriteLine(markdown);

        Directory.CreateDirectory(resultsDir);
        var slug = tool.ToLowerInvariant().Replace(' ', '-');
        await File.WriteAllTextAsync(Path.Combine(resultsDir, $"{slug}.md"), markdown);
        await File.WriteAllTextAsync(Path.Combine(resultsDir, $"{slug}.json"),
            JsonSerializer.Serialize(new { tool, toolVersion, rows }, new JsonSerializerOptions { WriteIndented = true }));

        // One compact line per tool, e.g. "Semgrep 1.183.0: R01=no R02=no R03=yes(mvc-missing-antiforgery) R07=no | fixed: R03(...)".
        var compact = $"{tool} {toolVersion}: " +
            string.Join(" ", rows.Select(r => $"{r.Rule}={(r.Detected.Count > 0 ? $"yes({string.Join(",", r.Detected.Select(ShortId))})" : "no")}")) +
            " | reported on Fixed: " +
            (rows.Any(r => r.ReportedOnFixed.Count > 0)
                ? string.Join(" ", rows.Where(r => r.ReportedOnFixed.Count > 0).Select(r => $"{r.Rule}({string.Join(",", r.ReportedOnFixed.Select(ShortId))})"))
                : "none");
        await File.WriteAllTextAsync(Path.Combine(resultsDir, $"{slug}.summary.txt"), compact + Environment.NewLine);
        return 0;
    }

    static string? DriverVersion(JsonElement run)
    {
        if (!run.TryGetProperty("tool", out var tool) || !tool.TryGetProperty("driver", out var driver)) return null;
        foreach (var name in new[] { "semanticVersion", "version" })
        {
            if (driver.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String) return v.GetString();
        }
        return null;
    }

    static (string File, int Line) Location(JsonElement result)
    {
        if (!result.TryGetProperty("locations", out var locations) || locations.GetArrayLength() == 0) return ("?", 0);
        var physical = locations[0].GetProperty("physicalLocation");
        var uri = physical.TryGetProperty("artifactLocation", out var a) && a.TryGetProperty("uri", out var u) ? u.GetString() ?? "?" : "?";
        var line = physical.TryGetProperty("region", out var r) && r.TryGetProperty("startLine", out var l) ? l.GetInt32() : 0;
        return (Path.GetFileName(uri), line);
    }

    /// <summary>Semgrep rule IDs carry the full path ("csharp.dotnet.security.mvc-missing-antiforgery"); keep the last part.</summary>
    static string ShortId(string id) => id.Contains('.') ? id[(id.LastIndexOf('.') + 1)..] : id;

    static string Render(string tool, string? version, List<Rule> rules, List<ScoreRow> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# {tool} {version} ({DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC)");
        sb.AppendLine();
        sb.AppendLine("| Rule | Detected in Vulnerable | Reported on Fixed |");
        sb.AppendLine("|---|---|---|");
        foreach (var r in rows)
        {
            var detected = r.Detected.Count > 0 ? "yes: " + string.Join(", ", r.Detected.Select(ShortId)) : "no";
            var onFixed = r.ReportedOnFixed.Count > 0 ? "yes: " + string.Join(", ", r.ReportedOnFixed.Select(ShortId)) : "no";
            sb.AppendLine($"| {r.Rule} | {detected} | {onFixed} |");
        }
        sb.AppendLine();
        sb.AppendLine($"Detected: {rows.Count(r => r.Detected.Count > 0)} of {rows.Count} rules. Reported on Fixed: {rows.Count(r => r.ReportedOnFixed.Count > 0)} of {rows.Count}.");
        return sb.ToString();
    }
}

record Finding(string RuleId, string File, int Line, string Message);

record ScoreRow(string Rule, List<string> Detected, List<string> ReportedOnFixed, List<Finding> VulnerableFindings, List<Finding> FixedFindings);
