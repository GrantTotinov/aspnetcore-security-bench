# Why CA5391 misses R03

CA5391 ("Use antiforgery tokens in ASP.NET Core MVC controllers") is the built-in analyzer meant
for R03, yet it stays silent on the R03 vulnerable app even with every rule enabled
(`AnalysisLevel=latest-all`).

The analyzer reports at compilation end only when, among other conditions, **at least one
antiforgery attribute is used somewhere in the project**. In the analyzer source
(`UseAutoValidateAntiforgeryToken.cs` in dotnet/roslyn-analyzers) the reporting condition starts with:

```csharp
if (usingValidateAntiForgeryAttribute && !hasGlobalAntiForgeryFilter && ...
```

and `usingValidateAntiForgeryAttribute` is set only when a controller or action carries an
attribute matching `*Validate*Antiforgery*Attribute`.

So the rule catches "protected most actions, forgot one", but not "never added antiforgery at
all", which is the more dangerous case.

## Reproduce

```bash
dotnet build experiments/ca5391-condition
```

| `ExampleController` contains | CA5391 on `PostAction` |
|---|---|
| `PostAction` + `ProtectedAction` with `[ValidateAntiForgeryToken]` | reported |
| `PostAction` only | not reported |

Checked on 2026-10-30 with .NET SDK 10.0.114.
