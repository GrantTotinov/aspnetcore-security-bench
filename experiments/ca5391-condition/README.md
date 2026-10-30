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

## CodeQL does the same

CodeQL's `cs/web/missing-token-validation` query (csharp-queries 1.10.2, CodeQL 2.27.3) has the
same condition, and its source explains why:

```ql
  // Verify that validate anti forgery token attributes are used somewhere within this project, to
  // avoid reporting false positives on projects that use an alternative approach to mitigate CSRF
  // issues.
  exists(getAValidatedElement())
```

Both tools trade the fully unprotected case for fewer false positives. Neither rule's
documentation states the condition. The CodeQL help only hints at it ("Web applications that use
tokens to prevent cross-site request forgery (CSRF) should validate the tokens for all Http POST
requests"), and the CA5391 page does not mention it.

## Reproduce

```bash
dotnet build experiments/ca5391-condition
```

| `ExampleController` contains | CA5391 on `PostAction` |
|---|---|
| `PostAction` + `ProtectedAction` with `[ValidateAntiForgeryToken]` | reported |
| `PostAction` only | not reported |

Checked on 2026-10-30 with .NET SDK 10.0.114.
