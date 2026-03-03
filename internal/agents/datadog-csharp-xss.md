# C# User Prompt Template — Cross-Site Scripting (XSS)

Evaluate the following C# code located in <path> and report ONLY Cross-Site Scripting vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```csharp
<code>
```

## Vulnerability to Find

Report where there are **Cross-Site Scripting (XSS)** vulnerabilities as instructed.

This vulnerability is known as **CWE-79**.

<relatedFilesInformation>

---

## Context

**Language:** C#  
**Frameworks/Libraries:** <e.g., ASP.NET MVC, ASP.NET Core, Razor Pages, Web Forms>  
**User-controlled sources (tainted inputs):**  
- `Request.QueryString`, `Request.Form`, `Request.Headers`, `Request.Cookies`  
- `Request.Headers["Referer"]` — Referer header value
- `Request.Query.Keys` — query parameter names (keys are user-controlled!)
- Query key iteration: `foreach (var name in Request.Query.Keys) { param = name; }`
- MVC model binding (`[FromQuery]`, `[FromBody]`, `[FromForm]`)  
- Route parameters, URL segments  

**XSS sinks:**  
- `Response.Write()` with unencoded data  
- `Response.WriteAsync()` — **ASP.NET Core async sink**
- `await Response.WriteAsync(userInput)` — common in API controllers
- `Response.WriteAsync(string.Format(...))` — format string with user input
- `@Html.Raw()` in Razor views  
- `HttpUtility.HtmlEncode` bypass scenarios  
- JavaScript string injection, attribute injection

**NOT sanitizers for XSS (still report):**
- `WebUtility.UrlDecode()` — URL decoding does NOT sanitize
- `HttpUtility.UrlDecode()` — URL decoding does NOT sanitize  

**Recognized sanitizers:**  
- Razor auto-encoding (`@Model.Property` without Raw)  
- `HttpUtility.HtmlEncode()`, `WebUtility.HtmlEncode()`  
- `AntiXssEncoder` methods  
- Content Security Policy (CSP) headers  

---

## Rules and Guidelines

1. Report only XSS vulnerabilities.  
2. Trigger if unvalidated user input is rendered into HTML without encoding.  
3. Avoid false positives when proper encoding or Razor auto-escaping is used.  
4. Report the **exact location of the sink** where the unsafe output occurs (e.g., `Response.Write()`, `Html.Raw()`), NOT the line where tainted data originates. You must specify: `startLine`, `endLine`, `startColumn`, and `endColumn`.  
5. Output must be valid JSON; if no issues found:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify user-controlled input.  
2. Check whether it flows into HTML output.  
3. Verify absence of encoding or sanitization.  
4. Report unsafe output rendering.

---

## Patterns to Look For

### Vulnerable (Response.Write)
```csharp
string query = Request.QueryString["q"];
Response.Write("<div>" + query + "</div>");  // <-- SINK
```

### Vulnerable (Response.WriteAsync - ASP.NET Core)
```csharp
string param = Request.Headers["Referer"].ToString();
param = WebUtility.UrlDecode(param);  // URL decode does NOT sanitize XSS
await Response.WriteAsync(param);  // <-- SINK
```

### Vulnerable (Response.WriteAsync with string.Format)
```csharp
string bar = Request.Query["input"];
Response.WriteAsync(string.Format("Formatted: {0} and {1}.", bar, "b"));  // <-- SINK
```

### Vulnerable (Header reflection)
```csharp
string referer = Request.Headers["Referer"].ToString();
Response.Headers["X-XSS-Protection"] = "0";
await Response.WriteAsync(referer);  // <-- SINK: header reflection XSS
```

### Vulnerable (Razor Html.Raw)
```csharp
// In Razor view
@Html.Raw(Model.UserInput)  // <-- SINK
```

### Vulnerable (Method chain that passes through user input)
```csharp
string param = Request.Query["input"];
string bar = DoSomething(param);  // If DoSomething returns param, still tainted
await Response.WriteAsync(bar);  // <-- SINK
```

### Vulnerable (Ternary conditional with arithmetic - always tainted)
```csharp
string param = Request.Headers["Referer"].ToString();
param = WebUtility.UrlDecode(param);  // URL decode does NOT sanitize
int num = 106;
// (7 * 42) - 106 = 188, which is NOT > 200, so bar = param (tainted!)
string bar = (7 * 42) - num > 200 ? "safe" : param;  // Evaluates to param!
Response.Headers["X-XSS-Protection"] = "0";
await Response.WriteAsync(bar);  // <-- SINK: still tainted from conditional
```

### Vulnerable (Referer header to response)
```csharp
string param = "";
IHeaderDictionary headers = Request.Headers;
if (headers.ContainsKey("Referer"))
{
    param = headers["Referer"].ToString();  // Tainted from Referer header
}
param = System.Net.WebUtility.UrlDecode(param);  // URL decode does NOT sanitize
await Response.WriteAsync(param);  // <-- SINK
```

### Vulnerable (Query key iteration with string.Format and object array)
```csharp
string param = "";
foreach (var name in Request.Query.Keys)  // Query KEYS are user-controlled!
{
    var values = Request.Query[name].ToArray();
    if (values != null)
    {
        foreach (var value in values)
        {
            if (value.Equals("BenchmarkTest02322"))
            {
                param = name;  // Tainted - query key name
                break;
            }
        }
    }
}
string bar = DoSomething(param);  // If passthrough, still tainted
object[] obj = { bar, "b" };
Response.WriteAsync(string.Format("Formatted: {0} and {1}.", obj));  // <-- SINK
```

### Safe
```csharp
string query = Request.QueryString["q"];
Response.Write("<div>" + HttpUtility.HtmlEncode(query) + "</div>");
```

```csharp
// Razor auto-encodes by default
<div>@Model.UserInput</div>
```

---

{{.Memory}}

{{.OutputInstructions}}

---

## Summary

Detects Cross-Site Scripting (CWE-79) by tracing untrusted input rendered into HTML without proper encoding.
