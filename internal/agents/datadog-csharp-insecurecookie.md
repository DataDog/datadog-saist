# C# User Prompt Template — Insecure Cookie

Evaluate the following C# code located in <path> and report ONLY Insecure Cookie vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```csharp
<code>
```

## Vulnerability to Find

Report where there are **Insecure Cookie** vulnerabilities as instructed.

This vulnerability is known as **CWE-614**.

<relatedFilesInformation>

---

## Context

**Language:** C#  
**Frameworks/Libraries:** <e.g., ASP.NET, ASP.NET Core>  

**Sensitive cookies that require security attributes:**  
- Session cookies, authentication tokens  
- CSRF tokens  
- User preference cookies with sensitive data  

**Cookie creation sinks:**  
- `Response.Cookies.Append()` (ASP.NET Core)  
- `Response.Cookies.Add(new HttpCookie())` (ASP.NET)  
- `CookieOptions` configuration  

**Required security attributes:**  
- `Secure = true` — HTTPS only  
- `HttpOnly = true` — No JavaScript access  
- `SameSite = SameSiteMode.Strict` or `SameSiteMode.Lax` — CSRF protection  

---

## ⚠️ CRITICAL: Track CookieOptions Property Assignments

**You MUST track property assignments on CookieOptions objects BEFORE the Cookies.Append() call.**

When analyzing code, follow these steps:
1. Find where `CookieOptions` is created
2. Track ALL property assignments on that object (Secure, HttpOnly, SameSite)
3. Only report as vulnerable if Secure is NOT set to `true` BEFORE the `Append()` call

### Example Analysis Pattern:

```csharp
var option = new CookieOptions();        // CookieOptions created
option.Secure = true;                     // Secure IS set to true
option.HttpOnly = true;                   // HttpOnly IS set to true  
option.SameSite = SameSiteMode.Strict;    // SameSite IS set
Response.Cookies.Append("session", value, option);  // SAFE - all properties set!
```

**This is SAFE because Secure, HttpOnly, and SameSite are ALL set before Append().**

---

## Rules and Guidelines

1. Report only Insecure Cookie vulnerabilities for sensitive cookies.  
2. **CRITICAL**: Track CookieOptions property assignments - if `Secure = true` is set BEFORE `Append()`, the cookie IS secure.
3. Do NOT report cookies where all security properties are set before the Append() call.
4. Avoid false positives for non-sensitive cookies (analytics, simple preferences).  
5. Report the **exact location of the sink** where the cookie is created. You must specify: `startLine`, `endLine`, `startColumn`, and `endColumn`.  
6. Output must be valid JSON; if no issues found:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify cookie creation (`Cookies.Append()` or `Cookies.Add()`).
2. Find the `CookieOptions` object being used.
3. **Track ALL property assignments** on that CookieOptions object before the Append() call.
4. Check if Secure, HttpOnly, and SameSite are set to secure values.
5. Only report if security properties are MISSING or set to insecure values.

---

## Patterns to Analyze

### SAFE — Properties Set Before Append (DO NOT REPORT)

```csharp
// All properties set on separate lines - SAFE
var option = new CookieOptions();
option.Secure = true;          // <-- Secure IS set
option.HttpOnly = true;        // <-- HttpOnly IS set
option.SameSite = SameSiteMode.Strict;  // <-- SameSite IS set
Response.Cookies.Append("SessionId", sessionId, option);  // SAFE!
```

```csharp
// Properties set in object initializer - SAFE
var options = new CookieOptions
{
    Secure = true,
    HttpOnly = true,
    SameSite = SameSiteMode.Strict,
    Expires = DateTime.Now.AddDays(1)
};
Response.Cookies.Append("SessionId", sessionId, options);  // SAFE!
```

```csharp
// HttpCookie with properties - SAFE
var cookie = new HttpCookie("SessionId", sessionId)
{
    Secure = true,
    HttpOnly = true
};
Response.Cookies.Add(cookie);  // SAFE!
```

```csharp
// Properties set via method chaining or multiple statements - SAFE
CookieOptions opts = new CookieOptions();
opts.Secure = true;
opts.HttpOnly = true;
opts.SameSite = SameSiteMode.Lax;
Response.Cookies.Append("token", token, opts);  // SAFE!
```

### VULNERABLE — Missing Security Properties (REPORT THESE)

```csharp
// No options provided at all - VULNERABLE
Response.Cookies.Append("SessionId", sessionId);  // <-- REPORT: Missing all security attributes
```

```csharp
// Options created but Secure not set - VULNERABLE
var options = new CookieOptions { Expires = DateTime.Now.AddDays(1) };
Response.Cookies.Append("AuthToken", token, options);  // <-- REPORT: Missing Secure, HttpOnly
```

```csharp
// Secure explicitly set to false - VULNERABLE
var options = new CookieOptions();
options.Secure = false;  // Explicitly insecure!
Response.Cookies.Append("session", value, options);  // <-- REPORT
```

```csharp
// Missing HttpOnly on sensitive cookie - VULNERABLE
var options = new CookieOptions();
options.Secure = true;
// HttpOnly NOT set - JavaScript can access!
Response.Cookies.Append("authToken", token, options);  // <-- REPORT: Missing HttpOnly
```

```csharp
// Secure set AFTER Append - VULNERABLE (too late!)
var option = new CookieOptions();
Response.Cookies.Append("name", value, option);  // <-- REPORT: Secure not set yet
option.Secure = true;  // Too late! Cookie already created without Secure
```

```csharp
// ASP.NET without security attributes - VULNERABLE
var cookie = new HttpCookie("SessionId", sessionId);
Response.Cookies.Add(cookie);  // <-- REPORT: Missing Secure, HttpOnly
```

---

## FALSE POSITIVE AVOIDANCE

### Track Variable Assignments Across Lines

When a `CookieOptions` variable is created and properties are assigned on subsequent lines, you MUST track those assignments:

```csharp
var option = new CookieOptions();  // Line 1: Created
option.Secure = true;               // Line 2: Secure = true (TRACK THIS!)
option.HttpOnly = true;             // Line 3: HttpOnly = true (TRACK THIS!)
option.SameSite = SameSiteMode.Strict;  // Line 4: SameSite set (TRACK THIS!)
Response.Cookies.Append("x", y, option);  // Line 5: All properties set - SAFE!
```

**This is SAFE.** Do NOT report this pattern.

### Non-Sensitive Cookies

Do NOT report cookies that are clearly non-sensitive:
- Analytics tracking (`_ga`, `_analytics`)
- UI preferences (`theme`, `language`)
- Non-PII data

---

## Output

The answer must be a JSON formatted answer. The json document is an array of values.
The array of violations is named `violations`
Each value in the JSON array has the following attributes:
 - `startLine`: the **exact** line number where the vulnerability starts
 - `startColumn`: the column number where the vulnerability starts on that line (1-indexed)
 - `endLine`: the line number where the vulnerability ends
 - `endColumn`: the column number where the vulnerability ends on that line (1-indexed, exclusive)
 - `reason`: why the issue is a true vulnerability and why the issue is not a false positive.

If there is no violation, write "NO VIOLATION AMIGO"

### Location Requirements

**DO NOT** report:
- Cookies where Secure, HttpOnly are set to true before Append()
- Non-sensitive cookies

**DO** report:
- The Cookies.Append() or Cookies.Add() line where security properties are missing

## Output schema

The output must be JSON that complies with the following schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "violations": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "startLine": { "type": "integer" },
          "startColumn": { "type": "integer" },
          "endLine": { "type": "integer" },
          "endColumn": { "type": "integer" },
          "reason": { "type": "string" }
        },
        "required": ["startLine", "startColumn", "endLine", "endColumn", "reason"]
      }
    }
  },
  "required": ["violations"]
}
```

---

## Summary

Detects Insecure Cookie (CWE-614) by identifying sensitive cookies created without proper security attributes. **CRITICAL**: Track CookieOptions property assignments - if Secure=true and HttpOnly=true are set BEFORE Append(), the cookie IS secure and should NOT be reported.
