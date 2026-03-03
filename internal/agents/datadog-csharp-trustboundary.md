# C# User Prompt Template — Trust Boundary Violation

Evaluate the following C# code located in <path> and report ONLY Trust Boundary Violation vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```csharp
<code>
```

## Vulnerability to Find

Report where there are **Trust Boundary Violation** vulnerabilities as instructed.

This vulnerability is known as **CWE-501**.

<relatedFilesInformation>

---

## Context

**Language:** C#  
**Frameworks/Libraries:** <e.g., ASP.NET, ASP.NET Core>  

**User-controlled sources (tainted inputs) - track these to sinks:**  
- `Request.Query[...]` — query string parameters
- `Request.Query["..."].FirstOrDefault()` — query string with null handling
- `Request.QueryString[...]` — legacy query string access
- `Request.Form[...]` — form data
- `Request.Headers[...]` — HTTP headers
- `Request.Cookies[...]` — cookies (direct access)
- Cookie iteration via foreach: `foreach (var cookie in Request.Cookies) { cookie.Value }` — cookie values
- `Request.Body` — request body stream
- MVC model binding parameters:
  - `[FromQuery]` — query string binding
  - `[FromBody]` — JSON body binding
  - `[FromForm]` — form data binding
  - `[FromHeader]` — header binding
- Method parameters that receive external data (e.g., action method parameters)
- Any data from external or untrusted sources  

**Trusted storage sinks (where tainted data should not flow directly):**  
- `HttpContext.Session.SetString(key, value)` — **most common sink**
- `HttpContext.Session.SetInt32(key, value)` — integer storage
- `HttpContext.Session.Set(key, bytes)` — byte array storage
- `HttpContext.Session[key] = value` — indexer assignment
- `Session[key] = value` — legacy session access
- `TempData[key] = value` — temporary data storage
- `ViewData[key] = value` — view data storage
- `ViewBag.Property = value` — dynamic view data
- Claims or identity data modifications  

**Authorization decision points:**  
- Role checks (`User.IsInRole()`)  
- Policy evaluations  
- Permission-based access control  
- `[Authorize(Roles = "...")]` attribute-based checks

**Recognized sanitizers:**  
- Database lookups for roles/permissions  
- Validation against strict allowlists  
- Server-side role/permission derivation

**NOT sanitizers for trust boundary (still report):**
- `HtmlEncoder.Default.Encode()` — prevents XSS but NOT trust boundary
- `HttpUtility.HtmlEncode()` — prevents XSS but NOT trust boundary
- `WebUtility.HtmlEncode()` — prevents XSS but NOT trust boundary
- URL encoding/decoding — does NOT sanitize
- `HttpUtility.UrlDecode()` — decoding does NOT sanitize
- Base64 encode/decode — data transformation, taint preserved
- Interface method calls that pass through input — taint preserved
- `Security.Encoder.HtmlEncode()` — Microsoft encoder prevents XSS but NOT trust boundary

**Trust boundary sinks include BOTH key and value:**
- Session value: `Session.SetString(key, userValue)` ← value is user-controlled
- Session key: `Session.SetString(userKey, value)` ← key is user-controlled (ALSO VULNERABLE!)  

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report only Trust Boundary Violation vulnerabilities.  
2. **Trigger if user-controlled data is stored in session/context WITHOUT validation** — the violation occurs at storage time, regardless of how the data is used later.
3. Avoid false positives when data is validated or derived from trusted sources.  
4. Report the **exact location of the sink** where untrusted data is stored in trusted storage (e.g., `Session["role"] = userInput`), NOT the line where tainted data originates. You must specify: `startLine`, `endLine`, `startColumn`, and `endColumn`.  
5. Output must be valid JSON; if no issues found:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify user-controlled input (Request.Query, Request.Form, Request.Headers, Request.Cookies, etc.).  
2. Check whether it flows into trusted storage (Session.SetString, Session[], TempData, ViewData, ViewBag).  
3. **Report if the data reaches trusted storage without validation** — do NOT require proof that the data is later used for authorization.
4. The vulnerability exists at the moment untrusted data crosses into trusted storage.

---

## Patterns to Look For

### Vulnerable (Session assignment from form)
```csharp
string role = Request.Form["role"];
Session["UserRole"] = role;  // <-- SINK: User controls their own role!
```

### Vulnerable (HttpContext.Items from query)
```csharp
string isAdmin = Request.QueryString["admin"];
HttpContext.Items["IsAdmin"] = isAdmin;  // <-- SINK
```

### Vulnerable (ASP.NET Core Session.SetString - MOST COMMON)
```csharp
var param = Request.Query["BenchmarkTest00031"].FirstOrDefault();
HttpContext.Session.SetString("userid", param);  // <-- SINK: User controls session data
```

### Vulnerable (Session indexer assignment)
```csharp
var role = HttpContext.Request.Query["role"].ToString();
HttpContext.Session["UserRole"] = role;  // <-- SINK
```

### Vulnerable (Session.Set with byte array)
```csharp
var userData = Encoding.UTF8.GetBytes(Request.Form["data"]);
HttpContext.Session.Set("userdata", userData);  // <-- SINK
```

### Vulnerable (Session.SetInt32)
```csharp
int level = int.Parse(Request.Query["level"]);
HttpContext.Session.SetInt32("accessLevel", level);  // <-- SINK: User controls access level
```

### Vulnerable (TempData)
```csharp
string permission = Request.Headers["X-Permission"];
TempData["UserPermission"] = permission;  // <-- SINK
```

### Vulnerable (ViewData)
```csharp
var adminFlag = Request.Query["isAdmin"].FirstOrDefault();
ViewData["IsAdmin"] = adminFlag;  // <-- SINK: User controls admin status
```

### Vulnerable (ViewBag)
```csharp
var role = Request.Form["role"];
ViewBag.UserRole = role;  // <-- SINK
```

### Vulnerable (Method chain passing user input)
```csharp
// Taint flows through interfaces/method chains
var param = Request.Cookies["BenchmarkTest01872"];
string bar = DoSomething(param);  // If DoSomething just returns param, still tainted
HttpContext.Session.SetString(bar, "10340");  // <-- SINK

private string DoSomething(string param) {
    ThingInterface thing = ThingFactory.CreateThing();
    return thing.DoSomething(param);  // Just passes through - STILL TAINTED
}
```

### Vulnerable (HTML encoding does NOT prevent trust boundary)
```csharp
var param = Request.Query["BenchmarkTest02165"];
string bar = HtmlEncoder.Default.Encode(param);  // HTML encode does NOT sanitize!
HttpContext.Session.SetString(bar, "10340");  // <-- SINK: still user-controlled
```

### Vulnerable (Cookie iteration through foreach loop)
```csharp
string param = "noCookieValueSupplied";
foreach (var cookie in Request.Cookies)
{
    if (cookie.Key.Equals("BenchmarkTest01872"))
    {
        param = HttpUtility.UrlDecode(cookie.Value, Encoding.UTF8);  // Tainted
        break;
    }
}
string bar = DoSomething(param);  // If DoSomething passes through, still tainted
HttpContext.Session.SetString(bar, "10340");  // <-- SINK
```

### Vulnerable (Direct query parameter to session - COMMON PATTERN)
```csharp
// This is the most basic trust boundary violation
var param = Request.Query["BenchmarkTest00031"].FirstOrDefault();
HttpContext.Session.SetString("userid", param);  // <-- SINK: Direct user input to session
```

### Vulnerable (User controls session KEY)
```csharp
var key = Request.Form["key"];
HttpContext.Session.SetString(key, "someValue");  // <-- SINK: user controls the key
```

### Safe (Role from authenticated user in database)
```csharp
var user = dbContext.Users.Find(userId);
Session["UserRole"] = user.Role;  // SAFE - from database, not user input
```

### Safe (Validated against allowlist)
```csharp
string role = Request.Form["role"];
var allowedRoles = new[] { "user", "moderator" };
if (allowedRoles.Contains(role))
    Session["UserRole"] = role;  // SAFE - validated
```

### Safe (Server-side derivation)
```csharp
// Role derived from authenticated user, not from user input
var claims = User.Claims.Where(c => c.Type == ClaimTypes.Role);
Session["UserRoles"] = string.Join(",", claims.Select(c => c.Value));  // SAFE
```

### Safe (Constant-returning method)
```csharp
// Even though 'Request' is tainted, GetTheValue() returns a hardcoded constant
var wrapper = new SeparateClassRequest(Request);
var role = wrapper.GetTheValue("key");  // Returns "user" (constant), NOT tainted
Session["UserRole"] = role;  // SAFE - role is not user-controlled
```

---

## Output

The answer must be a JSON formatted answer. The json document is an array of values.
The array of violations is named `violations`
Each value in the JSON array has the following attributes:
 - `startLine`: the **exact** line number where the vulnerability starts (see Location Requirements below)
 - `startColumn`: the column number where the vulnerability starts on that line (1-indexed)
 - `endLine`: the line number where the vulnerability ends
 - `endColumn`: the column number where the vulnerability ends on that line (1-indexed, exclusive)
 - `reason`: why the issue is a true vulnerability and why the issue is not a false positive.

If there is no violation, write "NO VIOLATION AMIGO"

### Location Requirements

The location values MUST point to the **exact position where the violation occurs** - specifically, the sink where tainted/untrusted data is used in a dangerous operation.

**DO NOT** report:
- The line where the function is defined
- The line where the class or method starts
- The first or last line of a code block
- A line "near" or "around" the vulnerability
- The line where tainted data originates (the source)

**DO** report:
- The precise line containing the dangerous operation (the sink)
- For trust boundary: the line where user-controlled data is stored in trusted storage

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
          "startLine": {
            "type": "integer",
            "description": "The line number where the violation starts (1-indexed)"
          },
          "startColumn": {
            "type": "integer",
            "description": "The column number where the violation starts (1-indexed)"
          },
          "endLine": {
            "type": "integer",
            "description": "The line number where the violation ends (1-indexed)"
          },
          "endColumn": {
            "type": "integer",
            "description": "The column number where the violation ends (1-indexed, exclusive)"
          },
          "reason": {
            "type": "string"
          }
        },
        "required": ["startLine", "startColumn", "endLine", "endColumn", "reason"],
        "additionalProperties": false
      }
    }
  },
  "required": ["violations"],
  "additionalProperties": false
}
```

---

## Summary

Detects Trust Boundary Violation (CWE-501) by tracing untrusted input stored in session or context for authorization without validation.
