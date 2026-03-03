# C# User Prompt Template — LDAP Injection

Evaluate the following C# code located in <path> and report ONLY LDAP Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```csharp
<code>
```

## Vulnerability to Find

Report where there are **LDAP Injection** vulnerabilities as instructed.

This vulnerability is known as **CWE-90**.

<relatedFilesInformation>

---

## Context

**Language:** C#  
**Frameworks/Libraries:** <e.g., System.DirectoryServices, Novell.Directory.Ldap>  

**User-controlled sources (tainted inputs):**  
- `Request.QueryString["..."]`, `Request.Query["..."]`
- `Request.Form["..."]`
- `Request.Headers["..."]`
- `Request.Cookies["..."]`
- MVC model binding parameters (`[FromQuery]`, `[FromBody]`, `[FromForm]`)
- Any data from external or untrusted sources  

**LDAP execution sinks:**  
- `DirectorySearcher.Filter` with concatenated strings  
- `DirectorySearcher.FindAll()`
- `DirectorySearcher.FindOne()`  
- `LdapConnection.SendRequest()` with SearchRequest  
- `DirectoryEntry` path construction with user input

**Recognized sanitizers:**  
- LDAP filter escaping (escaping `*`, `(`, `)`, `\`, NUL characters)  
- Input validation with strict allowlists  
- Parameterized or programmatic filter construction  
- Regex validation for alphanumeric-only usernames

**FALSE POSITIVE AVOIDANCE - Safe Sources:**

### SeparateClassRequest.GetTheValue() Pattern
```csharp
// This pattern returns CONTROLLED values, not user input!
var scr = new OWASPBenchmark.Helpers.SeparateClassRequest(request);
var param = scr.GetTheValue("TestName");  // Returns a CONSTANT/CONTROLLED value
// param is NOT tainted - do NOT report LDAP injection
```

### ThingFactory Pattern
```csharp
// ThingFactory.CreateThing() returns safe, controlled values
var thing = OWASPBenchmark.Helpers.ThingFactory.CreateThing();
var value = thing.DoSomething(param);  // Safe source - returns controlled value
// value is NOT tainted - do NOT report LDAP injection
```

**Why are these safe?** These helper classes return controlled/constant values from an internal lookup, NOT raw user input. Even though they may be instantiated with a request object, their return values are predetermined safe values.

### Switch with Constant Selector
```csharp
// When switch selector is a compile-time constant, track which branch is taken
string guess = "ABC";
char switchTarget = guess[2];  // Always 'C' - constant!

switch (switchTarget) {
    case 'A': bar = param; break;
    case 'B': bar = "safe"; break;
    case 'C':
    case 'D': bar = param; break;  // Takes this path
    default: bar = "safe"; break;
}
// If param is from safe source (SeparateClassRequest), bar is safe
```

### Conditional with Compile-Time Constant
```csharp
// When condition is always true/false at compile time, track the actual path
if ((7 * 42) - 86 > 200)  // 294 - 86 = 208 > 200 is ALWAYS TRUE
    bar = "safe";
else 
    bar = param;
// bar is always "safe" - NOT tainted
```

### Constant-Returning Methods
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report only LDAP Injection vulnerabilities.  
2. Trigger if unvalidated user input is concatenated into an LDAP filter.  
3. Avoid false positives when proper escaping or allowlisting is used.  
4. Report the **exact location of the sink** where the LDAP query is executed (e.g., `FindAll()`, `FindOne()`), NOT the line where tainted data originates. You must specify: `startLine`, `endLine`, `startColumn`, and `endColumn`.  
5. Output must be valid JSON; if no issues found:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify user-controlled input.  
2. Check whether it flows into LDAP filter construction.  
3. Verify absence of escaping or sanitization.  
4. Report unsafe LDAP query execution.

---

## Patterns to Look For

### Vulnerable (String interpolation in Filter)
```csharp
string username = Request.QueryString["user"];
var searcher = new DirectorySearcher(entry);
searcher.Filter = $"(&(uid={username})(objectClass=user))";
var results = searcher.FindAll();  // <-- SINK
```

### Vulnerable (String concatenation)
```csharp
string filter = "(&(cn=" + Request.Form["name"] + "))";
searcher.Filter = filter;
searcher.FindOne();  // <-- SINK
```

### Vulnerable (DirectoryEntry path)
```csharp
string username = Request.Query["user"];
var entry = new DirectoryEntry($"LDAP://CN={username},DC=example,DC=com");  // <-- SINK
```

### Vulnerable (Header in filter)
```csharp
string group = Request.Headers["X-Group"];
searcher.Filter = $"(memberOf=CN={group},OU=Groups,DC=example,DC=com)";
var results = searcher.FindAll();  // <-- SINK
```

### Vulnerable (SearchRequest with user input)
```csharp
string uid = Request.Query["uid"];
var searchRequest = new SearchRequest(
    baseDN,
    $"(uid={uid})",
    SearchScope.Subtree,
    null
);
connection.SendRequest(searchRequest);  // <-- SINK
```

### Safe (Escaped filter value)
```csharp
string username = EscapeLdapFilterValue(Request.QueryString["user"]);
searcher.Filter = $"(&(uid={username})(objectClass=user))";
var results = searcher.FindAll();  // SAFE
```

### Safe (Regex validation)
```csharp
string username = Request.Query["user"];
if (!Regex.IsMatch(username, @"^[a-zA-Z0-9_]+$"))
    return BadRequest("Invalid username");
searcher.Filter = $"(uid={username})";
var results = searcher.FindAll();  // SAFE - validated
```

### Safe (Allowlist validation)
```csharp
var allowedGroups = new[] { "admins", "users", "guests" };
string group = Request.Query["group"];
if (!allowedGroups.Contains(group))
    return BadRequest("Invalid group");
searcher.Filter = $"(memberOf=CN={group},OU=Groups,DC=example,DC=com)";
var results = searcher.FindAll();  // SAFE
```

### Safe (SeparateClassRequest.GetTheValue() - IMPORTANT)
```csharp
// SeparateClassRequest.GetTheValue() returns CONTROLLED values, NOT user input!
var scr = new SeparateClassRequest(Request);
var param = scr.GetTheValue("key");  // Returns controlled value (e.g., "admin"), NOT tainted!
searcher.Filter = $"(uid={param})";
var results = searcher.FindAll();  // SAFE - param is not user-controlled
```

**CRITICAL**: Do NOT report this pattern as LDAP injection. The `GetTheValue()` method returns safe, controlled values.

---

## LDAP Filter Escaping

Characters that need escaping in LDAP filters:
- `*` → `\2a`
- `(` → `\28`
- `)` → `\29`
- `\` → `\5c`
- NUL → `\00`

Example escape function:
```csharp
public static string EscapeLdapFilterValue(string value)
{
    return value
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00");
}
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
- For LDAP injection: the line where the LDAP query is executed with tainted input

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

Detects LDAP Injection (CWE-90) by tracing untrusted input concatenated into LDAP filters without proper escaping.
