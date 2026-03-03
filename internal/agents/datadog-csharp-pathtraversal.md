# C# User Prompt Template — Path Traversal

Evaluate the following C# code located in <path> and report ONLY Path Traversal vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```csharp
<code>
```

## Vulnerability to Find

Report where there are **Path Traversal** vulnerabilities as instructed.

This vulnerability is known as **CWE-22**.

<relatedFilesInformation>

---

## Context

**Language:** C#  
**Frameworks/Libraries:** <e.g., ASP.NET, ASP.NET Core, System.IO>  

**User-controlled sources (tainted inputs):**  
- `Request.QueryString["..."]`, `Request.Query["..."]`
- `Request.Form["..."]`
- `Request.Headers["..."]`
- `Request.Cookies["..."]` — direct cookie access
- Cookie iteration via foreach: `foreach (var cookie in Request.Cookies) { cookie.Value }` — cookie values through iteration
- `IRequestCookieCollection` iteration — cookie collection access
- MVC model binding (`[FromQuery]`, `[FromBody]`, `[FromForm]`)  
- File upload filenames (`IFormFile.FileName`)  

**File operation sinks:**  
- `File.ReadAllText(path)`, `File.ReadAllBytes(path)`, `File.ReadAllLines(path)`
- `File.WriteAllText(path, ...)`, `File.WriteAllBytes(path, ...)`
- `File.Open(path, ...)`, `File.OpenRead(path)`, `File.OpenWrite(path)`
- `File.Exists(path)`, `File.Delete(path)`
- `File.Copy(src, dst)`, `File.Move(src, dst)`
- `new FileStream(path, ...)`
- `new StreamReader(path)`, `new StreamWriter(path)`
- `Path.Combine(base, userpath)` followed by file operations (does NOT sanitize!)
- `Directory.GetFiles(path)`, `Directory.EnumerateFiles(path)`
- `Directory.CreateDirectory(path)`, `Directory.Delete(path)`
- `PhysicalFile(path)`, `File(path)` in controller actions

**FileInfo/DirectoryInfo sinks (IMPORTANT - often missed):**
- `new FileInfo(path)` — constructor with user-controlled path
- `fileInfo.Exists` — checking existence with tainted path
- `fileInfo.OpenRead()`, `fileInfo.OpenWrite()`, `fileInfo.Open()`
- `fileInfo.Delete()`, `fileInfo.CopyTo()`, `fileInfo.MoveTo()`
- `fileInfo.Create()`, `fileInfo.CreateText()`
- `new DirectoryInfo(path)` — constructor with user-controlled path
- `directoryInfo.GetFiles()`, `directoryInfo.GetDirectories()`

**Recognized sanitizers:**  
- `Path.GetFullPath()` with base directory validation  
- `Path.GetFileName()` to extract only filename  
- Allowlist validation of filenames  
- Rejection of ".." sequences  
- `StartsWith()` check after resolving full path

**NOT sanitizers (taint is MAINTAINED):**
- `HttpUtility.UrlDecode()` — URL decoding does NOT sanitize path traversal
- `WebUtility.UrlDecode()` — URL decoding does NOT sanitize
- Base64 encode/decode (`Convert.ToBase64String()` / `Convert.FromBase64String()`) — data transformation, taint preserved
- `Encoding.UTF8.GetBytes()` / `Encoding.UTF8.GetString()` — encoding conversion, taint preserved
- String concatenation, StringBuilder operations — taint flows through
- Dictionary/collection storage and retrieval — taint preserved

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report only Path Traversal vulnerabilities.  
2. Trigger if unvalidated user input is used to construct file paths.  
3. Avoid false positives when proper path validation is used.  
4. Report the **exact location of the sink** where the file operation occurs (e.g., `File.ReadAllText()`, `new FileStream()`), NOT the line where tainted data originates. You must specify: `startLine`, `endLine`, `startColumn`, and `endColumn`.  
5. Output must be valid JSON; if no issues found:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify user-controlled input.  
2. Check whether it flows into file path construction.  
3. Verify absence of path validation or sanitization.  
4. Report unsafe file operations with user-controlled paths.

---

## Patterns to Look For

### Vulnerable (Path.Combine with user input)
```csharp
string filename = Request.QueryString["file"];
string content = File.ReadAllText(Path.Combine("/var/data/", filename));  // <-- SINK
```

### Vulnerable (FileStream with user path)
```csharp
string path = Request.Form["path"];
using var stream = new FileStream(path, FileMode.Open);  // <-- SINK
```

### Vulnerable (File upload filename)
```csharp
var uploadedFile = Request.Form.Files[0];
string savePath = Path.Combine(uploadsDir, uploadedFile.FileName);
uploadedFile.CopyTo(new FileStream(savePath, FileMode.Create));  // <-- SINK
```

### Vulnerable (MVC PhysicalFile)
```csharp
public IActionResult Download(string file)
{
    var path = Path.Combine(_documentsRoot, file);
    return PhysicalFile(path, "application/octet-stream");  // <-- SINK
}
```

### Vulnerable (StreamReader)
```csharp
string logFile = Request.Query["log"];
using var reader = new StreamReader(logFile);  // <-- SINK
```

### Vulnerable (FileInfo with user input)
```csharp
string bar = Request.Query["file"];
FileInfo fileTarget = new FileInfo(Path.Combine(testfilesDir, bar));  // <-- SINK
if (fileTarget.Exists) { /* path traversal possible */ }
```

### Vulnerable (Cookie iteration to file path)
```csharp
string param = "default";
foreach (var cookie in Request.Cookies)
{
    if (cookie.Key.Equals("filename"))
    {
        param = HttpUtility.UrlDecode(cookie.Value);  // Still tainted!
        break;
    }
}
FileInfo fileTarget = new FileInfo(Path.Combine(testfilesDir, param));  // <-- SINK
```

### Vulnerable (Cookie with Base64 encode/decode - taint preserved)
```csharp
string param = "noCookieValueSupplied";
IRequestCookieCollection theCookies = Request.Cookies;
foreach (var theCookie in theCookies)
{
    if (theCookie.Key.Equals("BenchmarkTest00060"))
    {
        param = HttpUtility.UrlDecode(theCookie.Value, Encoding.UTF8);  // Tainted
        break;
    }
}
// Base64 encode/decode does NOT break taint flow
byte[] bytes = Encoding.UTF8.GetBytes(param);
string base64String = Convert.ToBase64String(bytes);
string bar = Encoding.UTF8.GetString(Convert.FromBase64String(base64String));  // Still tainted!

FileInfo fileTarget = new FileInfo(Path.Combine(testfilesDir, bar));  // <-- SINK
```

### Safe (GetFileName extracts only filename)
```csharp
string filename = Path.GetFileName(Request.QueryString["file"]);
string fullPath = Path.GetFullPath(Path.Combine("/var/data/", filename));
if (!fullPath.StartsWith("/var/data/"))
    throw new SecurityException();
string content = File.ReadAllText(fullPath);  // SAFE
```

### Safe (Allowlist validation)
```csharp
var allowedFiles = new[] { "readme.txt", "help.txt", "changelog.txt" };
string filename = Request.Query["file"];
if (!allowedFiles.Contains(filename))
    return BadRequest("Invalid file");
string content = File.ReadAllText(Path.Combine(docsDir, filename));  // SAFE
```

### Safe (Rejecting path traversal characters)
```csharp
string filename = Request.Query["file"];
if (filename.Contains("..") || Path.IsPathRooted(filename))
    return BadRequest("Invalid filename");
string content = File.ReadAllText(Path.Combine(baseDir, filename));  // SAFE
```

### Safe (Constant-returning method)
```csharp
// Even though 'Request' is tainted, GetTheValue() returns a hardcoded constant
var wrapper = new SeparateClassRequest(Request);
var filename = wrapper.GetTheValue("key");  // Returns "report.pdf" (constant), NOT tainted
string content = File.ReadAllText(Path.Combine(baseDir, filename));  // SAFE
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
- For path traversal: the line where the file operation occurs with tainted input

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

Detects Path Traversal (CWE-22) by tracing untrusted input used in file path construction without proper validation.
