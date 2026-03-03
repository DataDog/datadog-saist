# C# User Prompt Template — Command Injection

Evaluate the following C# code located in <path> and report ONLY Command Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```csharp
<code>
```

## Vulnerability to Find

Report where there are **Command Injection** vulnerabilities as instructed.

This vulnerability is known as **CWE-78** (also referenced as CWE-77).

<relatedFilesInformation>

---

## Context

**Language:** C#  
**Frameworks/Libraries:** <e.g., ASP.NET, ASP.NET Core>  

**User-controlled sources (tainted inputs):**  
- `Request.QueryString["..."]`, `Request.Query["..."]`
- `Request.Form["..."]`
- `Request.Headers["..."]`
- `Request.Cookies["..."]`
- User inputs in MVC controllers (`[FromQuery]`, `[FromBody]`, `[FromForm]`)  
- Command-line arguments or environment variables (`Environment.GetEnvironmentVariable`, `args[]`)  

**Command execution sinks:**  
- `Process.Start(filename)`, `Process.Start(filename, arguments)` — static method
- `Process.Start(ProcessStartInfo)` — static method with StartInfo
- `process.Start()` — **instance method** on Process object
- `ProcessStartInfo.FileName` with user input
- `ProcessStartInfo.Arguments` with user input
- `p.StartInfo.Arguments = userInput` — assigning tainted arguments
- `Process.Start("cmd.exe", "/c " + userInput)` — shell execution
- `Process.Start("powershell.exe", "-Command " + userInput)`
- `Process.Start("bash", "-c " + userInput)`

**Recognized sanitizers or validators (consider safe):**  
- Allowlist enforcement of executable names and arguments  
- Rejection or escaping of shell metacharacters (`;`, `|`, `&`, `>`, `<`, backticks, quotes)  
- Use of `ArgumentList` rather than shell command strings  
- Input validation ensuring only known commands or parameters are passed  

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report **only Command Injection** vulnerabilities.  
2. Report if **user-controlled data** reaches a command execution API without validation or sanitization.  
3. Avoid false positives where sanitization or allowlisting is clearly applied.  
4. Report the **exact location of the sink** where the command is executed (e.g., `Process.Start()`, `process.Start()`), NOT the line where tainted data originates or any intermediate line. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. Output must be valid JSON; if no issues found, output exactly:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify tainted input sources.  
2. Track data propagation to command execution sinks.  
3. Check if validation or sanitization occurs before execution.  
4. Report unvalidated use of user input in commands.  

---

## Patterns to Look For

### Vulnerable (cmd.exe with user input)
```csharp
string userInput = Request.QueryString["cmd"];
Process.Start("cmd.exe", "/c " + userInput);  // <-- SINK
```

### Vulnerable (ProcessStartInfo with user Arguments)
```csharp
string param = Request.Headers["X-Command"];
var psi = new ProcessStartInfo("bash", "-c echo " + param);
Process.Start(psi);  // <-- SINK
```

### Vulnerable (Direct Process.Start with user input)
```csharp
string program = Request.Form["program"];
Process.Start(program);  // <-- SINK: User controls which program runs
```

### Vulnerable (PowerShell execution)
```csharp
string script = Request.Query["script"];
Process.Start("powershell.exe", "-Command " + script);  // <-- SINK
```

### Vulnerable (FileName from user)
```csharp
var psi = new ProcessStartInfo();
psi.FileName = Request.QueryString["exe"];  // User controls executable
psi.Arguments = "-v";
Process.Start(psi);  // <-- SINK
```

### Vulnerable (String interpolation in arguments)
```csharp
string filename = Request.Form["file"];
Process.Start("cat", $"/data/{filename}");  // <-- SINK: Path injection possible
```

### Vulnerable (Process instance with Start method)
```csharp
string bar = Request.Headers["BenchmarkTest00302"];
Process p = new Process();
p.StartInfo.FileName = "echo";
p.StartInfo.Arguments = bar;  // User controls arguments
p.Start();  // <-- SINK: command injection via instance Start()
```

### Vulnerable (Ternary conditional with arithmetic - always tainted)
```csharp
string param = Request.Headers["X-Input"];
param = WebUtility.UrlDecode(param);  // URL decode does NOT sanitize
int num = 106;
// (7 * 42) - 106 = 188, which is NOT > 200, so bar = param (tainted!)
string bar = (7 * 42) - num > 200 ? "safe" : param;  // Evaluates to param!
Process p = new Process();
p.StartInfo.FileName = "echo";
p.StartInfo.Arguments = bar;  // Still tainted from conditional
p.Start();  // <-- SINK
```

### Vulnerable (ProcessStartInfo.Arguments assignment)
```csharp
string param = Request.Query["input"];
var psi = new ProcessStartInfo();
psi.FileName = "cmd";
psi.Arguments = param;  // <-- Tainted arguments
Process.Start(psi);  // <-- SINK
```

### Safe (ArgumentList instead of string)
```csharp
string service = SanitizeInput(Request.QueryString["service"]);
var psi = new ProcessStartInfo("systemctl");
psi.ArgumentList.Add("status");
psi.ArgumentList.Add(service);
Process.Start(psi);  // SAFE - using ArgumentList
```

### Safe (Hardcoded command)
```csharp
var psi = new ProcessStartInfo("ls");
psi.ArgumentList.Add("-l");
psi.ArgumentList.Add("/safe/dir");
Process.Start(psi);  // SAFE - no user input
```

### Safe (Allowlisted commands)
```csharp
var allowedCommands = new[] { "status", "restart", "stop" };
string cmd = Request.Query["action"];
if (!allowedCommands.Contains(cmd))
    return BadRequest("Invalid action");
Process.Start("systemctl", cmd + " myservice");  // SAFE - allowlisted
```

### Safe (Constant-returning method)
```csharp
// Even though 'Request' is tainted, GetTheValue() returns a hardcoded constant
var wrapper = new SeparateClassRequest(Request);
var cmd = wrapper.GetTheValue("key");  // Returns "status" (constant), NOT tainted
Process.Start("systemctl", cmd + " nginx");  // SAFE - cmd is not user-controlled
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
- For command injection: the line where `Process.Start()` is called with tainted input

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

Detects Command Injection (CWE-78) when untrusted data reaches OS command execution APIs without sanitization or validation.
