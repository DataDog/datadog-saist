# Java User Prompt Template — Command Injection

Evaluate the following Java code located in <path> and report ONLY Command Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```java
<code>
```

## Vulnerability to Find

Report where there are **Command Injection** vulnerabilities as instructed.

This vulnerability is known as **CWE-77**.

<relatedFilesInformation>

---

## Context

**Language:** Java  
**Frameworks/Libraries:** <e.g., Java Servlet API, Spring, Jakarta EE>  
**User-controlled sources (tainted inputs):**  
- `HttpServletRequest.getParameter`, `getHeader`, `getQueryString`, `getCookies`  
- `HttpServletRequest.getHeaders()` returning `Enumeration<String>`, then `headers.nextElement()`  
- User inputs in JSP pages (`<%= request.getParameter() %>`)  
- Command-line arguments or environment variables (`System.getenv`, `args[]`)  
- `java.net.URLDecoder.decode()` - this does NOT sanitize, it only decodes URL encoding  

**Command execution sinks:**  
- `Runtime.getRuntime().exec(String command)` - single string command
- `Runtime.getRuntime().exec(String command, String[] envp)` - **IMPORTANT: the envp parameter is ALSO a sink** when it contains tainted data
- `Runtime.getRuntime().exec(String command, String[] envp, File dir)` - both command AND envp are sinks
- `Runtime.getRuntime().exec(String[] cmdarray)` - command array
- `Runtime.getRuntime().exec(String[] cmdarray, String[] envp)` - **envp is a sink**
- `Runtime.getRuntime().exec(String[] cmdarray, String[] envp, File dir)` - **envp is a sink**
- `new ProcessBuilder()` or `ProcessBuilder.command()`  
- `ProcessBuilder.start()` when command list contains tainted data  
- `ProcessBuilder.environment().put()` when setting environment variables with tainted data
- Any element of `List<String>` passed to `ProcessBuilder.command()` that contains concatenated user input  
- Any system-level execution invoking the OS shell

**Recognized sanitizers or validators (consider safe):**  
- Allowlist enforcement of executable names and arguments  
- Rejection or escaping of shell metacharacters (`;`, `|`, `&`, `>`, `<`, backticks, quotes)  
- Use of argument arrays rather than shell commands  
- Input validation ensuring only known commands or parameters are passed

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Example: `new SomeClass(taintedRequest).getTheValue("key")` returning `"bar"` - the return is constant, NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data  

---

## Rules and Guidelines

1. Report **only Command Injection** vulnerabilities.  
2. Report if **user-controlled data** reaches a command execution API without validation or sanitization.  
3. Avoid false positives where sanitization or allowlisting is clearly applied.  
4. Report the **exact location of the sink** where the command is executed (e.g., `Runtime.exec()`, `ProcessBuilder.start()`), NOT the line where tainted data originates or any intermediate line. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
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

### Vulnerable (Direct Runtime.exec)
```java
String userInput = request.getParameter("cmd");
Runtime.getRuntime().exec("sh -c " + userInput);  // <-- SINK
```

### Vulnerable (ProcessBuilder with direct concatenation)
```java
String param = request.getHeader("X-Command");
new ProcessBuilder("bash", "-c", "echo " + param).start();  // <-- SINK
```

### Vulnerable (List-based ProcessBuilder - COMMON PATTERN)
```java
// Tainted input flows through List<String> - THIS IS VULNERABLE
String userInput = request.getParameter("cmd");
java.util.List<String> argList = new java.util.ArrayList<String>();
argList.add("sh");
argList.add("-c");
argList.add("echo " + userInput);  // <-- taint enters list here via concatenation
ProcessBuilder pb = new ProcessBuilder();
pb.command(argList);
Process p = pb.start();  // <-- SINK: report this line
```

### Vulnerable (Header input with URL decoding)
```java
String param = "";
if (request.getHeader("Command") != null) {
    param = request.getHeader("Command");
}
param = java.net.URLDecoder.decode(param, "UTF-8");  // URLDecoder does NOT sanitize!
java.util.List<String> args = new java.util.ArrayList<>();
args.add("cmd.exe");
args.add("/c");
args.add("echo " + param);
ProcessBuilder pb = new ProcessBuilder();
pb.command(args);
pb.start();  // <-- SINK
```

### Vulnerable (Enumeration-based header retrieval)
```java
java.util.Enumeration<String> headers = request.getHeaders("X-Cmd");
if (headers != null && headers.hasMoreElements()) {
    String param = headers.nextElement();
    Runtime.getRuntime().exec("cmd /c " + param);  // <-- SINK
}
```

### Vulnerable (envp parameter - CRITICAL PATTERN)
```java
// The second parameter (envp) to Runtime.exec() is ALSO a command injection sink!
String userEnv = request.getParameter("env");
String[] envp = new String[] { "PATH=/usr/bin", "USER=" + userEnv };  // tainted envp
Runtime.getRuntime().exec("ls", envp);  // <-- SINK: envp contains tainted data
```

```java
// Three-parameter exec with tainted envp
String param = request.getHeader("X-Env");
String[] cmd = new String[] { "ls", "-la" };
String[] envp = new String[] { param };  // tainted
Runtime.getRuntime().exec(cmd, envp, new File("/tmp"));  // <-- SINK
```

### Vulnerable (ProcessBuilder environment)
```java
String userPath = request.getParameter("path");
ProcessBuilder pb = new ProcessBuilder("ls");
pb.environment().put("PATH", userPath);  // tainted environment variable
pb.start();  // <-- SINK
```

### Safe
```java
String service = sanitizeInput(request.getParameter("service"));
new ProcessBuilder("systemctl", "status", service).start();
```

```java
// Static command array with no user input
String[] cmd = {"ls", "-l", "/safe/dir"};
Runtime.getRuntime().exec(cmd);
```

```java
// Allowlist validation before execution
String cmd = request.getParameter("cmd");
if (ALLOWED_COMMANDS.contains(cmd)) {
    new ProcessBuilder(cmd).start();
}
```

```java
// SAFE: Constant-returning method breaks taint flow
// Even though 'request' is tainted, getTheValue() returns a hardcoded constant
SeparateClassRequest scr = new SeparateClassRequest(request);
String param = scr.getTheValue("key");  // Returns "bar" (constant), NOT tainted
Runtime.getRuntime().exec(param);  // SAFE - param is not user-controlled

// In SeparateClassRequest.java:
// public String getTheValue(String key) {
//     return "bar";  // Always returns constant, ignores constructor parameter
// }
```

```java
// SAFE: Method returns constant regardless of tainted object construction
TaintedWrapper wrapper = new TaintedWrapper(request.getParameter("input"));
String value = wrapper.getConstantValue();  // Returns static string
new ProcessBuilder("echo", value).start();  // SAFE
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
- For command injection: the line where the command is executed with tainted input

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

Detects Command Injection (CWE-77) when untrusted data reaches OS command execution APIs without sanitization or validation.
