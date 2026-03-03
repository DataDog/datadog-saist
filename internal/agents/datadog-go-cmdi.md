# Go User Prompt Template — Command Injection

Evaluate the following Go code located in <path>:

```go
<code>
```

## Vulnerability to find

Report where there are Command injections as instructed. If you are unsure about the validity of a result do NOT report it.

This vulnerability is known as **CWE-78**.

<relatedFilesInformation>

---

## Context

**Language:** Go  
**Frameworks/Libraries:** <e.g., net/http, os/exec, syscall, cgo>  

**User-controlled sources (tainted inputs):**  
- HTTP inputs (e.g., `r.URL.Query().Get`, `r.FormValue`, JSON body fields)  
- Headers, cookies, path params, uploaded file names/paths  
- Environment variables (`os.Getenv`) and CLI args (`os.Args`)  
- Any content read from user-writable files, sockets, or external services

**Command execution sinks (ordered by frequency):**  
- `exec.Command(name, args...)` — **most common sink**
- `exec.CommandContext(ctx, name, args...)` — context-aware command
- `os.StartProcess(name, args, attr)` — low-level process start
- `syscall.Exec(path, args, env)` — direct syscall
- Shell invocation patterns:
  - `exec.Command("sh", "-c", userCommand)` — **CRITICAL**
  - `exec.Command("bash", "-c", userCommand)` — **CRITICAL**
  - `exec.Command("cmd", "/c", userCommand)` — Windows shell
- Execution methods on cmd:
  - `cmd.Run()` — runs and waits
  - `cmd.CombinedOutput()` — runs and captures output
  - `cmd.Output()` — runs and captures stdout
  - `cmd.Start()` — starts without waiting
- `C.system` via cgo or other native process-launch APIs

**Recognized sanitizers/validators (treat as safe when effectively applied before the sink):**  
- Strict allowlists for executable and arguments (fixed binary + enumerated args)  
- Rejection/removal of shell metacharacters: `|`, `;`, `&`, `>`, `<`, backticks, quotes, `$()`, `&&`, `||`  
- Safe argv construction with `exec.Command(name, arg1, arg2, ...)` (no shell) using validated values  
- Path validation: `filepath.Clean`, enforced base directory, and allowlisted filenames  
- Early returns on invalid inputs and explicit error handling

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a struct is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data

## Rules and Guidelines

1. You must only report command injection.
2. Only command injection and no other issues are reported.
3. If you think it may be a false positive, do not report it. Be accurate.
4. Report the **exact location of the sink** where the command is executed (e.g., `exec.Command()`, `cmd.CombinedOutput()`, `cmd.Run()`), NOT the line where tainted data originates or any intermediate line. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.
5. Try as much as possible to avoid false positives.
6. You should see artifacts that set up a command to execute.
7. You must return a valid JSON output (see JSON format below).
8. If there are **no vulnerabilities**, output:
   ```
   NO VIOLATION AMIGO
   ```

## Evaluation process

1. Look at the code.
2. Identify user-controlled data (from HTTP, CLI args, env vars, etc.).
3. If a function call with user data looks like a command injection, report it.
4. Report the line where you see the command injection, the closest to the actual command execution.

## Patterns to look for

### Vulnerable (Shell invocation with user input - CRITICAL)
```go
param := r.URL.Query().Get("parameter")
cmd := exec.Command("sh", "-c", "cat "+param)  // <-- SINK: shell with user input
output, err := cmd.CombinedOutput()
```

### Vulnerable (Argument injection)
```go
param := r.URL.Query().Get("file")
cmd := exec.Command("cat", param)  // <-- SINK: argument injection
out, _ := cmd.CombinedOutput()
```

### Vulnerable (cmd.Run with tainted argument)
```go
filename := r.FormValue("name")
cmd := exec.Command("ls", "-la", filename)
cmd.Run()  // <-- SINK
```

### Vulnerable (cmd.Output with tainted command)
```go
script := r.URL.Query().Get("script")
cmd := exec.Command("bash", script)
cmd.Output()  // <-- SINK
```

### Vulnerable (User-controlled command name)
```go
userProgram := r.URL.Query().Get("program")
cmd := exec.Command(userProgram)  // <-- SINK: user controls program name
cmd.Run()
```

### Vulnerable (User-controlled arguments spread)
```go
userArgs := strings.Split(r.FormValue("args"), " ")
cmd := exec.Command(program, userArgs...)  // <-- SINK: user controls all args
cmd.Run()
```

### Vulnerable (Command built from user input)
```go
cmdStr := "ls " + userDir
exec.Command("sh", "-c", cmdStr)  // <-- SINK: user input in shell command
```

### Safe (Validated input)
```go
parameter := r.URL.Query().Get("parameter")

if !isSafe(parameter) {
    http.Error(w, "Invalid parameter", http.StatusBadRequest)
    return
}

cmd := exec.Command("sh", "-c", "cat "+parameter)  // Validated before use - SAFE
output, err := cmd.CombinedOutput()
```

### Safe (No user input)
```go
cmd := exec.Command("ls", "-l", "/")  // Static command - SAFE
output, err := cmd.Output()
```

### Safe (Path validation)
```go
err := checkPath(path)

if err != nil {
    http.Error(w, "invalid parameter", http.StatusInternalServerError)
    return
}

cmd := exec.Command("ls", "-l", path)  // Validated - SAFE
output, err := cmd.Output()
```

### Safe (Sanitized input)
```go
safeInput := sanitizeData(input)
cmd := exec.Command("echo", "Message:", safeInput)  // Sanitized - SAFE
output, err := cmd.Output()
```

### Safe (Constant-returning method)
```go
// Even though 'r' is tainted, getTheValue() returns a hardcoded constant
scr := NewSeparateClassRequest(r)
param := scr.GetTheValue("key")  // Returns "bar" (constant), NOT tainted
cmd := exec.Command("echo", param)
cmd.Run()  // SAFE - param is not user-controlled
```

## Data Sanitization

If the data is checked or sanitized, this is not an injection and no vulnerability should be reported.
Sanitizing the data means removing any potential character or elements that are injected and run unexpected commands.

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

Detects **Command Injection (CWE-78)** vulnerabilities in Go code by tracking untrusted data flow into command execution functions without proper sanitization or validation.
