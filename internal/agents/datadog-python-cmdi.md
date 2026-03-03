# Python User Prompt Template — Command Injection

Evaluate the following Python code located in <path> and report ONLY Command Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```python
<code>
```

## Vulnerability to Find

Report where there are **Command Injection** vulnerabilities as instructed.

This vulnerability is known as **CWE-78**.

<relatedFilesInformation>

---

## Context

**Language:** Python  
**Frameworks/Libraries:** <e.g., Flask, Django, FastAPI, subprocess, os>  
**User-controlled sources (tainted inputs):**  
- Web request inputs (`request.args`, `request.form`, `request.get_json()`, Django `request.GET/POST`)  
- HTTP headers (`request.headers.get()`)
- Environment variables (`os.environ.get`) and CLI args (`sys.argv`)  
- Data loaded from files, headers, cookies, query strings, or user-controlled config

**Command execution sinks (ordered by frequency):**  
- `subprocess.run(cmd, shell=True)` — **most common sink**, CRITICAL with shell=True
- `subprocess.call(cmd, shell=True)` — simple execution with shell
- `subprocess.Popen(cmd, shell=True)` — process creation with shell
- `subprocess.check_output(cmd, shell=True)` — output capture with shell
- `os.system(cmd)` — **always shell execution** (always vulnerable with tainted input)
- `os.popen(cmd)` — opens pipe to shell command
- `exec(code)` — **code execution sink** - executes arbitrary Python code
- `eval(expr)` — **expression evaluation sink** - evaluates arbitrary Python expressions
- `commands.getoutput(cmd)` — Python 2 deprecated, but still used
- `pexpect.spawn` / `ptyprocess` with interpolated commands  
- Any shell handoff (`/bin/sh -c`, `cmd.exe /c`) via concatenated strings

**CRITICAL: `shell=True` makes string commands vulnerable**
- When `shell=True`, the command is passed to the shell for parsing
- User input in the command string can include shell metacharacters (`;`, `|`, `&&`, etc.)
- Even without `shell=True`, argument injection is possible if user controls arguments

**Recognized sanitizers/validators (safe when effectively applied before the sink):**  
- Avoiding `shell=True`; pass **argv list** (e.g., `subprocess.run(["ls", "-l", path])`)  
- Strict allowlists for executable and arguments (enums, exact matches)  
- Rejection or removal of shell metacharacters (`|`, `;`, `&`, `>`, `<`, `\``, `"`, `'`)  
- `shlex.split` for parsing trusted command strings; `shlex.quote` for **last-resort** quoting of validated fragments

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data

---

## Rules and Guidelines

1. Report **only** Command Injection vulnerabilities.  
2. Report a finding only if user-controlled data can reach a command execution sink **without effective validation/sanitization**.  
3. Avoid false positives; if inputs are validated or `shell=True` is not used and argv is safe, do not report.  
4. Report the **exact location of the sink** where the command is executed (e.g., `subprocess.run()`, `subprocess.Popen()`, `os.system()`), NOT the line where tainted data originates or any intermediate line. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. Output must be **valid JSON** per system schema. If no issues, output exactly:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify user-controlled inputs and follow their flow.  
2. Check how the command string/argv is built.  
3. Determine whether validation/sanitization occurs before the sink.  
4. If tainted data reaches a sink, report the sink's line and explain why validation is insufficient/absent.

---

## Patterns to Look For

### Vulnerable (subprocess.run with shell=True)
```python
param = request.args.get('cmd')
subprocess.run(param, shell=True)  # <-- SINK: CRITICAL - shell=True + user input
```

### Vulnerable (subprocess.Popen with shell=True and f-string)
```python
param = request.args.get('file')
result = subprocess.Popen(f"ls {param}", shell=True, stdout=subprocess.PIPE)  # <-- SINK
```

### Vulnerable (subprocess.check_output with shell=True)
```python
cmd = f"ping -c 1 {request.args.get('host')}"
subprocess.check_output(cmd, shell=True)  # <-- SINK
```

### Vulnerable (os.system - always shell execution)
```python
filename = request.form.get('file')
os.system(f"cat {filename}")  # <-- SINK: os.system always uses shell
```

### Vulnerable (Shell handoff via list)
```python
target = request.json["name"]
subprocess.run(["/bin/sh", "-c", "cat " + target])  # <-- SINK: shell via -c
```

### Vulnerable (exec() with user input)
```python
code = request.form.get('code')
exec(code)  # <-- SINK: executes arbitrary Python code
```

### Vulnerable (eval() with user input)
```python
expr = request.args.get('expr')
result = eval(expr)  # <-- SINK: evaluates arbitrary Python expressions
```

### Safe (List-based without shell)
```python
host = request.args.get("host", "")
if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
    abort(400)
subprocess.run(["ping", "-c", "1", host], check=True)  # no shell - SAFE
```

### Safe (Allowlist validation)
```python
arg = allowlisted_arg_from_user(user_arg)
subprocess.run(["systemctl", "status", arg], check=True)  # Validated - SAFE
```

### Safe (shlex.quote for escaping)
```python
import shlex
subprocess.run(f"echo {shlex.quote(user_input)}", shell=True)  # Escaped - SAFE
```

### Safe (shell=False with list args)
```python
subprocess.run(["ls", user_dir], shell=False)  # No shell - SAFE
subprocess.run(["echo", user_input])  # List args without shell - SAFE
```

### Safe (Constant-returning method)
```python
# Even though 'request' is tainted, get_the_value() returns a hardcoded constant
wrapper = SeparateClassRequest(request)
param = wrapper.get_the_value("key")  # Returns "bar" (constant), NOT tainted
subprocess.run(f"echo {param}", shell=True)  # SAFE - param is not user-controlled
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

Detects Command Injection (CWE-78) when untrusted input reaches OS command execution without safe argv construction or validation.
