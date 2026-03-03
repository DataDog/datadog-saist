# Python User Prompt Template — Path Traversal

Evaluate the following Python code located in <path> and report ONLY Path Traversal vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```python
<code>
```

## Vulnerability to Find

Report where there are **Path Traversal** vulnerabilities as instructed.

This vulnerability is known as **CWE-22**.

<relatedFilesInformation>

---

## ⚠️ CRITICAL: Recognize ALL User Input Sources

**You MUST detect vulnerabilities from ALL these input patterns:**

### 1. Cookie Access Pattern (VERY COMMON)
```python
# Flask
cookie_value = request.cookies.get("filename")
param = urllib.parse.unquote(cookie_value)  # URL decode does NOT sanitize!
# param is now user-controlled - if used in file path, REPORT IT
```

### 2. Headers Access Pattern
```python
# Flask
header_value = request.headers.get("X-Filename")
param = urllib.parse.unquote(header_value)  # URL decode does NOT sanitize!
# param is now user-controlled - if used in file path, REPORT IT
```

### 3. Form/Query Parameter Patterns
```python
param = request.args.get("file")      # TAINTED
param = request.form.get("file")      # TAINTED
param = request.json.get("file")      # TAINTED
```

---

## Context

**Language:** Python  
**Frameworks/Libraries:** <e.g., Flask, Django, FastAPI, os, pathlib>  

**What makes code vulnerable to Path Traversal (CWE-22):**  
User-controlled input is used to construct a file path that is then used in a file system operation, without proper validation. This allows attackers to use `../` sequences to access files outside the intended directory.

**Key detection rule:**  
Report when user input from HTTP request flows into ANY file system operation without path validation, AND the user input actually reaches the file operation (not replaced by a constant).

---

## User-Controlled Sources (ALL Must Be Tracked)

**Flask:**
- `request.args.get("...")` or `request.args["..."]`
- `request.form.get("...")` or `request.form["..."]`
- `request.values.get("...")` — combines args and form data
- `request.json.get("...")` or `request.json["..."]`
- `request.headers.get("...")` or `request.headers["..."]`
- `request.cookies.get("...")` or `request.cookies["..."]`
- `request.files["..."].filename`
- `request.data`
- `request.get_data()`

**Django:**
- `request.GET.get("...")` or `request.GET["..."]`
- `request.POST.get("...")` or `request.POST["..."]`
- `request.FILES["..."].name`
- `request.headers.get("...")` or `request.headers["..."]`
- `request.COOKIES.get("...")`
- `request.body`

**FastAPI:**
- Path parameters (function arguments)
- Query parameters (`Query(...)`)
- `UploadFile.filename`
- Header parameters (`Header(...)`)

**URL Decoding (still tainted):**
- `urllib.parse.unquote(...)` - does NOT sanitize
- `urllib.parse.quote(...)` - does NOT sanitize

**General:**
- `sys.argv` (command-line arguments)
- `os.environ.get("...")` (environment variables)

---

## File System Sinks (Report These)

**File Opening:**
- `open(path, ...)` 
- `io.open(path, ...)`
- `codecs.open(path, ...)`

**Path/OS Operations:**
- `os.path.exists(path)` — **reveals file existence information** (SINK!)
- `os.path.isfile(path)`, `os.path.isdir(path)` — reveal file/directory existence
- `os.path.join(base, userpath)` followed by file operations (join does NOT sanitize!)
- `os.open(path, ...)`
- `os.remove(path)`, `os.unlink(path)`
- `os.rename(src, dst)`
- `os.stat(path)`, `os.lstat(path)`
- `os.mkdir(path)`, `os.makedirs(path)`
- `os.listdir(path)`
- `os.walk(path)`
- `os.access(path, ...)`
- `os.getcwd()` + user path

**Pathlib Operations:**
- `Path(path).read_text()`, `Path(path).read_bytes()`
- `Path(path).write_text(...)`, `Path(path).write_bytes(...)`
- `Path(path).open(...)`
- `Path(path).unlink()`, `Path(path).rmdir()`
- `Path(path).exists()`, `Path(path).is_file()`
- `Path(base) / userpath` - division operator creates paths

**Shutil Operations:**
- `shutil.copy(src, dst)`, `shutil.copy2(src, dst)`
- `shutil.move(src, dst)`
- `shutil.rmtree(path)`
- `shutil.copyfile(src, dst)`

**Flask:**
- `send_file(path)`
- `send_from_directory(directory, filename)`

**FastAPI/Starlette:**
- `FileResponse(path)`

---

## Rules and Guidelines

1. Report when user input reaches ANY file system operation listed above.
2. Trace data flow through variables, function calls, and string operations.
3. `os.path.join()` does NOT sanitize paths - `../` still works.
4. **CRITICAL**: Verify that user-controlled data ACTUALLY flows to the sink. If a constant replaces the value, it's SAFE.
5. Report the **exact location of the sink** (the file operation), NOT the source.
6. You must specify: `startLine`, `endLine`, `startColumn`, and `endColumn`.
7. Output must be valid JSON; if no issues found, output exactly:
   ```
   NO VIOLATION AMIGO
   ```

---

## FALSE POSITIVE AVOIDANCE - Constant Propagation

When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Evaluation Process

1. Find user input sources (request.args, request.form, request.cookies, etc.).
2. Trace how the data flows through the code.
3. **VERIFY** the tainted data actually reaches the sink (not replaced by a constant).
4. Check for collection manipulations that might replace tainted data with safe data.
5. If user data reaches a file operation → REPORT the file operation line.

---

## Vulnerable Patterns — REPORT THESE

### Direct Flow

```python
# request.args to open() - VULNERABLE
filename = request.args.get("file")
with open(filename, "r") as f:  # REPORT THIS LINE
    content = f.read()
```

### Cookie Value to File Path

```python
# Cookie to file path - VULNERABLE
filename = request.cookies.get("filename")
with open(f"/uploads/{filename}", "rb") as f:  # REPORT THIS LINE
    return f.read()
```

### URL Decoding (Still Vulnerable)

```python
# URL decoding does NOT sanitize - VULNERABLE
cookie_value = request.cookies.get("filename")
param = urllib.parse.unquote(cookie_value)  # Still tainted!
with open(TESTFILES_DIR + param, "rb") as f:  # REPORT THIS LINE
    return f.read()
```

### os.path.join Does NOT Sanitize

```python
# os.path.join does NOT prevent path traversal - VULNERABLE
doc = request.form.get("doc")
path = os.path.join("./documents", doc)
return send_file(path)  # REPORT THIS LINE - ../still works!
```

### Pathlib Path Operations

```python
# Path operations with user input - VULNERABLE
name = request.args.get("name")
content = (Path("/data") / name).read_text()  # REPORT THIS LINE
```

### Flask send_file

```python
# send_file with user input - VULNERABLE
filename = request.args.get("file")
return send_file(f"/public/{filename}")  # REPORT THIS LINE
```

### Conditional with Integer Division (Always True)

```python
# Conditional logic that always evaluates to True - VULNERABLE
param = request.values.get("file", "")
num = 196
# (500 // 42) + 196 = 11 + 196 = 207 > 200 is True
if (500 // 42) + num > 200:
    bar = param  # Taint flows through!
else:
    bar = "safe"

file_exists = os.path.exists(bar)  # REPORT THIS LINE - reveals file existence
```

### os.path.exists() Information Disclosure

```python
# os.path.exists reveals file system information - VULNERABLE
filename = request.args.get("file")
if os.path.exists(filename):  # REPORT THIS LINE
    return "File found"
else:
    return "File not found"
```

---

## Safe Patterns — DO NOT REPORT

### Constant Replaces User Input

```python
# Value overwritten - SAFE
param = request.args.get("file")
filename = "safe_file.txt"  # param is NOT used
open(filename)  # SAFE
```

### werkzeug secure_filename

```python
# secure_filename - SAFE
from werkzeug.utils import secure_filename

filename = secure_filename(request.args.get("file"))
filepath = os.path.join(base_dir, filename)
with open(filepath, "r") as f:  # SAFE
    content = f.read()
```

### Path Validation with resolve

```python
# Path validation - SAFE
filename = request.args.get("file")
base = Path("/var/data").resolve()
requested = (base / filename).resolve()
if not str(requested).startswith(str(base)):
    abort(403)
content = requested.read_text()  # SAFE - validated
```

### os.path.basename

```python
# os.path.basename strips directory - SAFE
filename = request.args.get("file")
safe_name = os.path.basename(filename)
open(os.path.join(base_dir, safe_name))  # SAFE
```

### Constant-returning method

```python
# Even though 'request' is tainted, get_the_value() returns a hardcoded constant
wrapper = SeparateClassRequest(request)
param = wrapper.get_the_value("key")  # Returns "bar" (constant), NOT tainted
open(TESTFILES_DIR + param)  # SAFE - param is not user-controlled
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

Detects Path Traversal (CWE-22) when user input from HTTP requests flows into file system operations. Pay careful attention to:
1. ALL source patterns (cookies, headers, form data, query params)
2. Collection manipulations that might substitute safe values
3. `os.path.join()` does NOT prevent path traversal attacks
Report the file operation (sink) line only when tainted data ACTUALLY reaches it.
