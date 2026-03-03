# Go User Prompt Template — Path Traversal

Evaluate the following Go code located in `<path>`:

```go
<code>
```

## Vulnerability to Find

Report where there are **Path Traversal** vulnerabilities as instructed. If you are unsure about the validity of a result do NOT report it.

This vulnerability is known as **CWE-22**.

<relatedFilesInformation>

---

## ⚠️ CRITICAL: Recognize ALL User Input Sources

**You MUST detect vulnerabilities from ALL these input patterns:**

### 1. Cookie Access Pattern (VERY COMMON)
```go
cookie, err := r.Cookie("filename")
if err == nil {
    param, _ := url.QueryUnescape(cookie.Value)  // URL decode does NOT sanitize!
    // param is now user-controlled - if used in file path, REPORT IT
}
```

### 2. Cookie Iteration Pattern
```go
var param string
for _, cookie := range r.Cookies() {
    if cookie.Name == "filename" {
        param, _ = url.QueryUnescape(cookie.Value)  // TAINTED!
        break
    }
}
// param is now user-controlled - if used in file path, REPORT IT
```

### 3. Header Access Pattern
```go
headerValue := r.Header.Get("X-Filename")
param, _ := url.QueryUnescape(headerValue)  // URL decode does NOT sanitize!
// param is now user-controlled - if used in file path, REPORT IT
```

### 4. Simple Query/Form Patterns
```go
param := r.URL.Query().Get("file")   // TAINTED
param := r.FormValue("file")          // TAINTED
```

---

## Context

**Language:** Go  
**Frameworks/Libraries:** <e.g., net/http, os, io/ioutil, path/filepath>  

**What makes code vulnerable to Path Traversal (CWE-22):**  
User-controlled input is used to construct a file path that is then used in a file system operation, without proper validation. This allows attackers to use `../` sequences to access files outside the intended directory.

**Key detection rule:**  
Report when user input from HTTP request flows into ANY file system operation without path validation, AND the user input actually reaches the file operation (not replaced by a constant).

---

## User-Controlled Sources (ALL Must Be Tracked)

**Query Parameters:**
- `r.URL.Query().Get("...")`
- `r.URL.Query()["..."]` (returns []string, access via [0])
- `r.FormValue("...")`
- `r.PostFormValue("...")`
- `r.Form.Get("...")` or `r.Form["..."]`

**Path and URL:**
- `r.URL.Path`
- `r.URL.RawPath`
- `mux.Vars(r)["..."]` (gorilla/mux path variables)
- `chi.URLParam(r, "...")` (chi router)

**Headers:**
- `r.Header.Get("...")`
- `r.Header["..."]` (returns []string)

**Cookies (ANY of these patterns):**
- `r.Cookie("...")` returns `(*http.Cookie, error)`, then `cookie.Value`
- `r.Cookies()` returns `[]*http.Cookie`, iterate to get values
- Direct field access: `cookie.Value`

**Request Body:**
- `r.Body` (parsed JSON/form data)
- `json.Unmarshal(...)` from request body
- `r.MultipartReader()` for file uploads

**URL Decoding (still tainted):**
- `url.QueryUnescape(...)` - does NOT sanitize
- `url.PathUnescape(...)` - does NOT sanitize

**General:**
- `os.Getenv("...")` (environment variables)
- `os.Args` (command-line arguments)

---

## File System Sinks (Report These)

**File Opening:**
- `os.Open(path)`
- `os.OpenFile(path, ...)`
- `os.Create(path)`

**File Reading:**
- `os.ReadFile(path)` 
- `ioutil.ReadFile(path)` (deprecated but still used)

**File Writing:**
- `os.WriteFile(path, ...)`
- `ioutil.WriteFile(path, ...)` (deprecated but still used)

**File Operations:**
- `os.Remove(path)`, `os.RemoveAll(path)`
- `os.Rename(oldpath, newpath)`
- `os.Stat(path)`, `os.Lstat(path)`
- `os.Mkdir(path, ...)`, `os.MkdirAll(path, ...)`
- `os.Chmod(path, ...)`, `os.Chown(path, ...)`
- `os.Link(...)`, `os.Symlink(...)`
- `os.Readlink(path)`

**HTTP File Serving:**
- `http.ServeFile(w, r, path)`
- `http.FileServer(http.Dir(path))`
- `http.ServeContent(...)`

**IO Operations:**
- `io.Copy(dst, os.Open(path))`
- `bufio.NewReader(os.Open(path))`
- `bufio.NewScanner(os.Open(path))`

**Path Construction (report when result used in file ops):**
- `filepath.Join(base, userpath)` - does NOT sanitize!
- `path.Join(base, userpath)` - does NOT sanitize!
- String concatenation: `baseDir + userpath`
- `fmt.Sprintf(...)` with user path

---

## Rules and Guidelines

1. Report when user input reaches ANY file system operation listed above.
2. Trace data flow through variables, method calls, and string concatenations.
3. `filepath.Join()` does NOT sanitize paths - `../` still works after join.
4. **CRITICAL**: Verify that user-controlled data ACTUALLY flows to the sink. If a constant replaces the value, it's SAFE.
5. Report the **exact location of the sink** (the file operation), NOT the source.
6. You must specify: `startLine`, `endLine`, `startColumn`, and `endColumn`.
7. If you think it may be a false positive, **do not report it**.
8. Output must be valid JSON; if no issues found, output exactly:
   ```
   NO VIOLATION AMIGO
   ```

---

## FALSE POSITIVE AVOIDANCE - Constant Propagation

When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a struct is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Evaluation Process

1. Find user input sources (Query().Get, FormValue, Header.Get, Cookie, etc.).
2. Trace how the data flows through the code.
3. **VERIFY** the tainted data actually reaches the sink (not replaced by a constant).
4. Check for collection manipulations that might replace tainted data with safe data.
5. If user data reaches a file operation → REPORT the file operation line.

---

## Vulnerable Patterns — REPORT THESE

### Direct Flow

```go
// Query parameter to os.ReadFile - VULNERABLE
filename := r.URL.Query().Get("file")
data, err := os.ReadFile(filename)  // REPORT THIS LINE
```

### Cookie Value to File Path

```go
// Cookie value to file path - VULNERABLE
cookie, err := r.Cookie("filename")
if err == nil {
    // URL decode the cookie value
    param, _ := url.QueryUnescape(cookie.Value)  // Still tainted!
    file, err := os.Open(testFilesDir + param)  // REPORT THIS LINE
}
```

### Cookie Iteration

```go
// Iterating through cookies - VULNERABLE
var param string
for _, cookie := range r.Cookies() {
    if cookie.Name == "filename" {
        param, _ = url.QueryUnescape(cookie.Value)  // Tainted!
        break
    }
}
os.Open(testFilesDir + param)  // REPORT THIS LINE
```

### Header Value

```go
// Header to file operation - VULNERABLE
name := r.Header.Get("X-Filename")
data, _ := os.ReadFile("/uploads/" + name)  // REPORT THIS LINE
```

### filepath.Join Does NOT Sanitize

```go
// filepath.Join does NOT prevent path traversal - VULNERABLE
name := r.URL.Query().Get("file")
fullPath := filepath.Join("/uploads", name)
os.Open(fullPath)  // REPORT THIS LINE - ../still works!
```

### String Concatenation

```go
// Direct concatenation - VULNERABLE
param := r.FormValue("doc")
fileName := testFilesDir + param
os.Create(fileName)  // REPORT THIS LINE
```

### HTTP File Serving

```go
// http.ServeFile with user input - VULNERABLE
filename := r.URL.Query().Get("file")
http.ServeFile(w, r, "/public/"+filename)  // REPORT THIS LINE
```

---

## Safe Patterns — DO NOT REPORT

### Constant Replaces User Input

```go
// Value overwritten - SAFE
param := r.URL.Query().Get("file")
filename := "safe_file.txt"  // param is NOT used
os.ReadFile(filename)  // SAFE
```

### filepath.Clean + Prefix Check

```go
// filepath.Clean + prefix check - SAFE
filename := r.URL.Query().Get("file")
cleanPath := filepath.Clean(filename)
fullPath := filepath.Join(baseDir, cleanPath)
absPath, _ := filepath.Abs(fullPath)
if !strings.HasPrefix(absPath, baseDir) {
    http.Error(w, "Invalid path", http.StatusBadRequest)
    return
}
os.ReadFile(absPath)  // SAFE - validated
```

### Allowlist Validation

```go
// Allowlist validation - SAFE
allowedFiles := map[string]bool{"readme.txt": true, "help.txt": true}
filename := r.FormValue("file")
if !allowedFiles[filename] {
    http.Error(w, "File not allowed", http.StatusForbidden)
    return
}
os.ReadFile(filepath.Join(docDir, filename))  // SAFE
```

### Rejecting Path Traversal Characters

```go
// Rejecting path traversal - SAFE
filename := r.URL.Query().Get("file")
if strings.Contains(filename, "..") || filepath.IsAbs(filename) {
    http.Error(w, "Invalid filename", http.StatusBadRequest)
    return
}
os.Open(filepath.Join(baseDir, filename))  // SAFE
```

### Constant-returning method

```go
// Even though 'r' (request) is tainted, GetTheValue() returns a hardcoded constant
scr := NewSeparateClassRequest(r)
param := scr.GetTheValue("key")  // Returns "bar" (constant), NOT tainted
os.Open(testFilesDir + param)  // SAFE - param is not user-controlled
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
1. ALL source patterns (cookies, headers, query params, form values)
2. Collection manipulations that might substitute safe values
3. `filepath.Join()` does NOT prevent path traversal attacks
Report the file operation (sink) line only when tainted data ACTUALLY reaches it.
