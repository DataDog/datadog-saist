# Go User Prompt Template — Cross-Site Scripting (XSS)

Evaluate the following Go code located in `<path>`:

```go
<code>
```

## Vulnerability to Find

Report where there are **Cross-Site Scripting (XSS)** vulnerabilities as instructed. If you are unsure about the validity of a result do NOT report it.

This vulnerability is known as **CWE-79**.

<relatedFilesInformation>

---

## Context

**Language:** Go  
**Frameworks/Libraries:** <e.g., net/http, html/template>  
**User-controlled sources (tainted inputs):**  
- HTTP query parameters (`r.URL.Query().Get`, `r.FormValue`)  
- Manual query string parsing (`r.URL.RawQuery` with string manipulation)
- Form data (`r.ParseForm()` then `r.Form["key"]`)
- JSON body fields or unescaped template variables  
- Any unvalidated user input reflected into HTML

**NOT sanitizers (taint is MAINTAINED):**
- `url.QueryUnescape()` — URL decoding does NOT sanitize
- Base64 encode/decode (`base64.StdEncoding.Encode/Decode`) — taint preserved
- String operations (substring, index extraction) — taint preserved

**XSS sinks (ordered by frequency):**  
- `fmt.Fprintf(w, format, args...)` — **most common sink** - ResponseWriter output
- `fmt.Fprint(w, data)` — direct output without format string
- `fmt.Fprintln(w, data)` — direct output with newline
- `w.Write([]byte(data))` — direct response writing
- `io.WriteString(w, data)` — direct string writing
- `template.HTML(data)` — **DANGEROUS: marks string as safe HTML, bypassing escaping**
- `http.Error(w, message, code)` — error response with user message
- `w.Header().Set()` + `w.Write()` — manual response construction
- Template rendering without proper escaping
- Insertion into script blocks or HTML attributes

**Recognized sanitizers:**  
- Proper use of `html/template` package (auto-escapes content)  
- Manual escaping via `html.EscapeString`  
- Validation/allowlists rejecting HTML or JavaScript payloads

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a struct is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data

---

## Rules and Guidelines

1. You must only report **Cross-Site Scripting (XSS)** vulnerabilities.  
2. Report if user-controlled data is written to HTML output without escaping.  
3. Do **not** report XPath or SQL injections.  
4. Report the **exact location of the sink** where tainted data is written to HTML output (e.g., `fmt.Fprintf()`, `w.Write()`, `io.WriteString()`), NOT the line where tainted data originates. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. Avoid false positives — verify that escaping or templating is **not** applied.  
6. Output valid JSON; if no issues:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Look at the code carefully.  
2. Identify HTML-generating functions.  
3. Trace user-controlled inputs (query params, form values, etc.).  
4. Check if these inputs are embedded in HTML directly.  
5. Verify if `html/template` or escaping (`html.EscapeString`) is used.  
6. Report vulnerable write operations.

---

## Patterns to Look For

### Vulnerable (fmt.Fprintf - MOST COMMON)
```go
param := r.URL.Query().Get("name")
fmt.Fprintf(w, "<html><body>Hello %s</body></html>", param)  // <-- SINK: XSS
```

### Vulnerable (fmt.Fprint - direct output)
```go
param := r.URL.Query().Get("input")
bar := processInput(param)  // If processInput passes through param, still tainted
fmt.Fprint(w, bar)  // <-- SINK: XSS via fmt.Fprint
```

### Vulnerable (Manual query string parsing with Base64)
```go
// Manual extraction from RawQuery - still tainted!
queryString := r.URL.RawQuery
paramLoc := strings.Index(queryString, "param=")
param := queryString[paramLoc+len("param="):]
param, _ = url.QueryUnescape(param)  // URL decode does NOT sanitize

// Base64 encode/decode does NOT break taint
paramBytes := []byte(param)
encodedBytes := make([]byte, base64.StdEncoding.EncodedLen(len(paramBytes)))
base64.StdEncoding.Encode(encodedBytes, paramBytes)
decodedBytes := make([]byte, base64.StdEncoding.DecodedLen(len(encodedBytes)))
n, _ := base64.StdEncoding.Decode(decodedBytes, encodedBytes)
bar := string(decodedBytes[:n])  // Still tainted!

w.Header().Set("X-XSS-Protection", "0")
fmt.Fprint(w, bar)  // <-- SINK: XSS
```

### Vulnerable (fmt.Fprintln)
```go
userInput := r.FormValue("msg")
fmt.Fprintln(w, userInput)  // <-- SINK: XSS via fmt.Fprintln
```

### Vulnerable (w.Write with user input)
```go
name := r.FormValue("name")
w.Write([]byte("<h1>Welcome " + name + "</h1>"))  // <-- SINK
```

### Vulnerable (io.WriteString)
```go
userInput := r.URL.Query().Get("msg")
io.WriteString(w, "<script>alert('" + userInput + "')</script>")  // <-- SINK
```

### Vulnerable (template.HTML bypasses escaping)
```go
userContent := r.FormValue("content")
t.Execute(w, template.HTML(userContent))  // <-- SINK: DANGEROUS - marks as safe HTML
```

### Safe (html/template auto-escaping)
```go
tpl := template.Must(template.New("page").Parse("<html><body><h2>Hello, {{.}}</h2></body></html>"))
tpl.Execute(w, name)  // SAFE - html/template auto-escapes
```

### Safe (html.EscapeString)
```go
safeName := html.EscapeString(r.URL.Query().Get("name"))
fmt.Fprintf(w, "<html><body><h2>Hello, %s!</h2></body></html>", safeName)  // SAFE
```

### Safe (Constant-returning method)
```go
// Even though 'r' is tainted, getTheValue() returns a hardcoded constant
scr := NewSeparateClassRequest(r)
param := scr.GetTheValue("key")  // Returns "bar" (constant), NOT tainted
fmt.Fprintf(w, "<html><body>%s</body></html>", param)  // SAFE - param is not user-controlled
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
- For XSS: the line where tainted data is written to HTML output

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

Detects **Cross-Site Scripting (CWE-79)** vulnerabilities in Go code by tracing unescaped user input reaching HTML output functions.
