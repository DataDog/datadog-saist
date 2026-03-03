# Go User Prompt Template — XPath Injection

Evaluate the following Go code located in `<path>`:

```go
<code>
```

## Vulnerability to Find

Report where there are **XPath Injections** as instructed. If you are unsure about the validity of a result do NOT report it.

This vulnerability is known as **CWE-643** (also referenced as CWE-91).

<relatedFilesInformation>

---

## Context

**Language:** Go  
**Frameworks/Libraries:** <e.g., github.com/antchfx/xmlquery, github.com/antchfx/xpath, github.com/beevik/etree>  

**User-controlled sources (tainted inputs):**  
- HTTP query/form parameters: `r.URL.Query().Get()`, `r.FormValue()`
- HTTP headers: `r.Header.Get()`
- Environment variables: `os.Getenv()`
- User-provided XML content or attributes

**XPath execution sinks:**  
- `xmlquery.FindOne(doc, query)` — antchfx/xmlquery
- `xmlquery.Find(doc, query)` — antchfx/xmlquery
- `xpath.Compile(expr)` — antchfx/xpath
- `doc.SelectElements(path)` — beevik/etree
- `fmt.Sprintf` or `+` concatenation used to create XPath expressions

**Recognized sanitizers:**  
- Escaping of XPath input via safe escaping functions (e.g., `escapeXPathString`)  
- Fixed/allowlisted XPath fragments  
- Use of predefined XPath templates with parameter substitution

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a struct is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report only **XPath Injection** vulnerabilities.  
2. Report only when user data is directly concatenated into an XPath expression.  
3. Avoid false positives when escaping is properly applied.  
4. Report the **exact location of the sink** where the XPath query is executed (e.g., `xmlquery.FindOne()`, `xmlquery.Find()`, `xpath.Compile()`), NOT the line where tainted data originates or where the expression is constructed. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. Be accurate — do not report speculative issues.  
6. Output must be valid JSON; if none, print:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Look at the code carefully.  
2. Identify user-controlled data (HTTP params, env vars, XML fields, etc.).  
3. Trace concatenation or interpolation into XPath query strings.  
4. Verify whether escaping, encoding, or allowlisting is performed.  
5. If not sanitized, report the vulnerable line constructing or executing the XPath query.  

---

## Patterns to Look For

### Vulnerable (xmlquery.FindOne)
```go
username := r.URL.Query().Get("username")
password := r.URL.Query().Get("password")
query := fmt.Sprintf("//user[username='%s' and password='%s']", username, password)
node := xmlquery.FindOne(doc, query)  // <-- SINK: XPATH INJECTION
```

### Vulnerable (xmlquery.Find)
```go
tag := r.Header.Get("X-Tag")
query := fmt.Sprintf("//%s", tag)
nodes := xmlquery.Find(doc, query)  // <-- SINK
```

### Vulnerable (xpath.Compile)
```go
param := r.FormValue("path")
expr, err := xpath.Compile("/root/" + param)  // <-- SINK
```

### Vulnerable (etree SelectElements)
```go
selector := r.URL.Query().Get("selector")
elements := doc.SelectElements(selector)  // <-- SINK
```

### Safe (Escaped input)
```go
safeUser := escapeXPathString(username)
safePass := escapeXPathString(password)
query := fmt.Sprintf("//user[username=%s and password=%s]", safeUser, safePass)
node := xmlquery.FindOne(doc, query)  // SAFE - escaped
```

### Safe (Allowlisted values)
```go
allowedFields := map[string]bool{"name": true, "id": true, "status": true}
field := r.URL.Query().Get("field")
if !allowedFields[field] {
    return errors.New("invalid field")
}
query := fmt.Sprintf("//record/%s", field)
node := xmlquery.FindOne(doc, query)  // SAFE - allowlisted
```

### Safe (Constant-returning method)
```go
// Even though 'r' (request) is tainted, getTheValue() returns a hardcoded constant
scr := NewSeparateClassRequest(r)
param := scr.GetTheValue("key")  // Returns "bar" (constant), NOT tainted
query := fmt.Sprintf("//item[@id='%s']", param)
node := xmlquery.FindOne(doc, query)  // SAFE - param is not user-controlled
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
- For XPath injection: the line where the XPath query is executed with tainted input

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

Detects **XPath Injection** vulnerabilities in Go code by analyzing where untrusted data flows into XPath query construction without sanitization or escaping.
