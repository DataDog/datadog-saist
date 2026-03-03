# Python User Prompt Template — Cross-Site Scripting (XSS)

Evaluate the following Python code located in <path> and report ONLY XSS vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```python
<code>
```

## Vulnerability to Find

Report where there are **Cross-Site Scripting (XSS)** vulnerabilities as instructed.

This vulnerability is known as **CWE-79**.

<relatedFilesInformation>

---

## Context

**Language:** Python  
**Frameworks/Libraries:** <e.g., Flask with Jinja2, Django templates, FastAPI>  
**User-controlled sources:** request args/form/JSON, cookies, headers

**XSS sinks (ordered by frequency):**  
- `flask.Response(data)` — **most common sink** - Direct response with user data
- `response.data = bar` — Direct response data assignment (Flask Response object)
- `flask.make_response(data)` — Response builder
- `render_template_string(template)` — **VERY DANGEROUS** - Jinja2 string rendering with user input
- `Markup(data)` — Marking string as safe HTML (bypasses escaping)
- `return f"<html>{data}</html>"` — f-string in route return
- `HttpResponse(data)` — Django response
- `JsonResponse(data)` — Django JSON (if HTML in values)
- `response.write(content)` — direct response writing
- Jinja2/Django templates with `|safe` or `mark_safe` on tainted data  
- String concatenation of HTML with untrusted values

**User-controlled sources (additional):**
- `request.headers.get('Referer')` — HTTP Referer header (commonly misspelled "Referrer")
- `request.headers.get('User-Agent')` — Browser user agent string
- All HTTP headers are user-controlled input!

**NOT sanitizers (taint is MAINTAINED):**
- `urllib.parse.unquote()` — URL decoding does NOT sanitize
- String concatenation (`param + "_suffix"`) — appending safe strings does NOT sanitize
- Function passthrough (`do_something(param)` that returns `param + "..."`) — still tainted

**Recognized sanitizers:**  
- Framework auto-escaping (`render_template` with default settings, Django templates without `safe`)  
- Manual escaping (`html.escape`, `markupsafe.escape`, `markupsafe.Markup.escape`)  
- Returning JSON (`jsonify`) rather than HTML where appropriate

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data

---

## Rules and Guidelines

1. Report only XSS vulnerabilities.  
2. Report when user input is directly reflected into HTML without escaping.  
3. Ignore non-HTML contexts (e.g., plain text, XML unless embedded into HTML).  
4. Report the **exact location of the sink** where tainted data is written to HTML output (e.g., `Response()`, `make_response()`, `response.write()`, `render_template_string()`), NOT the line where tainted data originates. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. If no issues found, output:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify HTML responses.  
2. Trace tainted input into HTML strings or templates.  
3. Verify whether escaping/auto-escaping is bypassed.  
4. Report unescaped reflections.

---

## Patterns to Look For

### Vulnerable (Flask Response with f-string)
```python
param = request.args.get('input')
response = Response(f"<html><body>{param}</body></html>")  # <-- SINK: XSS
return response
```

### Vulnerable (make_response with tainted content)
```python
name = request.form.get('name')
html = f"<h1>Welcome {name}</h1>"
return make_response(html)  # <-- SINK
```

### Vulnerable (response.write)
```python
user_input = request.args.get('msg')
response.write(f"<div>{user_input}</div>")  # <-- SINK
```

### Vulnerable (render_template_string with tainted template)
```python
template = request.args.get('tpl')
return render_template_string(template)  # <-- SINK: user controls template
```

### Vulnerable (Basic return with HTML)
```python
name = request.args.get("name", "")
return f"<h1>Hello {name}</h1>"  # <-- SINK
```

### Vulnerable (String concatenation in Response)
```python
msg = request.form["msg"]
html = "<div>" + msg + "</div>"
return Response(html, mimetype="text/html")  # <-- SINK
```

### Vulnerable (response.data assignment)
```python
param = request.headers.get('Referer')
bar = do_something(param)  # If do_something passes through param, still tainted
response = Response()
response.data = bar  # <-- SINK: XSS via response.data attribute
return response
```

### Vulnerable (Header value to response)
```python
referer = request.headers.get('Referer')
param = urllib.parse.unquote(referer)  # URL decode does NOT sanitize
return Response(param)  # <-- SINK
```

### Safe (Manual escape)
```python
from markupsafe import escape
param = request.args.get('input')
return Response(f"<html>{escape(param)}</html>")  # Escaped - SAFE
```

### Safe (render_template with auto-escaping)
```python
return render_template('page.html', data=param)  # Jinja2 auto-escapes - SAFE
```

### Safe (Constant-returning method)
```python
# Even though 'request' is tainted, get_the_value() returns a hardcoded constant
wrapper = SeparateClassRequest(request)
param = wrapper.get_the_value("key")  # Returns "bar" (constant), NOT tainted
return Response(f"<html><body>{param}</body></html>")  # SAFE - param is not user-controlled
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

Detects Cross-Site Scripting (CWE-79) when untrusted inputs are injected into HTML without proper escaping or safe templating.
