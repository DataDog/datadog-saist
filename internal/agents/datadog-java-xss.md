# Java User Prompt Template — Cross-Site Scripting (XSS)

Evaluate the following Java code located in <path> and report ONLY XSS vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```java
<code>
```

## Vulnerability to Find

Report where there are **Cross-Site Scripting (XSS)** vulnerabilities as instructed.

This vulnerability is known as **CWE-79**.

<relatedFilesInformation>

---

## Context

**Language:** Java  
**Frameworks/Libraries:** <e.g., Servlet API, JSP, Spring MVC, JAX-RS>  
**User-controlled sources:**  
- `HttpServletRequest.getParameter`, `getHeader`, `getQueryString`  
- `HttpServletRequest.getHeaders()` returning `Enumeration<String>`, then `headers.nextElement()`  
- Form inputs or query params reflected in responses  
- JSP `<%= %>` expressions or response writers using user input  
- `java.net.URLDecoder.decode()` - this does NOT sanitize, it only decodes URL encoding  

**XSS sinks:**  
- `PrintWriter.println` or `response.getWriter().write` with user input in HTML  
- `PrintWriter.format()` or `printf()` when the **format string itself** is user-controlled  
- `response.getWriter().format(taintedString, args)` where taintedString comes from user input  
- `response.getWriter().print()` with unescaped user data  
- Returning unescaped HTML via REST or JSP templates  
- Inline script or attribute injection (`<script>`, `onerror`, etc.)  

**Recognized sanitizers:**  
- HTML encoding via `StringEscapeUtils.escapeHtml4`, `ESAPI.encoder().encodeForHTML`, or frameworks with auto-escaping (`Thymeleaf`, `Spring HTML templates`)

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Example: `new SeparateClassRequest(taintedRequest).getTheValue("key")` returning `"bar"` - the return is constant, NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data  

---

## Rules and Guidelines

1. Report only XSS vulnerabilities.  
2. Report if user input is directly written to HTML output without escaping.  
3. Ignore XML-only or non-HTML contexts.  
4. Report the **exact location of the sink** where tainted data is written to HTML output (e.g., `out.println()`, `response.getWriter().write()`), NOT the line where tainted data originates. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. If no issues found, output:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify HTML generation or response writing.  
2. Trace whether user input flows into HTML without escaping.  
3. Check for `escapeHtml` or safe template rendering.  
4. Report vulnerable write or print operations.  

---

## Patterns to Look For

### Vulnerable (Basic println)
```java
String user = request.getParameter("user");
out.println("<h2>Welcome, " + user + "</h2>");  // <-- SINK
```

```java
String msg = request.getParameter("msg");
return "<div>" + msg + "</div>";  // <-- SINK if returned as HTML response
```

### Vulnerable (Format string XSS - COMMON PATTERN)
```java
// User-controlled FORMAT STRING is XSS - the format string itself is tainted!
String param = request.getHeader("Referer");
response.setHeader("X-XSS-Protection", "0");
Object[] args = {"a", "b"};
response.getWriter().format(param, args);  // <-- SINK: format string is tainted
```

### Vulnerable (printf with tainted format)
```java
String userInput = request.getParameter("fmt");
response.getWriter().printf(userInput, someData);  // <-- SINK
```

### Vulnerable (Enumeration-based header with format)
```java
java.util.Enumeration<String> headers = request.getHeaders("Referer");
if (headers != null && headers.hasMoreElements()) {
    String param = headers.nextElement();
}
param = java.net.URLDecoder.decode(param, "UTF-8");
response.setHeader("X-XSS-Protection", "0");
Object[] obj = {"a", "b"};
response.getWriter().format(param, obj);  // <-- SINK
```

### Vulnerable (Locale-based format)
```java
String param = request.getHeader("Input");
Object[] obj = {"a", "b"};
response.getWriter().format(java.util.Locale.US, param, obj);  // <-- SINK
```

### Safe (User input as FORMAT ARGUMENT, not format string)
```java
// User input as argument to constant format string
String data = request.getParameter("name");
response.getWriter().format("Hello, %s", ESAPI.encoder().encodeForHTML(data));
```

### Safe
```java
String safeUser = ESAPI.encoder().encodeForHTML(request.getParameter("user"));
out.println("<h2>Welcome, " + safeUser + "</h2>");
```

```java
model.addAttribute("msg", msg); // auto-escaped by Thymeleaf or JSP EL
```

```java
// SAFE: Constant-returning method breaks taint flow
// Even though 'request' is tainted, getTheValue() returns a hardcoded constant
SeparateClassRequest scr = new SeparateClassRequest(request);
String param = scr.getTheValue("key");  // Returns "bar" (constant), NOT tainted
out.println("<h2>Welcome, " + param + "</h2>");  // SAFE - param is not user-controlled
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

Detects Cross-Site Scripting (CWE-79) when unescaped user input is rendered in HTML responses or templates.
