# Java User Prompt Template — XPath Injection

Evaluate the following Java code located in <path> and report ONLY XPath Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```java
<code>
```

## Vulnerability to Find

Report where there are **XPath Injections** as instructed.

This vulnerability is known as **CWE-643** (also referenced as CWE-91).

<relatedFilesInformation>

---

## Context

**Language:** Java  
**Frameworks/Libraries:** <e.g., javax.xml.xpath, org.w3c.dom>  
**User-controlled sources:**  
- HTTP request data (`getParameter`, `getHeader`)  
- `HttpServletRequest.getHeaders()` returning `Enumeration<String>`, then `headers.nextElement()`  
- External XML or SOAP data from user input  
- `java.net.URLDecoder.decode()` - this does NOT sanitize, it only decodes URL encoding  
- Base64 encoding/decoding (e.g., `Base64.decodeBase64()`) - does NOT sanitize!  

**XPath execution sinks:**  
- `XPath.compile()` followed by `evaluate()` using concatenated strings  
- **Direct `XPath.evaluate(expression, document)` with tainted expression string** - IMPORTANT SINK  
- `xpath.evaluate(expression, source, returnType)` when expression is tainted  
- Any string-based XPath expression using user input  

**Recognized sanitizers:**  
- Proper escaping (e.g., `escapeForXPath()` function)  
- Parameter substitution using safe XPath APIs (if available)  
- Validation or allowlist of expected node names or attribute values

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Example: `new SeparateClassRequest(taintedRequest).getTheValue("key")` returning `"bar"` - the return is constant, NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data  

---

## Rules and Guidelines

1. Report only XPath Injection vulnerabilities.  
2. Report when user input is directly concatenated into an XPath expression.  
3. Do not report if escaping or allowlisting occurs.  
4. Report the **exact location of the sink** where the XPath query is executed (e.g., `xpath.evaluate()`), NOT the line where tainted data originates or where the expression string is built. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. If no issues found, output:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify user-controlled input.  
2. Check concatenation into XPath strings.  
3. Determine whether escaping occurs.  
4. Report the vulnerable `XPath.compile` or `evaluate` call.  

---

## Patterns to Look For

### Vulnerable (XPathExpression.compile pattern)
```java
String user = request.getParameter("username");
String pass = request.getParameter("password");
String expr = "//user[name='" + user + "' and pass='" + pass + "']";
XPathExpression x = xpath.compile(expr);
x.evaluate(doc, XPathConstants.NODESET);  // <-- SINK
```

### Vulnerable (Direct XPath.evaluate - COMMON PATTERN)
```java
// Direct evaluation WITHOUT compile step - THIS IS THE SINK!
String param = request.getParameter("input");
param = org.apache.commons.codec.binary.Base64.decodeBase64(param);  // Base64 does NOT sanitize!
javax.xml.xpath.XPathFactory xpf = javax.xml.xpath.XPathFactory.newInstance();
javax.xml.xpath.XPath xp = xpf.newXPath();
String expression = "/data/content[@id='" + param + "']";
// The direct evaluate() call with tainted expression is the sink
String result = xp.evaluate(expression, xmlDocument);  // <-- SINK: report this line
```

### Vulnerable (Enumeration header with direct evaluate)
```java
java.util.Enumeration<String> headers = request.getHeaders("Input");
if (headers != null && headers.hasMoreElements()) {
    String param = headers.nextElement();
}
javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
String expression = "/items/item[name='" + param + "']";
xp.evaluate(expression, document);  // <-- SINK
```

### Vulnerable (With InputSource)
```java
String userInput = request.getParameter("query");
InputSource inputSource = new InputSource(xmlInput);
String expression = "//node[" + userInput + "]";
xpath.evaluate(expression, inputSource, XPathConstants.NODE);  // <-- SINK
```

### Safe
```java
String expr = "//user[name=" + escapeForXPath(user) + " and pass=" + escapeForXPath(pass) + "]";
XPathExpression x = xpath.compile(expr);
x.evaluate(doc, XPathConstants.NODESET);
```

```java
// Using parameterized XPath with variable resolver (if available)
xpath.setXPathVariableResolver(variableResolver);
String expr = "//user[name=$username]";  // variable substitution
XPathExpression x = xpath.compile(expr);
x.evaluate(doc, XPathConstants.NODESET);
```

```java
// SAFE: Constant-returning method breaks taint flow
// Even though 'request' is tainted, getTheValue() returns a hardcoded constant
SeparateClassRequest scr = new SeparateClassRequest(request);
String param = scr.getTheValue("key");  // Returns "bar" (constant), NOT tainted
String expr = "//node[@id='" + param + "']";
xpath.evaluate(expr, document);  // SAFE - param is not user-controlled
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
- For XPath injection: the line where the XPath query is evaluated with tainted input

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

Detects XPath Injection (CWE-643/CWE-91) when untrusted data is inserted into XPath queries without proper escaping or validation.
