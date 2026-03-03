# Python User Prompt Template — XPath Injection

Evaluate the following Python code located in <path> and report ONLY XPath Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```python
<code>
```

## Vulnerability to Find

Report where there are **XPath Injections** as instructed.

This vulnerability is known as **CWE-643** (also referenced as CWE-91).

<relatedFilesInformation>

---

## Context

**Language:** Python  
**Libraries:** <e.g., lxml.etree, xml.etree.ElementTree>  
**User-controlled sources:** web request parameters, JSON body values, env/CLI inputs

**XPath execution sinks:**  
- `tree.xpath(expression)` — lxml
- `etree.XPath(expression)` — lxml compiled XPath
- `root.find(path)` — ElementTree
- `root.findall(path)` — ElementTree
- `element.xpath(...)` or `etree.XPath(...).evaluate(...)` where expressions include user input via concatenation or f-strings

**Recognized sanitizers:**  
- Proper escaping for XPath string literals (e.g., building `concat()`-based strings)  
- Fixed/allowlisted fragments that do not include user-controlled text
- `lxml.etree.XPathEvaluator` with parameterized queries

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report only XPath Injection vulnerabilities.  
2. Report when user input is directly inserted into an XPath expression string.  
3. Avoid false positives when escaping/validation is clearly performed.  
4. Report the **exact location of the sink** where the XPath query is executed (e.g., `tree.xpath()`, `root.find()`), NOT the line where tainted data originates or where the expression string is built. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. If no issues found, output exactly:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify user input.  
2. Check construction of XPath expressions via `+`, f-strings, or `.format`.  
3. Determine whether escaping/allowlisting is present.  
4. Report the vulnerable line.

---

## Patterns to Look For

### Vulnerable (f-string in xpath)
```python
from lxml import etree

param = request.args.get('name')
xpath = f"//user[@name='{param}']"
results = tree.xpath(xpath)  # <-- SINK: XPATH INJECTION
```

### Vulnerable (String concatenation)
```python
username = request.form.get("username")
password = request.form.get("password")
expr = "//user[username/text()='" + username + "' and password/text()='" + password + "']"
nodes = root.xpath(expr)  # <-- SINK
```

### Vulnerable (ElementTree find)
```python
param = request.args.get('id')
element = root.find(f".//item[@id='{param}']")  # <-- SINK
```

### Vulnerable (ElementTree findall)
```python
tag = request.headers.get('X-Tag')
elements = root.findall(f".//{tag}")  # <-- SINK
```

### Safe (Escaped input)
```python
def escape_for_xpath(s):
    if "'" in s:
        return "concat(" + ", ".join("'" + p + "'" for p in s.split("'")) + ")"
    return f"'{s}'"

expr = f"//user[username/text()={escape_for_xpath(username)}]"
nodes = root.xpath(expr)  # SAFE - properly escaped
```

### Safe (Constant-returning method)
```python
# Even though 'request' is tainted, get_the_value() returns a hardcoded constant
wrapper = SeparateClassRequest(request)
param = wrapper.get_the_value("key")  # Returns "bar" (constant), NOT tainted
results = tree.xpath(f"//item[@id='{param}']")  # SAFE - param is not user-controlled
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

Detects XPath Injection (CWE-643/CWE-91) when untrusted inputs are embedded into XPath expressions without safe escaping.
