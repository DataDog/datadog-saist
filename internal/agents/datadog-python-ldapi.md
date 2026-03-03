# Python User Prompt Template — LDAP Injection

Evaluate the following Python code located in <path> and report ONLY LDAP Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```python
<code>
```

## Vulnerability to Find

Report where there are **LDAP Injection** vulnerabilities as instructed.

This vulnerability is known as **CWE-90**.

<relatedFilesInformation>

---

## Context

**Language:** Python  
**Frameworks/Libraries:** <e.g., python-ldap, ldap3, django-auth-ldap>  

**User-controlled sources (tainted inputs):**  
- Flask: `request.args`, `request.form`, `request.json`, `request.headers`, `request.cookies`  
- Django: `request.GET`, `request.POST`, `request.headers`  
- FastAPI: path/query parameters, request body  
- Command-line arguments (`sys.argv`), environment variables (`os.environ`)  

**LDAP execution sinks:**  
- `ldap.search_s()`, `ldap.search_ext_s()` with dynamic filter  
- `ldap3.Connection.search()` with dynamic filter  
- `ldap.bind_s()`, `ldap.simple_bind_s()` with dynamic DN  
- `ldap3.Connection.bind()` with dynamic user  
- Any function constructing LDAP filters or DNs dynamically  

**Recognized sanitizers or validators (consider safe):**  
- `ldap.filter.escape_filter_chars()` (python-ldap)  
- `ldap3.utils.dn.escape_rdn()` or `escape_filter_chars()`  
- Strict regex validation or allowlists  
- Using filter templates with proper parameter binding  

**FALSE POSITIVE AVOIDANCE - Safe Sources:**

### SeparateClassRequest.get_the_value() Pattern
```python
# This pattern returns CONTROLLED values, not user input!
from benchmark_helpers import SeparateClassRequest
scr = SeparateClassRequest(request)
param = scr.get_the_value("TestName")  # Returns a CONSTANT/CONTROLLED value
# param is NOT tainted - do NOT report LDAP injection
```

### ThingFactory Pattern
```python
# ThingFactory.create_thing() returns safe, controlled values
from benchmark_helpers import ThingFactory
thing = ThingFactory.create_thing()
value = thing.do_something(param)  # Safe source - returns controlled value
# value is NOT tainted - do NOT report LDAP injection
```

**Why are these safe?** These helper classes return controlled/constant values from an internal lookup, NOT raw user input. Even though they may be instantiated with a request object, their return values are predetermined safe values.

### Conditional with Compile-Time Constant
```python
# When condition is always true/false at compile time, track the actual path
if (7 * 42) - 86 > 200:  # 294 - 86 = 208 > 200 is ALWAYS TRUE
    bar = "safe"
else:
    bar = param
# bar is always "safe" - NOT tainted
```

### Constant-Returning Methods
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report only **LDAP Injection** vulnerabilities.  
2. Report when user input is used in LDAP filters or DNs without escaping.  
3. Ignore cases where proper escaping or validation is applied.  
4. Report the **exact location of the sink** where the LDAP operation is executed (e.g., `conn.search()`, `ldap.search_s()`), NOT the line where tainted data originates. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. If no issues found, output:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify LDAP operations.  
2. Trace tainted input into filter strings or DNs.  
3. Verify whether escaping is applied.  
4. Report unescaped user input in LDAP operations.

---

## Patterns to Look For

### Vulnerable (f-string in filter)
```python
username = request.args.get("username")
filter_str = f"(&(uid={username})(objectClass=user))"
results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)  # <-- SINK
```

### Vulnerable (Dynamic DN construction)
```python
user = request.form["user"]
user_dn = f"cn={user},dc=example,dc=com"
conn.simple_bind_s(user_dn, password)  # <-- SINK
```

### Vulnerable (String concatenation)
```python
group = request.headers.get("X-Group")
filter_str = "(memberOf=cn=" + group + ",ou=groups,dc=example,dc=com)"
connection.search(base_dn, filter_str)  # <-- SINK
```

### Vulnerable (ldap3 Connection.search)
```python
uid = request.args.get("uid")
filter_str = f"(uid={uid})"
conn.search(base_dn, filter_str, attributes=["cn", "mail"])  # <-- SINK
```

### Safe (Escaped filter)
```python
from ldap.filter import escape_filter_chars

username = escape_filter_chars(request.args.get("username"))
filter_str = f"(&(uid={username})(objectClass=user))"
conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)  # SAFE
```

### Safe (Regex validation)
```python
import re
if not re.match(r'^[a-zA-Z0-9_]+$', username):
    raise ValueError("Invalid username")
filter_str = f"(uid={username})"  # SAFE - validated
```

### Safe (ldap3 with escaping)
```python
# Using ldap3 with abstraction
from ldap3 import SUBTREE
from ldap3.utils.conv import escape_filter_chars

connection.search(base_dn, '(uid=%s)' % escape_filter_chars(username), SUBTREE)  # SAFE
```

### Safe (SeparateClassRequest.get_the_value() - IMPORTANT)
```python
# SeparateClassRequest.get_the_value() returns CONTROLLED values, NOT user input!
scr = SeparateClassRequest(request)
param = scr.get_the_value("key")  # Returns controlled value (e.g., "admin"), NOT tainted!
filter_str = f"(uid={param})"
conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)  # SAFE - param is not user-controlled
```

**CRITICAL**: Do NOT report this pattern as LDAP injection. The `get_the_value()` method returns safe, controlled values.

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
- For LDAP injection: the line where the LDAP query is executed with tainted input

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

Detects LDAP Injection (CWE-90) when untrusted inputs are used in LDAP filters or DNs without proper escaping or validation.
