# Go User Prompt Template — LDAP Injection

Evaluate the following Go code located in `<path>`:

```go
<code>
```

## Vulnerability to Find

Report where there are **LDAP Injection** vulnerabilities as instructed. If you are unsure about the validity of a result do NOT report it.

This vulnerability is known as **CWE-90**.

<relatedFilesInformation>

---

## Context

**Language:** Go  
**Frameworks/Libraries:** <e.g., go-ldap/ldap, gopkg.in/ldap.v3>  

**User-controlled sources (tainted inputs):**  
- HTTP input fields and query parameters (`r.URL.Query().Get`, `r.FormValue`, `json.NewDecoder(r.Body).Decode`)  
- Cookies and headers (`r.Header.Get`, `r.Cookies()`)  
- Environment variables (`os.Getenv`)  
- Command-line arguments (`os.Args`)  
- Any deserialized or user-controlled file content  

**LDAP execution sinks (report if tainted data reaches any of these without proper sanitization):**  
- `ldap.NewSearchRequest` with user-controlled filter strings  
- `conn.Search`, `conn.SearchWithPaging`  
- `conn.Modify`, `conn.Add`, `conn.Del`  
- `conn.Bind` with user-controlled DN  
- Any function constructing LDAP filters or DNs dynamically  

**Recognized sanitizers or validators (treat as safe when applied effectively before the sink):**  
- LDAP filter escaping using `ldap.EscapeFilter()` or equivalent  
- DN escaping using `ldap.EscapeDN()` or equivalent  
- Strict input validation with allowlists for usernames/attributes  
- Parameterized LDAP queries (rare but possible with some libraries)  

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a struct is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

## Rules and Guidelines

1. You must only report **LDAP Injection** vulnerabilities.  
2. Do **not** report other issues.  
3. If you think it may be a false positive, **do not report it** — accuracy is more important.  
4. Report the **exact location of the sink** where the LDAP operation is executed (e.g., `conn.Search()`, `ldap.NewSearchRequest()`), NOT the line where tainted data originates or where the filter string is constructed. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. Avoid false positives by checking for proper **escaping or validation**.  
6. Look for **artifacts where LDAP filters or DNs are dynamically built using user input**.  
7. You must return a **valid JSON output** (see JSON format below).  
8. If there are **no vulnerabilities**, output:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Look at the code carefully.  
2. Number each line mentally (or list them).  
3. Identify user-controlled data (from HTTP, CLI args, env vars, etc.).  
4. Check whether these values reach LDAP operation sinks.  
5. If user-controlled data reaches an LDAP operation without sanitization — report it.  
6. Report the **closest line** to the actual LDAP operation execution.

---

## Patterns to Look For

### Vulnerable (fmt.Sprintf in filter)
```go
username := r.FormValue("username")
filter := fmt.Sprintf("(&(uid=%s)(objectClass=user))", username)
searchReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"dn"}, nil)
conn.Search(searchReq)  // <-- SINK
```

### Vulnerable (String concatenation in DN)
```go
userDN := "cn=" + r.URL.Query().Get("user") + ",dc=example,dc=com"
err := conn.Bind(userDN, password)  // <-- SINK
```

### Vulnerable (Header in filter)
```go
group := r.Header.Get("X-Group")
filter := "(memberOf=cn=" + group + ",ou=groups,dc=example,dc=com)"
conn.Search(ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, nil, nil))  // <-- SINK
```

---

### Safe (Escaped filter)
```go
username := ldap.EscapeFilter(r.FormValue("username"))
filter := fmt.Sprintf("(&(uid=%s)(objectClass=user))", username)
searchReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"dn"}, nil)
conn.Search(searchReq)  // SAFE
```

### Safe (Validation function)
```go
if !isValidUsername(username) {
    return errors.New("invalid username")
}
filter := fmt.Sprintf("(uid=%s)", username)  // SAFE
```

### Safe (Allowlist validation)
```go
// Using allowlist validation
if !allowedGroups[group] {
    return errors.New("invalid group")
}
filter := fmt.Sprintf("(memberOf=cn=%s,ou=groups,dc=example,dc=com)", group)  // SAFE
```

### Safe (Constant-returning method)
```go
// Even though 'r' (request) is tainted, GetTheValue() returns a hardcoded constant
scr := NewSeparateClassRequest(r)
param := scr.GetTheValue("key")  // Returns "bar" (constant), NOT tainted
filter := fmt.Sprintf("(uid=%s)", param)
searchReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, nil, nil)
conn.Search(searchReq)  // SAFE - param is not user-controlled
```

---

## Recognized User Input Sources

Untrusted user input may come from:

- HTTP request data:  
  `r.URL.Query().Get("...")`, `r.FormValue(...)`, `json.NewDecoder(r.Body).Decode(...)`  
- Environment variables:  
  `os.Getenv(...)`  
- Command-line arguments:  
  `os.Args`  
- Deserialization or file input

---

## Recognized LDAP Execution Sinks

- `ldap.NewSearchRequest` with dynamic filter  
- `conn.Search`, `conn.SearchWithPaging`  
- `conn.Bind` with dynamic DN  
- `conn.Modify`, `conn.Add`, `conn.Del`  
- Any custom wrapper that constructs LDAP queries

---

## Data Sanitization

If data is sanitized or validated before being used in the LDAP operation, **do not** report it.

Examples of sanitization:

```go
username := ldap.EscapeFilter(r.FormValue("username"))
filter := fmt.Sprintf("(uid=%s)", username)
```

```go
if !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username) {
    return errors.New("invalid username format")
}
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

Detects **LDAP Injection** vulnerabilities in Go code by tracking untrusted data flow into LDAP operations **without** proper escaping or validation.
