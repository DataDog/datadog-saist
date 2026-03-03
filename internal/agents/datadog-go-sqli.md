# Go User Prompt Template — SQL Injection

Evaluate the following Go code located in `<path>`:

```go
<code>
```

## Vulnerability to Find

Report where there are **SQL Injections** as instructed. If you are unsure about the validity of a result do NOT report it.

This vulnerability is known as **CWE-89**.

<relatedFilesInformation>

---

## Context

**Language:** Go  
**Frameworks/Libraries:** <e.g., database/sql, GORM, sqlx>  

**User-controlled sources (tainted inputs):**  
- HTTP input fields and query parameters (`r.URL.Query().Get`, `r.FormValue`, `json.NewDecoder(r.Body).Decode`)  
- Cookies and headers (`r.Header.Get`, `r.Cookies()`)  
- Environment variables (`os.Getenv`)  
- Command-line arguments (`os.Args`)  
- Any deserialized or user-controlled file content  

**SQL execution sinks (ordered by frequency):**  
- `db.Query(query)` — **most common sink**
- `db.QueryRow(query)` — single row query
- `db.Exec(query)` — execute without results
- `db.QueryContext(ctx, query)` — context-aware query
- `db.ExecContext(ctx, query)` — context-aware exec
- `db.Prepare(query)` — **if query is dynamic**
- `tx.Query(query)` — transaction queries
- `tx.Exec(query)` — transaction exec
- `stmt.Query(args...)` — **if stmt from dynamic Prepare**
- ORM and query-builder APIs when raw strings are used:  
  - `db.Raw`, `db.Where`, `db.Find`, `db.First` (when using string concatenation or `fmt.Sprintf`)  
- Any helper or wrapper function that builds SQL queries dynamically before executing

**KEY INSIGHT: Look for `fmt.Sprintf` building SQL strings (612+ occurrences!)**
- This is the most common pattern for SQL injection in Go code

**IMPORTANT: Report Vulnerabilities Even When Execution is Simulated**
Report SQL injection vulnerabilities even when the actual database execution is:
- Commented out in the code
- Wrapped in fmt.Printf/fmt.Fprintf for logging or display
- In a code path that may not be reached at runtime
- Only the SQL string is constructed but not executed

**When execution is commented/simulated, report the SQL string construction as the sink:**
- Report `sqlQuery := "SELECT * FROM users WHERE id='" + param + "'"` as vulnerable
- The vulnerability is in building a dynamic SQL string with user input

**Recognized sanitizers or validators (treat as safe when applied effectively before the sink):**  
- Parameterized queries using placeholders (`?`, `$1`, etc.) and argument binding (`db.Query(query, arg)`)  
- Prepared statements created via `db.Prepare` or `db.PrepareContext` with bound parameters  
- ORM parameter binding (e.g., GORM `db.Where("name = ?", username)`)  
- Strict input validation or allowlists (e.g., `isValidTableName`, regex-validated identifiers)  
- Early rejection of unsafe input via validation checks

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a struct is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data

**TAINT FLOW through conditional logic:**
When a function contains conditional logic like:
```go
if someAlwaysTrueCondition {
    bar = param  // taint flows through
} else {
    bar = "constant"
}
```
- If the condition is always true (e.g., `500/42 + 196 > 200` = `207 > 200` = true), taint flows through
- If the condition is always false, taint does NOT flow
- When in doubt about runtime conditions, assume taint flows through

## Rules and Guidelines

1. You must only report **SQL Injection** vulnerabilities.  
2. Do **not** report other issues.  
3. If you think it may be a false positive, **do not report it** — accuracy is more important.  
4. Report the **exact location of the sink** where the SQL query is executed (e.g., `db.Query()`, `db.Exec()`), NOT the line where tainted data originates or where the query string is constructed. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. Avoid false positives by checking for proper **parameterization or sanitization**.  
6. Look for **artifacts where SQL queries are dynamically built using user input**.  
7. You must return a **valid JSON output** (see JSON format below).  
8. If there are **no vulnerabilities**, output:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Look at the code carefully.  
2. Identify user-controlled data (from HTTP, CLI args, env vars, etc.).  
3. Check whether these values reach SQL execution sinks.  
4. If user-controlled data reaches an SQL execution without sanitization or parameterization — report it.  
5. Report the **closest line** to the actual SQL query execution.

---

## Patterns to Look For

### Vulnerable (fmt.Sprintf - MOST COMMON PATTERN)
```go
param := r.URL.Query().Get("id")
sql := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", param)
rows, err := db.Query(sql)  // <-- SINK: VULNERABLE
```

### Vulnerable (String concatenation)
```go
query := "SELECT * FROM users WHERE name = '" + username + "'"
rows, err := db.Query(query)  // <-- SINK
```

### Vulnerable (db.Exec with fmt.Sprintf)
```go
query := fmt.Sprintf("DELETE FROM accounts WHERE id = %s", r.URL.Query().Get("id"))
db.Exec(query)  // <-- SINK
```

### Vulnerable (INSERT with string concatenation)
```go
name := r.FormValue("name")
query := "INSERT INTO logs (user) VALUES ('" + name + "')"
db.Exec(query)  // <-- SINK
```

### Vulnerable (Stored procedure injection)
```go
bar := r.FormValue("proc")
sqlQuery := fmt.Sprintf("{call %s}", bar)  // <-- SINK: procedure name injection
db.Exec(sqlQuery)
```

### Vulnerable (SQL query constructed for simulated/deferred execution)
```go
// Even if execution is simulated or deferred, report the vulnerable pattern
param := r.URL.Query().Get("id")
sqlQuery := "SELECT * FROM users WHERE PASSWORD='" + param + "'"
fmt.Fprintf(w, "Query: %s", sqlQuery)  // <-- Still VULNERABLE - query was constructed
```

### Safe (Parameterized query with placeholder)
```go
db.Query("SELECT * FROM users WHERE id = $1", param)  // PostgreSQL placeholder - SAFE
```

```go
db.Query("SELECT * FROM users WHERE id = ?", param)  // MySQL/SQLite placeholder - SAFE
```

### Safe (Prepared statement)
```go
stmt, _ := db.Prepare("SELECT * FROM users WHERE name = ?")
stmt.Query(username)  // SAFE
```

### Safe (GORM with parameter binding)
```go
db.Where("name = ?", username).Find(&users)  // SAFE
```

### Safe (Validation before use)
```go
if !isValidID(id) {
    return errors.New("invalid input")
}
db.Exec("DELETE FROM accounts WHERE id = ?", id)  // Validated - SAFE
```

### Safe (Constant-returning method)
```go
// Even though 'r' is tainted, getTheValue() returns a hardcoded constant
scr := NewSeparateClassRequest(r)
param := scr.GetTheValue("key")  // Returns "bar" (constant), NOT tainted
db.Query("SELECT * FROM users WHERE name = '" + param + "'")  // SAFE - param is not user-controlled
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
- For SQL injection: the line where the query is executed with tainted input

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

Detects **SQL Injection** vulnerabilities in Go code by tracking untrusted data flow into SQL execution functions **without** sanitization or parameterization.
