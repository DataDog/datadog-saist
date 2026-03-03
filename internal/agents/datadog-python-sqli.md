# Python User Prompt Template — SQL Injection

Evaluate the following Python code located in <path> and report ONLY SQL Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```python
<code>
```

## Vulnerability to Find

Report where there are **SQL Injection** vulnerabilities as instructed.

This vulnerability is known as **CWE-89**.

<relatedFilesInformation>

---

## Context

**Language:** Python  
**Frameworks/Libraries:** <e.g., sqlite3, psycopg2, MySQLdb, SQLAlchemy, Django ORM>  
**User-controlled sources (tainted inputs):**  
- Web request inputs (`request.args`, `request.form`, `request.get_json()`, JSON body), Django `request.GET/POST`
- HTTP headers (`request.headers.get()`, `request.environ.get()`)
- CLI args, env vars, files loaded from user-controlled locations
- `urllib.parse.unquote()` / `urllib.parse.unquote_plus()` - does NOT sanitize, only URL decodes

**SQL execution sinks (ordered by frequency):**  
- `cursor.execute(query)` — **most common sink** (sqlite3, psycopg2, mysql-connector)
- `cursor.executemany(query, ...)` — batch execution
- `conn.execute(query)` — SQLAlchemy core
- `engine.execute(query)` — SQLAlchemy engine
- `session.execute(text(query))` — SQLAlchemy ORM
- `Model.objects.raw(query)` — Django ORM raw queries
- `connection.cursor().execute()` — Django DB API
- `cursor.callproc(proc_name)` — stored procedure calls
- SQLAlchemy `text()`/raw SQL with string formatting or f-strings

**Taint propagation patterns to detect:**
- String concatenation: `sql = "SELECT * FROM users WHERE id = " + param`
- f-strings: `sql = f"SELECT * FROM users WHERE id = {param}"`
- % formatting: `sql = "SELECT ... WHERE id = %s" % param`
- `.format()`: `sql = "SELECT ... WHERE id = {}".format(param)`

**Recognized sanitizers/validators:**  
- Parameterized queries (`cursor.execute("... WHERE id = %s", (user_id,))` for psycopg2; `"?"` for sqlite3)  
- SQLAlchemy bound parameters (`text("... where id=:id").bindparams(id=val)`) or ORM query APIs (`filter(User.name==name)`)  
- Allowlists for identifiers (when strictly enforced and not interpolated into values/clauses)

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data

---

## Rules and Guidelines

1. Report **only** SQL Injection vulnerabilities.  
2. Report only if tainted data is concatenated or formatted into SQL text without parameters.  
3. Avoid false positives if parameters/bindings are used.  
4. Report the **exact location of the sink** where the SQL query is executed (e.g., `cursor.execute()`, `cursor.callproc()`, `connection.execute()`), NOT the line where tainted data originates or where the query string is constructed. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. Output must be valid JSON; if none, print exactly:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify user-controlled inputs.  
2. Trace to SQL construction/execution.  
3. Verify whether parameterization exists.  
4. Report unparameterized query lines using f-strings, `%`, `+`, or `.format()`.

---

## Patterns to Look For

### Vulnerable (Basic string concatenation)
```python
username = request.args.get("u")
q = f"SELECT * FROM users WHERE name = '{username}'"
cursor.execute(q)  # <-- SINK
```

### Vulnerable (Stored procedure call with string concatenation)
```python
param = request.headers.get("BenchmarkTest00008", "")
param = urllib.parse.unquote(param, encoding='utf-8')
sql = "{call " + param + "}"  # String concatenation with user input
cursor.execute(sql)  # <-- SINK: cursor.execute with tainted SQL
```

### Vulnerable (% formatting)
```python
table = request.args["t"]
cursor.execute("SELECT * FROM %s" % table)  # <-- SINK
```

### Vulnerable (.format() method)
```python
user_id = request.form.get("id")
sql = "DELETE FROM users WHERE id = {}".format(user_id)
cursor.execute(sql)  # <-- SINK
```

### Vulnerable (callproc with tainted procedure name)
```python
proc_name = request.args.get("proc")
cursor.callproc(proc_name)  # <-- SINK
```

### Vulnerable (executemany with tainted SQL)
```python
query = f"INSERT INTO {request.args.get('table')} VALUES (%s)"
cursor.executemany(query, data)  # <-- SINK
```

### Safe (Parameterized queries)
```python
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))  # psycopg2/MySQLdb
```

```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # sqlite3
```

```python
stmt = text("SELECT * FROM users WHERE name=:n")
db.session.execute(stmt, {"n": username})
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

Detects SQL Injection (CWE-89) by identifying tainted data concatenated into SQL queries without proper parameters.
