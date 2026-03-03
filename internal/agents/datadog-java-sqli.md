# Java User Prompt Template — SQL Injection

Evaluate the following Java code located in <path> and report ONLY SQL Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```java
<code>
```

## Vulnerability to Find

Report where there are **SQL Injection** vulnerabilities as instructed.

This vulnerability is known as **CWE-89**.

<relatedFilesInformation>

---

## Context

**Language:** Java  
**Frameworks/Libraries:** <e.g., JDBC, Hibernate, Spring JDBC>  
**User-controlled sources (tainted inputs):**  
- HTTP request data (`getParameter`, `getHeader`, `getCookies`)  
- `HttpServletRequest.getHeaders()` returning `Enumeration<String>`, then `headers.nextElement()`  
- JSON or XML deserialized fields  
- Any user input used to construct SQL strings  
- `java.net.URLDecoder.decode()` - this does NOT sanitize, it only decodes URL encoding  

**SQL execution sinks:**  
- `Statement.executeQuery`, `Statement.executeUpdate`, `Statement.execute`  
- `Connection.prepareCall`, `Connection.createStatement` with concatenated strings  
- `CallableStatement.execute()`, `CallableStatement.executeQuery()`, `CallableStatement.executeUpdate()`  
- Any `Statement` obtained from helper/factory methods (e.g., `DatabaseHelper.getStatement()`) when SQL string is tainted  
- ORM methods using raw SQL (`Session.createQuery`, `EntityManager.createNativeQuery`)  
- Spring JDBC methods like `JdbcTemplate.query()`, `JdbcTemplate.update()`, `batchUpdate()` with concatenated SQL  

**Recognized sanitizers:**  
- Prepared statements (`PreparedStatement` with placeholders `?`)  
- ORM parameter binding (`query.setParameter`)  
- Input allowlists or validation of SQL fragments

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Example: `new SeparateClassRequest(taintedRequest).getTheValue("key")` returning `"bar"` - the return is constant, NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?
- Methods that ignore their parameters and return hardcoded values break taint propagation
- Do NOT assume a method returns tainted data just because the object was constructed with tainted data
- See the detailed false positive example below showing the `SeparateClassRequest.getTheValue()` pattern  

---

## Rules and Guidelines

1. Report only SQL Injection vulnerabilities.  
2. Trigger if unvalidated or unsanitized user input is concatenated into an SQL query string.  
3. Avoid false positives when parameterized queries or ORM bindings are used.  
4. Report the **exact location of the sink** where the SQL query is executed (e.g., `executeQuery()`, `executeUpdate()`, `prepareCall()`), NOT the line where tainted data originates or where the query string is constructed. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. Output must be valid JSON; if no issues found:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify user-controlled input.  
2. Check whether it flows into query construction.  
3. Verify absence of parameterization or sanitization.  
4. Report unsafe string-based query execution.
5. Confirm if the result appears to be a false positive and discard if so.  

---

## Patterns to Look For

### Vulnerable (Basic string concatenation)
```java
String user = request.getParameter("username");
String sql = "SELECT * FROM users WHERE name='" + user + "'";
Statement stmt = conn.createStatement();
stmt.executeQuery(sql);  // <-- SINK
```

### Vulnerable (CallableStatement with stored procedure)
```java
String query = "CALL " + request.getParameter("procName");
conn.prepareCall(query).execute();  // <-- SINK
```

### Vulnerable (Helper class pattern - COMMON IN BENCHMARKS)
```java
String param = request.getHeader("userInput");
String sql = "INSERT INTO users VALUES ('" + param + "')";

// Statement obtained from helper class - still vulnerable!
java.sql.Statement statement = org.example.DatabaseHelper.getSqlStatement();
statement.executeUpdate(sql);  // <-- SINK: report this line
```

### Vulnerable (CallableStatement via prepareCall)
```java
String param = "";
if (request.getHeader("BenchmarkTest") != null) {
    param = request.getHeader("BenchmarkTest");
}
param = java.net.URLDecoder.decode(param, "UTF-8");

String sql = "{call " + param + "}";
java.sql.Connection connection = getConnection();
java.sql.CallableStatement statement = connection.prepareCall(sql);
java.sql.ResultSet rs = statement.executeQuery();  // <-- SINK
```

### Vulnerable (Enumeration-based header with INSERT)
```java
java.util.Enumeration<String> headers = request.getHeaders("Data");
if (headers != null && headers.hasMoreElements()) {
    String param = headers.nextElement();
    String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
    java.sql.Statement statement = DatabaseHelper.getSqlStatement();
    int count = statement.executeUpdate(sql);  // <-- SINK
}
```

### Safe
```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name=?");
ps.setString(1, request.getParameter("username"));
ps.executeQuery();
```

```java
Query q = entityManager.createQuery("SELECT u FROM User u WHERE u.name = :name");
q.setParameter("name", username);
```

---
## Example of vulnerable code (true positive)

In this example, the parameter is being retrieved from a header and later injected into the SQL statement. Therefore,
the user-controlled data is injected in the query.

```java
public class VulnerableCode extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String param = "";
        if (request.getHeader("BenchmarkTest00008") != null) {
            param = request.getHeader("BenchmarkTest00008");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String sql = "{call " + param + "}";

        try {
            java.sql.Connection connection = getConnection();
            java.sql.CallableStatement statement = connection.prepareCall(sql);
            java.sql.ResultSet rs = statement.executeQuery();

        } catch (java.sql.SQLException e) {
        }
    }
}
```


## Examples of non-vulnerable code (false positive)

The following example is a false positive and is not vulnerable. In this file, the value `bar` is concatenated
but it comes from a value that is not injected from the user. Therefore, since the variable
`bar` is not user-dependent, this is not a vulnerability.

Even if the `bar` value comes from the cookie, it is later overwritten by another function call and therefore, is
not vulnerable.

```java
@Override
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");

    String bar = "safe!";
    java.util.HashMap<String, Object> map11928 = new java.util.HashMap<String, Object>();
    map11928.put("keyA-11928", "a-Value"); // put some stuff in the collection
    map11928.put("keyB-11928", param); // put it in a collection
    map11928.put("keyC", "another-Value"); // put some stuff in the collection
    bar = (String) map11928.get("keyB-11928"); // get it back out

    String sql = "INSERT INTO users (username, password) VALUES ('foo','" + bar + "')";

    try {
        java.sql.Statement statement = getStatement();
        int count = statement.executeUpdate(sql, new String[] {"USERNAME", "PASSWORD"});
        org.owasp.benchmark.helpers.DatabaseHelper.outputUpdateComplete(sql, response);
    } catch (java.sql.SQLException e) {
    }
}
```

In the current code, the data flow and conditions are set up so that the code is not vulnerable. The condition
`((500 / 42) + num > 200)` always return true, which makes the variable `bar` always equal to the return
value of `getTheValue()`, which is `"bar"`. Since the value is static, there is no user-injected value
and no vulnerability.

```java

public class SeparateClassRequest {
    private HttpServletRequest request;

    public SeparateClassRequest(HttpServletRequest request) {
        this.request = request;
    }

    public String getTheParameter(String p) {
        return request.getParameter(p);
    }

    public String getTheCookie(String c) {
        Cookie[] cookies = request.getCookies();

        String value = "";

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(c)) {
                    value = cookie.getValue();
                    break;
                }
            }
        }

        return value;
    }

    public String getTheValue(String p) {
        return "bar";
    }
}

@WebServlet(value = "/sqli")
public class NotVulnerableServlet extends HttpServlet {

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        org.owasp.benchmark.helpers.SeparateClassRequest scr =
                new org.owasp.benchmark.helpers.SeparateClassRequest(request);
        // this method always return "bar"
        String param = scr.getTheValue("myvalue");

        String bar;

        int num = 196;
        if ((500 / 42) + num > 200) bar = param;
        else bar = "This should never happen";

        try {
            // since bar is a hardcoded value, there is no vulnerability
            String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";

            org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.batchUpdate(sql);
            response.getWriter()
                    .println(
                            "No results can be displayed for query: "
                                    + org.owasp.esapi.ESAPI.encoder().encodeForHTML(sql)
                                    + "<br>"
                                    + " because the Spring batchUpdate method doesn't return results.");
        } catch (org.springframework.dao.DataAccessException e) {
            if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
                response.getWriter().println("Error processing request.");
            } else throw new ServletException(e);
        }
    }
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

Detects SQL Injection (CWE-89) by tracing untrusted input concatenated into SQL strings or ORM queries without parameterization.
