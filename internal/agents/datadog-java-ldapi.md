# Java User Prompt Template — LDAP Injection

Evaluate the following Java code located in <path> and report ONLY LDAP Injection vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```java
<code>
```

## Vulnerability to Find

Report where there are **LDAP Injection** vulnerabilities as instructed.

This vulnerability is known as **CWE-90**.

<relatedFilesInformation>

---

## Context

**Language:** Java  
**Frameworks/Libraries:** <e.g., JNDI, Spring LDAP, UnboundID LDAP SDK>  

**User-controlled sources (tainted inputs):**  
- `HttpServletRequest.getParameter()`, `getHeader()`, `getQueryString()`, `getCookies()`  
- User inputs in JSP pages (`<%= request.getParameter() %>`)  
- Command-line arguments or environment variables (`System.getenv`, `args[]`)  

**LDAP execution sinks:**  
- `DirContext.search()` with dynamic filter  
- `LdapContext.search()`, `InitialDirContext.search()`  
- `LdapTemplate.search()`, `LdapTemplate.find()` (Spring LDAP)  
- `SearchRequest` construction with user-controlled filter  
- `context.bind()`, `context.rebind()` with dynamic DN  

**Recognized sanitizers or validators (consider safe):**  
- Filter encoding using `javax.naming.ldap.LdapName` or similar  
- Spring's `LdapEncoder.filterEncode()` or `LdapEncoder.nameEncode()`  
- Strict allowlist validation of usernames/attributes  
- Parameterized filters using `FilterBasedLdapUserSearch` with proper encoding  

---

## ⚠️ FALSE POSITIVE AVOIDANCE — Safe Sources

**The following are NOT tainted sources and should NOT trigger LDAP injection reports:**

### SeparateClassRequest.getTheValue() Pattern
```java
// This pattern returns CONTROLLED values, not user input!
org.owasp.benchmark.helpers.SeparateClassRequest scr = 
    new SeparateClassRequest(request);
String param = scr.getTheValue("TestName");  // Returns a CONSTANT/CONTROLLED value
// param is NOT tainted - do NOT report LDAP injection
```

### ThingFactory Pattern
```java
// ThingFactory.createThing() returns safe, controlled values
org.owasp.benchmark.helpers.ThingInterface thing = 
    ThingFactory.createThing();
String value = thing.doSomething(param);  // Safe source - returns controlled value
// value is NOT tainted - do NOT report LDAP injection
```

**Why are these safe?** These helper classes return controlled/constant values from an internal lookup, NOT raw user input. Even though they may be instantiated with a request object, their return values are predetermined safe values.

### Switch with Constant Selector
```java
// When switch selector is a compile-time constant, track which branch is taken
String guess = "ABC";
char switchTarget = guess.charAt(2);  // Always 'C' - constant!

switch (switchTarget) {
    case 'A': bar = param; break;
    case 'B': bar = "safe"; break;
    case 'C':
    case 'D': bar = param; break;  // Takes this path
    default: bar = "safe"; break;
}
// If param is from safe source (SeparateClassRequest), bar is safe
```

### Conditional with Compile-Time Constant
```java
// When condition is always true/false at compile time, track the actual path
if ((7 * 42) - 86 > 200)  // 294 - 86 = 208 > 200 is ALWAYS TRUE
    bar = "safe";
else 
    bar = param;
// bar is always "safe" - NOT tainted
```

### Constant-Returning Methods
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report **only LDAP Injection** vulnerabilities.  
2. Report if **user-controlled data** reaches an LDAP query without escaping or validation.  
3. Avoid false positives where sanitization or allowlisting is clearly applied.
4. **DO NOT report** when input comes from `SeparateClassRequest.getTheValue()` — this returns controlled values.
5. Report the **exact location of the sink** where the LDAP operation is executed (e.g., `context.search()`, `ldapTemplate.search()`), NOT the line where tainted data originates.
6. You must specify: `startLine`, `endLine`, `startColumn`, and `endColumn`.
7. Output must be valid JSON; if no issues found:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify input sources.
2. **Check if the source is actually tainted** (request parameters) or safe (getTheValue(), constants).
3. Track data propagation to LDAP operation sinks.
4. Check if escaping or validation occurs before execution.
5. Report only if truly tainted input reaches LDAP operations without sanitization.

---

## Patterns to Look For

### VULNERABLE (REPORT THESE)

```java
// Direct request parameter in LDAP filter - VULNERABLE
String username = request.getParameter("username");
String filter = "(&(uid=" + username + ")(objectClass=user))";
NamingEnumeration<?> results = ctx.search(baseDN, filter, searchControls);  // <-- REPORT
```

```java
// Header in DN - VULNERABLE
String userDN = "cn=" + request.getParameter("user") + ",dc=example,dc=com";
ctx.bind(userDN, userData);  // <-- REPORT
```

```java
// Header in filter - VULNERABLE
String group = request.getHeader("X-Group");
ldapTemplate.search("", "(memberOf=cn=" + group + ",ou=groups,dc=example,dc=com)", mapper);  // <-- REPORT
```

### SAFE — DO NOT REPORT

```java
// Escaped input - SAFE
String username = LdapEncoder.filterEncode(request.getParameter("username"));
String filter = "(&(uid=" + username + ")(objectClass=user))";
ctx.search(baseDN, filter, searchControls);  // SAFE
```

```java
// Input validated - SAFE
if (!isValidUsername(username)) {
    throw new IllegalArgumentException("Invalid username");
}
String filter = "(uid=" + username + ")";
ctx.search(baseDN, filter, searchControls);  // SAFE
```

```java
// SeparateClassRequest.getTheValue() - SAFE (returns controlled value)
SeparateClassRequest scr = new SeparateClassRequest(request);
String param = scr.getTheValue("TestName");  // Returns controlled value, NOT user input!
String filter = "(uid=" + param + ")";
ctx.search(baseDN, filter, searchControls);  // SAFE - param is not tainted
```

```java
// ThingFactory.createThing() - SAFE (returns controlled value)
ThingInterface thing = ThingFactory.createThing();
String value = thing.doSomething(someParam);  // Safe source
String filter = "(uid=" + value + ")";
ctx.search(baseDN, filter, searchControls);  // SAFE - value is not tainted
```

```java
// Using parameterized Spring LDAP query - SAFE
LdapQuery query = LdapQueryBuilder.query()
    .where("uid").is(username);  // Properly escaped by framework
ldapTemplate.search(query, mapper);  // SAFE
```

---

## Output

The answer must be a JSON formatted answer.
The array of violations is named `violations`
Each value has: `startLine`, `startColumn`, `endLine`, `endColumn`, `reason`

If there is no violation, write "NO VIOLATION AMIGO"

## Output schema

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
          "startLine": { "type": "integer" },
          "startColumn": { "type": "integer" },
          "endLine": { "type": "integer" },
          "endColumn": { "type": "integer" },
          "reason": { "type": "string" }
        },
        "required": ["startLine", "startColumn", "endLine", "endColumn", "reason"]
      }
    }
  },
  "required": ["violations"]
}
```

---

## Summary

Detects LDAP Injection (CWE-90) when untrusted data reaches LDAP query operations without proper escaping or validation.

**IMPORTANT**: `SeparateClassRequest.getTheValue()` returns controlled values and is NOT a tainted source. Do NOT report LDAP injection when input comes from this method.
