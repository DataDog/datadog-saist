# Java User Prompt Template — Weak Hash

Evaluate the following Java code located in <path> and report ONLY Weak Hash vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```java
<code>
```

## Vulnerability to Find

Report where there are **Weak Hash** vulnerabilities as instructed.

This vulnerability is known as **CWE-328**.

<relatedFilesInformation>

---

## Context

**Language:** Java  
**Frameworks/Libraries:** <e.g., java.security.MessageDigest, Spring Security, Apache Commons Codec>  

**Weak hash algorithms (ALWAYS report when used for security purposes):**  
- `MessageDigest.getInstance("MD5")` — **most common weak hash**
- `MessageDigest.getInstance("SHA-1")` or `MessageDigest.getInstance("SHA1")` — **both forms are weak**
- `DigestUtils.md5()`, `DigestUtils.md5Hex()` (Apache Commons)
- `DigestUtils.sha1()`, `DigestUtils.sha1Hex()` (Apache Commons)
- `Hashing.md5()`, `Hashing.sha1()` (Guava)
- Custom or homebrew hash implementations  

**Security-sensitive contexts (report if weak hash is used):**  
- Password hashing or storage  
- Digital signatures or integrity verification  
- Token generation for authentication  
- Certificate validation  
- Cryptographic key derivation  

**Non-security contexts (do NOT report):**  
- Cache keys or checksums for non-security purposes  
- Content-addressable storage identifiers  
- File deduplication  
- ETags for HTTP caching  
- Logging or debugging purposes  

**Strong alternatives (treat as safe):**  
- `MessageDigest.getInstance("SHA-256")`, `"SHA-384"`, `"SHA-512"`
- `DigestUtils.sha256Hex()`, `sha384Hex()`, `sha512Hex()` (Apache Commons)
- `BCryptPasswordEncoder` (Spring Security)  
- `Argon2PasswordEncoder`, `SCryptPasswordEncoder`  
- `PBKDF2` with sufficient iterations  

---

## Rules and Guidelines

1. Report **only Weak Hash** vulnerabilities in security-sensitive contexts.  
2. Do NOT report weak hashes used for non-security purposes.  
3. Consider the context — password storage vs. cache key.  
4. Report the **exact location of the sink** where the weak hash is used (e.g., `MessageDigest.getInstance("MD5")`), NOT the line where data originates. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.  
5. Output must be valid JSON; if no issues found, output exactly:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify hash function usage.  
2. Determine the hash algorithm (MD5, SHA-1, SHA-256, etc.).  
3. Assess if used for security purposes.  
4. Report weak hashes only in security contexts.  

---

## Patterns to Look For

### Vulnerable (MessageDigest with MD5)
```java
// Password hashing with MD5 - VULNERABLE
public String hashPassword(String password) {
    MessageDigest md = MessageDigest.getInstance("MD5");  // <-- SINK
    byte[] hash = md.digest(password.getBytes());
    return Base64.getEncoder().encodeToString(hash);
}
```

### Vulnerable (MessageDigest with SHA-1 or SHA1)
```java
// Token generation with SHA-1 - VULNERABLE
MessageDigest digest = MessageDigest.getInstance("SHA-1");  // <-- SINK
digest.update((userId + secret).getBytes());
String token = Hex.encodeHexString(digest.digest());
```

```java
// Alternative SHA1 spelling - ALSO VULNERABLE
MessageDigest sha1 = MessageDigest.getInstance("SHA1");  // <-- SINK
```

### Vulnerable (Apache Commons DigestUtils)
```java
// Using Apache Commons for password - VULNERABLE
String hashedPassword = DigestUtils.md5Hex(password + salt);  // <-- SINK
userRepository.save(new User(username, hashedPassword));
```

```java
// SHA-1 via Apache Commons - VULNERABLE
String hash = DigestUtils.sha1Hex(tokenData);  // <-- SINK
```

### Vulnerable (Guava Hashing)
```java
// Guava MD5 - VULNERABLE
String hash = Hashing.md5().hashString(password, StandardCharsets.UTF_8).toString();  // <-- SINK
```

### Vulnerable (Signature verification with MD5)
```java
byte[] expectedHash = MessageDigest.getInstance("MD5").digest(data);  // <-- SINK
return Arrays.equals(expectedHash, providedSignature);
```

### Safe (BCrypt for passwords)
```java
// Using BCrypt for passwords - SAFE
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hashedPassword = encoder.encode(password);
```

### Safe (SHA-256 for tokens)
```java
// SHA-256 for tokens - SAFE
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest((userId + secret).getBytes());
```

### Safe (MD5 for cache key - non-security)
```java
// MD5 for cache key - NOT SECURITY SENSITIVE, don't report
public String cacheKey(byte[] data) {
    return DigestUtils.md5Hex(data);
}
```

### Safe (PBKDF2 for password derivation)
```java
// PBKDF2 for password derivation - SAFE
SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
byte[] hash = factory.generateSecret(spec).getEncoded();
```

---

## How to Identify Security Context

Security-sensitive indicators:
- Method/variable names: `password`, `credential`, `token`, `auth`, `signature`, `verify`
- Storing hashes in user/credential tables
- Comparison for authentication
- Key derivation contexts

Non-security indicators:
- Names: `cache`, `checksum`, `etag`, `fingerprint`, `dedupe`, `content-hash`
- File integrity for content management
- Logging or metric generation

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

The location values MUST point to the **exact position where the violation occurs** - specifically, the sink where weak hash is used.

**DO NOT** report:
- The line where the function is defined
- The line where the class or method starts
- Non-security usage of weak hashes

**DO** report:
- The precise line containing the weak hash algorithm call in a security context

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

Detects Weak Hash (CWE-328) when MD5 or SHA-1 is used for security-sensitive operations like password hashing, token generation, or signature verification.
