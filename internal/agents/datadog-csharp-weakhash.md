# C# User Prompt Template — Weak Hash

Evaluate the following C# code located in <path> and report ONLY Weak Hash vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```csharp
<code>
```

## Vulnerability to Find

Report where there are **Weak Hash** vulnerabilities as instructed.

This vulnerability is known as **CWE-328**.

<relatedFilesInformation>

---

## Context

**Language:** C#  
**Frameworks/Libraries:** <e.g., System.Security.Cryptography>  

**Sensitive inputs that require strong hashing:**  
- Passwords, credentials  
- Security tokens, session IDs  
- Digital signatures  
- Cryptographic keys or key derivation  

**Weak hash algorithms (ALWAYS report for security-sensitive data):**  
- `MD5.Create()`, `MD5CryptoServiceProvider`, `new MD5CryptoServiceProvider()`
- `SHA1.Create()`, `SHA1CryptoServiceProvider`, `new SHA1CryptoServiceProvider()`
- `SHA1Managed`, `MD5Managed`
- `HMACMD5`, `HMACSHA1` (for security purposes)  
- `HashAlgorithm.Create("MD5")`, `HashAlgorithm.Create("SHA1")`

**Strong hash algorithms (safe):**  
- `SHA256.Create()`, `SHA384.Create()`, `SHA512.Create()`  
- `SHA256Managed`, `SHA384Managed`, `SHA512Managed`
- `Rfc2898DeriveBytes` (PBKDF2) for passwords  
- BCrypt, Argon2 (external libraries like BCrypt.Net)  

**Non-security uses (acceptable for weak hashes — do NOT report):**  
- Checksums for data integrity (non-security)  
- Cache keys, ETags  
- Content deduplication  
- File fingerprinting for content management

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report only Weak Hash vulnerabilities for security-sensitive operations.  
2. Trigger if MD5 or SHA-1 is used for passwords, tokens, or signatures.  
3. Avoid false positives for non-security uses like checksums or cache keys.  
4. Report the **exact location of the sink** where the weak hash is created or used (e.g., `MD5.Create()`, `ComputeHash()`). You must specify: `startLine`, `endLine`, `startColumn`, and `endColumn`.  
5. Output must be valid JSON; if no issues found:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify hash algorithm usage.  
2. Determine if the hash is used for security-sensitive purposes.  
3. Check if a weak algorithm (MD5, SHA-1) is being used.  
4. Report weak hash usage for sensitive data.

---

## How to Identify Security Context

Security-sensitive indicators:
- Method/variable names: `password`, `credential`, `token`, `auth`, `signature`, `verify`, `secret`
- Storing hashes in user/credential tables
- Comparison for authentication
- Key derivation contexts

Non-security indicators:
- Names: `cache`, `checksum`, `etag`, `fingerprint`, `dedupe`, `content-hash`
- File integrity for content management
- Logging or metric generation

---

## Patterns to Look For

### Vulnerable (MD5 for password)
```csharp
using var md5 = MD5.Create();  // <-- SINK
byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
```

### Vulnerable (SHA1 for token)
```csharp
using var sha1 = SHA1.Create();  // <-- SINK
byte[] tokenHash = sha1.ComputeHash(tokenBytes);
```

### Vulnerable (MD5CryptoServiceProvider)
```csharp
using var md5 = new MD5CryptoServiceProvider();  // <-- SINK
var passwordHash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
```

### Vulnerable (HashAlgorithm.Create)
```csharp
var hasher = HashAlgorithm.Create("MD5");  // <-- SINK
var hash = hasher.ComputeHash(Encoding.UTF8.GetBytes(password));
```

### Vulnerable (HMACSHA1 for authentication)
```csharp
using var hmac = new HMACSHA1(keyBytes);  // <-- SINK (weak for auth)
var signature = hmac.ComputeHash(messageBytes);
```

### Safe (SHA256 for security)
```csharp
using var sha256 = SHA256.Create();
byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));  // SAFE
```

### Safe (PBKDF2 for passwords)
```csharp
// For passwords, use PBKDF2
var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
byte[] hash = pbkdf2.GetBytes(32);  // SAFE
```

### Safe (BCrypt for passwords)
```csharp
// Using BCrypt.Net library
string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);  // SAFE
```

### Safe (MD5 for non-security checksum)
```csharp
// MD5 for non-security checksum is acceptable
using var md5 = MD5.Create();
byte[] checksum = md5.ComputeHash(fileBytes);  // Cache key/content hash, not security
```

### Safe (SHA1 for cache key)
```csharp
// SHA1 for ETag generation - not security sensitive
using var sha1 = SHA1.Create();
var etag = Convert.ToBase64String(sha1.ComputeHash(contentBytes));  // SAFE - cache use
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

Detects Weak Hash (CWE-328) by identifying MD5 or SHA-1 usage for security-sensitive operations like password hashing or token generation.
