# Go User Prompt Template — Weak Hash

Evaluate the following Go code located in `<path>` and report ONLY Weak Hash vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```go
<code>
```

## Vulnerability to Find

Report where there are **Weak Hash** vulnerabilities as instructed.

This vulnerability is known as **CWE-328**.

<relatedFilesInformation>

---

## 🚫🚫🚫 CRITICAL: ONLY FLAG MD5 AND SHA-1 🚫🚫🚫

**ONLY REPORT these specific function calls:**
- `md5.New()` — MD5 is weak
- `md5.Sum()` — MD5 is weak  
- `sha1.New()` — SHA-1 is weak
- `sha1.Sum()` — SHA-1 is weak

**NEVER REPORT any of these:**
- `crypto.SHA256` — STRONG
- `crypto.SHA384` — STRONG
- `crypto.SHA512` — STRONG
- `hashAlg.New()` when hashAlg is SHA256/SHA384/SHA512 — STRONG
- Any dynamic hash selection that DEFAULTS to SHA256 — STRONG

**If the code defaults to SHA256 for unknown algorithms, it is SAFE. Output "NO VIOLATION AMIGO".**

---

## ⚠️ CRITICAL: Distinguish WEAK vs STRONG Hash Algorithms

### WEAK ALGORITHMS — ONLY REPORT THESE:
- `crypto/md5` — MD5 is cryptographically broken
- `crypto/sha1` — SHA-1 has known collision attacks
- `md5.New()`, `md5.Sum()` — MD5 functions
- `sha1.New()`, `sha1.Sum()` — SHA-1 functions

### STRONG ALGORITHMS — NEVER REPORT:
- **`crypto.SHA256`** — SHA-256 is STRONG, NEVER report
- **`crypto.SHA384`** — SHA-384 is STRONG, NEVER report
- **`crypto.SHA512`** — SHA-512 is STRONG, NEVER report
- **`crypto/sha256`** — SHA-256 is STRONG, DO NOT report
- **`crypto/sha512`** — SHA-512 is STRONG, DO NOT report
- **`sha256.New()`**, **`sha256.Sum256()`** — Strong hash functions
- **`sha512.New()`**, **`sha512.Sum512()`** — Strong hash functions
- **`sha256.New224()`** — SHA-224 is acceptable
- **`sha512.New384()`** — SHA-384 is strong
- **`golang.org/x/crypto/sha3`** — SHA-3 family is strong
- **`golang.org/x/crypto/blake2b`**, **`blake2s`** — Modern strong hashes
- **`golang.org/x/crypto/bcrypt`** — Password hashing (strong)
- **`golang.org/x/crypto/scrypt`** — Key derivation (strong)
- **`golang.org/x/crypto/argon2`** — Password hashing (strong)

### DYNAMIC ALGORITHM SELECTION — ANALYZE CAREFULLY:
When code selects hash algorithm dynamically (e.g., from config), check the DEFAULT:
- If default is SHA256/SHA384/SHA512 → SAFE, DO NOT REPORT
- If default is MD5 or SHA1 → REPORT

---

## Context

**Language:** Go  
**Frameworks/Libraries:** crypto/md5, crypto/sha1, crypto/sha256, crypto/sha512

**Security-sensitive contexts (report if WEAK hash is used):**  
- Password hashing or storage  
- Digital signatures or integrity verification  
- Token generation for authentication  
- Certificate validation  
- Cryptographic key derivation  

**Non-security contexts (do NOT report even for weak hashes):**  
- Cache keys or checksums for non-security purposes  
- Content-addressable storage identifiers  
- File deduplication  
- ETags for HTTP caching  
- Logging or debugging purposes  

---

## Rules and Guidelines

1. Report **only Weak Hash** vulnerabilities (MD5, SHA-1) in security-sensitive contexts.  
2. **DO NOT report SHA-256, SHA-384, SHA-512** — these are STRONG hashes.
3. **DO NOT report SHA3, BLAKE2** — these are modern strong hashes.
4. Consider the context — password storage vs. cache key.  
5. Report the **exact location** where the weak hash is instantiated.
6. Output must be valid JSON; if no issues found:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify hash function usage by checking imports and function calls.
2. Determine the hash algorithm (MD5, SHA-1, SHA-256, etc.).
3. **If SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2, bcrypt, scrypt, or argon2** → DO NOT REPORT.
4. If MD5 or SHA-1 and used for security purposes → REPORT.

---

## Patterns to Look For

### Vulnerable (MD5 for password hashing)
```go
import "crypto/md5"

func hashPassword(password string) []byte {
    h := md5.New()  // <-- SINK: MD5 is weak
    h.Write([]byte(password))
    return h.Sum(nil)
}
```

### Vulnerable (SHA-1 for token generation)
```go
import "crypto/sha1"

func generateToken(data string) []byte {
    h := sha1.New()  // <-- SINK: SHA-1 is weak
    h.Write([]byte(data))
    return h.Sum(nil)
}
```

### Vulnerable (md5.Sum for integrity)
```go
hash := md5.Sum([]byte(sensitiveData))  // <-- SINK: MD5 is weak
```

### SAFE — Strong Algorithms (DO NOT REPORT)

```go
import "crypto/sha256"

func hashPassword(password string) []byte {
    h := sha256.New()  // DO NOT REPORT - SHA-256 is strong
    h.Write([]byte(password))
    return h.Sum(nil)
}
```

```go
// SHA-256 sum function - SAFE
hash := sha256.Sum256([]byte(data))  // DO NOT REPORT
```

```go
import "crypto/sha512"

func secureHash(data string) []byte {
    h := sha512.New()  // DO NOT REPORT - SHA-512 is strong
    h.Write([]byte(data))
    return h.Sum(nil)
}
```

```go
// SHA-384 - SAFE
h := sha512.New384()  // DO NOT REPORT
```

```go
// bcrypt for passwords - SAFE
import "golang.org/x/crypto/bcrypt"

hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)  // DO NOT REPORT
```

### SAFE — Algorithm from config that defaults to strong

```go
// When algorithm comes from config but defaults to SHA-256
algorithm := props["hashAlg2"]
if algorithm == "" {
    algorithm = "SHA256"  // Strong default
}
// If actual algorithm is SHA-256, SHA-384, or SHA-512 → DO NOT REPORT
```

### SAFE — Dynamic crypto.Hash selection with SHA256 default

```go
// This pattern is SAFE because unknown algorithms default to SHA256
func getHashAlgorithm(algName string) (crypto.Hash, error) {
    switch strings.ToUpper(algName) {
    case "SHA-1", "SHA1":
        return crypto.SHA1, nil
    case "SHA-256", "SHA256":
        return crypto.SHA256, nil  // STRONG
    case "MD5":
        return crypto.MD5, nil
    default:
        return crypto.SHA256, nil  // DEFAULT TO SHA256 = STRONG
    }
}

hashAlg, _ := getHashAlgorithm(algorithm)
md := hashAlg.New()  // DO NOT REPORT - defaults to SHA256 which is STRONG
md.Write(input)
result := md.Sum(nil)
```

### SAFE — crypto.Hash variable when default is strong

```go
// When a crypto.Hash is obtained from a function that defaults to SHA256
hashAlg := getHashAlgorithm(props["hashAlg2"])  // Defaults to SHA256
if hashAlg == crypto.SHA256 || hashAlg == crypto.SHA384 || hashAlg == crypto.SHA512 {
    // STRONG - DO NOT REPORT
}
md := hashAlg.New()  // DO NOT REPORT if default is strong
```

---

## Common False Positive to Avoid

**SHA-256/SHA-512 are NOT weak:**

```go
import "crypto/sha256"

h := sha256.New()  // DO NOT REPORT - this is a STRONG hash
```

**Dynamic algorithm selection that defaults to SHA256:**

```go
// Even if code reads algorithm from config, if the DEFAULT is SHA256,
// DO NOT REPORT the hashAlg.New() call
// The vulnerability would only exist if MD5 or SHA1 is explicitly selected
```

**Properties file specifying strong algorithm:**

```go
// If benchmark.properties contains "hashAlg2=SHA256" OR if the
// default case in getHashAlgorithm returns crypto.SHA256,
// The hash being used is SHA-256 which is STRONG
// DO NOT REPORT even if code has complex algorithm selection
```

---

## Output

The answer must be a JSON formatted answer.
Each value in the JSON array has the following attributes:
- `startLine`: the line number where the vulnerability starts
- `startColumn`: the column number where the vulnerability starts (1-indexed)
- `endLine`: the line number where the vulnerability ends
- `endColumn`: the column number where the vulnerability ends (1-indexed, exclusive)
- `reason`: why the issue is a true vulnerability

If there is no violation, write "NO VIOLATION AMIGO"

---

## Summary

Detects **Weak Hash (CWE-328)** vulnerabilities in Go code. Reports only MD5 and SHA-1 in security contexts. **Never reports SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2, bcrypt, scrypt, or argon2.**
