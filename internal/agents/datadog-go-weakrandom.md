# Go User Prompt Template — Weak Randomness

Evaluate the following Go code located in <path> and report ONLY Weak Randomness vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```go
<code>
```

## Vulnerability to Find

Report where there are **Weak Randomness** vulnerabilities as instructed.

This vulnerability is known as **CWE-330**.

<relatedFilesInformation>

---

## Context

**Language:** Go  
**Frameworks/Libraries:** math/rand, crypto/rand

**CRITICAL: Distinguish math/rand (WEAK) vs crypto/rand (SAFE)**

Check the import statement:
- `import "math/rand"` = **WEAK** (flag when used for security)
- `import "crypto/rand"` = **SAFE** (never flag)
- If aliased (e.g., `import mrand "math/rand"`), track the alias

**Weak random sources (from math/rand - flag when used for security purposes):**  
- `rand.Int()` — returns non-negative pseudo-random int
- `rand.Intn(n)` — returns [0, n) pseudo-random int
- `rand.Int31()` — returns 31-bit pseudo-random int
- `rand.Int63()` — returns 63-bit pseudo-random int
- `rand.Float32()` — returns [0.0, 1.0) pseudo-random float
- `rand.Float64()` — returns [0.0, 1.0) pseudo-random float
- `rand.Read(p)` — **from math/rand, NOT crypto/rand** - fills p with pseudo-random bytes
- `rand.Uint32()` — returns pseudo-random uint32
- `rand.Uint64()` — returns pseudo-random uint64
- `rand.Shuffle(n, swap)` — when used for security token generation
- `rand.New(rand.NewSource(...))` with predictable seeds
- `rand.Seed()` with predictable values (e.g., `time.Now().UnixNano()`)

**Security-sensitive contexts (report if weak random is used):**  
- Token generation (session tokens, CSRF tokens, API keys)
- Password generation or reset tokens
- Cryptographic key generation
- Nonce or IV generation
- One-time passwords (OTP)
- Random identifiers for security purposes (e.g., verification codes)

**Non-security contexts (do NOT report):**  
- Test data generation
- Game mechanics or simulations
- Shuffling for display purposes
- Load balancing or sampling
- Random delays or jitter
- Generating non-sensitive identifiers

**Secure alternatives (treat as safe - from crypto/rand):**  
- `crypto/rand.Read(buffer)` — cryptographically secure random bytes
- `crypto/rand.Int(rand.Reader, max)` — cryptographically secure random int
- `crypto/rand.Prime(rand.Reader, bits)` — cryptographically secure prime
- Any function from the `crypto/rand` package

**IMPORTANT: rand.Read() distinction**
```go
// WEAK - math/rand.Read (flag this)
import "math/rand"
rand.Read(buffer)  // VULNERABLE - pseudo-random, NOT crypto-secure

// SAFE - crypto/rand.Read (do NOT flag)
import "crypto/rand"
rand.Read(buffer)  // SAFE - cryptographically secure
```

---

## Rules and Guidelines

1. Report **only Weak Randomness** vulnerabilities in security-sensitive contexts.
2. Do NOT report weak random used for non-security purposes.
3. Consider the context — token generation vs. test data.
4. Report the **exact location of the sink** where the weak random is used (e.g., `rand.Intn()`), NOT the line where data originates. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.
5. Output must be valid JSON; if no issues found, output exactly:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify random number generation usage.
2. Determine the random source (math/rand vs. crypto/rand).
3. Assess if used for security purposes.
4. Report weak random sources only in security contexts.

---

## Patterns to Look For

### Vulnerable (Token generation with math/rand)
```go
func generateToken() string {
    token := make([]byte, 32)
    for i := range token {
        token[i] = byte(rand.Intn(256))  // <-- SINK: math/rand for security token
    }
    return base64.StdEncoding.EncodeToString(token)
}
```

### Vulnerable (Session ID with math/rand)
```go
func createSessionID() string {
    return fmt.Sprintf("session_%d", rand.Int63())  // <-- SINK
}
```

### Vulnerable (Password generation with math/rand)
```go
func generatePassword(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyz"
    password := make([]byte, length)
    for i := range password {
        password[i] = charset[rand.Intn(len(charset))]  // <-- SINK
    }
    return string(password)
}
```

### Vulnerable (API key with predictable seed)
```go
rand.Seed(time.Now().UnixNano())  // Predictable seed
apiKey := fmt.Sprintf("%016x", rand.Uint64())  // <-- SINK
```

### Vulnerable (OTP generation with math/rand)
```go
func generateOTP() string {
    return fmt.Sprintf("%06d", rand.Intn(1000000))  // <-- SINK
}
```

### Safe (crypto/rand for tokens)
```go
func generateSecureToken() (string, error) {
    token := make([]byte, 32)
    if _, err := cryptorand.Read(token); err != nil {  // crypto/rand - SAFE
        return "", err
    }
    return base64.StdEncoding.EncodeToString(token), nil
}
```

### Safe (crypto/rand.Int)
```go
func secureRandomInt(max int64) (int64, error) {
    n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(max))  // SAFE
    if err != nil {
        return 0, err
    }
    return n.Int64(), nil
}
```

### Safe (math/rand for test data - NOT SECURITY SENSITIVE)
```go
func generateTestData(count int) []int {
    data := make([]int, count)
    for i := range data {
        data[i] = rand.Intn(100)  // Don't report - test data
    }
    return data
}
```

### Safe (math/rand for shuffling display - NOT SECURITY SENSITIVE)
```go
rand.Shuffle(len(items), func(i, j int) {
    items[i], items[j] = items[j], items[i]  // Don't report - display shuffling
})
```

### Safe (math/rand for jitter - NOT SECURITY SENSITIVE)
```go
jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
time.Sleep(baseDelay + jitter)  // Don't report - timing jitter
```

### Vulnerable (Remember-me token with weak random)
```go
// Weak random for authentication tokens is ALWAYS vulnerable
// Even if validated server-side, the token is predictable and can be brute-forced
rememberMeKey := fmt.Sprintf("%d", rand.Intn(99))
session.Values[cookieName] = rememberMeKey  // <-- SINK: predictable token
```

### Vulnerable (Session token with rand.Int63)
```go
r := rand.Int63()
rememberMeKey := strconv.FormatInt(r, 10)  // <-- SINK: predictable token
```

### Safe (crypto/rand for actual token, math/rand for other purposes)
```go
func generateSessionID() (string, error) {
    b := make([]byte, 32)
    _, err := cryptorand.Read(b)  // crypto/rand for actual token - SAFE
    return base64.StdEncoding.EncodeToString(b), err
}
// Even if math/rand is also imported, the security-sensitive token uses crypto/rand
```

---

## CRITICAL: Do NOT Report These Patterns

1. **When crypto/rand is used for the actual security token** - even if math/rand is also present in the file for other purposes
2. **When the file imports both crypto/rand and math/rand** - check which is used for the security-sensitive operation

## IMPORTANT: Session Validation Does NOT Make Weak Random Safe

Even when a weak random token is:
- Stored server-side in a session
- Verified against session storage on subsequent requests

The vulnerability (CWE-330) still exists because:
- The token is predictable and can be brute-forced
- An attacker can guess valid tokens without knowing the session
- The small keyspace of math/rand makes exhaustive search feasible

**Always report weak random used for authentication tokens, regardless of verification method.**

---

## How to Identify Security Context

Security-sensitive indicators:
- Method/variable names: `token`, `password`, `key`, `secret`, `session`, `auth`, `otp`, `verification`, `csrf`, `nonce`
- Storing result in authentication or session context
- Sending result in email for verification
- Using result as cryptographic material

Non-security indicators:
- Names: `test`, `sample`, `mock`, `shuffle`, `random`, `jitter`, `delay`
- Unit test files or test methods (`_test.go`)
- Display ordering or pagination
- Timing or load balancing

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

The location values MUST point to the **exact position where the violation occurs** - specifically, the sink where weak random is used for security purposes.

**DO NOT** report:
- The line where the function is defined
- The line where the class or method starts
- Non-security usage of math/rand

**DO** report:
- The precise line containing the weak random call in a security context

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

Detects Weak Randomness (CWE-330) when math/rand is used for security-sensitive operations like token generation, password creation, or cryptographic key derivation.
