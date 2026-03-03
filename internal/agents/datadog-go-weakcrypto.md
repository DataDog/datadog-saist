# Go User Prompt Template — Broken Cryptography (Weak Algorithm)

Evaluate the following Go code located in `<path>` and report ONLY Broken Cryptography vulnerabilities.

```go
<code>
```

## Vulnerability to Find

Report **ONLY** vulnerabilities involving these specific weak algorithms: **DES, 3DES, or RC4**.

This vulnerability is known as **CWE-327**.

<relatedFilesInformation>

---

## 🛑 SCOPE: ONLY CHECK FOR DES AND RC4 🛑

**This rule ONLY detects these specific weak algorithms:**

1. **DES** — `crypto/des` package, `des.NewCipher()`
2. **3DES** — `des.NewTripleDESCipher()`  
3. **RC4** — `crypto/rc4` package, `rc4.NewCipher()`

**If the code does NOT use `crypto/des` or `crypto/rc4`, output "NO VIOLATION AMIGO".**

**DO NOT analyze or report any other cryptographic code.**

---

## What to Look For

Search ONLY for these specific patterns:

```go
import "crypto/des"      // ← If present, check for des.NewCipher or des.NewTripleDESCipher
import "crypto/rc4"      // ← If present, check for rc4.NewCipher
```

**If neither `crypto/des` nor `crypto/rc4` is imported, there is no vulnerability. Output "NO VIOLATION AMIGO".**

---

## WEAK ALGORITHMS — ONLY REPORT THESE SPECIFIC FUNCTIONS:

```go
des.NewCipher(key)           // ← REPORT: DES is weak (56-bit key)
des.NewTripleDESCipher(key)  // ← REPORT: 3DES is deprecated
rc4.NewCipher(key)           // ← REPORT: RC4 is broken
```

**NOTHING ELSE is a weak algorithm for this rule.**

---

## Rules and Guidelines

1. **ONLY report** `des.NewCipher()`, `des.NewTripleDESCipher()`, or `rc4.NewCipher()`.
2. **IGNORE all other crypto code** — it is out of scope for this rule.
3. If the code imports `crypto/aes` but NOT `crypto/des` or `crypto/rc4`, output "NO VIOLATION AMIGO".
4. Output must be valid JSON; if no issues found:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Check imports — does the code import `crypto/des` or `crypto/rc4`?
2. If NO → Output "NO VIOLATION AMIGO"
3. If YES → Search for `des.NewCipher()`, `des.NewTripleDESCipher()`, or `rc4.NewCipher()` and report those lines only.

---

## Patterns to Look For

### VULNERABLE — Weak Algorithms (REPORT THESE)

```go
// Using DES - VULNERABLE (56-bit key is broken)
import "crypto/des"

block, err := des.NewCipher(key)  // <-- REPORT: DES is weak
```

```go
// Using 3DES - VULNERABLE (deprecated)
block, err := des.NewTripleDESCipher(key)  // <-- REPORT: 3DES is deprecated
```

```go
// Using RC4 - VULNERABLE (broken cipher)
import "crypto/rc4"

cipher, err := rc4.NewCipher(key)  // <-- REPORT: RC4 is broken
```

```go
// RSA with small key - VULNERABLE
privateKey, err := rsa.GenerateKey(rand.Reader, 1024)  // <-- REPORT: Key size < 2048
```

```go
// RSA with 512-bit key - VULNERABLE
privateKey, err := rsa.GenerateKey(rand.Reader, 512)  // <-- REPORT: Trivially broken
```

### SAFE — Strong Algorithms (DO NOT REPORT)

```go
// AES cipher creation - SAFE (strong algorithm)
import "crypto/aes"

block, err := aes.NewCipher(key)  // DO NOT REPORT - AES is strong
```

```go
// AES-GCM - SAFE (authenticated encryption)
block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)  // DO NOT REPORT
```

```go
// AES-CBC - SAFE (strong algorithm)
block, _ := aes.NewCipher(key)
mode := cipher.NewCBCEncrypter(block, iv)  // DO NOT REPORT
```

```go
// AES-CTR - SAFE (strong algorithm)
block, _ := aes.NewCipher(key)
stream := cipher.NewCTR(block, iv)  // DO NOT REPORT
```

```go
// ChaCha20-Poly1305 - SAFE (modern authenticated encryption)
import "golang.org/x/crypto/chacha20poly1305"

aead, _ := chacha20poly1305.New(key)  // DO NOT REPORT
```

```go
// RSA with adequate key size - SAFE
privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)  // DO NOT REPORT
```

```go
// RSA with 4096-bit key - SAFE
privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)  // DO NOT REPORT
```

---

## Common False Positive to Avoid — CRITICAL

### 1. AES is NEVER a weak algorithm

```go
// SAFE - DO NOT REPORT ANY OF THESE:
import "crypto/aes"

block, _ := aes.NewCipher(key)          // SAFE - AES is strong
mode := cipher.NewCBCEncrypter(block, iv)  // SAFE - AES-CBC is strong
mode.CryptBlocks(encrypted, input)      // SAFE - using strong cipher

// The entire crypto/aes package is STRONG. Never flag it.
```

### 2. AES-192 and AES-256 are STRONG

```go
// 24-byte key = AES-192 = STRONG
var aesKey = []byte("thisisaverysecretkey12345")  // 24 bytes
block, _ := aes.NewCipher(aesKey)  // SAFE - AES-192

// 32-byte key = AES-256 = STRONG
var aesKey256 = []byte("thisisaverysecretkey12345678901")  // 32 bytes
block, _ := aes.NewCipher(aesKey256)  // SAFE - AES-256
```

### 3. Constant propagation - user input NOT used in crypto

```go
// Even if user input is processed earlier, if a CONSTANT is used for crypto, it's SAFE
param := r.FormValue("input")  // User input processed...
// ... complex processing of param ...
_ = param  // ...but then discarded

g87760 := "barbarians_at_the_gate"  // CONSTANT STRING used instead
bar := doSomething(g87760)           // Returns constant

input := []byte(bar)  // input derived from CONSTANT, not user
block, _ := aes.NewCipher(key)
mode := cipher.NewCBCEncrypter(block, iv)
mode.CryptBlocks(encrypted, input)  // DO NOT REPORT - using AES (strong) with constant input
```

### 4. Helper functions that return AES cipher

```go
func getCipherBlock() (cipher.Block, error) {
    return aes.NewCipher(aesKey)  // SAFE - returns AES cipher
}

block, _ := getCipherBlock()
mode := cipher.NewCBCEncrypter(block, aesIV)  // SAFE - AES-CBC
// DO NOT REPORT - this is AES which is a STRONG algorithm
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

Detects Broken Cryptography (CWE-327) when using **weak algorithms**: DES (`crypto/des`), RC4 (`crypto/rc4`), or RSA with key < 2048 bits.

**IMPORTANT**: AES (`crypto/aes`) is a STRONG algorithm. Do NOT report AES as weak regardless of how it's used.
