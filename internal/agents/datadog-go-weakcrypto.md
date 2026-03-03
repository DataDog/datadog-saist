# Go User Prompt Template — Broken Cryptography (Weak Algorithm)

Evaluate the following Go code located in `<path>` and report ONLY Broken Cryptography vulnerabilities involving **weak algorithms**. If you are unsure about the validity of a result do NOT report it.

```go
<code>
```

## Vulnerability to Find

Report where there are **Broken Cryptography** vulnerabilities as instructed.

This vulnerability is known as **CWE-327**.

<relatedFilesInformation>

---

## ⚠️ CRITICAL: What IS and IS NOT a Weak Algorithm

### WEAK ALGORITHMS — ALWAYS REPORT THESE:
- `crypto/des` — DES and 3DES have weak key sizes
- `crypto/rc4` — RC4 is a broken stream cipher
- RSA with key size < 2048 bits
- Any implementation of `RC2`, `Blowfish` (if key < 128 bits), `IDEA`, `CAST5`

### STRONG ALGORITHMS — DO NOT FLAG AS WEAK:
- **`crypto/aes`** — This is a STRONG algorithm. Do NOT report AES as weak.
- **`crypto/rsa`** (with key >= 2048) — Strong asymmetric encryption
- **`golang.org/x/crypto/chacha20poly1305`** — Modern authenticated encryption
- **`golang.org/x/crypto/nacl`** — High-level crypto library
- **`golang.org/x/crypto/twofish`** — Strong block cipher
- **`golang.org/x/crypto/serpent`** — Strong block cipher (if available)

### MODE ISSUES — Handle Separately:
- ECB-like patterns with AES are a **mode problem**, NOT a weak algorithm
- Using `cipher.NewCBCEncrypter`, `cipher.NewGCM`, `cipher.NewCTR` are all fine
- AES with any mode is NOT a weak algorithm

---

## Context

**Language:** Go  
**Frameworks/Libraries:** <e.g., crypto/aes, crypto/des, crypto/rsa, crypto/rand>  

**Weak/Broken cryptographic algorithms (REPORT when used):**  
- `des.NewCipher(key)` — DES is broken (56-bit key)
- `des.NewTripleDESCipher(key)` — 3DES is deprecated
- `rc4.NewCipher(key)` — RC4 is broken
- RSA with `rsa.GenerateKey(rand.Reader, 1024)` or smaller

**Strong algorithms (DO NOT report as weak):**  
- `aes.NewCipher(key)` — AES is STRONG, any usage
- `cipher.NewGCM(block)` — AES-GCM is excellent
- `cipher.NewCBCEncrypter(block, iv)` — AES-CBC is strong
- `cipher.NewCBCDecrypter(block, iv)` — AES-CBC is strong
- `cipher.NewCTR(block, iv)` — AES-CTR is strong
- `cipher.NewOFB(block, iv)` — AES-OFB is strong
- `rsa.GenerateKey(rand.Reader, 2048)` — RSA with adequate key
- `chacha20poly1305.New(key)` — Modern authenticated encryption
- `golang.org/x/crypto/nacl` — High-level crypto library

---

## Rules and Guidelines

1. Report **only weak ALGORITHM** vulnerabilities (DES, 3DES, RC4).
2. **DO NOT report AES as a weak algorithm** — AES is strong regardless of usage pattern.
3. **DO NOT report RSA as weak** if key size is >= 2048 bits.
4. Report the **exact location** where the weak algorithm is instantiated.
5. Output must be valid JSON; if no issues found:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify cryptographic algorithm instantiation.
2. Check the package — is it `crypto/des` or `crypto/rc4`?
3. For RSA, check the key size parameter — is it < 2048?
4. If weak algorithm found, report it.
5. **If `crypto/aes` is used, do NOT report it as weak.**

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

## Common False Positive to Avoid

**AES with any usage pattern is NOT a weak algorithm:**

```go
// This is NOT a weak algorithm vulnerability!
block, _ := aes.NewCipher(key)
// Even if used in a simple way, AES itself is strong.
// DO NOT REPORT THIS.
```

**Constant propagation - user input NOT used in crypto:**

```go
// Even if user input is processed earlier, if a CONSTANT is used for crypto, it's SAFE
param := r.FormValue("input")  // User input
// ... complex processing of param that is NOT used later ...
_ = param  // param explicitly discarded

g87760 := "barbarians_at_the_gate"  // CONSTANT STRING
bar := doSomething(g87760)           // Returns constant

input := []byte(bar)  // input derived from CONSTANT, not user
block, _ := aes.NewCipher(key)
mode := cipher.NewCBCEncrypter(block, iv)
mode.CryptBlocks(encrypted, input)  // DO NOT REPORT - input is constant
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
