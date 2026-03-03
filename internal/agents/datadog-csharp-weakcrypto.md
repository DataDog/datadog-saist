# C# User Prompt Template — Broken Cryptography (Weak Algorithm)

Evaluate the following C# code located in <path> and report ONLY Broken Cryptography vulnerabilities involving **weak algorithms**. If you are unsure about the validity of a result do NOT report it.

```csharp
<code>
```

## Vulnerability to Find

Report where there are **Broken Cryptography** vulnerabilities as instructed.

This vulnerability is known as **CWE-327**.

<relatedFilesInformation>

---

## ⚠️ CRITICAL: What IS and IS NOT a Weak Algorithm

### WEAK ALGORITHMS — ALWAYS REPORT THESE:
- `DES` — 56-bit key, trivially broken
- `TripleDES` / `3DES` / `Triple-DES` — deprecated, use AES instead
- `RC2` — weak and deprecated
- `RC4` / `ARC4` — broken stream cipher (if implemented)
- `Blowfish` — if key < 128 bits (if implemented)
- `IDEA` — older algorithm
- `CAST5` — older algorithm
- RSA with key size < 2048 bits

### STRONG ALGORITHMS — DO NOT FLAG AS WEAK:
- **`Aes`** / `AES-128` / `AES-256` — This is a STRONG algorithm. Do NOT report AES as weak.
- **`RSA`** (with key >= 2048) — Strong asymmetric encryption
- **`AesGcm`** — Authenticated AES encryption
- **`AesCcm`** — Authenticated AES encryption
- **`ChaCha20Poly1305`** — Modern authenticated encryption (if available)
- **`Camellia`** — Strong block cipher (if available)
- **`Twofish`** — Strong block cipher (if available)
- **`Serpent`** — Strong block cipher (if available)

### MODE ISSUES — Handle Separately:
- ECB mode with AES (`CipherMode.ECB`) is a **mode problem**, NOT a weak algorithm
- AES with ECB mode should NOT be reported as "weak algorithm"
- AES with CBC, GCM modes are all excellent

---

## Context

**Language:** C#  
**Frameworks/Libraries:** <e.g., System.Security.Cryptography>  

**Weak algorithms (REPORT when used):**  
- `DES.Create()`, `DESCryptoServiceProvider` — DES is broken
- `TripleDES.Create()`, `TripleDESCryptoServiceProvider` — 3DES is deprecated
- `RC2.Create()`, `RC2CryptoServiceProvider` — RC2 is weak
- RSA with key size < 2048

**Strong algorithms (DO NOT report as weak):**  
- `Aes.Create()` — AES is STRONG, regardless of mode
- `new AesManaged()` — AES is STRONG
- `AesCryptoServiceProvider` — AES is STRONG
- `new AesGcm(key)` — Authenticated AES encryption
- `AesCcm` — Authenticated AES encryption
- `RSACryptoServiceProvider` — RSA is STRONG (with key >= 2048)
- `RSA.Create()` with key size >= 2048 bits

**FALSE POSITIVE AVOIDANCE - Constant propagation:**
When analyzing taint flow, be aware of methods that return CONSTANT values regardless of their input:
- If a class is instantiated with tainted data but a method returns a hardcoded string, that return value is NOT tainted
- Track the actual data flow: does the method return user-controlled data, or does it return a constant/static value?

---

## Rules and Guidelines

1. Report **only weak ALGORITHM** vulnerabilities (DES, 3DES, RC2, small RSA keys).
2. **DO NOT report AES as a weak algorithm** — AES is strong regardless of mode.
3. **DO NOT report AES/ECB as weak algorithm** — ECB is a mode issue, not algorithm issue.
4. **DO NOT report RSA as weak** if key size is >= 2048 bits.
5. Report the **exact location** where the weak algorithm is instantiated.
6. Output must be valid JSON; if no issues found:  
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify cryptographic algorithm usage.  
2. Check for weak algorithms or configurations.  
3. Look for hardcoded keys or static IVs.  
4. Report weak cryptographic practices.

---

## Patterns to Look For

### VULNERABLE — Weak Algorithms (REPORT THESE)

```csharp
// Using DES - VULNERABLE (56-bit key is broken)
using var des = DES.Create();  // <-- REPORT: DES is weak
```

```csharp
// Using TripleDES - VULNERABLE (deprecated)
using var tdes = TripleDES.Create();  // <-- REPORT: 3DES is deprecated
```

```csharp
// Using RC2 - VULNERABLE
using var rc2 = RC2.Create();  // <-- REPORT: RC2 is weak
```

```csharp
// RSA with small key - VULNERABLE
using var rsa = RSA.Create(1024);  // <-- REPORT: Key size < 2048
```

```csharp
// RSA with 512-bit key - VULNERABLE
using var rsa = RSA.Create(512);  // <-- REPORT: Trivially broken
```

### SAFE — Strong Algorithms (DO NOT REPORT)

```csharp
// AES - SAFE (strong algorithm)
using var aes = Aes.Create();  // DO NOT REPORT - AES is strong
```

```csharp
// AES with CBC mode - SAFE
using var aes = Aes.Create();
aes.Mode = CipherMode.CBC;
aes.GenerateKey();
aes.GenerateIV();  // DO NOT REPORT
```

```csharp
// AES with ECB mode - Algorithm is STRONG (mode is suboptimal but don't flag as weak algorithm)
using var aes = Aes.Create();
aes.Mode = CipherMode.ECB;  // DO NOT REPORT as weak algorithm - AES itself is strong
```

```csharp
// AES-GCM - SAFE (authenticated encryption)
using var aesGcm = new AesGcm(key);
aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);  // DO NOT REPORT
```

```csharp
// RSA with adequate key size - SAFE
using var rsa = RSA.Create(2048);  // DO NOT REPORT - adequate key size
```

```csharp
// RSA with 4096-bit key - SAFE
using var rsa = RSA.Create(4096);  // DO NOT REPORT - excellent key size
```

---

## Common False Positive to Avoid

**AES with any mode is NOT a weak algorithm:**

```csharp
// This is NOT a weak algorithm vulnerability!
using var aes = Aes.Create();
aes.Mode = CipherMode.ECB;
// AES is strong. ECB mode is suboptimal but the ALGORITHM is not weak.
// DO NOT REPORT THIS.
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

The location values MUST point to the **exact position where the violation occurs** - specifically, the sink where weak crypto is used.

**DO NOT** report:
- The line where the function is defined
- The line where the class or method starts

**DO** report:
- The precise line containing the weak cryptographic algorithm or configuration

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

Detects Broken Cryptography (CWE-327) by identifying weak algorithms (DES, TripleDES, RC2, ECB mode), hardcoded keys, or static IVs.
