# Java User Prompt Template — Broken Cryptography (Weak Algorithm)

Evaluate the following Java code located in <path> and report ONLY Broken Cryptography vulnerabilities involving **weak algorithms**. If you are unsure about the validity of a result do NOT report it.

```java
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
- `DESede` / `3DES` / `TripleDES` / `Triple-DES` — deprecated, use AES instead
- `RC4` / `ARCFOUR` / `ARC4` — broken stream cipher with known biases
- `RC2` — weak block cipher
- `Blowfish` — if key < 128 bits
- `IDEA` — older algorithm
- `CAST5` — older algorithm
- RSA with key size < 2048 bits

### STRONG ALGORITHMS — DO NOT FLAG AS WEAK:
- **`AES`** / `AES-128` / `AES-256` — This is a STRONG algorithm. Do NOT report AES as weak.
- **`RSA`** (with key >= 2048) — Strong asymmetric encryption
- **`ChaCha20`** / **`ChaCha20-Poly1305`** — Modern stream cipher
- **`ECDSA`** / **`ECDH`** — Elliptic curve cryptography
- **`Camellia`** — Strong block cipher
- **`Twofish`** — Strong block cipher
- **`Serpent`** — Strong block cipher

### MODE ISSUES — Handle Separately:
- ECB mode with AES is a **mode problem**, NOT a weak algorithm
- AES/ECB should be reported as "insecure mode" not "weak algorithm"
- AES/CBC, AES/GCM, AES/CTR are all fine modes

---

## Context

**Language:** Java  
**Frameworks/Libraries:** <e.g., javax.crypto, java.security, Bouncy Castle>  

**Weak/Broken cryptographic algorithms (REPORT when used):**  
- `Cipher.getInstance("DES")` or `Cipher.getInstance("DES/...")` — DES is broken
- `Cipher.getInstance("DESede")` or `"DESede/..."` — 3DES is deprecated
- `Cipher.getInstance("RC4")` or `"ARCFOUR"` — RC4 is broken
- `Cipher.getInstance("RC2")` — RC2 is weak
- `Cipher.getInstance("Blowfish")` — Blowfish is outdated
- RSA with `keyGen.initialize(1024)` or smaller — key too small

**Strong algorithms (DO NOT report as weak):**  
- `Cipher.getInstance("AES/...")` — AES is STRONG, any mode (GCM, CBC, CTR, ECB)
- `Cipher.getInstance("AES/GCM/NoPadding")` — AES-GCM is excellent
- `Cipher.getInstance("AES/CBC/PKCS5Padding")` — AES-CBC is fine
- `Cipher.getInstance("AES/ECB/PKCS5Padding")` — AES is still strong (mode is suboptimal but algorithm is fine)
- `Cipher.getInstance("RSA/...")` — RSA is STRONG (with adequate key size)
- `Cipher.getInstance("ChaCha20")` or `"ChaCha20-Poly1305"` — Modern and secure
- `KeyGenerator.getInstance("AES")` — Strong key generation
- `KeyGenerator.getInstance("RSA")` — Strong key generation
- `SecretKeyFactory.getInstance("PBKDF2...")` — Strong key derivation
- RSA with `keyGen.initialize(2048)` or larger — adequate key size

---

## Rules and Guidelines

1. Report **only weak ALGORITHM** vulnerabilities (DES, 3DES, RC4, RC2).
2. **DO NOT report AES as a weak algorithm** — AES is strong regardless of mode.
3. **DO NOT report RSA as weak** if key size is >= 2048 bits.
4. ECB mode is a separate concern — if you must report it, classify it as "insecure mode" not "weak algorithm."
5. Report the **exact location** where the weak algorithm is instantiated.
6. Output must be valid JSON; if no issues found:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify cryptographic algorithm instantiation (`Cipher.getInstance()`, etc.).
2. Check the algorithm name — is it DES, 3DES, RC4, RC2, or Blowfish?
3. For RSA, check the key size — is it < 2048?
4. If weak algorithm found, report it.
5. **If AES is used, do NOT report it as weak** — AES is a strong algorithm.

---

## Patterns to Look For

### VULNERABLE — Weak Algorithms (REPORT THESE)

```java
// Using DES - VULNERABLE (56-bit key is broken)
Cipher cipher = Cipher.getInstance("DES");  // <-- REPORT: DES is weak
```

```java
// Using DES with mode - VULNERABLE
Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");  // <-- REPORT: DES is weak
```

```java
// Using 3DES - VULNERABLE (deprecated)
Cipher cipher = Cipher.getInstance("DESede");  // <-- REPORT: 3DES is deprecated
Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");  // <-- REPORT
```

```java
// Using RC4 - VULNERABLE (broken)
Cipher cipher = Cipher.getInstance("RC4");  // <-- REPORT: RC4 is broken
Cipher cipher = Cipher.getInstance("ARCFOUR");  // <-- REPORT: RC4 is broken
```

```java
// Using RC2 - VULNERABLE
Cipher cipher = Cipher.getInstance("RC2");  // <-- REPORT: RC2 is weak
```

```java
// RSA with small key - VULNERABLE
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(1024);  // <-- REPORT: Key size < 2048
```

```java
// RSA with 512-bit key - VULNERABLE
keyGen.initialize(512);  // <-- REPORT: Trivially broken
```

### SAFE — Strong Algorithms (DO NOT REPORT)

```java
// AES-GCM - SAFE (strong algorithm, authenticated encryption)
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");  // DO NOT REPORT
```

```java
// AES-CBC - SAFE (strong algorithm)
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");  // DO NOT REPORT
```

```java
// AES-ECB - Algorithm is STRONG (mode is suboptimal but don't flag as weak algorithm)
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // DO NOT REPORT as weak algorithm
```

```java
// AES without mode (defaults to ECB) - Algorithm is still STRONG
Cipher cipher = Cipher.getInstance("AES");  // DO NOT REPORT as weak algorithm
```

```java
// ChaCha20-Poly1305 - SAFE (modern authenticated encryption)
Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");  // DO NOT REPORT
```

```java
// RSA with adequate key size - SAFE
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(2048);  // DO NOT REPORT - key size is adequate
```

```java
// RSA with 4096-bit key - SAFE
keyGen.initialize(4096);  // DO NOT REPORT - excellent key size
```

---

## Common False Positive to Avoid

**AES with any mode is NOT a weak algorithm:**

```java
// This is NOT a weak algorithm vulnerability!
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
// AES is strong. ECB mode is suboptimal but the ALGORITHM is not weak.
// DO NOT REPORT THIS.
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

Detects Broken Cryptography (CWE-327) when using **weak algorithms**: DES, 3DES, RC4, RC2, Blowfish, or RSA with key < 2048 bits.

**IMPORTANT**: AES is a STRONG algorithm. Do NOT report AES as weak regardless of the mode (ECB, CBC, GCM, etc.).
