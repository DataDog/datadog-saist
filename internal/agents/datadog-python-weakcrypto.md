# Python User Prompt Template — Broken Cryptography (Weak Algorithm)

Evaluate the following Python code located in <path> and report ONLY Broken Cryptography vulnerabilities involving **weak algorithms**. If you are unsure about the validity of a result do NOT report it.

```python
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
- `DES3` / `TripleDES` / `Triple-DES` — deprecated, use AES instead
- `ARC4` / `RC4` — broken stream cipher with known biases
- `RC2` — weak block cipher
- `Blowfish` — if key < 128 bits
- `IDEA` — older algorithm
- `CAST5` — older algorithm
- RSA with key size < 2048 bits

### STRONG ALGORITHMS — DO NOT FLAG AS WEAK:
- **`AES`** / `AES-128` / `AES-256` — This is a STRONG algorithm. Do NOT report AES as weak.
- **`RSA`** (with key >= 2048) — Strong asymmetric encryption
- **`ChaCha20`** / **`ChaCha20Poly1305`** — Modern stream cipher
- **`Fernet`** — High-level encryption (uses AES internally)
- **`Camellia`** — Strong block cipher
- **`Twofish`** — Strong block cipher
- **`Serpent`** — Strong block cipher

### MODE ISSUES — Handle Separately:
- ECB mode with AES is a **mode problem**, NOT a weak algorithm
- AES with MODE_ECB should NOT be reported as "weak algorithm"
- AES with MODE_CBC, MODE_GCM, MODE_CTR are all fine

---

## Context

**Language:** Python  
**Frameworks/Libraries:** <e.g., cryptography, PyCryptodome, PyCrypto>  

**Weak/Broken cryptographic algorithms (REPORT when used):**  
- `DES.new(...)` — DES is broken
- `DES3.new(...)` — 3DES is deprecated  
- `ARC4.new(...)` — RC4 is broken
- `Blowfish.new(...)` — Blowfish is outdated
- RSA with `key_size=1024` or smaller — key too small

**Strong algorithms (DO NOT report as weak):**  
- `from Crypto.Cipher import AES` — AES is STRONG, any mode
- `AES.new(key, AES.MODE_GCM, ...)` — AES-GCM is excellent
- `AES.new(key, AES.MODE_CBC, ...)` — AES-CBC is strong
- `AES.new(key, AES.MODE_ECB)` — Algorithm is strong (mode is suboptimal)
- `AES.new(key, AES.MODE_CTR, ...)` — AES-CTR is strong
- `from cryptography.hazmat.primitives.ciphers.algorithms import AES` — Strong
- `ChaCha20.new(...)` — Modern and secure
- `ChaCha20Poly1305` — Authenticated encryption
- `from cryptography.fernet import Fernet` — High-level secure API
- RSA with `key_size=2048` or larger — adequate

---

## Rules and Guidelines

1. Report **only weak ALGORITHM** vulnerabilities (DES, 3DES, RC4, Blowfish).
2. **DO NOT report AES as a weak algorithm** — AES is strong regardless of mode.
3. **DO NOT report RSA as weak** if key size is >= 2048 bits.
4. ECB mode is a separate concern — do not classify it as "weak algorithm."
5. Report the **exact location** where the weak algorithm is instantiated.
6. Output must be valid JSON; if no issues found:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify cryptographic algorithm instantiation (`XXX.new()`, etc.).
2. Check the algorithm — is it DES, DES3, ARC4, or Blowfish?
3. For RSA, check the key_size — is it < 2048?
4. If weak algorithm found, report it.
5. **If AES is used, do NOT report it as weak** — AES is a strong algorithm.

---

## Patterns to Look For

### VULNERABLE — Weak Algorithms (REPORT THESE)

```python
# Using DES - VULNERABLE (56-bit key is broken)
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_CBC, iv)  # <-- REPORT: DES is weak
```

```python
# Using 3DES - VULNERABLE (deprecated)
from Crypto.Cipher import DES3
cipher = DES3.new(key, DES3.MODE_CBC, iv)  # <-- REPORT: 3DES is deprecated
```

```python
# Using RC4/ARC4 - VULNERABLE (broken)
from Crypto.Cipher import ARC4
cipher = ARC4.new(key)  # <-- REPORT: RC4 is broken
```

```python
# Using Blowfish - VULNERABLE (outdated)
from Crypto.Cipher import Blowfish
cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)  # <-- REPORT: Blowfish is outdated
```

```python
# RSA with small key - VULNERABLE
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,  # <-- REPORT: Key size < 2048
)
```

### SAFE — Strong Algorithms (DO NOT REPORT)

```python
# AES-GCM - SAFE (strong algorithm, authenticated encryption)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # DO NOT REPORT
```

```python
# AES-CBC - SAFE (strong algorithm)
cipher = AES.new(key, AES.MODE_CBC, iv)  # DO NOT REPORT
```

```python
# AES-ECB - Algorithm is STRONG (mode is suboptimal but don't flag as weak algorithm)
cipher = AES.new(key, AES.MODE_ECB)  # DO NOT REPORT as weak algorithm
```

```python
# AES-CTR - SAFE (strong algorithm)
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)  # DO NOT REPORT
```

```python
# ChaCha20 - SAFE (modern cipher)
from Crypto.Cipher import ChaCha20
cipher = ChaCha20.new(key=key, nonce=nonce)  # DO NOT REPORT
```

```python
# Fernet - SAFE (high-level secure API)
from cryptography.fernet import Fernet
f = Fernet(key)  # DO NOT REPORT
```

```python
# RSA with adequate key size - SAFE
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,  # DO NOT REPORT - adequate key size
)
```

---

## Common False Positive to Avoid

**AES with any mode is NOT a weak algorithm:**

```python
# This is NOT a weak algorithm vulnerability!
cipher = AES.new(key, AES.MODE_ECB)
# AES is strong. ECB mode is suboptimal but the ALGORITHM is not weak.
# DO NOT REPORT THIS.
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

Detects Broken Cryptography (CWE-327) when using **weak algorithms**: DES, 3DES, RC4/ARC4, Blowfish, or RSA with key < 2048 bits.

**IMPORTANT**: AES is a STRONG algorithm. Do NOT report AES as weak regardless of the mode (ECB, CBC, GCM, CTR, etc.).
