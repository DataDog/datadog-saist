# Python User Prompt Template — Weak Randomness

Evaluate the following Python code located in <path> and report ONLY Weak Randomness vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```python
<code>
```

## Vulnerability to Find

Report where there are **Weak Randomness** vulnerabilities as instructed.

This vulnerability is known as **CWE-330**.

<relatedFilesInformation>

---

## Context

**Language:** Python  
**Frameworks/Libraries:** random, secrets, os.urandom

**Weak random sources (flag when used for security purposes):**  
- `random.random()` — returns float [0.0, 1.0)
- `random.randint(a, b)` — returns integer in [a, b]
- `random.choice(seq)` — selecting from sequence
- `random.choices(seq, k=n)` — multiple selections with replacement
- `random.uniform(a, b)` — returns float in [a, b]
- `random.randrange(start, stop)` — returns integer in range
- `random.sample(population, k)` — k unique selections
- `random.shuffle(seq)` — **when used for security token generation**
- `random.randbytes(n)` — Python 3.9+, returns n random bytes
- `random.getrandbits(n)` — returns n random bits as integer
- `random.seed()` with predictable values (e.g., `time.time()`)

**Note:** `random.SystemRandom()` uses os.urandom internally and is SAFE

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

**Secure alternatives (treat as safe):**  
- `secrets.token_bytes()`, `secrets.token_hex()`, `secrets.token_urlsafe()`
- `secrets.choice()`, `secrets.randbelow()`
- `os.urandom()`
- `random.SystemRandom()` (acceptable but secrets module preferred)

---

## Rules and Guidelines

1. Report **only Weak Randomness** vulnerabilities in security-sensitive contexts.
2. Do NOT report weak random used for non-security purposes.
3. Consider the context — token generation vs. test data.
4. Report the **exact location of the sink** where the weak random is used (e.g., `random.choice()`, `random.randint()`), NOT the line where data originates. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position) to directly identify the exact problem location in the code.
5. Output must be valid JSON; if no issues found, output exactly:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

1. Identify random number generation usage.
2. Determine the random source (random module vs. secrets/os.urandom).
3. Assess if used for security purposes.
4. Report weak random sources only in security contexts.

---

## Patterns to Look For

### Vulnerable (Token generation with random)
```python
import random
import string

def generate_token(length=32):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))  # <-- SINK
```

### Vulnerable (Session ID with random.randint)
```python
def create_session_id():
    return f"session_{random.randint(0, 999999999)}"  # <-- SINK
```

### Vulnerable (Password generation with random.choices)
```python
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choices(chars, k=length))  # <-- SINK
```

### Vulnerable (API key with random)
```python
import base64
def create_api_key():
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])  # <-- SINK
    return base64.b64encode(random_bytes).decode()
```

### Vulnerable (OTP generation)
```python
def generate_otp():
    return str(random.randint(100000, 999999))  # <-- SINK
```

### Safe (secrets for tokens)
```python
import secrets

def generate_secure_token():
    return secrets.token_urlsafe(32)  # SAFE
```

### Safe (secrets for password)
```python
def generate_secure_password(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))  # SAFE
```

### Safe (os.urandom)
```python
def generate_key():
    return os.urandom(32)  # SAFE
```

### Safe (random for test data - NOT SECURITY SENSITIVE)
```python
def generate_test_data(count):
    return [random.randint(1, 100) for _ in range(count)]  # Don't report
```

### Safe (random for shuffling display - NOT SECURITY SENSITIVE)
```python
random.shuffle(display_items)  # Don't report
```

### Safe (random for jitter - NOT SECURITY SENSITIVE)
```python
jitter = random.uniform(0, 1.0)
time.sleep(base_delay + jitter)  # Don't report
```

### Vulnerable (Remember-me token with weak random)
```python
# Weak random for authentication tokens is ALWAYS vulnerable
# Even if validated server-side, the token is predictable and can be brute-forced
remember_me_key = str(random.randint(-2**31, 2**31 - 1))
session[cookie_name] = remember_me_key  # <-- SINK: predictable token
```

### Vulnerable (Gaussian random for security token)
```python
stuff = random.gauss(0, 1)
remember_me_key = str(stuff)[2:]  # <-- SINK: predictable token
```

### Vulnerable (random.random() for security token)
```python
rand = random.random()
remember_me_key = str(rand)[2:]  # <-- SINK: predictable token
```

### Safe (random.SystemRandom)
```python
secure_rng = random.SystemRandom()
token = ''.join(secure_rng.choice(chars) for _ in range(32))  # SAFE
```

---

## CRITICAL: Do NOT Report These Patterns

1. **When secrets module or os.urandom is used for the actual security token** - even if random module is also present for other purposes
2. **When the file imports both secrets and random** - check which is used for the security-sensitive operation
3. **When random.SystemRandom() is used** - this uses os.urandom internally and is cryptographically secure
4. **When user input is processed but NOT connected to the random token generation**

### Safe Pattern (User input processed but not used for token)
```python
# User input is processed but NOT used for the security token
param = request.headers.get("BenchmarkTest00188")
param = urllib.parse.unquote(param)

# Conditional processing of user input
if (500 // 42) + 196 > 200:
    bar = param
else:
    bar = "This should never happen"

# The weak random below is INDEPENDENT of user input
# DO NOT REPORT if user input (bar) is not used for the token
l = random.getrandbits(64)
remember_me_key = str(l)  # Token generated independently of user input
session[cookie_name] = remember_me_key
```

## IMPORTANT: Session Validation Does NOT Make Weak Random Safe

Even when a weak random token is:
- Stored server-side in a session
- Verified against session storage on subsequent requests

The vulnerability (CWE-330) still exists because:
- The token is predictable and can be brute-forced
- An attacker can guess valid tokens without knowing the session
- The small keyspace of the random module makes exhaustive search feasible

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
- Unit test files or test methods (`test_*.py`, `*_test.py`)
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
- Non-security usage of random

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

Detects Weak Randomness (CWE-330) when the random module is used for security-sensitive operations like token generation, password creation, or cryptographic key derivation.
