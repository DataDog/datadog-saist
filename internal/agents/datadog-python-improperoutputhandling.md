# Python User Prompt Template — Improper Output Handling

Evaluate the following Python code located in <path> and report ONLY Improper Output Handling vulnerabilities. If you are unsure about the validity of a result do NOT report it.

```python
<code>
```

## Vulnerability to Find

Report where there are **Improper Output Handling** vulnerabilities as instructed.

This vulnerability is known as **CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')**.

<relatedFilesInformation>

---

## Context

**Language:** Python
**Frameworks/Libraries:** openai, anthropic, langchain, huggingface, transformers, llama-index
**LLM output sources (tainted inputs):**
- OpenAI: `response.choices[0].message.content`, `completion.choices[0].text`
- Anthropic: `response.content[0].text`, `message.content`
- LangChain: return value of `chain.invoke()`, `chain.run()`, `llm.invoke()`, `llm.predict()`
- Any variable that stores or unpacks an LLM API response

**Dangerous downstream sinks:**
- SQL: `cursor.execute()`, `db.execute()`, SQLAlchemy `.execute()`, `.raw()`
- Shell: `subprocess.run()`, `subprocess.Popen()`, `os.system()`, `os.popen()`
- Code execution: `eval()`, `exec()`
- Template rendering: Flask `render_template_string()`, Jinja2 `Template().render()` with unsanitized content
- HTML output: string concatenation into HTML responses, `markupsafe.Markup()`
- File path: `open()`, `os.path.join()` used to construct file paths passed to `open()`
- Network requests: `requests.get()`, `requests.post()`, `urllib.request.urlopen()` where LLM output controls the URL (SSRF)

**Recognized sanitizers/validators:**
- Structured output with schema validation (JSON mode + Pydantic model parsing)
- LLM function calling / tool use where the model provides typed arguments, not raw strings
- Explicit allowlist or regex validation applied to LLM output before passing to the sink
- Parameterized queries where LLM-generated values are passed as bind parameters, not concatenated

---

## Rules and Guidelines

1. Report **only** Improper Output Handling vulnerabilities.
2. Report only if LLM-generated output is passed directly to a dangerous sink without validation or sanitization.
3. Avoid false positives if the LLM output is validated, parsed into a structured type, or used as a parameterized query argument.
4. Report the **exact location of the sink** where the unvalidated LLM output reaches the dangerous operation (e.g., `cursor.execute()`, `subprocess.run()`), NOT where the LLM call is made or where the response is stored. You must specify: `startLine` (where the vulnerability begins), `endLine` (where the vulnerability ends), `startColumn` (starting column position), and `endColumn` (ending column position).
5. Output must be valid JSON; if none, print exactly:
   ```
   NO VIOLATION AMIGO
   ```

---

## Evaluation Process

**Important:** For this rule, the tainted source is **LLM-generated output**, not user input. Treat any variable that captures an LLM API response the same way you would treat user-controlled input in SQLi, CMDi, or XSS rules. The LLM's response is untrusted and must be validated before use in any dangerous operation.

1. Identify LLM API calls and the variables that capture their output.
2. Trace those variables to downstream operations (SQL, shell, eval, HTML, templates, file paths, network requests).
3. Check whether the output is validated or structured before reaching the sink.
4. Report lines where raw LLM output reaches a dangerous sink without validation.

---

## Patterns to Look For

### Vulnerable
```python
# LLM output used directly in a SQL query
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}]
)
sql_query = response.choices[0].message.content
cursor.execute(sql_query)  # sink: raw LLM output in SQL
```

```python
# LLM output passed directly to shell
result = chain.invoke({"task": user_task})
os.system(result["output"])  # sink: unvalidated LLM output in shell command
```

```python
# LLM output evaluated as code
llm_response = client.messages.create(model="claude-3-opus", messages=[...])
code = llm_response.content[0].text
eval(code)  # sink: direct code execution of LLM output
```

```python
# LLM output rendered directly into HTML template
output = llm.invoke(prompt)
return render_template_string(f"<div>{output}</div>")  # sink: XSS via LLM output
```

```python
# LLM output used to construct a file path (path traversal)
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "system", "content": "Return only the filename."}, {"role": "user", "content": desc}]
)
filename = response.choices[0].message.content.strip()
with open(f"/var/app/docs/{filename}") as f:  # sink: LLM-controlled path
    return f.read()
```

```python
# LLM output used as a URL in an HTTP request (SSRF)
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "system", "content": "Return only the URL."}, {"role": "user", "content": desc}]
)
url = response.choices[0].message.content.strip()
resp = requests.get(url)  # sink: LLM-controlled URL enables SSRF
```

### Safe
```python
# Allowlist validation — LLM-chosen table name validated before use in SQL
response = client.chat.completions.create(model="gpt-4", messages=[...])
table_name = response.choices[0].message.content.strip()
if table_name not in ALLOWED_TABLES:
    raise ValueError("Invalid table")
cursor.execute(f"SELECT * FROM {table_name} WHERE id = %s", (user_id,))
```

```python
# Structured output with schema validation
from pydantic import BaseModel
from typing import Literal

class ShellCommand(BaseModel):
    action: Literal["list", "read"]
    path: str

response = client.beta.chat.completions.parse(
    model="gpt-4o",
    messages=[...],
    response_format=ShellCommand,
)
cmd = response.choices[0].message.parsed
# cmd.action is constrained to safe values by schema
```

```python
# LLM output validated with allowlist before use
output = llm.invoke(task_prompt)
allowed_commands = ["ls", "pwd", "whoami"]
if output.strip() not in allowed_commands:
    raise ValueError("Disallowed command")
subprocess.run([output.strip()], capture_output=True)
```

---

## Summary

Detects Improper Output Handling (CWE-74) by identifying LLM-generated output passed directly to dangerous downstream sinks — SQL queries, shell commands, eval/exec, HTML templates, file paths, or network requests — without validation, schema enforcement, or parameterization. The source is always an LLM API response; the sink is the downstream dangerous operation. Report the sink line, not the LLM call.
