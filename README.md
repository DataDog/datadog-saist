# Datadog Static AI Security Testing (SAIST) tool

  This project is an AI-Native SAST tool. Unlike traditional SAST tools that rely solely on
  parsing and analysis rules, this project uses LLMs (e.g. Claude from Anthropic, GPT from
  OpenAI, or Gemini from Google) to find vulnerabilities.

  This project can be used standalone on your laptop. It is also available as part of the
  [Datadog Code Security](https://docs.datadoghq.com/security/code_security/) offering.

  ## Project Status

  This project is under development and is in preview stage.

  ## Features

  - **AI-Powered Analysis**: Uses advanced AI models to detect security vulnerabilities
  - **Multiple Language Support**: Go, Java, Python, C#, C++, JavaScript, TypeScript, Kotlin, PHP, Ruby, Rust, Elixir, and Swift
  - **SARIF Output**: Generates industry-standard SARIF reports
  - **Context-Aware**: Builds project context for more accurate analysis

  ## Requirements

  - **LLM API key**: You must provide an API key for one of the supported LLM providers
  (Anthropic, OpenAI, or Google Gemini). See [LLM key](#llm-key) below.

  No Datadog account is required. SAIST fetches its detection rules from a public
  Datadog-hosted API endpoint — no Datadog API key or App key needed.

  ## Dependencies

  - **[Go Tree-sitter](https://github.com/tree-sitter/go-tree-sitter)**: Go bindings for
  Tree-sitter parsing library
  - **Standard Go text/template**: Built-in Go templating for prompt generation
  - **[Go-SARIF](https://github.com/owenrumney/go-sarif)**: SARIF (Static Analysis Results
  Interchange Format) library

  ## Usage

  ### LLM key

  Set the environment variable for your LLM provider:

  - Anthropic: `ANTHROPIC_API_KEY`
  - OpenAI: `OPENAI_API_KEY`
  - Google Gemini: `GOOGLE_API_KEY`

  ### Command Line Interface

  Build and run the binary:

  ```bash
  make build
  ./bin/datadog-saist --directory <path> --output <output-file> --detection-model <model>
  --validation-model <model> [options]
```

  Example with Gemini:
```bash
  make build
  GOOGLE_API_KEY=<...> ./bin/datadog-saist --directory <path> --output <output-file>
  --detection-model gemini-2.5-flash --validation-model gemini-2.5-flash
```

  Example with AI Gateway:
```bash
  ./bin/datadog-saist --directory <path> --output <output-file> --ai-gateway \
  --org-id <organization-id> --repository-id <repository-id> \
  --detection-model openai-gpt5-mini --validation-model openai-gpt5-mini
```

  Required Arguments
  - --directory: Directory to analyze
  - --output: Output file path for SARIF report
  - --detection-model: Model to use for vulnerability detection
  - --validation-model: Model to use for result validation

  Available Models
```
  ┌───────────────────────┬───────────┐
  │       CLI name        │ Provider  │
  ├───────────────────────┼───────────┤
  │ openai-gpt5-mini      │ OpenAI    │
  ├───────────────────────┼───────────┤
  │ openai-gpt5.2         │ OpenAI    │
  ├───────────────────────┼───────────┤
  │ openai-gpt5.2-codex   │ OpenAI    │
  ├───────────────────────┼───────────┤
  │ claude-4.5-sonnet     │ Anthropic │
  ├───────────────────────┼───────────┤
  │ claude-4.5-haiku      │ Anthropic │
  ├───────────────────────┼───────────┤
  │ gemini-2.5-pro        │ Google    │
  ├───────────────────────┼───────────┤
  │ gemini-2.5-flash      │ Google    │
  ├───────────────────────┼───────────┤
  │ gemini-2.0-flash-lite │ Google    │
  ├───────────────────────┼───────────┤
  │ gemini-3-flash        │ Google    │
  └───────────────────────┴───────────┘
```
  Optional Arguments

  - --ai-gateway: Use AI Gateway format for models
  - --org-id: Datadog organization ID (required with --ai-gateway)
  - --repository-id: Datadog repository ID (required with --ai-gateway)
  - --debug: Enable debug mode for verbose output
  - --request-timeout-sec: Request timeout in seconds for LLM API calls (default: 30)
  - --file-concurrency: Number of concurrent files to analyze (default: 20)
  - --write-prompts: Write prompts to files during analysis (suffixed .userprompt and
  .systemprompt)
  - --local-prompts: Use detection rules embedded in the binary instead of fetching from the
  Datadog API
  - --skip-indexing: Disable cross-file context indexing. Reduces memory usage on large
  repositories at the cost of cross-file vulnerability detection.
