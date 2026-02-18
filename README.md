# Datadog Static AI Security Testing (SAIST) tool

This project is an AI-Native SAST tool. Unlike traditional SAST tools that rely solely on parsing
and analysis rules, this project uses LLM (e.g. Claude from Anthropic, GPT from OpenAI or Gemini from Google)
to find vulnerabilities.

This project can be used standalone on your laptop. It is available as part of the [Datadog Code Security](https://docs.datadoghq.com/security/code_security/) 
offering.

## Project Status

This project is under development and is in preview stage.

## Features

- **AI-Powered Analysis**: Uses advanced AI models to detect security vulnerabilities
- **Multiple Language Support**: Analyzes code in various programming languages. Java, Python and Go are currently supported. C# support coming soon.
- **SARIF Output**: Generates industry-standard SARIF reports
- **Context-Aware**: Builds project context for more accurate analysis


## Dependencies

- **[Go Tree-sitter](https://github.com/tree-sitter/go-tree-sitter)**: Go bindings for Tree-sitter parsing library
- **Standard Go text/template**: Built-in Go templating for prompt generation
- **[Go-SARIF](https://github.com/owenrumney/go-sarif)**: SARIF (Static Analysis Results Interchange Format) library


## Usage

### LLM key

Set the following environment variables to specify the API key to your LLM provider

 - Anthropic: `ANTHROPIC_API_KEY`
 - OpenAI: `OPENAI_API_KEY`
 - Google Gemini: `GOOGLE_API_KEY`

### Command Line Interface

Build and run the binary:

```bash
make build
./bin/datadog-saist --directory <path> --output <output-file> --detection-model <model> --validation-model <model> [options]
```

Example to run with Gemini

```bash
make build
GOOGLE_API_KEY=<...> ./bin/datadog-saist --directory <path> --output <output-file> --detection-model gemini-3-flash --validation-model gemini-3-flash
```

### Required Arguments

- `--directory`: Directory to analyze (required)
- `--output`: Output file path for SARIF report (required) 
- `--model`: Model to use for analysis (required)

### Available Models

- `openai-gpt5.2`: OpenAI GPT-5.2
- `openai-gpt5.2-codex`: OpenAI GPT-5.2 codex
- `claude-4.5-haiku`: Claude 4.5 Haiku
- `claude-4.5-opus`: Claude 4.5 Haiku
- `gemini-2.5-pro`: Gemini 2.5 Pro
- `gemini-2.5-flash`: Gemini 2.5 Flash
- `gemini-3-flash`: Gemini 3 Flash

### Optional Arguments

- `--debug`: Enable debug mode for verbose output
- `--request-timeout-sec`: Request timeout in seconds (default: 30)
- `--file-concurrency`: Number of concurrent files to analyze (default: 20)
- `--write-prompts`: Write prompts to files during analysis


