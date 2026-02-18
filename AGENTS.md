# Instructions for agent for `datadog-saist`

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the Datadog AI-native SAST (Static Application Security Testing) engine - a security analysis tool focused on identifying vulnerabilities in source code using AI-powered techniques.

## Project Status

This repository is in early development stages. The codebase currently contains only basic repository setup files (README, LICENSE, .gitignore).

## Development Environment

This project is set up as a Go project based on the directory structure and Go-specific .gitignore patterns.

 - `cmd/` contains the code for the command-line (cli tool)
 - `internal/model` contains the structure definitions
 - `internal/sarif` handles all the SARIF creation files
 - `internal/api` contains all the code to handle the Datadog API
 - `internal/prompt` contains the code to handle the prompt

When adding constants, use a file `constants.go` in the package where the constant should be used.

For utility function, add functions in `internal/utils`.


## Common Commands

Since this is a Go project, the following commands will be relevant once source code is added.

### Building
```bash
go build
go build ./cmd/...
```

### Testing
```bash
go test ./...
go test -v ./...
go test -race ./...
go test -cover ./...
```

### Linting and Formatting
```bash
go fmt ./...
go vet ./...
golangci-lint run
```

### Dependencies
```bash
go mod tidy
go mod download
go mod verify
```

## Coding Guidelines

 - Use constants when appropriate (e.g. avoid raw strings and magic numbers)

## Tests

 - For writting tests and assertions, use `"github.com/stretchr/testify/assert"`
 - When updating code, update tests accordingly. The test file should append `_test` into the file name. For example, when having a file `foo.go`, the test file should be `foo_test.go` 
 - Do not use table tests, this is horrible, a real maintenance nightmware and it belongs to the "good intentions don't work" shelf

## Security Focus

This project is specifically for defensive security analysis (SAST). When working with this codebase:

- All code should be focused on identifying and analyzing security vulnerabilities
- The tool should help developers find and fix security issues
- Code analysis should be performed safely without executing analyzed code
- Security rules and detection logic should be well-documented

## Architecture Notes

As an AI-native SAST engine, the architecture will likely include:
- Code parsing and AST analysis components
- AI/ML models for vulnerability detection
- Rule engines for security pattern matching
- Reporting and output formatting
- Integration points with CI/CD systems

## License

This project is licensed under the Apache License 2.0.