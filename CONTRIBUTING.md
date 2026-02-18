# Contributing to Datadog SAIST Experiment

Thank you for your interest in contributing to the Datadog AI-native SAST engine!

## Development Setup

### Prerequisites

- Go 1.19 or later
- Git
- Python 3.7+ (for pre-commit hooks)

### Getting Started

1. **Clone the repository**

```bash
git clone https://github.com/DataDog/datadog-saist.git
cd datadog-saist
```

2. **Install Go dependencies**

```bash
go mod download
```

3. **Build the project**

```bash
make build
```

4. **Run tests**

```bash
make test
```

### Build for a specific version

```bash
go build -o bin/datadog-saist \
  -ldflags "-X github.com/DataDog/datadog-saist/internal/model.Version=v1.0.0 \
            -X github.com/DataDog/datadog-saist/internal/model.SCMCommit=$(git rev-parse HEAD)" \
  ./cmd/datadog-saist
```

## Pre-commit Hooks Setup

This project uses [pre-commit](https://pre-commit.com/) to ensure code quality. Pre-commit hooks will run automatically before each commit to:

- Format Go code with `go fmt`
- Run `go vet` for static analysis
- Execute all tests
- Build the project
- Check for common issues (trailing whitespace, large files, etc.)

### Installing Pre-commit

1. **Install pre-commit** (choose one method):
   
**Using pip:**
```bash
pip install pre-commit
```

**Using Homebrew (macOS):**
```bash
brew install pre-commit
```

**Using conda:**
```bash
conda install -c conda-forge pre-commit
```

2. **Install the git hook scripts**
```bash
pre-commit install
```

3. **Verify installation**
```bash
pre-commit --version
```

### Running Pre-commit Manually

To run all hooks on all files:
```bash
pre-commit run --all-files
```

To run hooks only on staged files:
```bash
pre-commit run
```

## Development Workflow

1. **Create a new branch**
```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes**
- Write code following Go best practices
- Add tests for new functionality
- Update documentation as needed

3. **Test your changes**
```bash
make test build
```

4. **Commit your changes**
```bash
git add .
git commit -m "your commit message"
```
   
The pre-commit hooks will run automatically. If they fail, fix the issues and commit again.

5. **Push and create a pull request**
```bash
git push origin feature/your-feature-name
```

## Code Standards

- **Go formatting**: Use `go fmt` (enforced by pre-commit)
- **Static analysis**: Code must pass `go vet` (enforced by pre-commit)
- **Tests**: All new code should have unit tests
- **Build**: Code must compile successfully (enforced by pre-commit)

## Project Structure

```
.
├── cmd/
│   └── datadog-saist/          # Main application entry point
├── internal/
│   └── files/                  # Internal packages for file handling
├── .pre-commit-config.yaml     # Pre-commit configuration
├── go.mod                      # Go module definition
├── AGENTS.md                   # AI assistant guidance
└── CONTRIBUTING.md             # This file
```

## Testing

Run all tests:
```bash
make test
```

## Troubleshooting

### Pre-commit Issues

If pre-commit hooks fail:

1. **Fix formatting issues:**
```bash
go fmt ./...
```

2. **Fix vet issues:**
```bash
go vet ./...
```

3. **Fix failing tests:**
```bash
go test ./...
```

4. **Ensure build works:**
```bash
go build -o datadog-saist ./cmd/datadog-saist
```

### Skipping Hooks (Not Recommended)

In exceptional cases, you can skip pre-commit hooks:
```bash
git commit --no-verify -m "your message"
```

**Note:** This should only be used in emergencies, as it bypasses quality checks.



## Questions?

If you have questions about contributing, please:
1. Check existing issues and documentation
2. Create a new issue for discussion
3. Reach out to the maintainers

Thank you for contributing to making our SAST engine better!