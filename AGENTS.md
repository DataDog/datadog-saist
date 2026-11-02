# Working on datadog-saist

SAIST is a Go CLI that selects source files/rules, calls LLMs for detection and verification, and writes SARIF. It runs standalone and as a binary invoked by the hosted Code Security runner.

Read [docs/development.md](docs/development.md) for the pipeline, validation, hosted cache contract, and releases. Read [internal/filtering/README.md](internal/filtering/README.md) when changing scan selection.

## Code map

- `cmd/datadog-saist`: CLI flags and startup.
- `internal/api`, `internal/model/api`: prompts API client and rule/filter decoding.
- `internal/analysis`: file/rule selection, scan scheduling, checkpoints, and aggregation.
- `internal/codesecurity`: local Code Security YAML selection and path filters.
- `internal/filtering`: comment preprocessing, conditional expressions, keyword fallback, and result exclusions.
- `internal/agents`, `internal/clients`: detection/verification and provider clients.
- `internal/prompt`: runtime prompt assembly; `internal/sarif`: output and successful-pair metadata.

## Contracts to preserve

- The hosted driver supplies file/rule IDs, not rule definitions. It restricts scan scope without bypassing `filtering.ShouldAnalyze`.
- Invalid or unsupported conditional metadata falls back to keyword filtering. Do not reintroduce per-language rule dispatch for ordinary keyword combinations.
- Keep `RULE_SUCCESS` artifact metadata accurate: consumers distinguish successful zero-finding scans from pairs that were skipped or failed.
- Release `Version` and cache `EngineVersion` in `internal/model/constants.go` are distinct. A model or release change does not automatically invalidate hosted caches.

## Development

- Put constants in the package's `constants.go`; general utilities belong in `internal/utils`.
- Use `github.com/stretchr/testify/assert` and focused `_test.go` tests. Do not introduce table-driven tests.
- Do not add maintainer Markdown directly under `internal/agents`: `embedded.go` loads every `*.md` there as a local detection rule. Put agent documentation under `docs/`.
- Preserve source files as data; tests should not execute the programs being scanned.
- Run `gofmt` on changed Go files and targeted `go test -race` / `go vet` checks. Build the CLI into a unique output directory, for example `build_dir=$(mktemp -d)` then `go build -o "$build_dir/datadog-saist" ./cmd/datadog-saist`; keep baseline and candidate binaries separate.
- Use the linter version pinned in [.github/workflows/lint.yml](.github/workflows/lint.yml), with a Go toolchain supported by that linter. An incompatible local linter/export-data format is a tooling failure, not evidence of a source error.
- Use [.github/workflows/build-test.yml](.github/workflows/build-test.yml) and [release.yml](.github/workflows/release.yml) for CI/release details. Local mocked tests do not establish live provider access or detection quality.

## Keeping this context current

Update the relevant guide in the same PR when scan ordering, filtering, SARIF completion metadata, cache compatibility, or development/release commands change. Verify instructions against the implementation and link to changing values rather than copying them. Propose a concise correction when an agent repeats a mistake; the code owners review it and remove stale guidance. Record task-specific results in the PR/ticket using the [evidence checklist](docs/development.md#evidence-to-retain).
