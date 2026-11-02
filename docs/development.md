# SAIST development

For Datadog contributors, this is the repository-specific application of the [AI Native SDLC Playbook](https://datadoghq.atlassian.net/wiki/spaces/ENG/pages/7376601403/Datadog+AI+Native+SDLC+Playbook). Before implementing a change, state its expected behavior and preserved contracts, identify existing tests/eval cases, and establish a baseline. Use the checks below during implementation and attach candidate-specific evidence before release; missing or incomparable evidence remains unverified.

## Execution and ownership

The CLI loads rules from the prompts API by default; `--local-prompts` selects the separately embedded rules. [internal/api/datadog_api.go](../internal/api/datadog_api.go) decodes the API response, including the optional `analysis_filter`. Do not assume embedded rules and current API rules have identical coverage or metadata.

```text
Load rules + discover source files + resolve configured scope
  → match language/globs
  → ShouldAnalyze: conditional expression or keyword fallback
  → build prompts and related-file context
  → restrict scans to driver/local-config file-rule pairs
  → detect candidate vulnerabilities
  → verify candidates and filter results
  → checkpoint/finalize SARIF
```

[internal/analysis/analyzer.go](../internal/analysis/analyzer.go) coordinates the pipeline; [rule_processor.go](../internal/analysis/rule_processor.go) builds scans and processes results. Conditional selection happens before building the detection prompt and calling the model.

In hosted mode, `DATADOG_DRIVER_ENABLED=true` and `.datadog-driver.json` provide a `files` map of paths to rule IDs. The schema is [internal/model/datadog_driver.go](../internal/model/datadog_driver.go). The host has already applied configuration and cache lookup. The binary still loads rules and filters the requested pairs; driver membership does not guarantee an LLM call. Without that driver, [internal/codesecurity](../internal/codesecurity) can narrow scope using local Code Security YAML.

The hosted runner, production rule definitions, prompt generation, and cache live in the separate dd-source repository. Changes to the driver schema or SARIF completion metadata require checking that consumer. Ordinary rule-specific condition changes belong with the rule definitions; changes to expression semantics belong in this binary.

## Results and validation

### Model selection and gateway execution

The hosted runner supplies default detection/validation models in dd-source's `libs/go/code-workload-runner/saist/saist.go`. `RunSAIST` in [ai_prod.go](https://github.com/ddoghq/dd-source/blob/main/domains/static-analysis/apps/apis/shared/services/ai/ai_impl/ai_prod.go) applies the `saist-models` flag before constructing the binary request. Inspect that selection for the org/repository rather than assuming compiled defaults were used.

Hosted calls use `--ai-gateway`, provider-qualified model IDs, `--openai-base-url`, and a gateway token obtained by the host. The OBO JWT for fetching org-specific prompts is separate from that model token. The direct-provider smoke test below uses provider credentials and does not reproduce gateway authentication or fallback behavior; setting `DD_SITE` selects the prompts API, not the model endpoint.

[agents/detection.go](../internal/agents/detection.go) owns detection attempts; [agents/fallback.go](../internal/agents/fallback.go) wraps detection and verification clients only in gateway mode. Fallback advances on errors recognized by `clients.IsRateLimitError`, not every error. Detection fallback uses the existing attempt budget, and cancellation prevents advancement. The ordered fallback models and attempt limit live in [agents/constants.go](../internal/agents/constants.go); inspect the released revision rather than copying model names into this guide. The warning `rate limited, switching to fallback model` identifies a switch. Record switches when comparing model-backed results.

### Result contracts

[internal/sarif/sarif.go](../internal/sarif/sarif.go) emits `RULE_SUCCESS` on artifacts. A successful scan with no findings still needs that metadata so a host can cache it. Skipped or failed pairs must not be represented as successful scans. The pipeline also writes checkpoints that a host can recover after interruption.

Detection results are provisional: verification may reject them, and result-keyword exclusions can remove findings afterward. A log saying a violation was found followed by an empty SARIF is not by itself a selection failure. Inspect verification and result filtering separately.

Use targeted checks based on the change, for example:

```sh
go test -race ./internal/filtering/ ./internal/api/ ./internal/analysis/
go vet ./internal/filtering/ ./internal/api/ ./internal/analysis/
```

For filter comparisons, pin a [saist-playground](https://github.com/muh-nee/saist-playground) revision and save both rule responses. Compare the accepted/rejected result for each eligible file/rule pair, including the outer keyword gate when reproducing hosted selection. Equal total counts do not prove that the same pairs were selected. Keep intentional coverage changes separate from refactors expected to preserve selection.

For prompt changes, selection tests establish that examples reach analysis; model-backed evaluations establish detection and verification behavior. Relevant workflows are [end-to-end-test.yml](../.github/workflows/end-to-end-test.yml), [datadog-driver.yml](../.github/workflows/datadog-driver.yml), and [evals.yml](../.github/workflows/evals.yml).

### Test boundaries

| Tests | What they establish | What still needs a live check |
|---|---|---|
| [Filter evaluator](../internal/filtering/analysis_filter_test.go) | Expression semantics, keyword fallback, and targeted pre-migration decisions | Whole-corpus equivalence and whether deployed metadata is the intended version |
| [API decoding](../internal/api/datadog_api_test.go) | Supplied JSON decodes into rules and filters | API availability, authentication, and deployed response contents. `TestGetPromptsFromApi` is a separate live test that skips without API/app keys. |
| [Analysis pipeline](../internal/analysis/analyzer_pipeline_test.go) | Related-file indexing precedes prompt assembly | Model detection and verification accuracy; this test does not call a model |
| [SARIF generation](../internal/sarif/sarif_test.go) | Output structure and metadata from supplied results | Hosted cache writes and successful intake/upload |

Keep fixture-based contract tests alongside the parser/evaluator they cover. Add a relevant error or boundary case when changing that contract; use existing eval ground truth for detection behavior rather than treating mocked responses as accuracy evidence.

## Local commands

Run from this repository's root with the Go version in `go.mod` and a working CGO C toolchain. Use the golangci-lint version and compatible Go toolchain from [lint.yml](../.github/workflows/lint.yml).

```sh
go test -race ./internal/filtering/ ./internal/api/ ./internal/analysis/
go vet ./internal/filtering/ ./internal/api/ ./internal/analysis/
golangci-lint run -c .golangci.yml --timeout 20m
```

Successful tests report `ok`; vet and lint exit zero without diagnostics. These checks make no LLM calls; the API package also includes the conditional live API test described above. A dependency/toolchain failure leaves the affected check blocked, not passed.

### One-file scan

This example makes live model calls. Set `SAIST_PLAYGROUND_DIR` to a checkout at the fixture revision under test, and `SAIST_DETECTION_MODEL` / `SAIST_VALIDATION_MODEL` to supported direct-provider model names from `go run ./cmd/datadog-saist --help`. Supply the provider credentials through its environment variables, such as `OPENAI_API_KEY`. Set `DD_SITE` for the desired prompts API; provide `DD_API_KEY` plus `DD_APP_KEY`, or `DD_JWT_TOKEN`, when that API requires authentication. Do not put credentials in saved evidence.

```sh
scan_dir=$(mktemp -d "${TMPDIR:-/tmp}/saist-smoke.XXXXXX")
mkdir -p "$scan_dir/go-sqli"
cp "${SAIST_PLAYGROUND_DIR:?Set the fixture checkout}/go-sqli/vulnerable1.go" "$scan_dir/go-sqli/"
printf '%s\n' '{"files":{"go-sqli/vulnerable1.go":["datadog/go-sqli"]}}' > "$scan_dir/.datadog-driver.json"
DATADOG_DRIVER_ENABLED=true go run ./cmd/datadog-saist \
  --directory "$scan_dir" --output "$scan_dir/report.sarif" \
  --detection-model "${SAIST_DETECTION_MODEL:?Set a supported model}" \
  --validation-model "${SAIST_VALIDATION_MODEL:?Set a supported model}" \
  --file-concurrency 1 --debug
jq -e '[.runs[].artifacts[]?.properties.tags[]?] | index("RULE_SUCCESS:datadog/go-sqli") != null' "$scan_dir/report.sarif"
```

Prerequisite: `jq`. A successful smoke test writes SARIF, has only the requested file/rule analyzed, and passes the success-tag check (`true`). Inspect findings separately against eval ground truth: verification can reject a detection, so zero findings does not by itself mean filtering failed. Each run gets a fresh directory; retain its SARIF/logs as evidence before removing that directory. This does not exercise hosted caching or upload.

## Evaluating with existing ground truth

Follow the eval repository's [development guide](https://github.com/ddoghq/datadog-saist-evals/blob/main/docs/development.md) for scoring semantics, ground-truth and LLMObs dataset maintenance, and evaluator-specific limitations. Keep those procedures with the evaluator rather than duplicating its implementation here.

Maintainers use [datadog-saist-evals](https://github.com/ddoghq/datadog-saist-evals). Ground truth lives in `output/<repo>/evals.json`, including existing vulnerable and secure playground cases. Follow the [rule guide's eval maintenance procedure](https://github.com/ddoghq/dd-source/blob/main/domains/static-analysis/shared/libs/go/saist/README.md#maintaining-eval-cases) when adding coverage, fixing FP/FN behavior, or changing fixtures/labels. Keep existing cases in the comparison; report new or corrected cases separately.

Default to affected cases in [muh-nee/saist-playground](https://github.com/muh-nee/saist-playground), including vulnerable, secure, and relevant regression cases. For targeted runs, select explicit file/rule pairs through the driver and retain the full pinned checkout for related-file context. Compare the same pairs and matching ground truth for baseline/candidate. The eval CLI's `--vulnerabilities` flag does not restrict scanning; follow the [eval guide](https://github.com/ddoghq/datadog-saist-evals/blob/main/docs/development.md#compare-baseline-and-candidate) rather than assuming a case-level CLI filter exists.

Use the [worked two-case comparison](https://github.com/ddoghq/datadog-saist-evals/blob/main/docs/development.md#worked-targeted-comparison) for the default targeted workflow. Capture deployed prompt metadata with the [API inspection procedure](https://github.com/ddoghq/dd-source/blob/main/domains/static-analysis/shared/libs/go/saist/README.md#inspect-the-deployed-rule).

Use the full playground when shared behavior changes or broader regression coverage is needed. Build the baseline/candidate binaries from their respective revisions. From an isolated eval-repository checkout, with the same prompt API/provider prerequisites as the scan above:

```sh
eval_output=$(mktemp -d "${TMPDIR:-/tmp}/saist-eval.XXXXXX")
go run ./cmd/datadog-saist-evals \
  --repo saist-playground \
  --saist-bin "${SAIST_BINARY:?Set the absolute binary path}" \
  --detection-model "${SAIST_DETECTION_MODEL:?Set a supported model}" \
  --validation-model "${SAIST_VALIDATION_MODEL:?Set a supported model}" \
  --file-concurrency 1 --json-output "$eval_output/metrics.json"
```

This scans the repository and makes live model calls; it is larger than the one-file smoke test. JSON metrics are written to `$eval_output/metrics.json`; SARIF and FP/FN reports are written under the eval checkout's `output/` tree. Use separate eval worktrees or preserve reports before another run overwrites them. Compare precision, recall, F1, execution failures, and individual cases for affected rules/languages. A zero exit status alone does not establish acceptable detection quality.

The current evaluator clones each benchmark's default-branch tip; it does not accept a fixture-SHA flag. Record the actual SHA in the temporary clone printed by the evaluator and confirm baseline/candidate used the same fixture revision. If they differ, the comparison is inconclusive until rerun on matching inputs. The binary's `evals.yml` also checks out the eval repository's `main`: unmerged eval changes require a run using the intended eval checkout, not an assumption that CI included them. Confirm the API serves the candidate prompt when testing dd-source prompt changes; `--local-prompts` selects separate embedded prompts.

## Evidence to retain

Attach commands and artifacts to the PR/ticket, including:

- Baseline/candidate commit SHAs and binary versions; prompt API site, response/checksum, and relevant rule versions/filters.
- Eval repository SHA, ground-truth path/checksum, actual fixture SHA, and links to fixture/eval updates. Explain deliberate label changes; preserve unchanged regression cases.
- Models, configuration, test scope, and cache state. For hosted runs include runner revision, org/site, source commit, task/run identifier, flags, and observation window.
- File/rule selection differences separately from eval metrics and case-level FP/FN results; include execution failures, skipped cases, and missing coverage.
- Each check's expected outcome, observed result, and status: **passed**, **failed**, **blocked**, or **inconclusive**. Missing access, mismatched input revisions, and absent artifacts are not passes.

Before release, independently review the final diff and supporting artifacts. Refresh affected evidence after changes to the candidate or its companion API/runner configuration; earlier branch results do not verify the integrated revision. Syntax checks and mocked responses do not establish that live scan commands succeeded. Record unexercised live steps as unverified. See the [acceptance example](https://github.com/ddoghq/datadog-saist-evals/blob/main/docs/development.md#example-acceptance-criteria) for a small change-specific plan.
## Releases and hosted consumers

[release.yml](../.github/workflows/release.yml) tests and builds the selected revision, packages platform ZIPs, and creates a draft GitHub release with `checksums.txt`. A branch test release can be marked as a prerelease. Publishing those assets and updating a consumer are separate steps.

With `gh` authenticated for this repository and the intended branch/tag pushed, this example creates a **draft prerelease**:

```sh
gh workflow run release.yml --repo DataDog/datadog-saist \
  --ref "${SAIST_RELEASE_REF:?Set the pushed branch or tag}" \
  -f version="${SAIST_RELEASE_TAG:?Set an unused version tag}" -f prerelease=true
```

For a normal release, use `prerelease=false`. Inspect the resulting workflow run: its `headSha` must be the intended candidate, and tests/builds/release creation must succeed. A successful dispatch alone is not a completed release. Then inspect and verify the draft assets:

```sh
gh release view "$SAIST_RELEASE_TAG" --repo DataDog/datadog-saist \
  --json tagName,isDraft,isPrerelease,assets,url
release_dir=$(mktemp -d "${TMPDIR:-/tmp}/saist-release.XXXXXX")
gh release download "$SAIST_RELEASE_TAG" --repo DataDog/datadog-saist \
  --pattern '*.zip' --pattern checksums.txt --dir "$release_dir"
(cd "$release_dir" && shasum -a 256 -c checksums.txt)
```

Each archive should report `OK`, and the assets should cover the platform matrix in `release.yml`. When ready to publish the verified draft:

```sh
gh release edit "$SAIST_RELEASE_TAG" --repo DataDog/datadog-saist --draft=false
```

Recheck the release: `isDraft` should be false, with the intended prerelease setting. Preserve the run URL, candidate SHA, tag, and checksums with the release evidence.

The hosted runner pins the release and ZIP checksums in dd-source's `domains/static-analysis/shared/rules/datadog-saist.bzl`; merging this repo alone does not change hosted scan behavior. Its prompts API deploys separately. When changing filter metadata, confirm that the API and the consuming binary support the same expression semantics.

[internal/model/constants.go](../internal/model/constants.go) distinguishes the build's `Version`/`SCMCommit` from `EngineVersion`. Hosted cache keys use engine/rule versions and file identity/content, not the release tag or selected model. Coordinate intentional cache invalidation with the runner rather than incrementing these values interchangeably.

Hosted deployment, test-drive isolation, and rollback are described in the [runner validation guide](https://github.com/ddoghq/dd-source/blob/main/domains/static-analysis/apps/apis/code-workload-runner-saist/docs/validation.md). A runner rollback restores its embedded binary; it does not restore the separately deployed prompts API or clear cached results.

## Checking these instructions with an agent

When changing agent instructions or the tools they depend on, run these small tasks in a fresh session using the repository docs and code. Record incorrect assumptions or missing steps in the PR, and correct the relevant guide.

| Task | Expected evidence |
|---|---|
| Trace one hosted file/rule pair | Correct ordering of outer keywords, cache, driver, binary conditionals, verification, and upload; identifies the actual binary pin and API source |
| Trace and regenerate one prompt | Finds the YAML/template/common-block sources, runs the existing generator/drift check, and explains any generated diff without hand-editing it |
| Verify a filter change | Locates applicable tests and existing eval cases, specifies comparable fixtures/metadata, reports newly admitted/rejected pairs separately from detection FP/FN, and marks checks not run as unverified |

These tasks validate the instructions, not model detection quality. Use the existing eval datasets and maintenance procedure above for that.
