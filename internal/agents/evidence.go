package agents

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-saist/internal/agenttools"
)

type EvidenceVerdict string

type EvidenceConfidence string

type EvidenceTrust string

// EvidenceCitation identifies one source-controlled code fact. Snippet must be
// the complete cited line so validation can detect stale model evidence.
type EvidenceCitation struct {
	Path        string `json:"path"`
	Line        uint   `json:"line"`
	Snippet     string `json:"snippet"`
	Symbol      string `json:"symbol"`
	Description string `json:"description"`
}

// SourceEvidence identifies the value origin and the verifier's trust finding.
type SourceEvidence struct {
	Citation EvidenceCitation `json:"citation"`
	Trust    EvidenceTrust    `json:"trust" jsonschema:"enum=untrusted,enum=trusted,enum=unknown"`
}

// StructuredVerdict is the agentic-only verification response. Sink and Source
// are required JSON properties that may be null so the generated schema remains
// compatible with strict response formats.
type StructuredVerdict struct {
	Verdict         EvidenceVerdict    `json:"verdict" jsonschema:"enum=confirm,enum=reject,enum=abstain"`
	Confidence      EvidenceConfidence `json:"confidence" jsonschema:"enum=high,enum=medium,enum=low"`
	Sink            *EvidenceCitation  `json:"sink" jsonschema:"nullable"`
	Source          *SourceEvidence    `json:"source" jsonschema:"nullable"`
	Flow            []EvidenceCitation `json:"flow"`
	Guards          []EvidenceCitation `json:"guards"`
	Counterevidence []EvidenceCitation `json:"counterevidence"`
	Reason          string             `json:"reason"`
}

type EvidenceValidationInput struct {
	Verdict                  StructuredVerdict
	CandidatePath            string
	CandidateStartLine       uint
	CandidateEndLine         uint
	CandidateFileHash        string
	SinkLineWindow           uint
	SearchCoverageIncomplete bool
	RequireUntrustedSource   bool
}

type EvidenceValidationError struct {
	Code    string `json:"code"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// EvidenceValidationIssue is kept as an alias for callers that describe
// validation failures as issues rather than errors.
type EvidenceValidationIssue = EvidenceValidationError

// EvidenceValidationResult preserves both the model verdict and the verdict
// accepted by server-side validation. Any validation error forces abstention.
type EvidenceValidationResult struct {
	RawVerdict       EvidenceVerdict           `json:"raw_verdict"`
	ValidatedVerdict EvidenceVerdict           `json:"validated_verdict"`
	Evidence         StructuredVerdict         `json:"evidence"`
	Errors           []EvidenceValidationError `json:"errors"`
}

func (result EvidenceValidationResult) Valid() bool {
	return len(result.Errors) == 0
}

// ParseStructuredVerdict parses exactly one JSON object without repairing or
// accepting unknown fields. Invalid structured output must not be upgraded into
// evidence by guessing at truncated content.
func ParseStructuredVerdict(content string) (StructuredVerdict, error) {
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.DisallowUnknownFields()

	var verdict StructuredVerdict
	if err := decoder.Decode(&verdict); err != nil {
		return StructuredVerdict{}, fmt.Errorf("parse structured verdict: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return StructuredVerdict{}, fmt.Errorf("parse structured verdict: trailing JSON value")
		}
		return StructuredVerdict{}, fmt.Errorf("parse structured verdict: %w", err)
	}
	return verdict, nil
}

type evidenceFile struct {
	data  []byte
	lines [][]byte
}

type evidenceValidator struct {
	sandbox *agenttools.Sandbox
	files   map[string]evidenceFile
	errors  []EvidenceValidationError
}

// ValidateEvidence validates all model-provided citations against files in the
// repository sandbox. It never returns a confirmed or rejected verdict when a
// citation or verdict requirement fails.
func ValidateEvidence(sandbox *agenttools.Sandbox, input EvidenceValidationInput) EvidenceValidationResult {
	validator := evidenceValidator{
		sandbox: sandbox,
		files:   make(map[string]evidenceFile),
		errors:  make([]EvidenceValidationError, 0),
	}
	verdict := cloneStructuredVerdict(input.Verdict)

	validator.validateVerdict(verdict)
	validator.validateCandidateRegion(input)
	validator.validateSink(input, &verdict)
	if verdict.Source != nil {
		validator.validateSource(verdict.Source)
	}
	if input.RequireUntrustedSource && verdict.Verdict == EvidenceVerdictConfirm &&
		(verdict.Source == nil || verdict.Source.Trust != EvidenceTrustUntrusted) {
		validator.addError("missing_untrusted_source", "source.trust",
			"confirm requires a cited source with untrusted trust")
	}
	for index := range verdict.Flow {
		field := fmt.Sprintf("flow[%d]", index)
		validator.validateCitation(field, &verdict.Flow[index])
	}
	for index := range verdict.Guards {
		field := fmt.Sprintf("guards[%d]", index)
		validator.validateCitation(field, &verdict.Guards[index])
	}
	for index := range verdict.Counterevidence {
		field := fmt.Sprintf("counterevidence[%d]", index)
		validator.validateCitation(field, &verdict.Counterevidence[index])
	}
	hasTrustedSource := verdict.Source != nil && verdict.Source.Trust == EvidenceTrustTrusted
	if verdict.Verdict == EvidenceVerdictReject && !hasTrustedSource &&
		len(verdict.Guards) == 0 && len(verdict.Counterevidence) == 0 {
		validator.addError("missing_rejection_evidence", "verdict",
			"reject requires a trusted source, guard, or counterevidence item")
	}
	if verdict.Verdict == EvidenceVerdictReject && input.SearchCoverageIncomplete {
		validator.addError("incomplete_search_rejection", "verdict",
			"reject is not allowed after incomplete search coverage")
	}

	validatedVerdict := verdict.Verdict
	if len(validator.errors) > 0 {
		validatedVerdict = EvidenceVerdictAbstain
	}
	return EvidenceValidationResult{
		RawVerdict:       verdict.Verdict,
		ValidatedVerdict: validatedVerdict,
		Evidence:         verdict,
		Errors:           validator.errors,
	}
}

func cloneStructuredVerdict(verdict StructuredVerdict) StructuredVerdict {
	cloned := verdict
	if verdict.Sink != nil {
		sink := *verdict.Sink
		cloned.Sink = &sink
	}
	if verdict.Source != nil {
		source := *verdict.Source
		cloned.Source = &source
	}
	cloned.Flow = cloneEvidenceCitations(verdict.Flow)
	cloned.Guards = cloneEvidenceCitations(verdict.Guards)
	cloned.Counterevidence = cloneEvidenceCitations(verdict.Counterevidence)
	return cloned
}

func cloneEvidenceCitations(citations []EvidenceCitation) []EvidenceCitation {
	if citations == nil {
		return nil
	}
	return append(make([]EvidenceCitation, 0, len(citations)), citations...)
}

func (validator *evidenceValidator) validateVerdict(verdict StructuredVerdict) {
	switch verdict.Verdict {
	case EvidenceVerdictConfirm, EvidenceVerdictReject, EvidenceVerdictAbstain:
	default:
		validator.addError("invalid_verdict", "verdict", fmt.Sprintf("unsupported verdict %q", verdict.Verdict))
	}
	switch verdict.Confidence {
	case EvidenceConfidenceHigh, EvidenceConfidenceMedium, EvidenceConfidenceLow:
	default:
		validator.addError("invalid_confidence", "confidence",
			fmt.Sprintf("unsupported confidence %q", verdict.Confidence))
	}
	if strings.TrimSpace(verdict.Reason) == "" {
		validator.addError("missing_reason", "reason", "reason is required")
	}
}

func (validator *evidenceValidator) validateCandidateRegion(input EvidenceValidationInput) {
	if input.CandidateStartLine == 0 {
		validator.addError("invalid_candidate_region", "candidate.start_line",
			"candidate start line must be greater than zero")
	}
	if input.CandidateEndLine < input.CandidateStartLine {
		validator.addError("invalid_candidate_region", "candidate.end_line",
			"candidate end line cannot be before its start line")
	}
	if err := validateEvidencePath(input.CandidatePath); err != nil {
		validator.addError("invalid_candidate_path", "candidate.path", err.Error())
	}
}

func (validator *evidenceValidator) validateSink(input EvidenceValidationInput, verdict *StructuredVerdict) {
	sink := verdict.Sink
	if sink == nil {
		if verdict.Verdict == EvidenceVerdictConfirm || verdict.Verdict == EvidenceVerdictReject {
			validator.addError("missing_sink", "sink", "confirm and reject require a sink citation")
		}
		return
	}

	file, _ := validator.validateCitation("sink", sink)
	if sink.Path != input.CandidatePath {
		validator.addError("sink_path_mismatch", "sink.path",
			fmt.Sprintf("sink path %q does not match candidate path %q", sink.Path, input.CandidatePath))
	}

	window := input.SinkLineWindow
	if window == 0 {
		window = DefaultSinkLineWindow
	}
	lower := uint64(1)
	if input.CandidateStartLine > window {
		lower = uint64(input.CandidateStartLine - window)
	}
	upper := uint64(input.CandidateEndLine) + uint64(window)
	line := uint64(sink.Line)
	if input.CandidateStartLine > 0 && input.CandidateEndLine >= input.CandidateStartLine &&
		(line < lower || line > upper) {
		validator.addError("sink_line_mismatch", "sink.line",
			fmt.Sprintf("sink line %d is outside candidate window %d-%d", sink.Line, lower, upper))
	}

	if sink.Path == input.CandidatePath && file.lines != nil && input.CandidateFileHash != "" {
		digest := sha256.Sum256(file.data)
		if hex.EncodeToString(digest[:]) != input.CandidateFileHash {
			validator.addError("stale_candidate_file", "sink.path",
				"candidate file content no longer matches the verification snapshot")
		}
	}
}

func (validator *evidenceValidator) validateSource(source *SourceEvidence) {
	validator.validateCitation("source", &source.Citation)
	switch source.Trust {
	case EvidenceTrustUntrusted, EvidenceTrustTrusted, EvidenceTrustUnknown:
	default:
		validator.addError("invalid_source_trust", "source.trust",
			fmt.Sprintf("unsupported source trust %q", source.Trust))
	}
}

func (validator *evidenceValidator) validateCitation(field string, citation *EvidenceCitation) (evidenceFile, bool) {
	citationPath := citation.Path
	line := citation.Line
	if err := validateEvidencePath(citationPath); err != nil {
		validator.addError("invalid_citation_path", field+".path", err.Error())
		return evidenceFile{}, false
	}
	if line == 0 {
		validator.addError("invalid_citation_line", field+".line", "citation line must be greater than zero")
		return evidenceFile{}, false
	}
	if validator.sandbox == nil {
		validator.addError("sandbox_unavailable", field+".path", "repository sandbox is unavailable")
		return evidenceFile{}, false
	}

	absolutePath, err := validator.sandbox.Resolve(citationPath)
	if err != nil {
		validator.addError("citation_outside_repository", field+".path", err.Error())
		return evidenceFile{}, false
	}
	relativePath, err := filepath.Rel(validator.sandbox.Root(), absolutePath)
	if err != nil || relativePath == "." || filepath.ToSlash(relativePath) != citationPath {
		validator.addError("citation_path_mismatch", field+".path",
			"citation path does not resolve to the same repository-relative path")
		return evidenceFile{}, false
	}

	file, found := validator.files[absolutePath]
	if !found {
		info, statErr := os.Stat(absolutePath)
		if statErr != nil {
			validator.addError("citation_file_unavailable", field+".path", statErr.Error())
			return evidenceFile{}, false
		}
		if !info.Mode().IsRegular() {
			validator.addError("citation_not_regular_file", field+".path", "citation path is not a regular file")
			return evidenceFile{}, false
		}
		data, readErr := os.ReadFile(absolutePath) // nolint:gosec // path is sandbox-resolved
		if readErr != nil {
			validator.addError("citation_file_unavailable", field+".path", readErr.Error())
			return evidenceFile{}, false
		}
		file = evidenceFile{data: data, lines: bytes.Split(data, []byte{'\n'})}
		validator.files[absolutePath] = file
	}
	if uint64(line) > uint64(len(file.lines)) {
		validator.addError("citation_line_out_of_bounds", field+".line",
			fmt.Sprintf("citation line %d is outside file with %d lines", line, len(file.lines)))
		return file, false
	}
	if strings.TrimSpace(citation.Description) == "" {
		validator.addError("missing_evidence_description", field+".description", "description is required")
		return file, false
	}
	if strings.TrimSpace(citation.Snippet) == "" {
		validator.addError("missing_citation_snippet", field+".snippet", "citation snippet is required")
		return file, false
	}
	actualLine := file.lines[line-1]
	if line == 1 {
		actualLine = bytes.TrimPrefix(actualLine, []byte{0xef, 0xbb, 0xbf})
	}
	actualLine = bytes.TrimSuffix(actualLine, []byte{'\r'})
	canonicalSnippet, matches := canonicalEvidenceSnippet(line, citation.Snippet, string(actualLine))
	if !matches {
		validator.addError("stale_citation", field+".snippet",
			"citation snippet does not match the current source line")
		return file, false
	}
	if strings.TrimSpace(canonicalSnippet) == "" {
		validator.addError("missing_citation_snippet", field+".snippet", "citation snippet is required")
		return file, false
	}
	citation.Snippet = canonicalSnippet
	return file, true
}

// canonicalEvidenceSnippet removes the exact line-number label emitted by
// read_file only when the label and remaining text both agree with the cited
// repository line. All other source mismatches remain validation failures.
func canonicalEvidenceSnippet(line uint, snippet, actualLine string) (string, bool) {
	if normalizeEvidenceLine(actualLine) == normalizeEvidenceLine(snippet) {
		return actualLine, true
	}
	lineLabel := fmt.Sprintf("%d: ", line)
	if !strings.HasPrefix(snippet, lineLabel) {
		return "", false
	}
	unnumbered := strings.TrimPrefix(snippet, lineLabel)
	if normalizeEvidenceLine(actualLine) != normalizeEvidenceLine(unnumbered) {
		return "", false
	}
	return actualLine, true
}

func validateEvidencePath(value string) error {
	if value == "" {
		return fmt.Errorf("citation path is required")
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("citation path contains a NUL byte")
	}
	if strings.Contains(value, "\\") {
		return fmt.Errorf("citation path must use forward slashes")
	}
	if filepath.IsAbs(value) || path.IsAbs(value) || hasEvidenceWindowsVolume(value) {
		return fmt.Errorf("citation path must be repository-relative")
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("citation path escapes the repository root")
	}
	if cleaned != value {
		return fmt.Errorf("citation path is not normalized")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return fmt.Errorf("citation path contains parent traversal")
		}
	}
	return nil
}

func hasEvidenceWindowsVolume(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'a' && value[0] <= 'z') ||
		(value[0] >= 'A' && value[0] <= 'Z')) && value[1] == ':'
}

func normalizeEvidenceLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func (validator *evidenceValidator) addError(code, field, message string) {
	validator.errors = append(validator.errors, EvidenceValidationError{
		Code:    code,
		Field:   field,
		Message: message,
	})
}
