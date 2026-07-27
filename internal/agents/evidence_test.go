package agents

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/stretchr/testify/assert"
)

func TestStructuredVerdictSchemaUsesSupportedNullableFields(t *testing.T) {
	schema, err := json.Marshal(clients.GenerateSchemaWithAnyOf[StructuredVerdict]())
	assert.NoError(t, err)

	assert.Contains(t, string(schema), `"anyOf"`)
	assert.Contains(t, string(schema), `"type":"null"`)
	assert.Contains(t, string(schema), `"additionalProperties":false`)
	assert.NotContains(t, string(schema), `"oneOf"`)
}

type evidenceFixture struct {
	sandbox *agenttools.Sandbox
	root    string
	source  []byte
	hash    string
}

func newEvidenceFixture(t *testing.T) evidenceFixture {
	t.Helper()
	root := t.TempDir()
	source := []byte("package example\nfunc handler(input string) {\n\trun(input)\n}\nfunc other() {}\nvar marker = true\n")
	assert.NoError(t, os.WriteFile(filepath.Join(root, "app.go"), source, 0o600))
	assert.NoError(t, os.Mkdir(filepath.Join(root, "internal"), 0o755))
	assert.NoError(t, os.WriteFile(filepath.Join(root, "internal", "guard.go"),
		[]byte("package internal\nfunc allowed(value string) bool { return value == \"safe\" }\n"), 0o600))
	sandbox, err := agenttools.NewSandbox(root)
	assert.NoError(t, err)
	digest := sha256.Sum256(source)
	return evidenceFixture{
		sandbox: sandbox,
		root:    root,
		source:  source,
		hash:    hex.EncodeToString(digest[:]),
	}
}

func validStructuredConfirm() StructuredVerdict {
	return StructuredVerdict{
		Verdict:    EvidenceVerdictConfirm,
		Confidence: EvidenceConfidenceHigh,
		Sink: &EvidenceCitation{
			Path:        "app.go",
			Line:        3,
			Snippet:     "run(input)",
			Symbol:      "handler",
			Description: "The value reaches the operation under review.",
		},
		Flow:            []EvidenceCitation{},
		Guards:          []EvidenceCitation{},
		Counterevidence: []EvidenceCitation{},
		Reason:          "Untrusted input reaches run.",
	}
}

func validateFixture(fixture evidenceFixture, verdict StructuredVerdict) EvidenceValidationResult {
	return ValidateEvidence(fixture.sandbox, EvidenceValidationInput{
		Verdict:            verdict,
		CandidatePath:      "app.go",
		CandidateStartLine: 3,
		CandidateEndLine:   3,
		CandidateFileHash:  fixture.hash,
	})
}

func hasEvidenceError(result EvidenceValidationResult, code string) bool {
	for _, validationError := range result.Errors {
		if validationError.Code == code {
			return true
		}
	}
	return false
}

func TestValidateEvidenceAcceptsConfirm(t *testing.T) {
	fixture := newEvidenceFixture(t)

	result := validateFixture(fixture, validStructuredConfirm())

	assert.True(t, result.Valid())
	assert.Equal(t, EvidenceVerdictConfirm, result.RawVerdict)
	assert.Equal(t, EvidenceVerdictConfirm, result.ValidatedVerdict)
	assert.NotNil(t, result.Evidence.Flow)
	assert.NotNil(t, result.Evidence.Guards)
	assert.NotNil(t, result.Evidence.Counterevidence)
}

func TestValidateEvidenceRequiresUntrustedSourceWhenConfigured(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()

	result := ValidateEvidence(fixture.sandbox, EvidenceValidationInput{
		Verdict:                verdict,
		CandidatePath:          "app.go",
		CandidateStartLine:     3,
		CandidateEndLine:       3,
		CandidateFileHash:      fixture.hash,
		RequireUntrustedSource: true,
	})

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "missing_untrusted_source"))
}

func TestValidateEvidenceRejectsUnknownRequiredSourceTrust(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Source = &SourceEvidence{
		Citation: EvidenceCitation{
			Path:        "app.go",
			Line:        2,
			Snippet:     "func handler(input string) {",
			Symbol:      "handler",
			Description: "The source trust is not established.",
		},
		Trust: EvidenceTrustUnknown,
	}

	result := ValidateEvidence(fixture.sandbox, EvidenceValidationInput{
		Verdict:                verdict,
		CandidatePath:          "app.go",
		CandidateStartLine:     3,
		CandidateEndLine:       3,
		CandidateFileHash:      fixture.hash,
		RequireUntrustedSource: true,
	})

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "missing_untrusted_source"))
}

func TestValidateEvidenceAcceptsRequiredUntrustedSource(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Source = &SourceEvidence{
		Citation: EvidenceCitation{
			Path:        "app.go",
			Line:        2,
			Snippet:     "func handler(input string) {",
			Symbol:      "handler",
			Description: "The handler receives attacker-controlled input.",
		},
		Trust: EvidenceTrustUntrusted,
	}

	result := ValidateEvidence(fixture.sandbox, EvidenceValidationInput{
		Verdict:                verdict,
		CandidatePath:          "app.go",
		CandidateStartLine:     3,
		CandidateEndLine:       3,
		CandidateFileHash:      fixture.hash,
		RequireUntrustedSource: true,
	})

	assert.True(t, result.Valid())
	assert.Equal(t, EvidenceVerdictConfirm, result.ValidatedVerdict)
}

func TestValidateEvidenceCanonicalizesReadFileLineLabels(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Snippet = "3: \trun(input)"
	verdict.Source = &SourceEvidence{
		Citation: EvidenceCitation{
			Path:        "app.go",
			Line:        2,
			Snippet:     "2: func handler(input string) {",
			Symbol:      "handler",
			Description: "The handler receives the value.",
		},
		Trust: EvidenceTrustUntrusted,
	}
	verdict.Flow = []EvidenceCitation{{
		Path:        "app.go",
		Line:        3,
		Snippet:     "3: \trun(input)",
		Symbol:      "handler",
		Description: "The value reaches the operation.",
	}}

	result := validateFixture(fixture, verdict)

	assert.True(t, result.Valid())
	assert.Equal(t, "\trun(input)", result.Evidence.Sink.Snippet)
	assert.Equal(t, "func handler(input string) {", result.Evidence.Source.Citation.Snippet)
	assert.Equal(t, "\trun(input)", result.Evidence.Flow[0].Snippet)
	assert.Equal(t, "3: \trun(input)", verdict.Sink.Snippet)
}

func TestValidateEvidenceRejectsReadFileLabelForDifferentLine(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Snippet = "2: \trun(input)"

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "stale_citation"))
}

func TestValidateEvidenceRejectsReadFileLabelWithDifferentSource(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Snippet = "3: \trun(other)"

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "stale_citation"))
}

func TestValidateEvidenceAcceptsRejectWithSource(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdictReject
	verdict.Source = &SourceEvidence{
		Citation: EvidenceCitation{
			Path:        "app.go",
			Line:        2,
			Snippet:     "func handler(input string) {",
			Symbol:      "handler",
			Description: "The caller supplies a trusted value.",
		},
		Trust: EvidenceTrustTrusted,
	}
	verdict.Reason = "The source is trusted."

	result := validateFixture(fixture, verdict)

	assert.True(t, result.Valid())
	assert.Equal(t, EvidenceVerdictReject, result.ValidatedVerdict)
}

func TestValidateEvidenceRejectWithUntrustedSourceAbstains(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdictReject
	verdict.Source = &SourceEvidence{
		Citation: EvidenceCitation{
			Path:        "app.go",
			Line:        2,
			Snippet:     "func handler(input string) {",
			Symbol:      "handler",
			Description: "The caller accepts an untrusted value.",
		},
		Trust: EvidenceTrustUntrusted,
	}
	verdict.Reason = "The source is untrusted."

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "missing_rejection_evidence"))
}

func TestValidateEvidenceAcceptsRejectWithGuard(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdictReject
	verdict.Guards = []EvidenceCitation{{
		Path:        "internal/guard.go",
		Line:        2,
		Snippet:     "func allowed(value string) bool { return value == \"safe\" }",
		Symbol:      "allowed",
		Description: "The value is restricted to a constant.",
	}}
	verdict.Reason = "A strict guard rejects other values."

	result := validateFixture(fixture, verdict)

	assert.True(t, result.Valid())
	assert.Equal(t, EvidenceVerdictReject, result.ValidatedVerdict)
}

func TestValidateEvidenceAcceptsRejectWithCounterevidence(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdictReject
	verdict.Counterevidence = []EvidenceCitation{{
		Path:        "app.go",
		Line:        3,
		Snippet:     "run(input)",
		Symbol:      "handler",
		Description: "The operation does not invoke a shell.",
	}}
	verdict.Reason = "Direct argument passing does not interpret shell syntax."

	result := validateFixture(fixture, verdict)

	assert.True(t, result.Valid())
	assert.Equal(t, EvidenceVerdictReject, result.ValidatedVerdict)
}

func TestValidateEvidenceIncompleteSearchRejectWithCounterevidenceAbstains(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdictReject
	verdict.Counterevidence = []EvidenceCitation{{
		Path:        "app.go",
		Line:        3,
		Snippet:     "run(input)",
		Symbol:      "handler",
		Description: "No other vulnerable operation was found.",
	}}
	verdict.Reason = "The incomplete search did not find another operation."

	result := ValidateEvidence(fixture.sandbox, EvidenceValidationInput{
		Verdict:                  verdict,
		CandidatePath:            "app.go",
		CandidateStartLine:       3,
		CandidateEndLine:         3,
		CandidateFileHash:        fixture.hash,
		SearchCoverageIncomplete: true,
	})

	assert.Equal(t, EvidenceVerdictReject, result.RawVerdict)
	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "incomplete_search_rejection"))
}

func TestValidateEvidenceIncompleteSearchRejectWithCitedGuardAbstains(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdictReject
	verdict.Guards = []EvidenceCitation{{
		Path:        "internal/guard.go",
		Line:        2,
		Snippet:     "func allowed(value string) bool { return value == \"safe\" }",
		Symbol:      "allowed",
		Description: "The observed guard restricts the value to a safe constant.",
	}}
	verdict.Reason = "The cited guard proves the candidate safe."

	result := ValidateEvidence(fixture.sandbox, EvidenceValidationInput{
		Verdict:                  verdict,
		CandidatePath:            "app.go",
		CandidateStartLine:       3,
		CandidateEndLine:         3,
		CandidateFileHash:        fixture.hash,
		SearchCoverageIncomplete: true,
	})

	assert.Equal(t, EvidenceVerdictReject, result.RawVerdict)
	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "incomplete_search_rejection"))
}

func TestValidateEvidenceIncompleteSearchRejectWithTrustedSourceAbstains(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdictReject
	verdict.Source = &SourceEvidence{
		Citation: EvidenceCitation{
			Path:        "app.go",
			Line:        2,
			Snippet:     "func handler(input string) {",
			Symbol:      "handler",
			Description: "The caller supplies a trusted value.",
		},
		Trust: EvidenceTrustTrusted,
	}
	verdict.Reason = "The cited source proves the candidate safe."

	result := ValidateEvidence(fixture.sandbox, EvidenceValidationInput{
		Verdict:                  verdict,
		CandidatePath:            "app.go",
		CandidateStartLine:       3,
		CandidateEndLine:         3,
		CandidateFileHash:        fixture.hash,
		SearchCoverageIncomplete: true,
	})

	assert.Equal(t, EvidenceVerdictReject, result.RawVerdict)
	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "incomplete_search_rejection"))
}

func TestValidateEvidenceRejectWithFlowOnlyAbstains(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdictReject
	verdict.Flow = []EvidenceCitation{{
		Path:        "app.go",
		Line:        2,
		Snippet:     "func handler(input string) {",
		Symbol:      "handler",
		Description: "The value enters the handler.",
	}}
	verdict.Reason = "The flow was inspected."

	result := validateFixture(fixture, verdict)

	assert.False(t, result.Valid())
	assert.Equal(t, EvidenceVerdictReject, result.RawVerdict)
	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "missing_rejection_evidence"))
}

func TestValidateEvidencePreservesExplicitAbstain(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdictAbstain
	verdict.Confidence = EvidenceConfidenceLow
	verdict.Reason = "Repository context is insufficient."

	result := validateFixture(fixture, verdict)

	assert.True(t, result.Valid())
	assert.Equal(t, EvidenceVerdictAbstain, result.RawVerdict)
	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
}

func TestValidateEvidenceConfirmWithoutSinkAbstains(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink = nil

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "missing_sink"))
}

func TestValidateEvidenceRejectsParentTraversal(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Path = "../app.go"

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "invalid_citation_path"))
}

func TestValidateEvidenceRejectsAbsolutePath(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Path = filepath.Join(fixture.root, "app.go")

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "invalid_citation_path"))
}

func TestValidateEvidenceRejectsNonNormalizedPath(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Path = "internal/../app.go"

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "invalid_citation_path"))
}

func TestValidateEvidenceRejectsSymlinkEscape(t *testing.T) {
	fixture := newEvidenceFixture(t)
	externalRoot := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(externalRoot, "outside.go"), []byte("package outside\n"), 0o600))
	if err := os.Symlink(externalRoot, filepath.Join(fixture.root, "escape")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}
	verdict := validStructuredConfirm()
	verdict.Flow = []EvidenceCitation{{
		Path:        "escape/outside.go",
		Line:        1,
		Snippet:     "package outside",
		Symbol:      "",
		Description: "Outside evidence.",
	}}

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "citation_outside_repository"))
}

func TestValidateEvidenceRejectsMissingCitationFile(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Flow = []EvidenceCitation{{
		Path:        "missing.go",
		Line:        1,
		Snippet:     "package missing",
		Symbol:      "",
		Description: "Missing evidence.",
	}}

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "citation_file_unavailable"))
}

func TestValidateEvidenceRejectsLinePastEndOfFile(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Flow = []EvidenceCitation{{
		Path:        "app.go",
		Line:        200,
		Snippet:     "missing",
		Symbol:      "",
		Description: "Out-of-range evidence.",
	}}

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "citation_line_out_of_bounds"))
}

func TestValidateEvidenceRejectsWrongSinkPath(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Path = "internal/guard.go"
	verdict.Sink.Line = 2
	verdict.Sink.Snippet = "func allowed(value string) bool { return value == \"safe\" }"

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "sink_path_mismatch"))
	assert.False(t, hasEvidenceError(result, "stale_candidate_file"))
}

func TestValidateEvidenceAcceptsSinkAtLineWindowBoundary(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Line = 1
	verdict.Sink.Snippet = "package example"

	result := validateFixture(fixture, verdict)

	assert.True(t, result.Valid())
	assert.Equal(t, EvidenceVerdictConfirm, result.ValidatedVerdict)
}

func TestValidateEvidenceRejectsSinkOutsideLineWindow(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Line = 6
	verdict.Sink.Snippet = "var marker = true"

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "sink_line_mismatch"))
}

func TestValidateEvidenceDetectsStaleCandidateFile(t *testing.T) {
	fixture := newEvidenceFixture(t)
	assert.NoError(t, os.WriteFile(filepath.Join(fixture.root, "app.go"),
		[]byte("package example\nfunc handler(input string) {\n\trun(\"safe\")\n}\nfunc other() {}\nvar marker = true\n"), 0o600))

	result := validateFixture(fixture, validStructuredConfirm())

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "stale_candidate_file"))
}

func TestValidateEvidenceInvalidOptionalCitationAbstains(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Guards = []EvidenceCitation{{
		Path:        "internal/guard.go",
		Line:        99,
		Snippet:     "missing",
		Symbol:      "allowed",
		Description: "Invalid optional evidence.",
	}}

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictConfirm, result.RawVerdict)
	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "citation_line_out_of_bounds"))
}

func TestParseStructuredVerdictAcceptsValidJSON(t *testing.T) {
	content := `{"verdict":"abstain","confidence":"low","sink":{"path":"app.go","line":3,"snippet":"run(input)","symbol":"handler","description":"Candidate sink."},"source":null,"flow":[],"guards":[],"counterevidence":[],"reason":"More context is required."}`

	verdict, err := ParseStructuredVerdict(content)

	assert.NoError(t, err)
	assert.Equal(t, EvidenceVerdictAbstain, verdict.Verdict)
	assert.Nil(t, verdict.Source)
}

func TestParseStructuredVerdictRejectsUnknownField(t *testing.T) {
	content := `{"verdict":"abstain","confidence":"low","sink":{"path":"app.go","line":3,"snippet":"run(input)","symbol":"handler","description":"Candidate sink."},"source":null,"flow":[],"guards":[],"counterevidence":[],"reason":"More context is required.","unknown":true}`

	_, err := ParseStructuredVerdict(content)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")
}

func TestParseStructuredVerdictRejectsTrailingJSON(t *testing.T) {
	content := `{"verdict":"abstain","confidence":"low","sink":{"path":"app.go","line":3,"snippet":"run(input)","symbol":"handler","description":"Candidate sink."},"source":null,"flow":[],"guards":[],"counterevidence":[],"reason":"More context is required."} {}`

	_, err := ParseStructuredVerdict(content)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trailing JSON value")
}

func TestParseStructuredVerdictRejectsTruncatedJSON(t *testing.T) {
	content := `{"verdict":"reject","confidence":"high","sink":{"path":"app.go"`

	_, err := ParseStructuredVerdict(content)

	assert.Error(t, err)
}

func TestValidateEvidenceUnknownVerdictAbstains(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Verdict = EvidenceVerdict("maybe")

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdict("maybe"), result.RawVerdict)
	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "invalid_verdict"))
}

func TestValidateEvidenceUnknownConfidenceAbstains(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Confidence = EvidenceConfidence("certain")

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "invalid_confidence"))
}

func TestValidateEvidenceRejectsWindowsAbsolutePath(t *testing.T) {
	fixture := newEvidenceFixture(t)
	verdict := validStructuredConfirm()
	verdict.Sink.Path = `C:\source\app.go`

	result := validateFixture(fixture, verdict)

	assert.Equal(t, EvidenceVerdictAbstain, result.ValidatedVerdict)
	assert.True(t, hasEvidenceError(result, "invalid_citation_path"))
	assert.True(t, strings.Contains(result.Errors[0].Message, "forward slashes") ||
		strings.Contains(result.Errors[0].Message, "repository-relative"))
}
