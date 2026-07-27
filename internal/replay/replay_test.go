package replay

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/agents"
	"github.com/DataDog/datadog-saist/internal/candidates"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

type fakeCandidateVerifier struct {
	calls                 int
	mode                  string
	validateErr           error
	verificationViolation *model.Violation
	verificationResult    *agents.VerificationResult
	verificationErr       error
}

func (verifier *fakeCandidateVerifier) VerifyCandidate(_ context.Context, scanData *model.ScanData,
	candidate model.LLMResultViolation) (*model.Violation, *agents.VerificationResult, error) {
	verifier.calls++
	if verifier.verificationViolation != nil || verifier.verificationResult != nil || verifier.verificationErr != nil {
		return verifier.verificationViolation, verifier.verificationResult, verifier.verificationErr
	}
	verification := &agents.VerificationResult{
		VerificationResultData: agents.VerificationResultData{
			Confirmed:  candidate.StartLine == 1,
			Confidence: "high",
			Reason:     "verified",
		},
		InputTokens:  11,
		OutputTokens: 7,
	}
	if !verification.Confirmed {
		return nil, verification, nil
	}
	return &model.Violation{
		StartLine:   candidate.StartLine,
		StartColumn: candidate.StartColumn,
		EndLine:     candidate.EndLine,
		EndColumn:   candidate.EndColumn,
		Path:        scanData.RelativeFilePath,
		Rule:        scanData.Rule.ID,
		Message:     verification.Reason,
		Cwe:         scanData.Rule.Cwe,
	}, verification, nil
}

func (verifier *fakeCandidateVerifier) VerificationMode() string {
	return verifier.mode
}

func (verifier *fakeCandidateVerifier) ValidateVerificationMode() error {
	return verifier.validateErr
}

func replayTestCandidate(t *testing.T, source []byte, repositorySHA string, startLine uint) candidates.Candidate {
	t.Helper()
	candidate, err := candidates.NewCandidate(candidates.NewCandidateInput{
		RepositoryID:     "repository",
		RepositorySHA:    repositorySHA,
		ScanRoot:         "",
		RelativeFilePath: "source.go",
		Source:           source,
		Rule: api.AiPrompt{
			ID:      "test-rule",
			Content: "test prompt",
		},
		StartLine:       startLine,
		StartColumn:     1,
		EndLine:         startLine,
		EndColumn:       7,
		DetectionReason: "candidate",
		DetectionMode:   candidates.DetectionModeStandard,
	})
	assert.NoError(t, err)
	return candidate
}

func writeReplaySource(t *testing.T, source []byte) string {
	t.Helper()
	root := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(root, "source.go"), source, 0o600))
	return root
}

func TestRunDeduplicatesBeforeVerification(t *testing.T) {
	source := []byte("first\nsecond\n")
	candidate := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	verifier := &fakeCandidateVerifier{mode: "standard"}

	results, err := Run(context.Background(), []candidates.Candidate{candidate, candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, source),
		RepositorySHA:  strings.Repeat("a", 40),
	}, verifier)

	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, 1, verifier.calls)
	assert.Equal(t, OutcomeConfirmed, results[0].Outcome)
	assert.False(t, results[0].Contaminated)
}

func TestRunRejectsRepositorySHAMismatchBeforeVerification(t *testing.T) {
	source := []byte("first\n")
	candidate := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	verifier := &fakeCandidateVerifier{mode: "standard"}

	_, err := Run(context.Background(), []candidates.Candidate{candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, source),
		RepositorySHA:  strings.Repeat("b", 40),
	}, verifier)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "repository_sha_mismatch")
	assert.Equal(t, 0, verifier.calls)
}

func TestRunRejectsMixedCandidateSHAs(t *testing.T) {
	source := []byte("first\nsecond\n")
	first := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	second := replayTestCandidate(t, source, strings.Repeat("b", 40), 2)
	verifier := &fakeCandidateVerifier{mode: "standard"}

	_, err := Run(context.Background(), []candidates.Candidate{first, second}, SourceRevision{
		RepositoryID:     "repository",
		RepositoryRoot:   writeReplaySource(t, source),
		RepositorySHA:    strings.Repeat("c", 40),
		AllowSourceDrift: true,
	}, verifier)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple repository SHAs")
	assert.Equal(t, 0, verifier.calls)
}

func TestRunRejectsSourceFileHashMismatchBeforeVerification(t *testing.T) {
	originalSource := []byte("first\n")
	candidate := replayTestCandidate(t, originalSource, strings.Repeat("a", 40), 1)
	verifier := &fakeCandidateVerifier{mode: "standard"}

	_, err := Run(context.Background(), []candidates.Candidate{candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, []byte("changed\n")),
		RepositorySHA:  strings.Repeat("a", 40),
	}, verifier)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "source_file_hash_mismatch")
	assert.Equal(t, 0, verifier.calls)
}

func TestRunMarksEveryResultContaminatedWhenDriftIsAllowed(t *testing.T) {
	source := []byte("first\nsecond\n")
	first := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	second := replayTestCandidate(t, source, strings.Repeat("a", 40), 2)
	verifier := &fakeCandidateVerifier{mode: "agentic"}

	results, err := Run(context.Background(), []candidates.Candidate{first, second}, SourceRevision{
		RepositoryID:     "repository",
		RepositoryRoot:   writeReplaySource(t, source),
		RepositorySHA:    strings.Repeat("b", 40),
		AllowSourceDrift: true,
	}, verifier)

	assert.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, 2, verifier.calls)
	assert.True(t, results[0].Contaminated)
	assert.True(t, results[1].Contaminated)
	assert.Equal(t, "agentic", results[0].VerificationMode)
	assert.Contains(t, results[0].ContaminationReasons, "repository_sha_mismatch")
}

func TestRunRejectsUnavailableVerificationModeBeforeVerification(t *testing.T) {
	source := []byte("first\n")
	candidate := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	verifier := &fakeCandidateVerifier{
		mode:        "agentic",
		validateErr: errors.New("tool calling unavailable"),
	}

	_, err := Run(context.Background(), []candidates.Candidate{candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, source),
		RepositorySHA:  strings.Repeat("a", 40),
	}, verifier)

	assert.EqualError(t, err, "tool calling unavailable")
	assert.Equal(t, 0, verifier.calls)
}

func TestRunEmitsAbstainedOutcomeWithAuditFields(t *testing.T) {
	source := []byte("first\n")
	candidate := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	evidence := &agents.StructuredVerdict{
		Verdict:    agents.EvidenceVerdictReject,
		Confidence: agents.EvidenceConfidenceHigh,
		Sink: &agents.EvidenceCitation{
			Path:        "source.go",
			Line:        1,
			Snippet:     "first",
			Symbol:      "sink",
			Description: "Candidate sink.",
		},
		Flow:            []agents.EvidenceCitation{},
		Guards:          []agents.EvidenceCitation{},
		Counterevidence: []agents.EvidenceCitation{},
		Reason:          "The rejection lacks supporting evidence.",
	}
	validationErrors := []agents.EvidenceValidationError{{
		Code:    "missing_rejection_evidence",
		Field:   "verdict",
		Message: "A rejection requires source, guard, or counterevidence.",
	}}
	verifier := &fakeCandidateVerifier{
		mode: "agentic",
		verificationResult: &agents.VerificationResult{
			VerificationResultData: agents.VerificationResultData{
				Confidence: "high",
				Reason:     evidence.Reason,
			},
			InputTokens:              11,
			OutputTokens:             7,
			RawVerdict:               agents.EvidenceVerdictReject,
			ValidatedVerdict:         agents.EvidenceVerdictAbstain,
			Evidence:                 evidence,
			EvidenceValidationErrors: validationErrors,
		},
	}

	results, err := Run(context.Background(), []candidates.Candidate{candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, source),
		RepositorySHA:  strings.Repeat("a", 40),
	}, verifier)

	assert.NoError(t, err)
	if assert.Len(t, results, 1) {
		result := results[0]
		assert.Equal(t, OutcomeAbstained, result.Outcome)
		assert.Equal(t, agents.EvidenceVerdictReject, result.RawVerdict)
		assert.Equal(t, agents.EvidenceVerdictAbstain, result.ValidatedVerdict)
		assert.Equal(t, evidence, result.Evidence)
		assert.Equal(t, validationErrors, result.EvidenceValidationErrors)
		assert.Equal(t, "high", result.Confidence)
		assert.Equal(t, evidence.Reason, result.Reason)
		assert.NotNil(t, result.Violation)
	}

	var output bytes.Buffer
	assert.NoError(t, WriteJSONL(&output, results))
	assert.Contains(t, output.String(), `"outcome":"abstained"`)
	assert.Contains(t, output.String(), `"raw_verdict":"reject"`)
	assert.Contains(t, output.String(), `"validated_verdict":"abstain"`)
	assert.Contains(t, output.String(), `"evidence":{`)
	assert.Contains(t, output.String(), `"evidence_validation_errors":[{`)
}

func TestRunRecordsRetainedStandardFallbackRejection(t *testing.T) {
	source := []byte("first\n")
	candidate := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	telemetry := &agents.VerificationTelemetry{
		ModelCalls: []agents.ModelCallTelemetry{
			{Sequence: 1, Kind: agents.ModelCallKindAgenticVerdict, InputTokens: 3, OutputTokens: 4},
			{Sequence: 2, Kind: agents.ModelCallKindStandardFallback, InputTokens: 5, OutputTokens: 6},
		},
	}
	verifier := &fakeCandidateVerifier{
		mode: "agentic",
		verificationResult: &agents.VerificationResult{
			VerificationResultData: agents.VerificationResultData{
				Confidence: "low",
				Reason:     "Verification could not reach a reliable verdict.",
			},
			InputTokens:          8,
			OutputTokens:         10,
			RawVerdict:           agents.EvidenceVerdictAbstain,
			ValidatedVerdict:     agents.EvidenceVerdictAbstain,
			FinalVerdict:         agents.EvidenceVerdictAbstain,
			VerdictSource:        agents.VerificationSourceRetained,
			FallbackUsed:         true,
			FallbackReason:       agents.FallbackExplicitAbstain,
			FallbackVerdict:      agents.EvidenceVerdictReject,
			AgenticInputTokens:   3,
			AgenticOutputTokens:  4,
			FallbackInputTokens:  5,
			FallbackOutputTokens: 6,
			DurationMillis:       42,
			Telemetry:            telemetry,
		},
	}

	results, err := Run(context.Background(), []candidates.Candidate{candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, source),
		RepositorySHA:  strings.Repeat("a", 40),
	}, verifier)

	assert.NoError(t, err)
	if assert.Len(t, results, 1) {
		result := results[0]
		assert.Equal(t, OutcomeAbstained, result.Outcome)
		assert.Equal(t, agents.EvidenceVerdictAbstain, result.FinalVerdict)
		assert.Equal(t, agents.VerificationSourceRetained, result.VerdictSource)
		assert.Equal(t, agents.EvidenceVerdictReject, result.FallbackVerdict)
		assert.True(t, result.FallbackUsed)
		assert.Equal(t, agents.FallbackExplicitAbstain, result.FallbackReason)
		assert.Equal(t, int32(3), result.AgenticInputTokens)
		assert.Equal(t, int32(4), result.AgenticOutputTokens)
		assert.Equal(t, int32(5), result.FallbackInputTokens)
		assert.Equal(t, int32(6), result.FallbackOutputTokens)
		assert.Equal(t, int64(42), result.CandidateDurationMillis)
		assert.Equal(t, int32(2), result.ModelCalls)
		assert.Equal(t, telemetry, result.Telemetry)
	}
}

func TestRunRetainedAbstainCarriesFingerprintedViolation(t *testing.T) {
	source := []byte("first\n")
	candidate := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	retained := &model.Violation{
		StartLine:   1,
		StartColumn: 1,
		EndLine:     1,
		EndColumn:   6,
		Path:        "source.go",
		Rule:        "test-rule",
		Message:     "candidate",
	}
	verifier := &fakeCandidateVerifier{
		mode:                  "agentic",
		verificationViolation: retained,
		verificationResult: &agents.VerificationResult{
			VerificationResultData: agents.VerificationResultData{
				Confidence: "low",
				Reason:     "The fallback failed, so the candidate was retained.",
			},
			FinalVerdict:   agents.EvidenceVerdictAbstain,
			VerdictSource:  agents.VerificationSourceRetained,
			FallbackUsed:   true,
			FallbackReason: agents.FallbackAgenticFailure,
			AgenticError:   "agentic unavailable",
			FallbackError:  "standard unavailable",
		},
	}

	results, err := Run(context.Background(), []candidates.Candidate{candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, source),
		RepositorySHA:  strings.Repeat("a", 40),
	}, verifier)

	assert.NoError(t, err)
	if assert.Len(t, results, 1) {
		result := results[0]
		assert.Equal(t, OutcomeAbstained, result.Outcome)
		assert.Equal(t, agents.VerificationSourceRetained, result.VerdictSource)
		assert.Equal(t, "agentic unavailable", result.AgenticError)
		assert.Equal(t, "standard unavailable", result.FallbackError)
		if assert.NotNil(t, result.Violation) {
			assert.Equal(t, "source.go", result.Violation.Path)
			assert.NotEmpty(t, result.Violation.FileHash)
			assert.NotEmpty(t, result.Violation.Fingerprint)
		}
	}
}

func TestRunRejectVerdictWithRetainedViolationFailsClosed(t *testing.T) {
	source := []byte("first\n")
	candidate := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	verifier := &fakeCandidateVerifier{
		mode: "agentic",
		verificationViolation: &model.Violation{
			StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 6,
			Path: "source.go", Rule: "test-rule", Message: "candidate",
		},
		verificationResult: &agents.VerificationResult{
			FinalVerdict:  agents.EvidenceVerdictReject,
			VerdictSource: agents.VerificationSourceStandardFallback,
		},
	}

	results, err := Run(context.Background(), []candidates.Candidate{candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, source),
		RepositorySHA:  strings.Repeat("a", 40),
	}, verifier)

	assert.NoError(t, err)
	if assert.Len(t, results, 1) {
		assert.Equal(t, OutcomeAbstained, results[0].Outcome)
		assert.Equal(t, agents.EvidenceVerdictAbstain, results[0].FinalVerdict)
		assert.Equal(t, agents.VerificationSourceRetained, results[0].VerdictSource)
		assert.NotNil(t, results[0].Violation)
		assert.Contains(t, results[0].Error, "reject verdict")
	}
}

func TestRunLegacyValidatedAbstainWinsOverRetainedViolation(t *testing.T) {
	source := []byte("first\n")
	candidate := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	verifier := &fakeCandidateVerifier{
		mode: "agentic",
		verificationViolation: &model.Violation{
			StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 6,
			Path: "source.go", Rule: "test-rule", Message: "candidate",
		},
		verificationResult: &agents.VerificationResult{
			RawVerdict:       agents.EvidenceVerdictReject,
			ValidatedVerdict: agents.EvidenceVerdictAbstain,
		},
	}

	results, err := Run(context.Background(), []candidates.Candidate{candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, source),
		RepositorySHA:  strings.Repeat("a", 40),
	}, verifier)

	assert.NoError(t, err)
	if assert.Len(t, results, 1) {
		assert.Equal(t, OutcomeAbstained, results[0].Outcome)
		assert.Equal(t, agents.EvidenceVerdictAbstain, results[0].FinalVerdict)
		assert.Equal(t, agents.VerificationSourceAgentic, results[0].VerdictSource)
		assert.NotNil(t, results[0].Violation)
	}
}

func TestRunPreservesPartialTelemetryOnVerifierError(t *testing.T) {
	source := []byte("first\n")
	candidate := replayTestCandidate(t, source, strings.Repeat("a", 40), 1)
	telemetry := &agents.VerificationTelemetry{
		ModelCalls: []agents.ModelCallTelemetry{{
			Sequence:     1,
			Kind:         agents.ModelCallKindAgenticInvestigation,
			InputTokens:  9,
			OutputTokens: 2,
			Error:        "request failed",
		}},
		StopReason: agents.LoopStopReasonInvestigationCallFailed,
	}
	verifier := &fakeCandidateVerifier{
		mode: "agentic",
		verificationResult: &agents.VerificationResult{
			VerificationResultData: agents.VerificationResultData{
				Confidence: "low",
				Reason:     "The agentic request failed.",
			},
			InputTokens:         9,
			OutputTokens:        2,
			AgenticInputTokens:  9,
			AgenticOutputTokens: 2,
			AgenticError:        "request failed",
			Telemetry:           telemetry,
		},
		verificationErr: errors.New("verification failed"),
	}

	results, err := Run(context.Background(), []candidates.Candidate{candidate}, SourceRevision{
		RepositoryID:   "repository",
		RepositoryRoot: writeReplaySource(t, source),
		RepositorySHA:  strings.Repeat("a", 40),
	}, verifier)

	assert.NoError(t, err)
	if assert.Len(t, results, 1) {
		result := results[0]
		assert.Equal(t, OutcomeError, result.Outcome)
		assert.Equal(t, "verification failed", result.Error)
		assert.Equal(t, int32(9), result.InputTokens)
		assert.Equal(t, int32(2), result.OutputTokens)
		assert.Equal(t, "request failed", result.AgenticError)
		assert.Equal(t, telemetry, result.Telemetry)
	}
}

func TestWriteJSONLOmitsRawToolResults(t *testing.T) {
	const sentinelRawToolResult = "RAW_TOOL_RESULT_SENTINEL"
	telemetry := &agents.VerificationTelemetry{
		ToolCalls: []agents.ToolCallTelemetry{{
			Sequence:          1,
			ModelCallSequence: 1,
			ToolCallID:        "call-1",
			Name:              "read_file",
			Arguments:         `{"path":"source.go"}`,
			ResultBytes:       len(sentinelRawToolResult),
			Disposition:       agents.ToolCallDispositionExecuted,
		}},
	}
	var output bytes.Buffer

	err := WriteJSONL(&output, []Result{{
		SchemaVersion: ResultSchemaVersion,
		CandidateID:   "candidate",
		Outcome:       OutcomeRejected,
		Telemetry:     telemetry,
	}})

	assert.NoError(t, err)
	assert.Contains(t, output.String(), `"name":"read_file"`)
	assert.Contains(t, output.String(), `"result_bytes":24`)
	assert.NotContains(t, output.String(), sentinelRawToolResult)
}

func TestWriteJSONLEmitsRejectedCandidates(t *testing.T) {
	var output bytes.Buffer
	results := []Result{{
		SchemaVersion: ResultSchemaVersion,
		CandidateID:   "candidate",
		Outcome:       OutcomeRejected,
		Contaminated:  true,
	}}

	err := WriteJSONL(&output, results)

	assert.NoError(t, err)
	assert.Contains(t, output.String(), `"outcome":"rejected"`)
	assert.Contains(t, output.String(), `"contaminated":true`)
}

func TestWriteFileRestrictsExistingOutputPermissions(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "results.jsonl")
	assert.NoError(t, os.WriteFile(filePath, []byte("stale"), 0o644))
	assert.NoError(t, os.Chmod(filePath, 0o644))

	err := WriteFile(filePath, []Result{{
		SchemaVersion: ResultSchemaVersion,
		CandidateID:   "candidate",
		Outcome:       OutcomeRejected,
	}})

	assert.NoError(t, err)
	info, err := os.Stat(filePath)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
