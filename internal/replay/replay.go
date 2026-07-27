package replay

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/DataDog/datadog-saist/internal/agents"
	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/candidates"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/utils"
)

type Outcome string

type SourceRevision struct {
	RepositoryID     string
	RepositoryRoot   string
	RepositorySHA    string
	RepositoryDirty  bool
	AllowSourceDrift bool
}

type Result struct {
	SchemaVersion            int                               `json:"schema_version"`
	CandidateID              string                            `json:"candidate_id"`
	RepositoryID             string                            `json:"repository_id"`
	RepositorySHA            string                            `json:"repository_sha"`
	RelativeFilePath         string                            `json:"relative_file_path"`
	RuleID                   string                            `json:"rule_id"`
	CWE                      *string                           `json:"cwe,omitempty"`
	DetectionMode            candidates.DetectionMode          `json:"detection_mode"`
	VerificationMode         string                            `json:"verification_mode"`
	Contaminated             bool                              `json:"contaminated"`
	ContaminationReasons     []string                          `json:"contamination_reasons,omitempty"`
	Outcome                  Outcome                           `json:"outcome"`
	Confidence               string                            `json:"confidence,omitempty"`
	Reason                   string                            `json:"reason,omitempty"`
	InputTokens              int32                             `json:"input_tokens"`
	OutputTokens             int32                             `json:"output_tokens"`
	ModelCalls               int32                             `json:"model_calls"`
	RawVerdict               agents.EvidenceVerdict            `json:"raw_verdict,omitempty"`
	ValidatedVerdict         agents.EvidenceVerdict            `json:"validated_verdict,omitempty"`
	Evidence                 *agents.StructuredVerdict         `json:"evidence,omitempty"`
	EvidenceValidationErrors []agents.EvidenceValidationError  `json:"evidence_validation_errors,omitempty"`
	FinalVerdict             agents.EvidenceVerdict            `json:"final_verdict,omitempty"`
	VerdictSource            agents.VerificationVerdictSource  `json:"verdict_source,omitempty"`
	FallbackUsed             bool                              `json:"fallback_used"`
	FallbackReason           agents.VerificationFallbackReason `json:"fallback_reason,omitempty"`
	FallbackVerdict          agents.EvidenceVerdict            `json:"fallback_verdict,omitempty"`
	AgenticError             string                            `json:"agentic_error,omitempty"`
	FallbackError            string                            `json:"fallback_error,omitempty"`
	AgenticInputTokens       int32                             `json:"agentic_input_tokens"`
	AgenticOutputTokens      int32                             `json:"agentic_output_tokens"`
	FallbackInputTokens      int32                             `json:"fallback_input_tokens"`
	FallbackOutputTokens     int32                             `json:"fallback_output_tokens"`
	CandidateDurationMillis  int64                             `json:"candidate_duration_ms"`
	Telemetry                *agents.VerificationTelemetry     `json:"telemetry,omitempty"`
	Violation                *model.Violation                  `json:"violation,omitempty"`
	Error                    string                            `json:"error,omitempty"`
}

// IsScoreable reports whether a replay result contains a fail-closed verdict
// that an experiment may persist as a completed candidate trial. Operational
// errors remain retryable and must not consume an experiment slot.
func (result Result) IsScoreable() bool {
	switch result.Outcome {
	case OutcomeConfirmed, OutcomeRejected, OutcomeAbstained:
		return true
	default:
		return false
	}
}

// OperationalFailure converts replay and model call failures back into an
// error for callers that require an uninterrupted scoreable verdict, such as
// the experiment runner.
func (result Result) OperationalFailure() error {
	if result.Outcome == OutcomeError {
		message := strings.TrimSpace(result.Error)
		if message == "" {
			message = "replay ended with an operational error"
		}
		return errors.New(message)
	}
	if result.Telemetry == nil {
		return nil
	}
	for _, call := range result.Telemetry.ModelCalls {
		if message := strings.TrimSpace(call.Error); message != "" {
			return fmt.Errorf("model call %d failed, %s", call.Sequence, message)
		}
	}
	return nil
}

type CandidateVerifier interface {
	VerifyCandidate(context.Context, *model.ScanData, model.LLMResultViolation) (
		*model.Violation, *agents.VerificationResult, error)
	VerificationMode() string
	ValidateVerificationMode() error
}

type sourceRecord struct {
	content []byte
	err     error
}

func Run(ctx context.Context, values []candidates.Candidate, revision SourceRevision,
	verifier CandidateVerifier) ([]Result, error) {
	unique, err := candidates.Dedupe(values)
	if err != nil {
		return nil, err
	}
	if len(unique) == 0 {
		return []Result{}, nil
	}
	if err := verifier.ValidateVerificationMode(); err != nil {
		return nil, err
	}

	expectedRepositoryID := unique[0].RepositoryID
	expectedRepositorySHA := unique[0].RepositorySHA
	expectedRepositoryDirty := unique[0].RepositoryDirty
	pathHashes := make(map[string]string, len(unique))
	ruleHashes := make(map[string]string, len(unique))
	for _, candidate := range unique[1:] {
		if candidate.RepositoryID != expectedRepositoryID {
			return nil, fmt.Errorf("candidate manifest contains multiple repository IDs")
		}
		if candidate.RepositorySHA != expectedRepositorySHA {
			return nil, fmt.Errorf("candidate manifest contains multiple repository SHAs")
		}
		if candidate.RepositoryDirty != expectedRepositoryDirty {
			return nil, fmt.Errorf("candidate manifest contains inconsistent dirty state")
		}
	}
	for _, candidate := range unique {
		repositoryPath := candidate.RepositoryRelativePath()
		if previous, found := pathHashes[repositoryPath]; found && previous != candidate.SourceFileHash {
			return nil, fmt.Errorf("candidate manifest contains multiple source hashes for %q", repositoryPath)
		}
		pathHashes[repositoryPath] = candidate.SourceFileHash
		if previous, found := ruleHashes[candidate.Rule.ID]; found && previous != candidate.RuleContentHash {
			return nil, fmt.Errorf("candidate manifest contains multiple content hashes for rule %q", candidate.Rule.ID)
		}
		ruleHashes[candidate.Rule.ID] = candidate.RuleContentHash
	}
	if revision.RepositoryID != expectedRepositoryID {
		return nil, fmt.Errorf("candidate repository ID %q does not match replay repository ID %q",
			expectedRepositoryID, revision.RepositoryID)
	}

	sandbox, err := agenttools.NewSandbox(revision.RepositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("create replay source sandbox: %w", err)
	}

	reasons := make(map[string]struct{})
	if expectedRepositoryDirty {
		reasons["exported_repository_dirty"] = struct{}{}
	}
	if revision.RepositorySHA != expectedRepositorySHA {
		reasons["repository_sha_mismatch"] = struct{}{}
	}
	if revision.RepositoryDirty {
		reasons["current_repository_dirty"] = struct{}{}
	}

	sources := make(map[string]sourceRecord, len(unique))
	for _, candidate := range unique {
		repositoryPath := candidate.RepositoryRelativePath()
		if _, found := sources[repositoryPath]; found {
			continue
		}
		absolutePath, resolveErr := sandbox.Resolve(repositoryPath)
		if resolveErr != nil {
			sources[repositoryPath] = sourceRecord{err: resolveErr}
			reasons["source_file_unavailable"] = struct{}{}
			continue
		}
		content, readErr := os.ReadFile(absolutePath)
		if readErr != nil {
			sources[repositoryPath] = sourceRecord{err: readErr}
			reasons["source_file_unavailable"] = struct{}{}
			continue
		}
		sources[repositoryPath] = sourceRecord{content: content}
	}
	for _, candidate := range unique {
		source := sources[candidate.RepositoryRelativePath()]
		if source.err == nil && hashBytes(source.content) != candidate.SourceFileHash {
			reasons["source_file_hash_mismatch"] = struct{}{}
		}
	}

	contaminationReasons := sortedReasons(reasons)
	contaminated := len(contaminationReasons) > 0
	if contaminated && !revision.AllowSourceDrift {
		return nil, fmt.Errorf("candidate source revision does not match replay source, %s",
			strings.Join(contaminationReasons, ","))
	}

	results := make([]Result, 0, len(unique))
	for _, candidate := range unique {
		result := newResult(candidate, verifier.VerificationMode(), contaminated, contaminationReasons)
		source := sources[candidate.RepositoryRelativePath()]
		if source.err != nil {
			result.Outcome = OutcomeError
			result.Error = source.err.Error()
			results = append(results, result)
			continue
		}

		rule := candidate.Rule
		scanData := &model.ScanData{
			RelativeFilePath:           candidate.RelativeFilePath,
			RepositoryRelativeFilePath: candidate.RepositoryRelativePath(),
			CandidateID:                candidate.ID,
			FileHash:                   hashBytes(source.content),
			FileText:                   string(source.content),
			NumberedFileText:           utils.AddLineNumbers(string(source.content)),
			Rule:                       &rule,
		}
		rawCandidate := model.LLMResultViolation{
			StartLine:   candidate.StartLine,
			StartColumn: candidate.StartColumn,
			EndLine:     candidate.EndLine,
			EndColumn:   candidate.EndColumn,
			Reason:      candidate.DetectionReason,
		}
		violation, verification, verifyErr := verifier.VerifyCandidate(ctx, scanData, rawCandidate)
		copyVerificationAudit(&result, verification)
		if verifyErr != nil {
			result.Outcome = OutcomeError
			result.Error = verifyErr.Error()
			results = append(results, result)
			continue
		}

		finalVerdict := result.FinalVerdict
		if finalVerdict == "" {
			finalVerdict = compatibilityFinalVerdict(violation, verification)
			result.FinalVerdict = finalVerdict
			if result.VerdictSource == "" && verification != nil {
				if result.VerificationMode == "agentic" {
					result.VerdictSource = agents.VerificationSourceAgentic
				} else {
					result.VerdictSource = agents.VerificationSourceStandard
				}
			}
		}

		switch finalVerdict {
		case agents.EvidenceVerdictConfirm:
			if violation == nil {
				result.Outcome = OutcomeError
				result.Error = "confirmed verdict did not return a violation"
				results = append(results, result)
				continue
			}
			setResultViolation(&result, violation, scanData, revision.RepositoryID)
			result.Outcome = OutcomeConfirmed
		case agents.EvidenceVerdictReject:
			if violation != nil {
				result.Outcome = OutcomeAbstained
				result.FinalVerdict = agents.EvidenceVerdictAbstain
				result.VerdictSource = agents.VerificationSourceRetained
				result.Error = "reject verdict returned a retained violation"
				setResultViolation(&result, violation, scanData, revision.RepositoryID)
			} else {
				result.Outcome = OutcomeRejected
			}
		case agents.EvidenceVerdictAbstain:
			result.Outcome = OutcomeAbstained
			if violation == nil {
				violation = retainedReplayViolation(scanData, rawCandidate)
			}
			setResultViolation(&result, violation, scanData, revision.RepositoryID)
		default:
			result.Outcome = OutcomeError
			result.Error = fmt.Sprintf("unsupported final verdict %q", finalVerdict)
		}
		results = append(results, result)
	}
	return results, nil
}

func retainedReplayViolation(scanData *model.ScanData, candidate model.LLMResultViolation) *model.Violation {
	return &model.Violation{
		StartLine:   candidate.StartLine,
		StartColumn: candidate.StartColumn,
		EndLine:     candidate.EndLine,
		EndColumn:   candidate.EndColumn,
		Path:        scanData.RelativeFilePath,
		Rule:        scanData.Rule.ID,
		Message:     candidate.Reason,
		Cwe:         scanData.Rule.Cwe,
	}
}

func copyVerificationAudit(result *Result, verification *agents.VerificationResult) {
	if verification == nil {
		return
	}
	result.Confidence = verification.Confidence
	result.Reason = verification.Reason
	result.InputTokens = verification.InputTokens
	result.OutputTokens = verification.OutputTokens
	if verification.Telemetry != nil {
		result.ModelCalls = int32(len(verification.Telemetry.ModelCalls))
	}
	result.RawVerdict = verification.RawVerdict
	result.ValidatedVerdict = verification.ValidatedVerdict
	result.Evidence = verification.Evidence
	result.EvidenceValidationErrors = append(
		[]agents.EvidenceValidationError(nil), verification.EvidenceValidationErrors...)
	result.FinalVerdict = verification.FinalVerdict
	result.VerdictSource = verification.VerdictSource
	result.FallbackUsed = verification.FallbackUsed
	result.FallbackReason = verification.FallbackReason
	result.FallbackVerdict = verification.FallbackVerdict
	result.AgenticError = verification.AgenticError
	result.FallbackError = verification.FallbackError
	result.AgenticInputTokens = verification.AgenticInputTokens
	result.AgenticOutputTokens = verification.AgenticOutputTokens
	result.FallbackInputTokens = verification.FallbackInputTokens
	result.FallbackOutputTokens = verification.FallbackOutputTokens
	result.CandidateDurationMillis = verification.DurationMillis
	result.Telemetry = verification.Telemetry
}

func compatibilityFinalVerdict(violation *model.Violation,
	verification *agents.VerificationResult) agents.EvidenceVerdict {
	if verification != nil && verification.ValidatedVerdict == agents.EvidenceVerdictAbstain {
		return agents.EvidenceVerdictAbstain
	}
	if violation != nil {
		return agents.EvidenceVerdictConfirm
	}
	return agents.EvidenceVerdictReject
}

func setResultViolation(result *Result, violation *model.Violation, scanData *model.ScanData,
	repositoryID string) {
	violation.FileHash = scanData.FileHash
	lineContent := model.GetLineContent(scanData.FileText, violation.StartLine)
	violation.Fingerprint = model.GenerateFingerprint(
		repositoryID, violation.Rule, violation.Path, lineContent)
	result.Violation = violation
}

func newResult(candidate candidates.Candidate, verificationMode string, contaminated bool,
	reasons []string) Result {
	return Result{
		SchemaVersion:        ResultSchemaVersion,
		CandidateID:          candidate.ID,
		RepositoryID:         candidate.RepositoryID,
		RepositorySHA:        candidate.RepositorySHA,
		RelativeFilePath:     candidate.RelativeFilePath,
		RuleID:               candidate.Rule.ID,
		CWE:                  candidate.Rule.Cwe,
		DetectionMode:        candidate.DetectionMode,
		VerificationMode:     verificationMode,
		Contaminated:         contaminated,
		ContaminationReasons: append([]string(nil), reasons...),
	}
}

func WriteJSONL(writer io.Writer, results []Result) error {
	buffered := bufio.NewWriter(writer)
	encoder := json.NewEncoder(buffered)
	encoder.SetEscapeHTML(false)
	for index, result := range results {
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("replay result %d, %w", index+1, err)
		}
	}
	if err := buffered.Flush(); err != nil {
		return fmt.Errorf("flush replay results: %w", err)
	}
	return nil
}

func WriteFile(filePath string, results []Result) error {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create replay output %q: %w", filePath, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set replay output permissions %q: %w", filePath, err)
	}
	if err := WriteJSONL(file, results); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close replay output %q: %w", filePath, err)
	}
	return nil
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func sortedReasons(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
