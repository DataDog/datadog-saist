package candidates

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

type DetectionMode string

// Candidate is an unverified finding tied to a source snapshot and rule snapshot.
type Candidate struct {
	SchemaVersion    int           `json:"schema_version"`
	ID               string        `json:"candidate_id"`
	RepositoryID     string        `json:"repository_id"`
	RepositorySHA    string        `json:"repository_sha"`
	RepositoryDirty  bool          `json:"repository_dirty"`
	ScanRoot         string        `json:"scan_root"`
	RelativeFilePath string        `json:"relative_file_path"`
	SourceFileHash   string        `json:"source_file_hash"`
	Rule             api.AiPrompt  `json:"rule"`
	RuleContentHash  string        `json:"rule_content_hash"`
	StartLine        uint          `json:"start_line"`
	StartColumn      uint          `json:"start_column"`
	EndLine          uint          `json:"end_line"`
	EndColumn        uint          `json:"end_column"`
	DetectionReason  string        `json:"detection_reason"`
	SinkLineHash     string        `json:"sink_line_hash"`
	DetectionMode    DetectionMode `json:"detection_mode"`
}

// NewCandidateInput contains the source data needed to construct a candidate.
type NewCandidateInput struct {
	RepositoryID     string
	RepositorySHA    string
	RepositoryDirty  bool
	ScanRoot         string
	RelativeFilePath string
	Source           []byte
	Rule             api.AiPrompt
	StartLine        uint
	StartColumn      uint
	EndLine          uint
	EndColumn        uint
	DetectionReason  string
	DetectionMode    DetectionMode
}

// NewCandidate builds a normalized candidate and computes all integrity hashes.
func NewCandidate(input NewCandidateInput) (Candidate, error) {
	scanRoot, err := normalizeScanRoot(input.ScanRoot)
	if err != nil {
		return Candidate{}, err
	}
	relativeFilePath, err := normalizeRelativeFilePath(input.RelativeFilePath)
	if err != nil {
		return Candidate{}, err
	}

	sinkLineHash, err := normalizedSinkLineHash(input.Source, input.StartLine)
	if err != nil {
		return Candidate{}, err
	}

	candidate := Candidate{
		SchemaVersion:    SchemaVersion,
		RepositoryID:     input.RepositoryID,
		RepositorySHA:    strings.ToLower(input.RepositorySHA),
		RepositoryDirty:  input.RepositoryDirty,
		ScanRoot:         scanRoot,
		RelativeFilePath: relativeFilePath,
		SourceFileHash:   hashBytes(input.Source),
		Rule:             cloneRule(input.Rule),
		RuleContentHash:  hashBytes([]byte(input.Rule.Content)),
		StartLine:        input.StartLine,
		StartColumn:      input.StartColumn,
		EndLine:          input.EndLine,
		EndColumn:        input.EndColumn,
		DetectionReason:  input.DetectionReason,
		SinkLineHash:     sinkLineHash,
		DetectionMode:    input.DetectionMode,
	}

	candidate.ID, err = candidate.expectedID()
	if err != nil {
		return Candidate{}, err
	}
	if err := candidate.Validate(); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

// Validate checks schema, identity, paths, rule data, and coordinates.
func (candidate Candidate) Validate() error {
	if candidate.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", candidate.SchemaVersion)
	}
	if candidate.RepositoryID == "" {
		return fmt.Errorf("repository_id is required")
	}
	if strings.ContainsRune(candidate.RepositoryID, '\x00') {
		return fmt.Errorf("repository_id contains a NUL byte")
	}
	if !isGitSHA(candidate.RepositorySHA) {
		return fmt.Errorf("repository_sha must be a lowercase 40 or 64 character hexadecimal commit hash")
	}

	scanRoot, err := normalizeScanRoot(candidate.ScanRoot)
	if err != nil {
		return err
	}
	if scanRoot != candidate.ScanRoot {
		return fmt.Errorf("scan_root is not normalized")
	}
	relativeFilePath, err := normalizeRelativeFilePath(candidate.RelativeFilePath)
	if err != nil {
		return err
	}
	if relativeFilePath != candidate.RelativeFilePath {
		return fmt.Errorf("relative_file_path is not normalized")
	}

	if !isSHA256(candidate.SourceFileHash) {
		return fmt.Errorf("source_file_hash must be a lowercase SHA-256 hash")
	}
	if candidate.Rule.ID == "" {
		return fmt.Errorf("rule id is required")
	}
	if !isSHA256(candidate.RuleContentHash) {
		return fmt.Errorf("rule_content_hash must be a lowercase SHA-256 hash")
	}
	if candidate.RuleContentHash != hashBytes([]byte(candidate.Rule.Content)) {
		return fmt.Errorf("rule_content_hash does not match rule content")
	}
	if candidate.StartLine == 0 || candidate.StartColumn == 0 || candidate.EndLine == 0 || candidate.EndColumn == 0 {
		return fmt.Errorf("candidate coordinates must be greater than zero")
	}
	if candidate.EndLine < candidate.StartLine {
		return fmt.Errorf("end_line is before start_line")
	}
	if candidate.EndLine == candidate.StartLine && candidate.EndColumn < candidate.StartColumn {
		return fmt.Errorf("end_column is before start_column")
	}
	if !isSHA256(candidate.SinkLineHash) {
		return fmt.Errorf("sink_line_hash must be a lowercase SHA-256 hash")
	}
	if candidate.DetectionMode != DetectionModeStandard && candidate.DetectionMode != DetectionModeAgentic {
		return fmt.Errorf("unsupported detection_mode %q", candidate.DetectionMode)
	}

	expectedID, err := candidate.expectedID()
	if err != nil {
		return err
	}
	if candidate.ID != expectedID {
		return fmt.Errorf("candidate_id does not match candidate identity")
	}
	return nil
}

// RepositoryRelativePath returns the candidate path relative to the repository root.
func (candidate Candidate) RepositoryRelativePath() string {
	if candidate.ScanRoot == "" {
		return candidate.RelativeFilePath
	}
	return path.Join(candidate.ScanRoot, candidate.RelativeFilePath)
}

func (candidate Candidate) expectedID() (string, error) {
	if candidate.RepositoryID == "" || candidate.RepositorySHA == "" || candidate.Rule.ID == "" {
		return "", fmt.Errorf("candidate identity fields are incomplete")
	}
	if candidate.StartLine == 0 || candidate.SinkLineHash == "" {
		return "", fmt.Errorf("candidate sink identity fields are incomplete")
	}

	h := sha256.New()
	writeHashField(h, candidateIDDomain)
	writeHashField(h, candidate.RepositoryID)
	writeHashField(h, candidate.RepositorySHA)
	writeHashField(h, candidate.RepositoryRelativePath())
	writeHashField(h, candidate.Rule.ID)
	var line [8]byte
	binary.BigEndian.PutUint64(line[:], uint64(candidate.StartLine))
	_, _ = h.Write(line[:])
	writeHashField(h, candidate.SinkLineHash)
	return "candidate-v1-" + hex.EncodeToString(h.Sum(nil)), nil
}

func writeHashField(h hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(value))
}

func normalizedSinkLineHash(source []byte, lineNumber uint) (string, error) {
	if lineNumber == 0 {
		return "", fmt.Errorf("start_line must be greater than zero")
	}
	lines := bytes.Split(source, []byte{'\n'})
	if lineNumber > uint(len(lines)) {
		return "", fmt.Errorf("start_line %d is outside the source file", lineNumber)
	}

	line := lines[lineNumber-1]
	if lineNumber == 1 {
		line = bytes.TrimPrefix(line, []byte{0xef, 0xbb, 0xbf})
	}
	line = bytes.TrimSuffix(line, []byte{'\r'})
	normalized := strings.Join(strings.Fields(string(line)), " ")
	return hashBytes([]byte(normalized)), nil
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func normalizeScanRoot(value string) (string, error) {
	normalized, err := normalizePath(value, true)
	if err != nil {
		return "", fmt.Errorf("invalid scan_root %q, %w", value, err)
	}
	return normalized, nil
}

func normalizeRelativeFilePath(value string) (string, error) {
	normalized, err := normalizePath(value, false)
	if err != nil {
		return "", fmt.Errorf("invalid relative_file_path %q, %w", value, err)
	}
	return normalized, nil
}

func normalizePath(value string, allowRoot bool) (string, error) {
	if strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	if filepath.IsAbs(value) {
		return "", fmt.Errorf("path must be relative")
	}
	value = strings.ReplaceAll(value, "\\", "/")
	if path.IsAbs(value) || hasWindowsVolume(value) {
		return "", fmt.Errorf("path must be relative")
	}

	cleaned := path.Clean(value)
	if cleaned == "." {
		if allowRoot {
			return "", nil
		}
		return "", fmt.Errorf("path is required")
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path escapes the repository root")
	}
	return cleaned, nil
}

func hasWindowsVolume(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'a' && value[0] <= 'z') ||
		(value[0] >= 'A' && value[0] <= 'Z')) && value[1] == ':'
}

func isGitSHA(value string) bool {
	return (len(value) == 40 || len(value) == 64) && isLowerHex(value)
}

func isSHA256(value string) bool {
	return len(value) == 64 && isLowerHex(value)
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func cloneRule(rule api.AiPrompt) api.AiPrompt {
	clone := rule
	clone.Globs = append([]string(nil), rule.Globs...)
	clone.Directories = append([]string(nil), rule.Directories...)
	clone.ResultKeywordsExclude = append([]string(nil), rule.ResultKeywordsExclude...)
	clone.FileSearchKeywords = append([]string(nil), rule.FileSearchKeywords...)
	if rule.Cwe != nil {
		cwe := *rule.Cwe
		clone.Cwe = &cwe
	}
	return clone
}
