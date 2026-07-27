package candidates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJSONLRoundTripPreservesCandidates(t *testing.T) {
	first, err := NewCandidate(candidateInputForTest())
	assert.NoError(t, err)

	secondInput := candidateInputForTest()
	secondInput.RelativeFilePath = "service/other.go"
	second, err := NewCandidate(secondInput)
	assert.NoError(t, err)

	var output bytes.Buffer
	err = WriteJSONL(&output, []Candidate{second, first})
	assert.NoError(t, err)

	read, err := ReadJSONL(&output)
	assert.NoError(t, err)
	assert.Len(t, read, 2)
	assert.Equal(t, first, read[0])
	assert.Equal(t, second, read[1])
}

func TestJSONLRoundTripSupportsLargeRuleContent(t *testing.T) {
	input := candidateInputForTest()
	input.Rule.Content = strings.Repeat("Inspect this security rule content. ", 20_000)
	candidate, err := NewCandidate(input)
	assert.NoError(t, err)

	var output bytes.Buffer
	err = WriteJSONL(&output, []Candidate{candidate})
	assert.NoError(t, err)
	assert.Greater(t, output.Len(), 64*1024)

	read, err := ReadJSONL(&output)
	assert.NoError(t, err)
	assert.Equal(t, []Candidate{candidate}, read)
}

func TestReadJSONLReportsMalformedLineNumber(t *testing.T) {
	valid, err := NewCandidate(candidateInputForTest())
	assert.NoError(t, err)
	validRecord, err := json.Marshal(valid)
	assert.NoError(t, err)

	input := append(validRecord, '\n')
	input = append(input, []byte(`{"schema_version":`)...)
	input = append(input, '\n')
	_, err = ReadJSONL(bytes.NewReader(input))

	assert.ErrorContains(t, err, "line 2")
	assert.ErrorContains(t, err, "decode candidate")
}

func TestReadJSONLRejectsUnknownSchema(t *testing.T) {
	candidate, err := NewCandidate(candidateInputForTest())
	assert.NoError(t, err)
	candidate.SchemaVersion = SchemaVersion + 1
	record, err := json.Marshal(candidate)
	assert.NoError(t, err)

	_, err = ReadJSONL(bytes.NewReader(record))
	assert.ErrorContains(t, err, "line 1")
	assert.ErrorContains(t, err, "unsupported schema_version 2")
}

func TestDedupeRemovesIdenticalCandidates(t *testing.T) {
	candidate, err := NewCandidate(candidateInputForTest())
	assert.NoError(t, err)

	unique, err := Dedupe([]Candidate{candidate, candidate})
	assert.NoError(t, err)
	assert.Equal(t, []Candidate{candidate}, unique)

	var output bytes.Buffer
	err = WriteJSONL(&output, []Candidate{candidate, candidate})
	assert.NoError(t, err)
	assert.Equal(t, 1, strings.Count(strings.TrimSpace(output.String()), "\n")+1)

	read, err := ReadJSONL(bytes.NewReader(append(output.Bytes(), output.Bytes()...)))
	assert.NoError(t, err)
	assert.Equal(t, []Candidate{candidate}, read)
}

func TestDedupeRejectsConflictingCandidateID(t *testing.T) {
	candidate, err := NewCandidate(candidateInputForTest())
	assert.NoError(t, err)
	conflicting := candidate
	conflicting.DetectionReason = "Conflicting explanation"

	_, err = Dedupe([]Candidate{candidate, conflicting})
	assert.ErrorContains(t, err, "conflicts with an earlier candidate")

	firstRecord, err := json.Marshal(candidate)
	assert.NoError(t, err)
	secondRecord, err := json.Marshal(conflicting)
	assert.NoError(t, err)
	input := append(firstRecord, '\n')
	input = append(input, secondRecord...)
	input = append(input, '\n')
	_, err = ReadJSONL(bytes.NewReader(input))
	assert.ErrorContains(t, err, "line 2")
	assert.ErrorContains(t, err, "conflicts with line 1")
}

func TestExporterTruncatesAndAppendsUniqueCandidates(t *testing.T) {
	candidate, err := NewCandidate(candidateInputForTest())
	assert.NoError(t, err)
	filePath := filepath.Join(t.TempDir(), "candidates.jsonl")
	assert.NoError(t, os.WriteFile(filePath, []byte("stale data"), 0o644))
	assert.NoError(t, os.Chmod(filePath, 0o644))

	exporter, err := NewExporter(filePath)
	assert.NoError(t, err)
	assert.NoError(t, exporter.Append(candidate))
	assert.NoError(t, exporter.Append(candidate))
	assert.NoError(t, exporter.Close())

	content, err := os.ReadFile(filePath)
	assert.NoError(t, err)
	assert.NotContains(t, string(content), "stale data")
	info, err := os.Stat(filePath)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	read, err := ReadJSONL(bytes.NewReader(content))
	assert.NoError(t, err)
	assert.Equal(t, []Candidate{candidate}, read)
}

func TestExporterIsSafeForConcurrentAppends(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "candidates.jsonl")
	exporter, err := NewExporter(filePath)
	assert.NoError(t, err)

	const candidateCount = 20
	var waitGroup sync.WaitGroup
	errors := make(chan error, candidateCount)
	for index := 0; index < candidateCount; index++ {
		input := candidateInputForTest()
		input.Rule.ID = fmt.Sprintf("rule-%02d", index)
		candidate, buildErr := NewCandidate(input)
		assert.NoError(t, buildErr)
		waitGroup.Add(1)
		go func(value Candidate) {
			defer waitGroup.Done()
			errors <- exporter.Append(value)
		}(candidate)
	}
	waitGroup.Wait()
	close(errors)
	for appendErr := range errors {
		assert.NoError(t, appendErr)
	}
	assert.NoError(t, exporter.Close())

	file, err := os.Open(filePath)
	assert.NoError(t, err)
	defer file.Close()
	read, err := ReadJSONL(file)
	assert.NoError(t, err)
	assert.Len(t, read, candidateCount)
}
