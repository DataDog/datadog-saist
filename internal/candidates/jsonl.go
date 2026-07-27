package candidates

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"sync"
)

// WriteJSONL writes validated candidates in deterministic candidate ID order.
func WriteJSONL(writer io.Writer, values []Candidate) error {
	unique, err := Dedupe(values)
	if err != nil {
		return err
	}

	buffered := bufio.NewWriter(writer)
	for index, candidate := range unique {
		record, err := marshalRecord(candidate)
		if err != nil {
			return fmt.Errorf("candidate %d, %w", index+1, err)
		}
		if _, err := buffered.Write(record); err != nil {
			return fmt.Errorf("candidate %d, write record, %w", index+1, err)
		}
	}
	if err := buffered.Flush(); err != nil {
		return fmt.Errorf("flush candidate records, %w", err)
	}
	return nil
}

// ReadJSONL reads, validates, and deduplicates candidate records.
func ReadJSONL(reader io.Reader) ([]Candidate, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxJSONLLineBytes)

	values := make([]Candidate, 0)
	seen := make(map[string]seenCandidate)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, fmt.Errorf("line %d, empty candidate record", lineNumber)
		}

		candidate, err := decodeRecord(line)
		if err != nil {
			return nil, fmt.Errorf("line %d, %w", lineNumber, err)
		}
		if previous, found := seen[candidate.ID]; found {
			if !reflect.DeepEqual(previous.candidate, candidate) {
				return nil, fmt.Errorf("line %d, candidate_id %q conflicts with line %d",
					lineNumber, candidate.ID, previous.line)
			}
			continue
		}
		seen[candidate.ID] = seenCandidate{candidate: candidate, line: lineNumber}
		values = append(values, candidate)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("line %d, read candidate record, %w", lineNumber+1, err)
	}

	sortCandidates(values)
	return values, nil
}

type seenCandidate struct {
	candidate Candidate
	line      int
}

// Dedupe validates candidates, removes identical records, and rejects ID conflicts.
func Dedupe(values []Candidate) ([]Candidate, error) {
	unique := make([]Candidate, 0, len(values))
	seen := make(map[string]Candidate, len(values))
	for index, candidate := range values {
		if err := candidate.Validate(); err != nil {
			return nil, fmt.Errorf("candidate %d, %w", index+1, err)
		}
		if previous, found := seen[candidate.ID]; found {
			if !reflect.DeepEqual(previous, candidate) {
				return nil, fmt.Errorf("candidate %d, candidate_id %q conflicts with an earlier candidate",
					index+1, candidate.ID)
			}
			continue
		}
		seen[candidate.ID] = candidate
		unique = append(unique, candidate)
	}
	sortCandidates(unique)
	return unique, nil
}

func sortCandidates(values []Candidate) {
	sort.Slice(values, func(left, right int) bool {
		return values[left].ID < values[right].ID
	})
}

func marshalRecord(candidate Candidate) ([]byte, error) {
	if err := candidate.Validate(); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(candidate); err != nil {
		return nil, fmt.Errorf("encode candidate, %w", err)
	}
	return output.Bytes(), nil
}

func decodeRecord(record []byte) (Candidate, error) {
	decoder := json.NewDecoder(bytes.NewReader(record))
	decoder.DisallowUnknownFields()
	var candidate Candidate
	if err := decoder.Decode(&candidate); err != nil {
		return Candidate{}, fmt.Errorf("decode candidate, %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Candidate{}, err
	}
	if err := candidate.Validate(); err != nil {
		return Candidate{}, err
	}
	return candidate, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("candidate record contains multiple JSON values")
		}
		return fmt.Errorf("decode trailing candidate data, %w", err)
	}
	return nil
}

// Exporter truncates a JSONL file on creation and appends unique candidates safely.
type Exporter struct {
	mu     sync.Mutex
	file   *os.File
	seen   map[string]Candidate
	closed bool
}

// NewExporter creates a candidate exporter with owner-only file permissions.
func NewExporter(filePath string) (*Exporter, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create candidate export %q, %w", filePath, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("set candidate export permissions %q, %w", filePath, err)
	}
	return &Exporter{
		file: file,
		seen: make(map[string]Candidate),
	}, nil
}

// Append validates a candidate and writes it unless an identical ID was already written.
func (exporter *Exporter) Append(candidate Candidate) error {
	exporter.mu.Lock()
	defer exporter.mu.Unlock()

	if exporter.closed {
		return fmt.Errorf("candidate exporter is closed")
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	if previous, found := exporter.seen[candidate.ID]; found {
		if !reflect.DeepEqual(previous, candidate) {
			return fmt.Errorf("candidate_id %q conflicts with an earlier candidate", candidate.ID)
		}
		return nil
	}

	record, err := marshalRecord(candidate)
	if err != nil {
		return err
	}
	written, err := exporter.file.Write(record)
	if err != nil {
		return fmt.Errorf("append candidate %q, %w", candidate.ID, err)
	}
	if written != len(record) {
		return fmt.Errorf("append candidate %q, %w", candidate.ID, io.ErrShortWrite)
	}
	exporter.seen[candidate.ID] = candidate
	return nil
}

// Close closes the candidate export file.
func (exporter *Exporter) Close() error {
	exporter.mu.Lock()
	defer exporter.mu.Unlock()

	if exporter.closed {
		return nil
	}
	exporter.closed = true
	if err := exporter.file.Close(); err != nil {
		return fmt.Errorf("close candidate export, %w", err)
	}
	return nil
}
