package planning

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

type Counts struct {
	Candidates   int `json:"candidates"`
	Before       int `json:"before_selected"`
	After        int `json:"after_selected"`
	Both         int `json:"both_selected"`
	Added        int `json:"added"`
	Removed      int `json:"removed"`
	BeforeErrors int `json:"before_errors"`
	AfterErrors  int `json:"after_errors"`
}

type Comparison struct {
	Counts
	ByRule  map[string]*Counts `json:"by_rule"`
	Added   []WorkItem         `json:"added_pairs"`
	Removed []WorkItem         `json:"removed_pairs"`
}

func ReadDecisions(input io.Reader) (map[string]Decision, error) {
	decoder := json.NewDecoder(input)
	decisions := make(map[string]Decision)
	manifest, complete := false, false
	selected, errors := 0, 0
	for {
		var record Record
		err := decoder.Decode(&record)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if complete {
			return nil, fmt.Errorf("records after completion summary")
		}
		if !manifest && record.Type != "manifest" {
			return nil, fmt.Errorf("missing manifest")
		}
		switch record.Type {
		case "manifest":
			if manifest || record.SchemaVersion != SchemaVersion {
				return nil, fmt.Errorf("invalid manifest")
			}
			manifest = true
		case "decision":
			if record.Decision == nil {
				return nil, fmt.Errorf("missing decision")
			}
			d := *record.Decision
			if d.Path == "" || d.RuleID == "" || d.FileHash == "" || d.RuleHash == "" {
				return nil, fmt.Errorf("incomplete work item")
			}
			key := d.Path + "\x00" + d.RuleID
			if _, exists := decisions[key]; exists {
				return nil, fmt.Errorf("duplicate pair %s %s", d.Path, d.RuleID)
			}
			decisions[key] = d
			if d.Selected {
				selected++
			}
			if d.Error != "" {
				errors++
			}
		case "file":
		case "summary":
			if record.Summary == nil || record.Summary.CandidatePairs != len(decisions) ||
				record.Summary.SelectedPairs != selected || record.Summary.ErrorPairs != errors {
				return nil, fmt.Errorf("summary does not match decisions")
			}
			complete = true
		default:
			return nil, fmt.Errorf("unknown record type %q", record.Type)
		}
	}
	if !manifest || !complete {
		return nil, fmt.Errorf("incomplete plan")
	}
	return decisions, nil
}

func Compare(before, after io.Reader) (Comparison, error) {
	result := Comparison{ByRule: make(map[string]*Counts)}
	old, err := ReadDecisions(before)
	if err != nil {
		return result, fmt.Errorf("before: %w", err)
	}
	next, err := ReadDecisions(after)
	if err != nil {
		return result, fmt.Errorf("after: %w", err)
	}
	if len(old) != len(next) {
		return result, fmt.Errorf("candidate sets differ: %d vs %d", len(old), len(next))
	}
	keys := make([]string, 0, len(old))
	for key := range old {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		a := old[key]
		b, exists := next[key]
		if !exists || a.WorkItem != b.WorkItem {
			return result, fmt.Errorf("candidate or content mismatch: %s %s", a.Path, a.RuleID)
		}
		counts := result.ByRule[a.RuleID]
		if counts == nil {
			counts = &Counts{}
			result.ByRule[a.RuleID] = counts
		}
		for _, c := range []*Counts{&result.Counts, counts} {
			c.Candidates++
			if a.Selected {
				c.Before++
			}
			if b.Selected {
				c.After++
			}
			if a.Selected && b.Selected {
				c.Both++
			}
			if !a.Selected && b.Selected {
				c.Added++
			}
			if a.Selected && !b.Selected {
				c.Removed++
			}
			if a.Error != "" {
				c.BeforeErrors++
			}
			if b.Error != "" {
				c.AfterErrors++
			}
		}
		if !a.Selected && b.Selected {
			result.Added = append(result.Added, a.WorkItem)
		}
		if a.Selected && !b.Selected {
			result.Removed = append(result.Removed, a.WorkItem)
		}
	}
	return result, nil
}
