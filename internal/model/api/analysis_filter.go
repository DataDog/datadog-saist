package api

import (
	"bytes"
	"encoding/json"
)

// AnalysisFilter is optional metadata evaluated against stripped, lowercase code.
// Exactly one operator must be set on each expression.
type AnalysisFilter struct {
	Version    int              `json:"version"`
	Expression FilterExpression `json:"expression"`
}

type FilterExpression struct {
	Not         *FilterExpression  `json:"not,omitempty"`
	RegexAny    []string           `json:"regex_any,omitempty"`
	CountEquals *FilterCount       `json:"count_equals,omitempty"`
	All         []FilterExpression `json:"all,omitempty"`
	Any         []FilterExpression `json:"any,omitempty"`
	ContainsAny []string           `json:"contains_any,omitempty"`
	WordsAny    []string           `json:"words_any,omitempty"`
}

// FilterCount sums non-overlapping occurrences of each substring.
type FilterCount struct {
	Substrings []string `json:"substrings"`
	Count      int      `json:"count"`
}

func (f *AnalysisFilter) UnmarshalJSON(data []byte) error {
	*f = AnalysisFilter{}
	var envelope struct {
		Version    int             `json:"version"`
		Expression json.RawMessage `json:"expression"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil
	}
	*f = AnalysisFilter{Version: envelope.Version}
	if f.Version != AnalysisFilterVersion || len(envelope.Expression) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(envelope.Expression))
	decoder.DisallowUnknownFields()
	var expression FilterExpression
	if err := decoder.Decode(&expression); err != nil {
		return nil
	}
	f.Expression = expression
	return nil
}
