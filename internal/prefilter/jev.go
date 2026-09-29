package prefilter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

type Jev struct {
	Client      *http.Client
	BearerToken string
	Model       string
	Threshold   float64
	Questions   map[string]string
}

func (*Jev) Name() string { return "jev" }

func (j *Jev) Configuration() any {
	return map[string]any{"model": j.Model, "threshold": j.Threshold, "questions": j.Questions,
		"endpoint": JevEndpoint, "source": JevSource, "org_id": JevOrgID,
		"source_transform": "StripCodeForDetection"}
}

func (j *Jev) Select(ctx context.Context, file File, rules []api.AiPrompt) (Result, error) {
	result := Result{}
	if len(rules) == 0 {
		return result, nil
	}
	if strings.TrimSpace(j.BearerToken) == "" {
		return result, fmt.Errorf("OPENAI_BEARER_TOKEN is required for staging AI Gateway")
	}
	if j.Threshold < 0 || j.Threshold > 1 || math.IsNaN(j.Threshold) {
		return result, fmt.Errorf("invalid Jev threshold")
	}
	questions := make(map[string]any, len(rules))
	for _, rule := range rules {
		question := j.Questions[rule.ID]
		if strings.TrimSpace(question) == "" {
			return result, fmt.Errorf("missing prefilter question for %s", rule.ID)
		}
		questions[rule.ID] = map[string]any{"type": "noul", "instructions": question}
	}
	data, err := json.Marshal(map[string]any{
		"model":     j.Model,
		"state":     "Language: " + file.Language.String() + "\n\n" + file.StrippedCode,
		"questions": questions,
	})
	if err != nil {
		return result, err
	}
	if len(data) > MaxJevRequestBytes {
		return result, fmt.Errorf("Jev request exceeds %d bytes", MaxJevRequestBytes)
	}
	timer := time.NewTimer(JevRequestInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	case <-timer.C:
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, JevEndpoint, bytes.NewReader(data))
	if err != nil {
		return result, err
	}
	request.Header.Set("Authorization", "Bearer "+j.BearerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("source", JevSource)
	request.Header.Set("org-id", JevOrgID)
	client := j.Client
	if client == nil {
		client = &http.Client{Timeout: JevTimeout}
	}
	response, err := client.Do(request)
	if err != nil {
		return result, fmt.Errorf("Jev request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("Jev HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxJevResponseBytes+1))
	if err != nil {
		return result, fmt.Errorf("read Jev response: %w", err)
	}
	if len(body) > MaxJevResponseBytes {
		return result, fmt.Errorf("Jev response too large")
	}
	var decoded struct {
		Model   string `json:"model"`
		Answers map[string]struct {
			Type string   `json:"type"`
			Noul *float64 `json:"noul"`
		} `json:"answers"`
		Usage Usage `json:"usage"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return result, fmt.Errorf("invalid Jev response JSON")
	}
	result.Model = decoded.Model
	result.Usage = decoded.Usage
	for _, rule := range rules {
		answer, ok := decoded.Answers[rule.ID]
		decision := Decision{RuleID: rule.ID, Selected: true, Reason: "fail_open"}
		if !ok || answer.Type != "noul" || answer.Noul == nil || *answer.Noul < 0 || *answer.Noul > 1 {
			decision.Error = "missing or invalid Jev answer"
		} else {
			decision.Selected = *answer.Noul >= j.Threshold
			decision.Score = answer.Noul
			decision.Reason = "jev_threshold"
		}
		result.Decisions = append(result.Decisions, decision)
	}
	return result, nil
}
