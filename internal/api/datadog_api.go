package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/utils"
)

// Define the JSON:API response structure
type jsonApiResponse struct {
	Data []struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Category         string   `json:"category"`
			Checksum         string   `json:"checksum"`
			Content          string   `json:"content"`
			Cwe              string   `json:"cwe"`
			Description      string   `json:"description"`
			Directories      []string `json:"directories"`
			ExecutionMode    string   `json:"execution_mode"`
			Globs            []string `json:"globs"`
			IsDefault        bool     `json:"is_default"`
			IsTesting        bool     `json:"is_testing"`
			Severity         string   `json:"severity"`
			ShortDescription string   `json:"short_description"`
			Version          string   `json:"rule_version"`
		} `json:"attributes"`
	} `json:"data"`
}

func GetPromptsFromApi(ctx context.Context, auth DatadogAuth) ([]api.AiPrompt, error) {
	url := fmt.Sprintf("https://api.%s/api/v2/static-analysis/ai/prompts", auth.Site)

	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if auth.HasJWTAuth() {
		req.Header.Set("dd-auth-jwt", *auth.JWTToken)
	} else if auth.HasAPIKeyAuth() {
		req.Header.Set("dd-api-key", *auth.ApiKey)
		req.Header.Set("dd-application-key", *auth.AppKey)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func(r *http.Response) {
		_ = r.Body.Close()
	}(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	return GetPromptsFromApiData(resp.Body)
}

func GetPromptsFromApiData(data io.ReadCloser) ([]api.AiPrompt, error) {
	var response jsonApiResponse
	if err := json.NewDecoder(data).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert the JSON:API response to AiPrompt structs
	prompts := make([]api.AiPrompt, len(response.Data))
	for i := range response.Data {
		var cwe *string
		item := &response.Data[i] // getting the item as a pointer for speed
		if item.Attributes.Cwe != "" {
			cwe = &item.Attributes.Cwe
		}

		content, err := utils.DecodeFromBase64(item.Attributes.Content)
		if err != nil {
			continue
		}

		short_description, err := utils.DecodeFromBase64(item.Attributes.ShortDescription)
		if err != nil {
			continue
		}

		description, err := utils.DecodeFromBase64(item.Attributes.Description)
		if err != nil {
			continue
		}

		ruleVersion := item.Attributes.Version
		if item.Attributes.Version == "" {
			ruleVersion = "0.0.0"
		}

		prompts[i] = api.AiPrompt{
			ID:               item.ID,
			Content:          content,
			Globs:            item.Attributes.Globs,
			Directories:      item.Attributes.Directories,
			ExecutionMode:    api.ExecutionMode(item.Attributes.ExecutionMode),
			Cwe:              cwe,
			Checksum:         item.Attributes.Checksum,
			Severity:         api.Severity(item.Attributes.Severity),
			Category:         api.Category(item.Attributes.Category),
			IsTesting:        item.Attributes.IsTesting,
			IsDefault:        item.Attributes.IsDefault,
			Description:      description,
			ShortDescription: short_description,
			Version:          ruleVersion,
		}
	}

	return prompts, nil
}
