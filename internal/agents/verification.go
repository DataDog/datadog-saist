// nolint:lll
package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/utils"
)

const VerificationSystemPrompt = `You are a security expert tasked with verifying potential security vulnerabilities.
  Your job is to carefully review a reported violation and determine if it is a true positive or false positive.

  When analyzing the vulnerability, perform taint analysis where applicable:
  1. SOURCE: Where does the untrusted/user-controlled data originate?
  2. SINK: Where does the potentially dangerous operation occur?
  3. DATAFLOW: How does the tainted data flow from source to sink?
  4. SANITIZATION: Is the data properly validated, escaped, or sanitized?

  Respond with JSON in this format:
  {
    "confirmed": true/false,
    "confidence": "high/low",
    "reason": "Your explanation. If you can identify them, include:\n\nSource: [description]\n\nSink: [description]\n\nDataflow: [description]\n\nSanitization: [description]\n\nOnly include sections that are applicable and that you can determine from the code. Always end with your conclusion."
  }

  If you determine this is NOT a violation, set confirmed to false and explain why. If you require more information to be able 
  to determine if this is a violation with absolute confidence, err on the side of caution and consider this to NOT be a violation and set confirmed to 
  false and explain why.`

const VerificationUserPrompt = `A security analysis tool reported the following potential vulnerability:

  File: %s
  Line: %d
  Original Finding: %s

  Please verify if this is a real security vulnerability. Where applicable, perform taint analysis to identify:
  - Source of untrusted data
  - Sink where the dangerous operation occurs  
  - Dataflow from source to sink
  - Any sanitization applied

  Only include these details in your reason if you can determine them from the code.

  If you require more information to be able to determine if this is a violation with absolute confidence, 
  err on the side of caution and consider this to NOT be a violation.

  Code Context:
  %s

  The prompt that resulted in this analysis result was:
  %s

  Provide your verification result in JSON format:
  {
    "confirmed": true/false,
    "confidence": "high/low",
    "reason": "A short explanation with applicable taint analysis details (Source/Sink/Dataflow/Sanitization) followed by your conclusion. Keep it short (less than 100 words)."
  }`

func getVerificationUserPrompt(scanData *model.ScanData, violation model.LLMResultViolation) string {
	// Use pre-computed numbered code if available, otherwise compute it
	numberedCode := scanData.NumberedFileText
	if numberedCode == "" {
		numberedCode = utils.AddLineNumbers(scanData.FileText)
	}
	return fmt.Sprintf(
		VerificationUserPrompt,
		scanData.RelativeFilePath,
		violation.StartLine,
		violation.Reason,
		numberedCode, // Code with line numbers (pre-computed)
		scanData.Rule.Content,
	)
}

// sanitizeJSONString fixes common LLM JSON output issues like literal newlines in string values
func sanitizeJSONString(content string) string {
	// Replace literal newlines that appear inside JSON string values with escaped newlines
	// This is a simple approach: replace newlines that aren't at the start of a line with a key
	var result strings.Builder
	inString := false
	escaped := false

	for i := 0; i < len(content); i++ {
		c := content[i]

		if escaped {
			result.WriteByte(c)
			escaped = false
			continue
		}

		if c == '\\' {
			result.WriteByte(c)
			escaped = true
			continue
		}

		if c == '"' {
			inString = !inString
			result.WriteByte(c)
			continue
		}

		// If we're inside a string and encounter a literal newline, escape it
		if inString && (c == '\n' || c == '\r') {
			if c == '\r' {
				// Skip \r, handle \n
				continue
			}
			result.WriteString("\\n")
			continue
		}

		result.WriteByte(c)
	}

	return result.String()
}

// repairTruncatedVerificationJSON attempts to repair truncated verification JSON
func repairTruncatedVerificationJSON(content string) (VerificationResultData, error) {
	trimmed := strings.TrimSpace(content)

	// Check if content appears to be truncated (doesn't end with } and contains expected fields)
	if strings.HasSuffix(trimmed, "}") {
		return VerificationResultData{}, errors.New("content does not appear to be truncated")
	}

	if !strings.Contains(content, "confirmed") && !strings.Contains(content, "confidence") {
		return VerificationResultData{}, errors.New("content does not contain expected verification fields")
	}

	// First sanitize to fix literal newlines
	fixedContent := sanitizeJSONString(content)

	// Try different repair strategies
	repairStrategies := []string{
		// Most common: truncated in middle of reason string
		fixedContent + "\"\n}",
		// Truncated with different formatting
		fixedContent + "\"}",
		// Truncated right after opening quote
		fixedContent + "\n}",
		// Minimal closing
		fixedContent + "}",
	}

	var result VerificationResultData
	for _, repaired := range repairStrategies {
		err := json.Unmarshal([]byte(repaired), &result)
		if err == nil && result.Reason != "" {
			return result, nil
		}
	}

	return VerificationResultData{}, errors.New("unable to repair truncated verification JSON")
}

// nolint: gocyclo
func parseVerificationResult(ctx context.Context, content string, debugEnabled bool) (VerificationResultData, error) {
	logger := log.FromContext(ctx)
	verificationData := &VerificationResultData{}

	// First, try to parse directly
	jsonContent := sanitizeJSONString(content)
	err := json.Unmarshal([]byte(jsonContent), &verificationData)
	if err == nil && verificationData.Reason != "" {
		return *verificationData, nil
	}

	// If direct parsing failed, try to repair truncated JSON
	if err != nil {
		repairedResult, repairErr := repairTruncatedVerificationJSON(jsonContent)
		if repairErr == nil {
			return repairedResult, nil
		}
	}

	// Try to parse if verification data is wrapped in a "content" object field
	var wrapped struct {
		Content VerificationResultData `json:"content"`
	}
	err = json.Unmarshal([]byte(jsonContent), &wrapped)
	if err == nil && wrapped.Content.Reason != "" {
		return wrapped.Content, nil
	}

	// Try to extract JSON from code blocks
	jsonContent = content
	if strings.Contains(content, "```json") {
		startIndex := strings.Index(content, "```json")
		if startIndex != -1 {
			startIndex += 7
			endIndex := strings.Index(content[startIndex:], "```")
			if endIndex != -1 {
				jsonContent = strings.TrimSpace(content[startIndex : startIndex+endIndex])
			}
		}
	} else if strings.Contains(content, "```") {
		startIndex := strings.Index(content, "```")
		if startIndex != -1 {
			startIndex += 3
			endIndex := strings.Index(content[startIndex:], "```")
			if endIndex != -1 {
				jsonContent = strings.TrimSpace(content[startIndex : startIndex+endIndex])
			}
		}
	}

	// Sanitize JSON: LLMs sometimes output literal newlines inside string values
	// which breaks JSON parsing. Replace unescaped newlines with escaped ones.
	jsonContent = sanitizeJSONString(jsonContent)

	verificationData = &VerificationResultData{}
	err = json.Unmarshal([]byte(jsonContent), &verificationData)
	if err != nil {
		// Try to repair truncated JSON
		repairedResult, repairErr := repairTruncatedVerificationJSON(jsonContent)
		if repairErr == nil {
			return repairedResult, nil
		}

		if debugEnabled {
			logger.Warnf("[debug] failed to parse verification response: %s", content)
			logger.Warnf("[debug] verification parsing failed: %v", err)
		}
		return VerificationResultData{}, fmt.Errorf("failed to parse verification response: %w", err)
	}
	return *verificationData, nil
}
