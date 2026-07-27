// nolint:lll
package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/utils"
)

func standardVerificationOptions() clients.GenerateOptions {
	return clients.GenerateOptions{
		MaxTokens:    verificationMaxTokens,
		ResponseType: verificationResponseType,
		Temperature:  verificationTemperature,
		Schema: clients.GenerateOptionSchema{
			Name:        "results",
			Description: "verify if a violation is a false positive or not",
			JsonSchema:  clients.GenerateSchema[VerificationResultData](),
		},
	}
}

func agenticVerificationOptions() clients.GenerateOptions {
	return clients.GenerateOptions{
		MaxTokens:    verificationMaxTokens,
		ResponseType: verificationResponseType,
		Temperature:  verificationTemperature,
		Schema: clients.GenerateOptionSchema{
			Name:        "evidence_verdict",
			Description: "structured verification verdict with source-controlled evidence",
			JsonSchema:  clients.GenerateSchemaWithAnyOf[StructuredVerdict](),
		},
	}
}

const goPathTraversalAgenticGuidance = `Rule-specific guidance for datadog/go-pathtraversal.

A path from a command-line flag is not automatically attacker-controlled. Establish who invokes the process and whether a less-privileged actor can influence the path. Also establish whether the process crosses a filesystem security boundary by escaping an intended directory, running with greater privilege, or exposing file contents to that actor.

When repository evidence shows a local operator CLI that intentionally accepts a full path, no untrusted network or automation input, no privilege gain, and no disclosure to another principal, treat the flag as trusted operator input and reject the path traversal candidate. The absence of filepath.Clean, base-directory enforcement, or traversal checks alone does not make that case a vulnerability.

Confirm only when observed repository evidence shows that a less-privileged actor can control the path and gain read or write access unavailable to that actor. Inspect entrypoints, callers, deployment configuration, and documentation when the flagged file does not establish those facts. Cite the evidence supporting the source trust decision.`

const promptInjectionAgenticGuidance = `Rule-specific guidance for prompt-injection rules.

Do not confirm merely because variable data enters an LLM prompt. Confirm only when cited repository evidence establishes both that a less-privileged actor can directly or indirectly influence the prompt content and that manipulating the model can affect a protected security property. Protected effects include unauthorized access, confidential data disclosure, privileged tool use, authorization decisions, and changes to code, configuration, or external systems.

Protected integrity effects also include attacker-controlled changes to durable stored content and manipulation of release, review, or validation gates. Trace model output to its consumers before concluding that an LLM call has no protected effect.

Internal evaluation scoring alone is not a protected security effect. When an intended evaluation harness deliberately sends agent output to an LLM judge and the only supported effect is corruption of an internal score or reasoning field, reject the candidate. Confirm only if cited evidence shows that a less-privileged actor can use the manipulation to affect another protected resource or cross a trust boundary.

Do not infer attacker control from a hypothetical statement such as "if this input were controlled." Local developer input, an operator-selected file, internal evaluation data, route strings, filesystem paths, and syntactically constrained identifiers are not automatically untrusted. Require cited evidence of an actual less-privileged influence path. The absence of sanitization, escaping, or role separation does not establish that path.

Indirect influence remains relevant. Retrieved documents, stored content, model output, tool output, PR content, repository content, and caller-supplied templates can be attacker-controlled when cited callers or ingestion paths establish less-privileged influence. The protected effect can occur downstream from the flagged function. Inspect API callers, ingestion paths, PR provenance, prompt templates, output consumers, and configured agent tools when those facts are not visible in the flagged file. Cite the evidence for both influence and effect.`

const pythonWeakHashAgenticGuidance = `Rule-specific guidance for datadog/python-weakhash.

Classify the exact cryptographic construction and the requested weak-hash category before deciding. The presence of hashlib.sha1 as digestmod in an HMAC API does not by itself establish a weak-hash vulnerability. Collision weaknesses in bare SHA-1 do not alone establish that a keyed HMAC can be forged. Confirm only when cited evidence establishes a construction-specific weakness that matters to the security property provided by this use.

Preserve separately evidenced weak cases. Confirm when cited evidence shows that MD5 or SHA-1 is used directly for password hashing, security token generation, collision-sensitive integrity or signature input, or another security purpose whose required property is broken for that construction. Reject non-security hashing and keyed HMAC uses when no applicable construction-specific weakness is established. Do not generalize the HMAC distinction to bare hashing, password hashing, signatures, or other constructions.`

const agenticCandidateSinkCitationInstruction = `The final sink citation must use path %q and line %d, which is the reported candidate location. Cite that exact numbered row as the sink. Downstream assignments, calls, or dangerous operations belong in flow evidence and must not replace the required candidate sink citation.`

func agenticRuleGuidance(ruleID string) string {
	switch ruleID {
	case "datadog/go-promptinjection", "datadog/python-promptinjection":
		return promptInjectionAgenticGuidance
	case "datadog/go-pathtraversal":
		return goPathTraversalAgenticGuidance
	case "datadog/python-weakhash":
		return pythonWeakHashAgenticGuidance
	default:
		return ""
	}
}

func isPromptInjectionRule(ruleID string) bool {
	return ruleID == "datadog/go-promptinjection" || ruleID == "datadog/python-promptinjection"
}

// VerificationPromptHash identifies the complete verifier prompt contract used
// by an experiment mode. It includes the response schema and agentic loop
// instructions so stored trajectories can detect prompt drift.
func VerificationPromptHash(agentic bool) (string, error) {
	values := verificationPromptContract(agentic)
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("encode verification prompt contract, %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func verificationPromptContract(agentic bool) []any {
	values := []any{
		VerificationSystemPrompt,
		VerificationUserPrompt,
		standardVerificationOptions(),
		LocationDeterminationSystemPrompt,
		LocationDeterminationUserPrompt,
		locationDeterminationOptions(),
	}
	if agentic {
		values = append(values,
			AgenticVerificationSystemPrompt,
			AgenticVerificationUserPrompt,
			agenticToolNudge,
			agenticToolOutputCharBudget,
			agenticMinCompletionTokens,
			toolBudgetNote,
			toolDuplicateNote,
			investigationSummaryRequest,
			structuredVerdictRequest,
			citationSnippetRepairSystemPrompt,
			citationSnippetRepairImmutablePolicy,
			citationSnippetRepairUserPrompt,
			agenticCandidateSinkCitationInstruction,
			promptInjectionAgenticGuidance,
			goPathTraversalAgenticGuidance,
			pythonWeakHashAgenticGuidance,
			agenticVerificationOptions(),
		)
	}
	return values
}

// verifierCorrectionPolicyVersion identifies the invalid-output correction
// policy applied to the final verifier response (see parseVerificationResult).
// It is part of the shared final-verifier contract so any change to correction
// behavior is versioned and detected across arms.
const verifierCorrectionPolicyVersion = "standard-local-repair-v1"

// finalVerifierContract enumerates the shared final-verifier contract used
// identically by both the standard and agentic arms: the base system prompt,
// the standard user-prompt template, the response schema and decoding settings,
// and the invalid-output correction policy version. It deliberately excludes
// every agentic-only element (exploration prompts, tool nudges, rule guidance,
// the structured-verdict schema) and the location-determination call, because
// none of those are part of the KEEP/OMIT decision contract.
func finalVerifierContract() []any {
	return []any{
		VerificationSystemPrompt,
		VerificationUserPrompt,
		standardVerificationOptions(),
		verifierCorrectionPolicyVersion,
	}
}

// FinalVerifierContractHash identifies the shared final-verifier contract. It is
// arm-independent by construction: the agentic arm adds only a rendered
// repository-evidence section to the request, which is not part of this
// contract. The scorer compares this hash across arms and requires it to match,
// while the per-measurement rendered-request hash is expected to differ.
func FinalVerifierContractHash() (string, error) {
	encoded, err := json.Marshal(finalVerifierContract())
	if err != nil {
		return "", fmt.Errorf("encode final verifier contract, %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

const VerificationSystemPrompt = `You are a security expert tasked with verifying potential security vulnerabilities.
  Your job is to carefully review a reported violation and determine if it is a true positive or false positive.

  When analyzing the vulnerability, perform taint analysis where applicable:
  1. SOURCE: Where does the untrusted/user-controlled data originate?
  2. SINK: Where does the potentially dangerous operation occur?
  3. DATAFLOW: How does the tainted data flow from source to sink?
  4. SANITIZATION: Is the data properly validated, escaped, or sanitized?

  Before confirming, verify that the finding clearly matches the vulnerability category requested by the rule prompt.
  If the code appears vulnerable but not to the requested rule category, set confirmed=false.
  Confirm only if you can identify a concrete sink line in the code. If no concrete sink line exists, set confirmed=false.

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
  Confirm only if the issue clearly matches the requested rule category and you can name the concrete sink line.
  If the finding is a different vulnerability type than the rule requested, set confirmed=false.

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

func getAgenticVerificationUserPrompt(scanData *model.ScanData, violation model.LLMResultViolation,
	repositoryRelativePath string) string {
	numberedCode := scanData.NumberedFileText
	if numberedCode == "" {
		numberedCode = utils.AddLineNumbers(scanData.FileText)
	}
	prompt := fmt.Sprintf(
		AgenticVerificationUserPrompt,
		repositoryRelativePath,
		violation.StartLine,
		violation.Reason,
		numberedCode,
		scanData.Rule.Content,
	)
	if guidance := agenticRuleGuidance(scanData.Rule.ID); guidance != "" {
		prompt += "\n\n" + guidance
	}
	prompt += "\n\n" + fmt.Sprintf(agenticCandidateSinkCitationInstruction, repositoryRelativePath, violation.StartLine)
	return prompt
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

	jsonContent = extractJSONFromCodeBlock(content)

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
