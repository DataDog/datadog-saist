package agents

const (
	DefaultSinkLineWindow uint = 2

	EvidenceVerdictConfirm EvidenceVerdict = "confirm"
	EvidenceVerdictReject  EvidenceVerdict = "reject"
	EvidenceVerdictAbstain EvidenceVerdict = "abstain"

	EvidenceConfidenceHigh   EvidenceConfidence = "high"
	EvidenceConfidenceMedium EvidenceConfidence = "medium"
	EvidenceConfidenceLow    EvidenceConfidence = "low"

	EvidenceTrustUntrusted EvidenceTrust = "untrusted"
	EvidenceTrustTrusted   EvidenceTrust = "trusted"
	EvidenceTrustUnknown   EvidenceTrust = "unknown"

	VerificationSourceStandard         VerificationVerdictSource = "standard"
	VerificationSourceAgentic          VerificationVerdictSource = "agentic"
	VerificationSourceStandardFallback VerificationVerdictSource = "standard_fallback"
	VerificationSourceRetained         VerificationVerdictSource = "retained"

	FallbackExplicitAbstain    VerificationFallbackReason = "explicit_abstain"
	FallbackInvalidEvidence    VerificationFallbackReason = "invalid_evidence"
	FallbackParseFailure       VerificationFallbackReason = "parse_failure"
	FallbackToolFailure        VerificationFallbackReason = "tool_failure"
	FallbackAgenticFailure     VerificationFallbackReason = "agentic_failure"
	FallbackAgenticUnavailable VerificationFallbackReason = "agentic_unavailable"
	FallbackContextCanceled    VerificationFallbackReason = "context_canceled"

	ModelCallKindAgenticInvestigation     ModelCallKind = "agentic_investigation"
	ModelCallKindAgenticSummary           ModelCallKind = "agentic_summary"
	ModelCallKindAgenticVerdict           ModelCallKind = "agentic_verdict"
	ModelCallKindAgenticVerdictRepair     ModelCallKind = "agentic_verdict_repair"
	ModelCallKindAgenticFinalVerification ModelCallKind = "agentic_final_verification"
	ModelCallKindSingleShot               ModelCallKind = "single_shot"
	ModelCallKindStandardVerification     ModelCallKind = "standard_verification"
	ModelCallKindStandardFallback         ModelCallKind = "standard_fallback"
	ModelCallKindProviderFallback         ModelCallKind = "provider_fallback"
	ModelCallKindLocation                 ModelCallKind = "location"

	ToolCallDispositionExecuted      ToolCallDisposition = "executed"
	ToolCallDispositionDuplicate     ToolCallDisposition = "duplicate"
	ToolCallDispositionBudgetRefused ToolCallDisposition = "budget_refused"
	ToolCallDispositionInvalidArgs   ToolCallDisposition = "invalid_arguments"

	LoopStopReasonReadyToAnswer             LoopStopReason = "ready_to_answer"
	LoopStopReasonReadyToAnswerToolUnmet    LoopStopReason = "ready_to_answer_tool_unmet"
	LoopStopReasonIterationBudgetExhausted  LoopStopReason = "iteration_budget_exhausted"
	LoopStopReasonToolCallBudgetExhausted   LoopStopReason = "tool_call_budget_exhausted"
	LoopStopReasonToolOutputBudgetExhausted LoopStopReason = "tool_output_budget_exhausted"
	LoopStopReasonInvestigationCallFailed   LoopStopReason = "investigation_call_failed"
	LoopStopReasonSummaryCallFailed         LoopStopReason = "summary_call_failed"
	LoopStopReasonEmptySummary              LoopStopReason = "empty_summary"
	LoopStopReasonVerdictCallFailed         LoopStopReason = "verdict_call_failed"
	LoopStopReasonUnsupportedClient         LoopStopReason = "unsupported_client"
	LoopStopReasonSandboxUnavailable        LoopStopReason = "sandbox_unavailable"

	defaultAgenticMaxIterations          = 6
	defaultAgenticMaxToolCalls           = 16
	agenticToolOutputCharBudget          = 60000
	agenticMinCompletionTokens           = 8192
	detectionMaxTokens                   = 0
	verificationMaxTokens                = 0
	verificationTemperature              = 1.0
	verificationResponseType             = "application/json"
	locationMaxTokens                    = 0
	locationTemperature                  = 0.0
	toolBudgetNote                       = `{"note":"tool budget exhausted. Stop calling tools and produce your final answer now"}`
	toolDuplicateNote                    = `{"note":"duplicate tool call. Reuse the result from the earlier identical call"}`
	agenticToolNudge                     = `You have read-only tools to inspect the rest of the codebase. The tools are search_code (regex or substring search across the repository), read_file (read a file, optionally a line range), and list_directory. Every search_code call must include path_glob as a non-empty repository-relative glob that bounds the search, for example domains/team/**/*.go. The code shown to you is often incomplete. A taint source, sink, sanitizer, helper function, or type may be defined in another file that is not included here. Before you decide, if confirming or ruling out the issue depends on code you cannot see (for example the body of a called function, where a value originates, or whether input is validated elsewhere), call the tools to read that code. Base your conclusion on the actual code rather than assumptions. When you have gathered enough information, stop calling tools and give your final answer.`
	agenticEnumerateSitesNudge           = `If this file contains more than one call site matching this rule's sink pattern, evaluate every one of them independently. Confirming that a sanitizer, allow-list, or safe helper covers one call site does not establish that it covers a different call site, even if both call the same function. List each matching site you find, then check each one on its own, before producing your final answer.`
	investigationSummaryRequest          = `Summarize the evidence you actually observed during this investigation. Include repository-relative paths, 1-based line numbers, complete cited source lines, symbols, and the security significance of each fact. In read_file output, the leading "N: " is display metadata and is not part of the source line. Distinguish observed facts from unresolved questions. Do not return the final verdict JSON yet.`
	structuredVerdictRequest             = `Return the final structured evidence verdict now. Use confirm only when the candidate is a real instance of the requested vulnerability. Use reject only when cited source-controlled evidence proves the candidate safe or outside the requested category. A rejection requires a candidate sink citation and at least one trusted source, guard, or counterevidence citation. The sink citation must remain in the flagged file and within the candidate line window. Record deeper downstream operations as flow citations, not as the sink. Do not treat truncated search results or the absence of a search match as counterevidence. Use abstain when evidence is incomplete or uncertain. Every citation must use a repository-relative path, a 1-based line number, and the complete source line exactly as observed. For each read_file citation, copy the line number and complete snippet from the same output row. Never pair one row's line number with an adjacent row's snippet. In read_file output, omit the leading "N: " display metadata from the snippet.`
	citationSnippetRepairSystemPrompt    = `You repair stale citation snippet strings in one structured security verdict. You have no tools. The authoritative source rows in the request are the only allowed replacement text. Return the complete StructuredVerdict under the supplied strict schema.`
	citationSnippetRepairImmutablePolicy = `Only the snippet value of each exact failed citation slot may change. Freeze the verdict, confidence, reason, source trust, array identity, array order, array cardinality, citation paths, citation lines, symbols, descriptions, and every citation slot not named by a stale_citation error. Do not add, remove, reorder, or reinterpret evidence.`
	citationSnippetRepairUserPrompt      = `Repair the stale citation snippets in the original StructuredVerdict.

Immutable repair policy.

%s

Original StructuredVerdict JSON.

%s

Exact evidence validation errors JSON.

%s

Authoritative current source rows JSON. Each row is bound to its exact failed citation field, path, and line.

%s

Exact candidate sink constraint.

%s

Return the complete StructuredVerdict. Copy every frozen value exactly. Replace only each named failed snippet with the snippet from its authoritative row.`
)

const AgenticVerificationSystemPrompt = `You are a security expert investigating one exact security candidate. Use read-only repository tools when the flagged file does not establish the source, sink, data flow, guards, sanitization, or runtime semantics. Base every conclusion on code you actually observed. Do not infer safety from names or from a search with incomplete coverage. A separate final call will request a structured confirm, reject, or abstain verdict. Before that call, provide a concise evidence summary with repository-relative paths, 1-based lines, complete source lines, symbols, and security significance.`

const AgenticVerificationUserPrompt = `Investigate this exact security candidate.

Flagged file. %s
Flagged line. %d
Original finding. %s

Answer these questions where they apply.

1. What concrete dangerous operation exists at the candidate sink?
2. Can attacker-controlled or otherwise untrusted data reach it?
3. What transformations, guards, or sanitizers are applied?
4. Does the behavior match the vulnerability category requested by the rule?

Use tools when the flagged source below does not answer a question. Cite only files and complete source lines you actually read.

Numbered flagged source.

%s

Rule content.

%s`

// Frozen agentic exploration limits for the verifier-only benchmark. These are
// the initial defaults and are frozen before the scored run. The runtime may
// override the turn and total-tool-call budgets through AgentOption during
// development, but the scored run pins them.
const (
	agenticMaxInvestigationTurns      = 12
	agenticMaxToolCallsPerTurn        = 5
	agenticMaxTotalToolCalls          = 20
	agenticMaxDistinctFilesRead       = 20
	agenticTotalToolOutputBudgetBytes = 100 * 1024

	// LoopStopReasonNoSuccessfulTool marks an agentic protocol failure: the
	// exploration budget was exhausted without a single successfully executed
	// tool call, so the final verifier is never called.
	LoopStopReasonNoSuccessfulTool   LoopStopReason = "no_successful_tool"
	LoopStopReasonDistinctFileBudget LoopStopReason = "distinct_file_budget_exhausted"

	// investigationToolReminder is appended when the exploration model tries to
	// finish before any tool call has succeeded. It keeps the requirement without
	// instructing the eventual decision.
	investigationToolReminder = `Repository investigation is required before this step can finish. Call one of the read-only tools (search_code, read_file, list_directory) now to gather the code that determines whether the candidate is real. Do not answer without investigating.`
)

// InvestigationSystemPrompt drives the collect-only exploration phase of the
// agentic arm. The exploration model gathers repository evidence with the
// read-only tools and never produces a verdict, recommendation, confidence, or
// summary. The shared final verifier makes the decision from the raw tool
// transcript, so this prompt is never part of the final-verifier contract.
const InvestigationSystemPrompt = `You are investigating one specific security candidate to COLLECT repository evidence. Use the read-only tools to read the code that determines whether the candidate is a real instance of the requested vulnerability: the sink, where its inputs originate, any sanitizers or guards, relevant types, and callers. Investigate only by calling tools. Do NOT produce a verdict, a recommendation, a confidence, or a summary. A separate system makes the decision from the raw tool transcript. When you have read the relevant code, stop.`

// InvestigationUserPrompt is the collect-only investigation user prompt. It
// deliberately asks for no conclusion.
const InvestigationUserPrompt = `Investigate this security candidate by reading the repository with the read-only tools.

Flagged file. %s
Flagged line. %d
Original finding. %s

Read the code needed to determine whether this is a real instance of the requested vulnerability. Follow inputs to the sink, look up cross-file definitions and callers, and check for guards or sanitizers. Do not state a conclusion. Gather evidence only.

Numbered flagged source.

%s

Rule content.

%s`
