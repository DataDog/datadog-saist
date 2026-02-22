package api

type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
	SeverityNotice  Severity = "NOTICE"
	SeverityNone    Severity = "NONE"
)

type Category string

const (
	CategoryBestPractices Category = "BEST_PRACTICES"
	CategoryCodeStyle     Category = "CODE_STYLE"
	CategoryErrorProne    Category = "ERROR_PRONE"
	CategoryPerformance   Category = "PERFORMANCE"
	CategorySecurity      Category = "SECURITY"
)

type ExecutionMode string

const ExecutionModeAuto ExecutionMode = "AUTO"
const ExecutionModeManual ExecutionMode = "MANUAL"
const ExecutionModeAlways ExecutionMode = "ALWAYS"
const ExecutionModeUnknown ExecutionMode = "UNKNOWN"

type AiPrompt struct {
	ID                    string        `jsonapi:"primary,ai_prompt" json:"id"`
	Description           string        `jsonapi:"attribute" json:"description"`
	ShortDescription      string        `jsonapi:"attribute" json:"short_description"`
	Content               string        `jsonapi:"attribute" json:"content"`
	Globs                 []string      `jsonapi:"attribute" json:"globs"`
	Directories           []string      `jsonapi:"attribute" json:"directories"`
	ExecutionMode         ExecutionMode `jsonapi:"attribute" json:"execution_mode"`
	Cwe                   *string       `jsonapi:"attribute" json:"cwe,omitempty"` // omit if the string is empty
	Checksum              string        `jsonapi:"attribute" json:"checksum"`
	Severity              Severity      `jsonapi:"attribute" json:"severity"`
	Category              Category      `jsonapi:"attribute" json:"category"`
	IsTesting             bool          `jsonapi:"attribute" json:"is_testing"`
	IsDefault             bool          `jsonapi:"attribute" json:"is_default"`
	Version               string        `jsonapi:"attribute" json:"rule_version"`
	ResultKeywordsExclude []string      `jsonapi:"attribute" json:"result_keywords_exclude,omitempty"`
	FileSearchKeywords    []string      `jsonapi:"attribute" json:"file_search_keywords,omitempty"`
}
