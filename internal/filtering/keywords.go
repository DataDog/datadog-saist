package filtering

// ResultKeywordsToFilter contains keywords that, if found in a violation's reason,
// indicate the result is likely a false positive for that rule (e.g., SQLi rule
// finding an XPath injection should be filtered out).
var ResultKeywordsToFilter = map[string][]string{
	// SQL Injection should not report XPath or LDAP issues
	"datadog/java-sqli":   {"xpath injection", "ldap injection"},
	"datadog/go-sqli":     {"xpath injection", "ldap injection"},
	"datadog/python-sqli": {"xpath injection", "ldap injection"},

	// XPath Injection should not report SQL issues
	"datadog/java-xpathi":   {"sql injection"},
	"datadog/go-xpathi":     {"sql injection"},
	"datadog/python-xpathi": {"sql injection"},

	// Command Injection should not report code injection issues
	"datadog/java-cmdi":   {"code injection", "script injection"},
	"datadog/go-cmdi":     {"code injection", "script injection"},
	"datadog/python-cmdi": {"code injection", "script injection"},

	// Code Injection should not report command injection issues
	"datadog/java-codei":   {"command injection", "os command"},
	"datadog/go-codei":     {"command injection", "os command"},
	"datadog/python-codei": {"command injection", "os command"},

	// XSS should not report other injection types
	"datadog/java-xss":   {"sql injection", "command injection"},
	"datadog/go-xss":     {"sql injection", "command injection"},
	"datadog/python-xss": {"sql injection", "command injection"},
}

func GetKeywordsToFilter(ruleID string) []string {
	keywords, ok := ResultKeywordsToFilter[ruleID]
	if !ok {
		return nil
	}

	return keywords
}
