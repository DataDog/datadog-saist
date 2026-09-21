package clients

import (
	"strconv"
	"strings"
)

// splitPromptCacheablePrefix splits userPrompt into a stable cacheable prefix and a dynamic
// suffix. It assumes boundary strings (e.g. "## Analyzed File") do not appear in rule content
// itself; if they do, the prefix would be cut short and the cache key would cover less than
// intended (no functional bug, just suboptimal caching).
func splitPromptCacheablePrefix(userPrompt string) (cacheablePrefix, dynamicSuffix string) {
	for _, boundary := range []string{
		analyzedFileCacheBoundary,
		indentedRequestSpecificFindingCacheBoundary,
		requestSpecificFindingCacheBoundary,
	} {
		if index := strings.Index(userPrompt, boundary); index >= 0 {
			return userPrompt[:index], userPrompt[index:]
		}
	}
	return "", userPrompt
}

// GPT-5.6+ charges for implicit cache writes and supports explicit boundaries to avoid caching changing input.
// https://developers.openai.com/api/docs/guides/prompt-caching
func supportsExplicitPromptCaching(modelName string) bool {
	modelName = strings.TrimPrefix(modelName, "openai/")
	version, ok := strings.CutPrefix(modelName, "gpt-")
	if !ok {
		return false
	}
	version, _, _ = strings.Cut(version, "-")
	majorString, minorString, hasMinor := strings.Cut(version, ".")
	major, err := strconv.ParseUint(majorString, 10, 32)
	if err != nil {
		return false
	}
	var minor uint64
	if hasMinor {
		minor, err = strconv.ParseUint(minorString, 10, 32)
		if err != nil {
			return false
		}
	}
	return major > 5 || (major == 5 && minor >= 6)
}
