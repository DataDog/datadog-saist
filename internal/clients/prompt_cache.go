package clients

import "strings"

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
