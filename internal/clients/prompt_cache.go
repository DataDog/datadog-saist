package clients

import "strings"

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
