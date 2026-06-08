package clients

import "github.com/DataDog/datadog-saist/internal/prompt"

const (
	ApplicationJsonHeader              = "application/json"
	anthropicContentTypeText           = "text"
	anthropicCacheControlTypeEphemeral = "ephemeral"

	// promptCacheKeyHashBytes is the number of SHA-256 bytes kept in the cache key (64-bit
	// collision space, ~1/2^64 probability — sufficient at current request volumes).
	promptCacheKeyHashBytes = 8

	// analyzedFileCacheBoundary is derived from prompt.AnalyzedFileSectionHeader so a rename
	// of the section header is caught at compile time rather than silently degrading caching.
	analyzedFileCacheBoundary                   = "\n\n" + prompt.AnalyzedFileSectionHeader + "\n\n"
	indentedRequestSpecificFindingCacheBoundary = "\n\n  Request-Specific Finding:\n"
	requestSpecificFindingCacheBoundary         = "\n\nRequest-Specific Finding:\n"
)
