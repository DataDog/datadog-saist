package clients

const (
	ApplicationJsonHeader                       = "application/json"
	anthropicContentTypeText                    = "text"
	anthropicCacheControlTypeEphemeral          = "ephemeral"
	promptCacheKeyHashBytes                     = 8
	analyzedFileCacheBoundary                   = "\n\n## Analyzed File\n\n"
	indentedRequestSpecificFindingCacheBoundary = "\n\n  Request-Specific Finding:\n"
	requestSpecificFindingCacheBoundary         = "\n\nRequest-Specific Finding:\n"
)
