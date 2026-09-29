package prefilter

import "time"

const (
	JevEndpoint        = "https://ai-gateway.us1.staging.dog/v1/systemone"
	JevSource          = "k9-saist-jev-prefilter"
	JevOrgID           = "2"
	DefaultJevModel    = "typesafe/jev-latest"
	DefaultThreshold   = 0.1
	JevTimeout         = 120 * time.Second
	JevRequestInterval = 100 * time.Millisecond
	// Conservative byte bound; oversized files fail open without truncation.
	MaxJevRequestBytes  = 90000
	MaxJevResponseBytes = 1024 * 1024
)
