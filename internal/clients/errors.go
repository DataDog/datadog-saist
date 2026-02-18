package clients

import "errors"

// ErrRateLimited is returned when the API returns a 429 status (rate limit exceeded).
// This error triggers fail-fast behavior - the analysis stops immediately without retries.
var ErrRateLimited = errors.New("rate limited by API")

// IsRateLimitError checks if an error is or wraps a rate limit error
func IsRateLimitError(err error) bool {
	return errors.Is(err, ErrRateLimited)
}
