package model

// Version is the release version, set at build time via ldflags.
// Example: go build -ldflags "-X github.com/DataDog/datadog-saist/internal/model.Version=v1.0.0"
var Version = "dev"

// EngineVersion is the current version of the engine.
const EngineVersion = "1.0.1"

// Unknown is a constant for unknown values
const Unknown = "unknown"

const (
	OpenAIGPT56LunaName     = "openai-gpt5.6-luna"
	OpenAIGPT56LunaAPIModel = "gpt-5.6-luna"
)

// SCMCommit is the git commit hash, set at build time via ldflags.
// Example: go build -ldflags "-X github.com/DataDog/datadog-saist/internal/model.SCMCommit=abc123"
var SCMCommit = Unknown
