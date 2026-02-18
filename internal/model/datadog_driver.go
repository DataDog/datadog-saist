package model

const (
	// DatadogDriverConfigFilename is the name of the Datadog driver configuration file
	DatadogDriverConfigFilename = ".datadog-driver.json"

	// DatadogDriverEnabledEnvVar is the environment variable name to enable Datadog driver
	DatadogDriverEnabledEnvVar = "DATADOG_DRIVER_ENABLED"
)

// DatadogDriverConfig stores configuration for the Datadog driver
type DatadogDriverConfig struct {
	Files map[string][]string `json:"files"`
}
