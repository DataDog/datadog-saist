package analysis

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccumulateRunScanUsageSumsReportedModelCalls(t *testing.T) {
	var inputTokens int32
	var outputTokens int32
	var modelCalls int32

	accumulateRunScanUsage(&inputTokens, &outputTokens, &modelCalls, RunScanResult{
		FileInputTokens:  11,
		FileOutputTokens: 7,
		FileLLMCalls:     4,
	})
	accumulateRunScanUsage(&inputTokens, &outputTokens, &modelCalls, RunScanResult{
		FileInputTokens:  13,
		FileOutputTokens: 5,
		FileLLMCalls:     2,
	})

	assert.Equal(t, int32(24), inputTokens)
	assert.Equal(t, int32(12), outputTokens)
	assert.Equal(t, int32(6), modelCalls)
}
