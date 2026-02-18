package model

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

func TestHasFalsePositive(t *testing.T) {
	memory := []VulnerabilityMemory{
		{RuleID: "rule1", File: "file1.go", Line: 10, MemoryType: MemoryTypeFP, Reason: "false positive"},
		{RuleID: "rule2", File: "file2.go", Line: 20, MemoryType: MemoryTypeTP, Reason: "true positive"},
		{RuleID: "rule1", File: "file3.go", Line: 30, MemoryType: MemoryTypeFP, Reason: "another false positive"},
	}

	// Test case: matching rule, file, line with FP type
	assert.True(t, HasFalsePositive(memory, "rule1", "file1.go", 10), "Expected HasFalsePositive to return true for matching FP entry")

	// Test case: matching rule, file, line but with TP type
	assert.False(t, HasFalsePositive(memory, "rule2", "file2.go", 20), "Expected HasFalsePositive to return false for TP entry")

	// Test case: non-matching rule
	assert.False(t, HasFalsePositive(memory, "rule3", "file1.go", 10), "Expected HasFalsePositive to return false for non-matching rule")

	// Test case: non-matching file
	assert.False(t, HasFalsePositive(memory, "rule1", "file999.go", 10), "Expected HasFalsePositive to return false for non-matching file")

	// Test case: non-matching line
	assert.False(t, HasFalsePositive(memory, "rule1", "file1.go", 999), "Expected HasFalsePositive to return false for non-matching line")

	// Test case: empty memory
	assert.False(t, HasFalsePositive([]VulnerabilityMemory{}, "rule1", "file1.go", 10), "Expected HasFalsePositive to return false for empty memory")
}

func TestFilterVulnerabilityMemory(t *testing.T) {
	memory := []VulnerabilityMemory{
		{RuleID: SqlInjection.ShortName(), File: "file1.go", Line: 10, MemoryType: MemoryTypeFP},
		{RuleID: SqlInjection.ShortName(), File: "file2.go", Line: 20, MemoryType: MemoryTypeTP},
		{RuleID: CommandInjection.ShortName(), File: "file3.go", Line: 30, MemoryType: MemoryTypeFP},
		{RuleID: CommandInjection.ShortName(), File: "file4.go", Line: 40, MemoryType: MemoryTypeTP},
	}

	filtered := FilterVulnerabilityMemory(memory, &api.AiPrompt{ID: SqlInjection.ShortName()}, Go)
	assert.Len(t, filtered, 2)
	for _, item := range filtered {
		assert.Equal(t, SqlInjection.ShortName(), item.RuleID)
	}

	filtered = FilterVulnerabilityMemory(memory, &api.AiPrompt{ID: SqlInjection.ShortName()}, Go)
	assert.Len(t, filtered, 2)
	if len(filtered) > 0 {
		assert.Equal(t, SqlInjection.ShortName(), filtered[0].RuleID)
	}

	filtered = FilterVulnerabilityMemory(memory, &api.AiPrompt{ID: SqlInjection.ShortName()}, Python)
	assert.Len(t, filtered, 0)

	// Test filtering by non-existent rule
	filtered = FilterVulnerabilityMemory(memory, &api.AiPrompt{ID: Vulnerability(Xss).ShortName()}, Go)
	assert.Len(t, filtered, 0)

	// Test filtering empty memory
	filtered = FilterVulnerabilityMemory([]VulnerabilityMemory{}, &api.AiPrompt{ID: SqlInjection.ShortName()}, Go)
	assert.Len(t, filtered, 0, "Expected 0 items for empty memory")
}

func TestRankVulnerabilityMemory(t *testing.T) {
	memory := []VulnerabilityMemory{
		{RuleID: "rule1", File: "src/package/file1.go", Line: 10},
		{RuleID: "rule2", File: "src/other/file2.go", Line: 20},
		{RuleID: "rule3", File: "src/package/subdir/file3.go", Line: 30},
		{RuleID: "rule4", File: "completely/different/path.go", Line: 40},
		{RuleID: "rule5", File: "src/package/file4.go", Line: 50},
	}

	// Test ranking by "src/package/file1.go" (exact match should be first)
	ranked := RankVulnerabilityMemory(memory, "src/package/file1.go")
	assert.Len(t, ranked, len(memory), "Expected ranked slice to have same length as input")
	assert.Equal(t, "src/package/file1.go", ranked[0].File, "Expected exact match to be first")

	// Test ranking by "src/package/" (directory path)
	ranked = RankVulnerabilityMemory(memory, "src/package/")
	// Items in src/package should come before items in src/other or completely different paths
	firstTwoShouldBeInPackage := true
	for i := 0; i < 2 && i < len(ranked); i++ {
		if ranked[i].File != "src/package/file1.go" && ranked[i].File != "src/package/file4.go" {
			firstTwoShouldBeInPackage = false
			break
		}
	}
	assert.True(t, firstTwoShouldBeInPackage, "Expected files in src/package to be ranked higher")

	// Test with empty memory
	ranked = RankVulnerabilityMemory([]VulnerabilityMemory{}, "some/path")
	assert.Len(t, ranked, 0, "Expected empty slice for empty input")

	// Test that original slice is not modified
	originalFirst := memory[0].File
	RankVulnerabilityMemory(memory, "some/other/path")
	assert.Equal(t, originalFirst, memory[0].File, "Expected original slice to remain unmodified")
}

func TestPathDistance(t *testing.T) {
	// Test exact match
	assert.Equal(t, 0, pathDistance("src/file.go", "src/file.go"), "Expected distance 0 for exact match")

	// Test same directory
	distance := pathDistance("src/file1.go", "src/file2.go")
	assert.Equal(t, 2, distance, "Expected distance 2 for same directory different files")

	// Test parent-child relationship
	distance = pathDistance("src/package", "src/package/file.go")
	assert.Equal(t, 1, distance, "Expected distance 1 for parent-child paths")

	// Test completely different paths
	distance = pathDistance("src/package/file.go", "test/other/file.go")
	assert.Equal(t, 6, distance, "Expected distance 6 for completely different paths")

	// Test with trailing slashes
	distance = pathDistance("src/package/", "src/package/file.go")
	assert.Equal(t, 1, distance, "Expected distance 1 with trailing slash")
}
