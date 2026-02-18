package model

import (
	"sort"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

type VulnerabilityMemory struct {
	RuleID     string
	File       string
	Line       uint
	MemoryType MemoryType
	Reason     string
}

type MemoryType string

const (
	MemoryTypeTP MemoryType = "TP"
	MemoryTypeFP MemoryType = "FP"
)

// HasFalsePositive checks that the memory argument contains an element that matches the arguments
// and has a MemoryType FP for False Positive
func HasFalsePositive(memory []VulnerabilityMemory, ruleId, file string, line uint) bool {
	for _, item := range memory {
		if item.RuleID == ruleId && item.File == file && item.Line == line && item.MemoryType == MemoryTypeFP {
			return true
		}
	}
	return false
}

// FilterVulnerabilityMemory filter the elements based on the ruleId
func FilterVulnerabilityMemory(memory []VulnerabilityMemory, rule *api.AiPrompt, language Language) []VulnerabilityMemory {
	vulnShortName := rule.ID
	var filtered []VulnerabilityMemory
	for _, item := range memory {
		lang := GetLanguage(item.File)

		if lang != language {
			continue
		}

		if item.RuleID == vulnShortName {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

// RankVulnerabilityMemory returns the items the closer to the path passed in parameters. It evaluates
// the path passed as argument with the File attribute of each element of the memory.
func RankVulnerabilityMemory(memory []VulnerabilityMemory, path string) []VulnerabilityMemory {
	if len(memory) == 0 {
		return memory
	}

	// Create a copy to avoid modifying the original slice
	ranked := make([]VulnerabilityMemory, len(memory))
	copy(ranked, memory)

	// Sort by path similarity (closer paths first)
	sort.Slice(ranked, func(i, j int) bool {
		distanceI := pathDistance(path, ranked[i].File)
		distanceJ := pathDistance(path, ranked[j].File)
		return distanceI < distanceJ
	})

	return ranked
}

// pathDistance calculates the "distance" between two paths
// Returns 0 for exact match, lower values for closer paths
func pathDistance(path1, path2 string) int {
	if path1 == path2 {
		return 0
	}

	// Split paths into components
	parts1 := strings.Split(strings.Trim(path1, "/"), "/")
	parts2 := strings.Split(strings.Trim(path2, "/"), "/")

	// Find common prefix length
	commonLen := 0
	minLen := len(parts1)
	if len(parts2) < minLen {
		minLen = len(parts2)
	}

	for i := 0; i < minLen; i++ {
		if parts1[i] == parts2[i] {
			commonLen++
		} else {
			break
		}
	}

	// Distance is the sum of uncommon parts
	return (len(parts1) - commonLen) + (len(parts2) - commonLen)
}
