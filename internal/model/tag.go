package model

import (
	"sort"
	"strings"
)

type TagType int

const (
	TagUnknown TagType = iota
	TagReference
	TagDefinition
	TagPackage
)

type Tag struct {
	Name     string
	Path     string
	Type     TagType
	Language Language
}

func RankTagsPerLocality(tags []Tag, path string) []Tag {
	if len(tags) == 0 {
		return tags
	}

	// Create a copy of the tags slice to avoid modifying the original
	result := make([]Tag, len(tags))
	copy(result, tags)

	// Clean and normalize the reference path
	refPath := strings.TrimSuffix(path, "/")
	refSegments := strings.Split(refPath, "/")

	// Filter out empty segments
	var cleanRefSegments []string
	for _, segment := range refSegments {
		if segment != "" {
			cleanRefSegments = append(cleanRefSegments, segment)
		}
	}

	// Sort tags by locality score (higher score = more local)
	sort.Slice(result, func(i, j int) bool {
		scoreI := calculateLocalityScore(result[i].Path, cleanRefSegments)
		scoreJ := calculateLocalityScore(result[j].Path, cleanRefSegments)
		return scoreI > scoreJ
	})

	return result
}

// calculateLocalityScore calculates how "local" a tag path is to the reference path
// Returns a score where higher values indicate closer proximity
func calculateLocalityScore(tagPath string, refSegments []string) int {
	// Clean the tag path
	cleanTagPath := strings.TrimSuffix(tagPath, "/")
	tagSegments := strings.Split(cleanTagPath, "/")

	// Filter out empty segments
	var cleanTagSegments []string
	for _, segment := range tagSegments {
		if segment != "" {
			cleanTagSegments = append(cleanTagSegments, segment)
		}
	}

	// Calculate common prefix length
	commonPrefixLength := 0
	minLength := len(refSegments)
	if len(cleanTagSegments) < minLength {
		minLength = len(cleanTagSegments)
	}

	for i := 0; i < minLength; i++ {
		if refSegments[i] == cleanTagSegments[i] {
			commonPrefixLength++
		} else {
			break
		}
	}

	// Score calculation:
	// - Common prefix length is weighted heavily (multiply by 100)
	// - Penalize by the difference in path depth to prefer closer matches
	pathDepthDiff := abs(len(refSegments) - len(cleanTagSegments))
	score := commonPrefixLength*100 - pathDepthDiff

	return score
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
