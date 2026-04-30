package agents

import (
	"strings"
)

func extractJSONFromCodeBlock(content string) string {
	if strings.Contains(content, "```json") {
		startIndex := strings.Index(content, "```json")
		if startIndex != -1 {
			startIndex += 7
			endIndex := strings.Index(content[startIndex:], "```")
			if endIndex != -1 {
				return strings.TrimSpace(content[startIndex : startIndex+endIndex])
			}
		}
	} else if strings.Contains(content, "```") {
		startIndex := strings.Index(content, "```")
		if startIndex != -1 {
			startIndex += 3
			endIndex := strings.Index(content[startIndex:], "```")
			if endIndex != -1 {
				return strings.TrimSpace(content[startIndex : startIndex+endIndex])
			}
		}
	}
	return content
}
