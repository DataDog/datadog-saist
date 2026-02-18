package utils

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func DecodeFromBase64(s string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("base64 decoding failed: %w", err)
	}
	return string(data), nil
}

// AddLineNumbers prefixes each line of code with its line number for accurate LLM line identification
func AddLineNumbers(code string) string {
	lines := strings.Split(code, "\n")
	var result strings.Builder
	for i, line := range lines {
		result.WriteString(fmt.Sprintf("%d: %s\n", i+1, line))
	}
	return result.String()
}
