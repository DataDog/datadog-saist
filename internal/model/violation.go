package model

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
)

type Violation struct {
	Rule        string
	Cwe         *string
	Path        string
	FileHash    string
	StartLine   uint
	StartColumn uint
	EndLine     uint
	EndColumn   uint
	Message     string
	Fingerprint string
}

func (violation Violation) String() string {
	return fmt.Sprintf("%s:%d:%d %s: %s", violation.Path, violation.StartLine, violation.StartColumn, violation.Rule, violation.Message)
}

// GenerateFingerprint creates a hash based on repo ID, rule name, filepath,
// directory length, line content, and line length
func GenerateFingerprint(repoID, ruleName, filePath, lineContent string) string {
	// Get directory path and its length
	dirPath := filepath.Dir(filePath)
	dirLength := len(dirPath)

	// Get line content length
	lineLength := len(lineContent)

	// Concatenate all components
	fingerprintData := fmt.Sprintf("%s|%s|%s|%d|%s|%d",
		repoID,
		ruleName,
		filePath,
		dirLength,
		lineContent,
		lineLength,
	)

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(fingerprintData))
	return fmt.Sprintf("%x", hash)
}

// GetLineContent extracts the content of a specific line from file text
func GetLineContent(fileText string, lineNumber uint) string {
	if lineNumber == 0 {
		return ""
	}

	lines := strings.Split(fileText, "\n")
	if int(lineNumber) > len(lines) {
		return ""
	}

	return lines[lineNumber-1]
}
