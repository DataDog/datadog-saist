package model

import (
	"path/filepath"
	"strings"
)

type Language int

const (
	LanguageUnknown Language = iota
	Java
	Go
	Python
	CSharp
	JavaScript
	TypeScript
	Kotlin
	PHP
	Ruby
	Rust
	Elixir
	Swift
)

func (l Language) String() string {
	switch l {
	case Java:
		return "Java"
	case Go:
		return "Go"
	case Python:
		return "Python"
	case CSharp:
		return "CSharp"
	case JavaScript:
		return "JavaScript"
	case TypeScript:
		return "TypeScript"
	case Kotlin:
		return "Kotlin"
	case PHP:
		return "PHP"
	case Ruby:
		return "Ruby"
	case Rust:
		return "Rust"
	case Elixir:
		return "Elixir"
	case Swift:
		return "Swift"
	default:
		return "LanguageUnknown"
	}
}

func GetLanguage(filePath string) Language {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".java":
		return Java
	case ".go":
		return Go
	case ".py", ".py3":
		return Python
	case ".cs":
		return CSharp
	case ".js", ".jsx", ".mjs":
		return JavaScript
	case ".ts", ".tsx", ".mts", ".cts":
		return TypeScript
	case ".kt", ".kts":
		return Kotlin
	case ".php", ".phtml", ".php3", ".php4", ".php5":
		return PHP
	case ".rb":
		return Ruby
	case ".rs":
		return Rust
	case ".ex", ".exs":
		return Elixir
	case ".swift":
		return Swift
	default:
		return LanguageUnknown
	}
}

// GetLanguageForPath is an alias for GetLanguage for compatibility
func GetLanguageForPath(filePath string) Language {
	return GetLanguage(filePath)
}

func GetAllLanguages() []Language {
	return []Language{
		Java,
		Go,
		Python,
		CSharp,
		JavaScript,
		TypeScript,
		Kotlin,
		PHP,
		Ruby,
		Rust,
		Elixir,
		Swift,
	}
}
