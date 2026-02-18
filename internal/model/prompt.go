package model

type DetectionPromptSystem struct {
	Language   Language
	Frameworks []string
}

type DetectionPromptUser struct {
	Language   Language
	Frameworks []string
	Libraries  []string
	Path       string
	Code       string
}

type PromptMemoryItem struct {
	MemoryType MemoryType
	Language   Language
	Code       string
	Reason     string
}

type PromptMemory struct {
	Language       Language
	TruePositives  []PromptMemoryItem
	FalsePositives []PromptMemoryItem
}
