package model

type FunctionDefinition struct {
	Name      string
	Language  Language
	Path      string
	StartLine uint
	EndLine   uint
}

type FunctionCall struct {
	Name     string
	Language Language
	Path     string
	Line     uint
}

type AiContextFile struct {
	Language Language `json:"language"`
	Tags     []Tag    `json:"tags"`
}

type AiContextProject struct {
	// for each language, list the files for this language
	Languages map[Language]map[string]struct{} `json:"languages"`

	// the file context for each file
	FileContext map[string]AiContextFile `json:"file_context"`
	// list of tags definition for each tag
	Tags map[string][]Tag `json:"tags"`
}

func NewAiContextProject() AiContextProject {
	return AiContextProject{
		Languages:   make(map[Language]map[string]struct{}),
		FileContext: make(map[string]AiContextFile),
		Tags:        make(map[string][]Tag),
	}
}

func (e *AiContextProject) HumanPrint() {
	println("LANGUAGES")
	println("=========")
	for lang, files := range e.Languages {
		println(lang.String())
		for file := range files {
			println("  -", file)
		}
	}

	println()

	println("FRAMEWORKS")
	println("==========")
	for tag, tags := range e.Tags {
		println(tag)
		for _, t := range tags {
			println("  -", t.Path)
		}
	}
	println()
}

func (e *AiContextProject) GetFilesForTagsAndType(tagName string, tagType TagType) []Tag {
	res := make([]Tag, 0)
	if e == nil {
		return res
	}
	tags, ok := e.Tags[tagName]
	if !ok {
		return res
	}

	for _, tag := range tags {
		if tag.Type == tagType {
			res = append(res, tag)
		}
	}
	return res
}

func (e *AiContextProject) GetTagsForFile(filePath string) []Tag {
	res := make([]Tag, 0)
	if e == nil {
		return res
	}
	fileContext, ok := e.FileContext[filePath]
	if !ok {
		return res
	}

	return fileContext.Tags
}

func (e *AiContextProject) MergeFileContext(path string, aiContext AiContextFile) {
	// handle the language part
	_, ok := e.Languages[aiContext.Language]
	if !ok {
		e.Languages[aiContext.Language] = make(map[string]struct{})
	}
	e.Languages[aiContext.Language][path] = struct{}{}

	// handle the tags
	for _, tag := range aiContext.Tags {
		_, ok := e.Tags[tag.Name]
		if !ok {
			e.Tags[tag.Name] = make([]Tag, 0)
		}
		e.Tags[tag.Name] = append(e.Tags[tag.Name], tag)
	}

	// Finally, adding the file context
	e.FileContext[path] = aiContext
}
