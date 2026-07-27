package agenttools

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestProjectSymbolIndexReturnsUniqueDefinitionPaths(t *testing.T) {
	project := model.NewAiContextProject()
	project.Tags["helper"] = []model.Tag{
		{Name: "helper", Path: "first.go", Type: model.TagDefinition},
		{Name: "helper", Path: "first.go", Type: model.TagDefinition},
		{Name: "helper", Path: "caller.go", Type: model.TagReference},
		{Name: "helper", Path: "second.go", Type: model.TagDefinition},
	}
	index := NewProjectSymbolIndex(&project)

	paths := index.LookupSymbol("helper", SymbolSearchDefinition)
	if len(paths) != 2 || paths[0] != "first.go" || paths[1] != "second.go" {
		t.Fatalf("unexpected definition paths %+v", paths)
	}
}

func TestProjectSymbolIndexIsNilSafe(t *testing.T) {
	index := NewProjectSymbolIndex(nil)
	if paths := index.LookupSymbol("helper", SymbolSearchReference); len(paths) != 0 {
		t.Fatalf("expected no paths from nil index, got %+v", paths)
	}
}

func TestProjectSymbolIndexPrefixesScanRelativePaths(t *testing.T) {
	project := model.NewAiContextProject()
	project.Tags["helper"] = []model.Tag{
		{Name: "helper", Path: "pkg/helper.go", Type: model.TagDefinition},
	}
	index := NewProjectSymbolIndexWithPrefix(&project, "domains/team")

	paths := index.LookupSymbol("helper", SymbolSearchDefinition)
	if len(paths) != 1 || paths[0] != "domains/team/pkg/helper.go" {
		t.Fatalf("unexpected prefixed paths %+v", paths)
	}
}

func TestProjectSymbolIndexHonorsCanceledContext(t *testing.T) {
	project := model.NewAiContextProject()
	project.Tags["helper"] = []model.Tag{{
		Name: "helper", Path: "helper.go", Type: model.TagDefinition,
	}}
	index := NewProjectSymbolIndex(&project)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	paths := index.LookupSymbolContext(ctx, "helper", SymbolSearchDefinition)

	assert.Empty(t, paths)
}
