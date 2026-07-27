package analysis

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/DataDog/datadog-saist/internal/candidates"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	modelapi "github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/replay"
)

func runCandidateReplay(ctx context.Context, opts *model.AnalysisOptions,
	outputPath string) (AnalysisSummary, error) {
	manifest, err := os.Open(opts.ReplayCandidatesPath)
	if err != nil {
		return AnalysisSummary{}, fmt.Errorf("open candidate replay manifest %q: %w",
			opts.ReplayCandidatesPath, err)
	}
	values, readErr := candidates.ReadJSONL(manifest)
	closeErr := manifest.Close()
	if readErr != nil {
		return AnalysisSummary{}, readErr
	}
	if closeErr != nil {
		return AnalysisSummary{}, fmt.Errorf("close candidate replay manifest %q: %w",
			opts.ReplayCandidatesPath, closeErr)
	}

	agent, err := newDetectionAgent(ctx, opts)
	if err != nil {
		return AnalysisSummary{}, fmt.Errorf("create candidate replay verifier: %w", err)
	}
	defer func() {
		if err := agent.Close(); err != nil {
			log.FromContext(ctx).Warnf("Failed to close candidate replay verifier: %v", err)
		}
	}()

	results, err := replay.Run(ctx, values, replay.SourceRevision{
		RepositoryID:     opts.RepositoryID,
		RepositoryRoot:   opts.RepositoryRoot,
		RepositorySHA:    opts.RepositorySHA,
		RepositoryDirty:  opts.RepositoryDirty,
		AllowSourceDrift: opts.AllowSourceDrift,
	}, agent)
	if err != nil {
		return AnalysisSummary{}, err
	}
	if err := replay.WriteFile(outputPath, results); err != nil {
		return AnalysisSummary{}, err
	}

	violations := make([]model.Violation, 0)
	var inputTokens int32
	var outputTokens int32
	var modelCalls int32
	fileSet := make(map[string]struct{})
	ruleSet := make(map[string]modelapi.AiPrompt)
	for _, candidate := range values {
		fileSet[candidate.RelativeFilePath] = struct{}{}
		ruleSet[candidate.Rule.ID] = candidate.Rule
	}
	for _, result := range results {
		inputTokens += result.InputTokens
		outputTokens += result.OutputTokens
		modelCalls += result.ModelCalls
		if result.Violation != nil {
			violations = append(violations, *result.Violation)
		}
	}
	files := make([]string, 0, len(fileSet))
	for filePath := range fileSet {
		files = append(files, filePath)
	}
	sort.Strings(files)
	rules := make([]modelapi.AiPrompt, 0, len(ruleSet))
	for _, rule := range ruleSet {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(left, right int) bool {
		return rules[left].ID < rules[right].ID
	})

	log.FromContext(ctx).Infof("Candidate replay completed, candidates=%d confirmed=%d output=%s",
		len(results), len(violations), outputPath)
	return AnalysisSummary{
		FilesAnalyzed: files,
		Rules:         rules,
		Violations:    violations,
		InputTokens:   inputTokens,
		OutputTokens:  outputTokens,
		ModelCalls:    modelCalls,
	}, nil
}
