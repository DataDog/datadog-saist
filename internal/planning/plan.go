package planning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/DataDog/datadog-saist/internal/codesecurity"
	"github.com/DataDog/datadog-saist/internal/filtering"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/prefilter"
	"github.com/DataDog/datadog-saist/internal/rulecatalog"
	"github.com/DataDog/datadog-saist/internal/source"
	"github.com/DataDog/datadog-saist/internal/utils"
)

type WorkItem struct {
	Path     string `json:"path"`
	FileHash string `json:"file_hash"`
	Language string `json:"language"`
	RuleID   string `json:"rule_id"`
	RuleHash string `json:"rule_hash"`
}

type Decision struct {
	WorkItem
	Selected bool     `json:"selected"`
	Reason   string   `json:"reason"`
	Error    string   `json:"error,omitempty"`
	Score    *float64 `json:"score,omitempty"`
}

type Summary struct {
	DiscoveredFiles int             `json:"discovered_files"`
	CandidateFiles  int             `json:"candidate_files"`
	CandidatePairs  int             `json:"candidate_pairs"`
	SelectedPairs   int             `json:"selected_pairs"`
	ErrorPairs      int             `json:"error_pairs"`
	Usage           prefilter.Usage `json:"usage"`
}

type Record struct {
	RuleSource    *rulecatalog.Provenance `json:"rule_source,omitempty"`
	Type          string                  `json:"type"`
	SchemaVersion int                     `json:"schema_version,omitempty"`
	Prefilter     string                  `json:"prefilter,omitempty"`
	Configuration any                     `json:"configuration,omitempty"`
	Decision      *Decision               `json:"decision,omitempty"`
	Path          string                  `json:"path,omitempty"`
	Model         string                  `json:"model,omitempty"`
	LatencyMS     int64                   `json:"latency_ms,omitempty"`
	Usage         *prefilter.Usage        `json:"usage,omitempty"`
	Summary       *Summary                `json:"summary,omitempty"`
}

type Options struct {
	RuleSource *rulecatalog.Provenance
	Directory  string
	Rules      []api.AiPrompt
	Driver     *model.DatadogDriverConfig
	Selector   prefilter.Selector
	MaxFiles   int
}

// Plan writes a manifest, per-file usage, every candidate decision, and a completion summary.
// It holds source text for one file at a time and never constructs a detection agent.
func Plan(ctx context.Context, opts Options, output io.Writer) (Summary, error) {
	var summary Summary
	if opts.Selector == nil {
		return summary, fmt.Errorf("prefilter is required")
	}
	if opts.MaxFiles < 0 {
		return summary, fmt.Errorf("max-files must be nonnegative")
	}
	root, err := filepath.Abs(opts.Directory)
	if err != nil {
		return summary, err
	}
	files, err := source.NewFileDiscoverer(root, false).DiscoverFiles(ctx)
	if err != nil {
		return summary, err
	}
	slices.SortFunc(files, func(a, b source.File) int {
		if a.RelPath < b.RelPath {
			return -1
		}
		if a.RelPath > b.RelPath {
			return 1
		}
		return 0
	})
	summary.DiscoveredFiles = len(files)
	rules, candidates, requireKeywords, err := candidateRules(ctx, root, files, opts.Rules, opts.Driver)
	if err != nil {
		return summary, err
	}
	rulesByID := make(map[string]api.AiPrompt, len(rules))
	hashes := make(map[string]string, len(rules))
	for _, rule := range rules {
		if rule.ID == "" {
			return summary, fmt.Errorf("empty rule ID")
		}
		if _, exists := rulesByID[rule.ID]; exists {
			return summary, fmt.Errorf("duplicate rule %s", rule.ID)
		}
		rulesByID[rule.ID] = rule
		encoded, err := json.Marshal(rule)
		if err != nil {
			return summary, err
		}
		sum := sha256.Sum256(encoded)
		hashes[rule.ID] = hex.EncodeToString(sum[:])
	}
	encoder := json.NewEncoder(output)
	manifest := Record{Type: "manifest", SchemaVersion: SchemaVersion, Prefilter: opts.Selector.Name(), RuleSource: opts.RuleSource}
	if configured, ok := opts.Selector.(interface{ Configuration() any }); ok {
		manifest.Configuration = configured.Configuration()
	}
	if err := encoder.Encode(manifest); err != nil {
		return summary, err
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		ids := candidates[file.RelPath]
		if len(ids) == 0 {
			continue
		}
		if opts.MaxFiles > 0 && summary.CandidateFiles >= opts.MaxFiles {
			break
		}
		slices.Sort(ids)
		fileRules := make([]api.AiPrompt, 0, len(ids))
		for _, id := range ids {
			fileRules = append(fileRules, rulesByID[id])
		}
		content, err := os.ReadFile(file.AbsPath)
		if err != nil {
			return summary, fmt.Errorf("read %s: %w", file.RelPath, err)
		}
		if source.CalculateFileHashFromBytes(content) != file.Hash {
			return summary, fmt.Errorf("file changed during planning: %s", file.RelPath)
		}
		started := time.Now()
		result, selectErr := opts.Selector.Select(ctx, prefilter.File{
			Path: filepath.ToSlash(file.RelPath), Language: file.Language, Code: string(content),
			StrippedCode:    filtering.StripCodeForDetection(string(content), file.Language),
			RequireKeywords: requireKeywords,
		}, fileRules)
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		if selectErr != nil {
			result.Decisions = nil
			for _, id := range ids {
				result.Decisions = append(result.Decisions, prefilter.Decision{
					RuleID: id, Selected: true, Reason: "fail_open", Error: selectErr.Error(),
				})
			}
		}
		decisions := make(map[string]prefilter.Decision, len(ids))
		for _, decision := range result.Decisions {
			if !slices.Contains(ids, decision.RuleID) {
				return summary, fmt.Errorf("prefilter returned unknown rule %s", decision.RuleID)
			}
			if _, exists := decisions[decision.RuleID]; exists {
				return summary, fmt.Errorf("prefilter returned duplicate rule %s", decision.RuleID)
			}
			decisions[decision.RuleID] = decision
		}
		if len(decisions) != len(ids) {
			return summary, fmt.Errorf("prefilter omitted decisions for %s", file.RelPath)
		}
		if err := encoder.Encode(Record{Type: "file", Path: filepath.ToSlash(file.RelPath),
			Model: result.Model, Usage: &result.Usage, LatencyMS: time.Since(started).Milliseconds()}); err != nil {
			return summary, err
		}
		summary.CandidateFiles++
		summary.Usage.InputTokens += result.Usage.InputTokens
		summary.Usage.OutputTokens += result.Usage.OutputTokens
		for _, id := range ids {
			selected := decisions[id]
			decision := Decision{
				WorkItem: WorkItem{Path: filepath.ToSlash(file.RelPath), FileHash: file.Hash,
					Language: file.Language.String(), RuleID: id, RuleHash: hashes[id]},
				Selected: selected.Selected, Reason: selected.Reason, Error: selected.Error, Score: selected.Score,
			}
			if err := encoder.Encode(Record{Type: "decision", Decision: &decision}); err != nil {
				return summary, err
			}
			summary.CandidatePairs++
			if decision.Selected {
				summary.SelectedPairs++
			}
			if decision.Error != "" {
				summary.ErrorPairs++
			}
		}
	}
	return summary, encoder.Encode(Record{Type: "summary", Summary: &summary})
}

func candidateRules(ctx context.Context, root string, files []source.File, rules []api.AiPrompt,
	driver *model.DatadogDriverConfig) ([]api.AiPrompt, map[string][]string, bool, error) {
	var cfg *codesecurity.File
	var enabled map[string]bool
	var rulesets map[string][]string
	if driver == nil {
		var basename string
		var err error
		cfg, basename, err = codesecurity.LoadLocalFile(root)
		if err != nil {
			return nil, nil, false, fmt.Errorf("local config: %w", err)
		}
		if cfg != nil && cfg.Sast != nil {
			rulesets = codesecurity.BuildRulesetToRuleIDs(rules)
			enabled, rules, _ = codesecurity.FilterRulesBySastConfig(rules, cfg.Sast, rulesets, codesecurity.IsLegacyConfigBasename(basename))
		}
	}
	configured := cfg != nil && cfg.Sast != nil
	candidates := make(map[string][]string)
	for _, file := range files {
		for _, rule := range rules {
			languages := utils.InferLanguagesFromGlobs(rule.Globs)
			if len(languages) > 0 && !slices.Contains(languages, file.Language) {
				continue
			}
			if !utils.RuleMatchesFile(&rule, filepath.ToSlash(file.RelPath)) {
				continue
			}
			// Local YAML previously used rule-ID language grouping as well as the analyzer's glob index.
			if configured && codesecurity.ExtractLanguageFromRuleID(rule.ID) != codesecurity.LanguageKey(file.Language) {
				continue
			}
			if driver != nil && !slices.Contains(driver.Files[file.RelPath], rule.ID) {
				continue
			}
			candidates[file.RelPath] = append(candidates[file.RelPath], rule.ID)
		}
	}
	if configured {
		candidates = codesecurity.ApplyGlobalPathFiltersToFileRuleMapping(candidates, cfg.Sast.GlobalConfig)
		if cfg.Sast.RulesetConfigs != nil {
			codesecurity.ForEachRulesetConfigPathFilter(ctx, *cfg.Sast.RulesetConfigs, enabled, rulesets,
				func(configs map[string]codesecurity.YamlRuleConfig) {
					candidates = codesecurity.ApplyRuleConfigFilters(candidates, configs)
				})
		}
	}
	return rules, candidates, configured, nil
}
