package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/planning"
	"github.com/DataDog/datadog-saist/internal/prefilter"
	"github.com/DataDog/datadog-saist/internal/rulecatalog"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("datadog-saist-prefilter", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "Source root (also the local YAML configuration root)")
	output := flags.String("output", "", "New output file; default stdout")
	kind := flags.String("prefilter", "legacy", "legacy, none, or jev")
	rulesDirectory := flags.String("rules-directory", "", "Explicit local markdown directory (does not supply full catalog metadata)")
	rulesJSON := flags.String("rules-json", "", "Versioned shared-catalog snapshot or local JSON array of AiPrompt rules")
	questions := flags.String("questions", "", "Jev JSON map of rule IDs to prefilter questions")
	jevModel := flags.String("jev-model", prefilter.DefaultJevModel, "Gateway Jev model ID or alias")
	threshold := flags.Float64("threshold", prefilter.DefaultThreshold, "Minimum Jev relevance probability to retain a pair")
	maxFiles := flags.Int("max-files", 0, "Maximum candidate files in sorted path order; zero means all")
	driverPath := flags.String("driver", "", "Optional explicit driver JSON restricting candidate pairs")
	before := flags.String("before", "", "Compare: baseline plan JSONL")
	after := flags.String("after", "", "Compare: candidate plan JSONL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *before != "" || *after != "" {
		if *before == "" || *after == "" {
			return fmt.Errorf("comparison requires both --before and --after")
		}
		a, err := os.Open(*before)
		if err != nil {
			return err
		}
		defer a.Close()
		b, err := os.Open(*after)
		if err != nil {
			return err
		}
		defer b.Close()
		result, err := planning.Compare(a, b)
		if err != nil {
			return err
		}
		return writeOutput(*output, stdout, func(w io.Writer) error { return json.NewEncoder(w).Encode(result) })
	}
	if *directory == "" {
		return fmt.Errorf("--directory is required")
	}
	if *maxFiles < 0 {
		return fmt.Errorf("--max-files must be nonnegative")
	}
	if (*rulesJSON == "") == (*rulesDirectory == "") {
		return fmt.Errorf("provide exactly one of --rules-json or --rules-directory; shared-catalog snapshots are recommended")
	}
	if os.Getenv(model.DatadogDriverEnabledEnvVar) == "true" {
		return fmt.Errorf("prefilter experiments require local mode; unset %s and use --driver explicitly if needed", model.DatadogDriverEnabledEnvVar)
	}
	var selector prefilter.Selector
	switch *kind {
	case "legacy":
		selector = prefilter.Legacy{}
	case "none":
		selector = prefilter.None{}
	case "jev":
		if *questions == "" {
			return fmt.Errorf("--questions is required for Jev")
		}
		if math.IsNaN(*threshold) || *threshold < 0 || *threshold > 1 {
			return fmt.Errorf("--threshold must be between 0 and 1")
		}
		key := os.Getenv("OPENAI_BEARER_TOKEN")
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("OPENAI_BEARER_TOKEN is required for staging AI Gateway")
		}
		var prompts map[string]string
		if err := readJSON(*questions, &prompts); err != nil {
			return err
		}
		selector = &prefilter.Jev{BearerToken: key, Model: *jevModel, Threshold: *threshold, Questions: prompts}
	default:
		return fmt.Errorf("unknown prefilter %q", *kind)
	}
	var rules []api.AiPrompt
	var provenance rulecatalog.Provenance
	var err error
	if *rulesJSON != "" {
		var data []byte
		data, err = os.ReadFile(*rulesJSON)
		if err == nil {
			rules, provenance, err = rulecatalog.LoadJSON(data)
		}
	} else {
		rules, err = rulecatalog.Load(os.DirFS(*rulesDirectory))
		provenance = rulecatalog.Provenance{Source: "local-markdown", RuleCount: len(rules)}
		fmt.Fprintln(stderr, "Local markdown does not supply catalog keyword/version metadata; this is not a shared-catalog baseline.")
	}
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	if len(rules) == 0 {
		return fmt.Errorf("no rules loaded")
	}
	var driver *model.DatadogDriverConfig
	if *driverPath != "" {
		driver = &model.DatadogDriverConfig{}
		if err := readJSON(*driverPath, driver); err != nil {
			return err
		}
	}
	return writeOutput(*output, stdout, func(w io.Writer) error {
		summary, err := planning.Plan(ctx, planning.Options{
			Directory: *directory, Rules: rules, Driver: driver, Selector: selector, MaxFiles: *maxFiles, RuleSource: &provenance,
		}, w)
		if err != nil {
			return err
		}
		fmt.Fprintf(stderr, "%d candidate pairs, %d selected, %d error pairs across %d files\n",
			summary.CandidatePairs, summary.SelectedPairs, summary.ErrorPairs, summary.CandidateFiles)
		if summary.ErrorPairs > 0 {
			return fmt.Errorf("plan completed with prefilter errors; affected pairs were retained")
		}
		return nil
	})
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func writeOutput(path string, stdout io.Writer, write func(io.Writer) error) error {
	if path == "" {
		return write(stdout)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = write(file)
	return errors.Join(err, file.Close())
}
