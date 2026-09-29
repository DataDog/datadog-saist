package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-saist/internal/analysis"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/rulecatalog"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	directory := flag.String("directory", "", "Non-customer local source directory")
	output := flag.String("output", "", "SARIF output")
	rulesPath := flag.String("rules-json", "", "Explicit rule catalog")
	driverPath := flag.String("driver", "", "Authoritative experimental file/rule selection")
	detection := flag.String("detection-model", "", "Gateway detection model")
	validation := flag.String("validation-model", "", "Gateway validation model")
	concurrency := flag.Int("file-concurrency", 1, "Concurrent source files")
	flag.Parse()
	if *directory == "" || *output == "" || *rulesPath == "" || *driverPath == "" || *detection == "" || *validation == "" || *concurrency < 1 {
		return fmt.Errorf("directory, output, rules-json, driver, both models and positive concurrency are required")
	}
	if os.Getenv(model.DatadogDriverEnabledEnvVar) == "true" {
		return fmt.Errorf("this command is for local experiments; unset DATADOG_DRIVER_ENABLED")
	}
	if os.Getenv("OPENAI_BEARER_TOKEN") == "" {
		return fmt.Errorf("OPENAI_BEARER_TOKEN is required for staging")
	}
	data, err := os.ReadFile(*rulesPath)
	if err != nil {
		return err
	}
	rules, _, err := rulecatalog.LoadJSON(data)
	if err != nil {
		return err
	}
	data, err = os.ReadFile(*driverPath)
	if err != nil {
		return err
	}
	var driver model.DatadogDriverConfig
	if err := json.Unmarshal(data, &driver); err != nil {
		return err
	}
	if driver.Files == nil {
		return fmt.Errorf("driver must contain a files map (empty is allowed)")
	}
	known := map[string]bool{}
	for _, rule := range rules {
		known[rule.ID] = true
	}
	for path, ids := range driver.Files {
		if !filepath.IsLocal(path) {
			return fmt.Errorf("non-local driver path: %s", path)
		}
		if info, err := os.Stat(filepath.Join(*directory, path)); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("missing source: %s", path)
		}
		for _, id := range ids {
			if !known[id] {
				return fmt.Errorf("unknown rule: %s", id)
			}
		}
	}
	dm, err := model.GetModelOrPassthrough(*detection, true)
	if err != nil {
		return err
	}
	vm, err := model.GetModelOrPassthrough(*validation, true)
	if err != nil {
		return err
	}
	_, err = analysis.RunConfiguredAnalysis(context.Background(), &model.AnalysisOptions{
		Directory: *directory, Output: *output, Rules: rules, DatadogDriver: &driver,
		ExperimentalDriverOnly: true, DetectionModel: dm, ValidationModel: vm,
		OpenAIBaseURL: "https://ai-gateway.us1.staging.dog", IsAIGateway: true,
		OrgID: 2, RepositoryID: "k9-saist-jev-prefilter", FileConcurrency: *concurrency,
		RequestTimeoutSec: 120,
	})
	return err
}
