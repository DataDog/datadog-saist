package filtering

import (
	"strings"

	"github.com/DataDog/datadog-saist/internal/model"
)

func FilterViolations(violations []model.Violation, predicate func(model.Violation) bool) []model.Violation {
	var filtered []model.Violation
	for _, violation := range violations {
		if predicate(violation) {
			filtered = append(filtered, violation)
		}
	}
	return filtered
}

func FilterViolationsByKeywords(violations []model.Violation, keywords []string) []model.Violation {
	if keywords == nil {
		return violations
	}
	return FilterViolations(violations, func(violation model.Violation) bool {
		message := strings.ToLower(violation.Message)
		for _, keyword := range keywords {
			if strings.Contains(message, strings.ToLower(keyword)) {
				return false
			}
		}
		return true
	})
}
