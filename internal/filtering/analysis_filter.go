package filtering

import (
	"regexp"
	"strings"
	"sync"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

var analysisFilterRegexps sync.Map

type filterRegexp struct {
	re  *regexp.Regexp
	err error
}

// Unsupported expressions fall back to the existing rule filter as a whole.
func matchFilterExpression(code string, e *api.FilterExpression) (matches, supported bool) {
	if countFilterOperators(e) != 1 {
		return false, false
	}
	switch {
	case len(e.All) > 0:
		return matchFilterGroup(code, e.All, true)
	case len(e.Any) > 0:
		return matchFilterGroup(code, e.Any, false)
	case e.Not != nil:
		matches, supported = matchFilterExpression(code, e.Not)
		return !matches, supported
	case len(e.RegexAny) > 0:
		return matchFilterRegexps(code, e.RegexAny)
	case e.CountEquals != nil:
		return matchFilterCount(code, e.CountEquals)
	default:
		return matchFilterKeywords(code, e)
	}
}

func countFilterOperators(e *api.FilterExpression) int {
	count := 0
	for _, present := range []bool{
		len(e.All) > 0, len(e.Any) > 0, e.Not != nil,
		len(e.ContainsAny) > 0, len(e.WordsAny) > 0,
		len(e.RegexAny) > 0, e.CountEquals != nil,
	} {
		if present {
			count++
		}
	}
	return count
}

func matchFilterKeywords(code string, e *api.FilterExpression) (matches, supported bool) {
	values := e.ContainsAny
	if len(e.WordsAny) > 0 {
		values = e.WordsAny
	}
	normalized := make([]string, len(values))
	for i, value := range values {
		if value == "" {
			return false, false
		}
		normalized[i] = strings.ToLower(value)
	}
	if len(e.WordsAny) > 0 {
		return containsAnyWord(code, normalized), true
	}
	return containsAny(code, normalized), true
}

func matchFilterGroup(code string, children []api.FilterExpression, all bool) (matches, supported bool) {
	matches = all
	for i := range children {
		childMatches, valid := matchFilterExpression(code, &children[i])
		if !valid {
			return false, false
		}
		if all {
			matches = matches && childMatches
		} else {
			matches = matches || childMatches
		}
	}
	return matches, true
}

func matchFilterCount(code string, condition *api.FilterCount) (matches, supported bool) {
	if len(condition.Substrings) == 0 || condition.Count < 0 {
		return false, false
	}
	count := 0
	for _, substring := range condition.Substrings {
		if substring == "" {
			return false, false
		}
		count += strings.Count(code, strings.ToLower(substring))
	}
	return count == condition.Count, true
}

func matchFilterRegexps(code string, patterns []string) (matches, supported bool) {
	for _, pattern := range patterns {
		if pattern == "" {
			return false, false
		}
		compiled := compileFilterRegexp(pattern)
		if compiled.err != nil {
			return false, false
		}
		matches = compiled.re.MatchString(code) || matches
	}
	return matches, true
}

func compileFilterRegexp(pattern string) filterRegexp {
	if cached, ok := analysisFilterRegexps.Load(pattern); ok {
		return cached.(filterRegexp)
	}
	re, err := regexp.Compile(pattern)
	compiled := filterRegexp{re: re, err: err}
	cached, _ := analysisFilterRegexps.LoadOrStore(pattern, compiled)
	return cached.(filterRegexp)
}
