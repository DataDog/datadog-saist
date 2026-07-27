package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEffectiveAgenticModesEnablesBothPhasesForCompatibilityAlias(t *testing.T) {
	detection, verification := effectiveAgenticModes(true, false, false)

	assert.True(t, detection)
	assert.True(t, verification)
}

func TestEffectiveAgenticModesEnablesDetectionOnly(t *testing.T) {
	detection, verification := effectiveAgenticModes(false, true, false)

	assert.True(t, detection)
	assert.False(t, verification)
}

func TestEffectiveAgenticModesEnablesVerificationOnly(t *testing.T) {
	detection, verification := effectiveAgenticModes(false, false, true)

	assert.False(t, detection)
	assert.True(t, verification)
}

func TestEffectiveAgenticModesLeavesBothPhasesDisabled(t *testing.T) {
	detection, verification := effectiveAgenticModes(false, false, false)

	assert.False(t, detection)
	assert.False(t, verification)
}

func TestValidateCandidateModesRejectsExportAndReplayTogether(t *testing.T) {
	err := validateCandidateModes("export.jsonl", "replay.jsonl", false)

	assert.EqualError(t, err, "candidate export and replay cannot be enabled together")
}

func TestValidateCandidateModesRejectsDriftOutsideReplay(t *testing.T) {
	err := validateCandidateModes("", "", true)

	assert.EqualError(t, err, "source drift can only be allowed during candidate replay")
}

func TestValidateCandidateModesAllowsReplayWithDrift(t *testing.T) {
	err := validateCandidateModes("", "replay.jsonl", true)

	assert.NoError(t, err)
}
