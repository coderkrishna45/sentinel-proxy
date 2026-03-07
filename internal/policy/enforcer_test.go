package policy

import (
"testing"

"github.com/kayden-vs/sentinel-proxy/internal/config"
)

func TestGradeFromCount(t *testing.T) {
	cfg := config.GraceConfig{
		ViolationWindowSec: 300,
		LogOnlyCount:       1,
		ThrottleCount:      2,
		TerminateCount:     3,
	}

	e := &Enforcer{cfg: cfg}

	tests := []struct {
		count    int
		expected EnforcementGrade
	}{
		{0, GradeAllow},
		{1, GradeLogOnly},
		{2, GradeThrottle},
		{3, GradeTerminate},
		{5, GradeTerminate},
	}

	for _, tt := range tests {
		got := e.gradeFromCount(tt.count)
		if got != tt.expected {
			t.Errorf("gradeFromCount(%d) = %s, want %s", tt.count, got, tt.expected)
		}
	}
}

func TestGradeString(t *testing.T) {
	tests := []struct {
		grade    EnforcementGrade
		expected string
	}{
		{GradeAllow, "allow"},
		{GradeLogOnly, "log_only"},
		{GradeThrottle, "throttle"},
		{GradeTerminate, "terminate"},
	}

	for _, tt := range tests {
		if got := tt.grade.String(); got != tt.expected {
			t.Errorf("grade %d String() = %s, want %s", tt.grade, got, tt.expected)
		}
	}
}

func TestIsBypassed(t *testing.T) {
	if IsBypassed("", "", "") {
		t.Error("should not bypass with empty config")
	}
	if IsBypassed("X-Bypass", "secret", "wrong") {
		t.Error("should not bypass with wrong token")
	}
	if !IsBypassed("X-Bypass", "secret", "secret") {
		t.Error("should bypass with correct token")
	}
}