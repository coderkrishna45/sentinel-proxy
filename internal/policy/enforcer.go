package policy

import (
	"context"

	"github.com/kayden-vs/sentinel-proxy/internal/config"
	redisclient "github.com/kayden-vs/sentinel-proxy/internal/redis"
)

type EnforcementGrade int

const (
	GradeAllow EnforcementGrade = iota
	GradeLogOnly
	GradeThrottle
	GradeTerminate
)

func (g EnforcementGrade) String() string {
	switch g {
	case GradeAllow:
		return "allow"
	case GradeLogOnly:
		return "log_only"
	case GradeThrottle:
		return "throttle"
	case GradeTerminate:
		return "terminate"
	default:
		return "unknown"
	}
}

type Enforcer struct {
	redis *redisclient.FailOpenClient
	cfg   config.GraceConfig
}

func NewEnforcer(redis *redisclient.FailOpenClient, cfg config.GraceConfig) *Enforcer {
	return &Enforcer{
		redis: redis,
		cfg:   cfg,
	}
}

func (e *Enforcer) Evaluate(ctx context.Context, userID string) (EnforcementGrade, *redisclient.ViolationRecord, error) {
	record, err := e.redis.GetViolationCount(ctx, userID, e.cfg.ViolationWindowSec)
	if err != nil {
		return GradeLogOnly, &redisclient.ViolationRecord{Count: 1}, nil
	}

	record, err = e.redis.IncrementViolation(ctx, userID, e.cfg.ViolationWindowSec)
	if err != nil {
		return GradeLogOnly, &redisclient.ViolationRecord{Count: 1}, nil
	}

	return e.gradeFromCount(record.Count), record, nil
}

func (e *Enforcer) gradeFromCount(count int) EnforcementGrade {
	if count <= 0 {
		return GradeAllow
	}
	if count <= e.cfg.LogOnlyCount {
		return GradeLogOnly
	}
	if count <= e.cfg.ThrottleCount {
		return GradeThrottle
	}
	return GradeTerminate
}

func IsBypassed(bypassHeader, bypassSecret, headerValue string) bool {
	if bypassHeader == "" || bypassSecret == "" {
		return false
	}
	return headerValue == bypassSecret
}
