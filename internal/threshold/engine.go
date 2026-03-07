package threshold

import (
	"github.com/kayden-vs/sentinel-proxy/internal/config"
	redisclient "github.com/kayden-vs/sentinel-proxy/internal/redis"
)

type BreachType int

const (
	BreachNone BreachType = iota
	BreachSoft            // Adaptive threshold exceeded
	BreachHard            // Absolute ceiling exceeded
)

func (b BreachType) String() string {
	switch b {
	case BreachSoft:
		return "soft"
	case BreachHard:
		return "hard"
	default:
		return "none"
	}
}

type Decision struct {
	Allowed         int64   `json:"allowed"`
	GlobalFloor     int64   `json:"global_floor"`
	AbsoluteCeiling int64   `json:"absolute_ceiling"`
	HistoricalAvg   float64 `json:"historical_avg"`
	BurstAllowed    float64 `json:"burst_allowed"`
	IsNewUser       bool    `json:"is_new_user"`
	AnomalyDetected bool    `json:"anomaly_detected"`
	Explanation     string  `json:"explanation"`
}

type Engine struct {
	cfg config.ThresholdConfig
}

func NewEngine(cfg config.ThresholdConfig) *Engine {
	return &Engine{cfg: cfg}
}

func (e *Engine) Evaluate(
	stats *redisclient.BehaviorStats,
	endpoint string,
	role string,
	policies config.PoliciesConfig,
	currentRateBPS float64,
) *Decision {
	d := &Decision{
		GlobalFloor:     e.cfg.GlobalFloorBytes,
		AbsoluteCeiling: e.cfg.AbsoluteCeilingBytes,
		HistoricalAvg:   stats.AverageBytes,
		IsNewUser:       stats.IsNewUser,
	}

	floorMult := 1.0
	ceilingMult := 1.0
	burstMult := e.cfg.BurstMultiplier

	if ep, ok := policies.EndpointOverrides[endpoint]; ok {
		floorMult = ep.FloorMultiplier
		ceilingMult = ep.CeilingMultiplier
		if ep.BurstMultiplier > 0 {
			burstMult *= ep.BurstMultiplier
		}
	}

	roleMult := 1.0
	if role != "" {
		if rm, ok := policies.RoleMultipliers[role]; ok {
			roleMult = rm
		}
	}

	effectiveFloor := int64(float64(e.cfg.GlobalFloorBytes) * floorMult * roleMult)
	effectiveCeiling := int64(float64(e.cfg.AbsoluteCeilingBytes) * ceilingMult * roleMult)

	d.GlobalFloor = effectiveFloor
	d.AbsoluteCeiling = effectiveCeiling

	if stats.IsNewUser || stats.RequestCount < int64(e.cfg.MinSamplesForAvg) {
		d.Allowed = effectiveFloor
		d.IsNewUser = true
		d.Explanation = "new user or insufficient history, using global floor"
		return d
	}

	burstAllowed := stats.AverageBytes * burstMult * roleMult
	d.BurstAllowed = burstAllowed

	allowed := effectiveFloor
	if int64(burstAllowed) > allowed {
		allowed = int64(burstAllowed)
	}

	if allowed > effectiveCeiling {
		allowed = effectiveCeiling
	}

	d.Allowed = allowed
	d.Explanation = "adaptive threshold computed from historical average"

	if currentRateBPS > 0 && stats.AverageRateBPS > 0 {
		if currentRateBPS > stats.AverageRateBPS*e.cfg.RateAnomalyFactor {
			d.AnomalyDetected = true
			d.Explanation = "rate anomaly detected: current rate significantly exceeds historical average"
		}
	}

	return d
}

func (e *Engine) ShouldKill(totalBytes int64, decision *Decision) (bool, BreachType, string) {
	// on HARD BREACH - unconditional immediate termination
	if totalBytes > decision.AbsoluteCeiling {
		return true, BreachHard, "absolute ceiling exceeded"
	}

	// on SOFT BREACH - adaptive threshold exceeded
	if totalBytes > decision.Allowed {
		reason := "adaptive threshold exceeded"
		if decision.AnomalyDetected {
			reason += " (with rate anomaly)"
		}
		return true, BreachSoft, reason
	}

	return false, BreachNone, ""
}

func (e *Engine) ShouldThrottle(totalBytes int64, decision *Decision) bool {
	throttlePoint := int64(float64(decision.Allowed) * 0.7)
	return totalBytes > throttlePoint && totalBytes <= decision.Allowed
}
