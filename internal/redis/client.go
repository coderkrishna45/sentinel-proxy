package redis

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/kayden-vs/sentinel-proxy/internal/config"
	"github.com/redis/go-redis/v9"
)
//We use structured "blueprints" to separate who a user is from what they are doing.
type Client struct {
	rdb                 *redis.Client
	windowSize          time.Duration
	blendWeightWindow   float64
	blendWeightLifetime float64
}

type BehaviorStats struct {
	TotalBytesInWindow int64   `json:"total_bytes_in_window"`
	RequestCount       int64   `json:"request_count"`
	AverageBytes       float64 `json:"average_bytes"`
	AverageRateBPS     float64 `json:"average_rate_bps"`
	LastRequestTime    int64   `json:"last_request_time"`
	IsNewUser          bool    `json:"is_new_user"`
}

type ViolationRecord struct {
	Count          int   `json:"count"`
	FirstViolation int64 `json:"first_violation"`
	LastViolation  int64 `json:"last_violation"`
}
//The NewClient function checks the system is healthy before it starts.
func NewClient(cfg config.RedisConfig) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	blendW := cfg.BlendWeightWindow
	blendL := cfg.BlendWeightLifetime
	if blendW <= 0 && blendL <= 0 {
		blendW, blendL = 0.7, 0.3 // sensible defaults if not configured
	}

	return &Client{
		rdb:                 rdb,
		windowSize:          cfg.WindowSize,
		blendWeightWindow:   blendW,
		blendWeightLifetime: blendL,
	}, nil
}
// this function tracks every byte of data going out of the network.
func (c *Client) RecordRequest(ctx context.Context, userID string, byteCount int64) (*BehaviorStats, error) {
	now := time.Now()
	nowUnix := now.UnixMilli()
	windowStart := now.Add(-c.windowSize).UnixMilli()

	bytesKey := fmt.Sprintf("user:%s:bytes", userID)
	sumKey := fmt.Sprintf("user:%s:sum", userID)
	countKey := fmt.Sprintf("user:%s:count", userID)

	pipe := c.rdb.Pipeline()

	member := fmt.Sprintf("%d:%d", nowUnix, byteCount)
	pipe.ZAdd(ctx, bytesKey, redis.Z{
		Score:  float64(nowUnix),
		Member: member,
	})

	pipe.ZRemRangeByScore(ctx, bytesKey, "-inf", strconv.FormatInt(windowStart, 10))

	// for safety : we will prevent unbounded set growth which is sorted and will keep last 1000 enties.
	pipe.ZRemRangeByRank(ctx, bytesKey, 0, -1001)

	pipe.IncrBy(ctx, sumKey, byteCount)
	pipe.Incr(ctx, countKey)

	ttl := c.windowSize + 10*time.Minute
	pipe.Expire(ctx, bytesKey, ttl)
	pipe.Expire(ctx, sumKey, ttl)
	pipe.Expire(ctx, countKey, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis pipeline exec: %w", err)
	}

	return c.GetBehaviorStats(ctx, userID)
}
// LUA
// this  helps improving  speed by sending data in a single trip rather than 6 7 times with help of pipelining
var behaviorStatsScript = redis.NewScript(`
local bytesKey = KEYS[1]
local sumKey = KEYS[2]
local countKey = KEYS[3]
local windowStart = ARGV[1]

local entries = redis.call('ZRANGEBYSCORE', bytesKey, windowStart, '+inf', 'WITHSCORES')
local windowBytes = 0
local windowCount = 0
local minTs = 0
local maxTs = 0

for i = 1, #entries, 2 do
    local member = entries[i]
    local score = tonumber(entries[i+1])
    windowCount = windowCount + 1
    local colonPos = 0
    for j = #member, 1, -1 do
        if string.byte(member, j) == 58 then
            colonPos = j
            break
        end
    end
    if colonPos > 0 then
        local bytes = tonumber(string.sub(member, colonPos + 1))
        if bytes then windowBytes = windowBytes + bytes end
    end
    if score then
        if minTs == 0 or score < minTs then minTs = score end
        if score > maxTs then maxTs = score end
    end
end

local lifetimeSum = tonumber(redis.call('GET', sumKey) or '0') or 0
local lifetimeCount = tonumber(redis.call('GET', countKey) or '0') or 0
return {windowBytes, windowCount, minTs, maxTs, lifetimeSum, lifetimeCount}
`)

func (c *Client) GetBehaviorStats(ctx context.Context, userID string) (*BehaviorStats, error) {
	now := time.Now()
	windowStart := now.Add(-c.windowSize).UnixMilli()

	bytesKey := fmt.Sprintf("user:%s:bytes", userID)
	sumKey := fmt.Sprintf("user:%s:sum", userID)
	countKey := fmt.Sprintf("user:%s:count", userID)

	// Execute Lua script in (O(1) network transfer)
	raw, err := behaviorStatsScript.Run(ctx, c.rdb,
		[]string{bytesKey, sumKey, countKey},
		strconv.FormatInt(windowStart, 10),
	).Int64Slice()
	if err != nil {
		// if Lua script fails  return to  safe defaults
		return &BehaviorStats{IsNewUser: true}, fmt.Errorf("behavior stats script: %w", err)
	}

	if len(raw) < 6 {
		return &BehaviorStats{IsNewUser: true}, nil
	}

	windowBytes := raw[0]
	windowCount := raw[1]
	minTimestamp := raw[2]
	maxTimestamp := raw[3]
	lifetimeSum := raw[4]
	lifetimeCount := raw[5]

	stats := &BehaviorStats{}

	if windowCount == 0 {
		stats.IsNewUser = true
		return stats, nil
	}

	stats.TotalBytesInWindow = windowBytes
	stats.RequestCount = windowCount
	stats.LastRequestTime = maxTimestamp

	windowedAvg := float64(windowBytes) / float64(windowCount)
	stats.AverageBytes = windowedAvg

	if maxTimestamp > minTimestamp {
		durationSec := float64(maxTimestamp-minTimestamp) / 1000.0
		if durationSec > 0 {
			stats.AverageRateBPS = float64(windowBytes) / durationSec
		}
	}

	if lifetimeCount > 0 {
		lifetimeAvg := float64(lifetimeSum) / float64(lifetimeCount)
		stats.AverageBytes = (c.blendWeightWindow * windowedAvg) + (c.blendWeightLifetime * lifetimeAvg)
	}

	return stats, nil
}

func (c *Client) GetViolationCount(ctx context.Context, userID string, windowSec int) (*ViolationRecord, error) {
	key := fmt.Sprintf("user:%s:violations", userID)

	pipe := c.rdb.Pipeline()
	countCmd := pipe.Get(ctx, key)
	firstCmd := pipe.Get(ctx, key+":first")
	lastCmd := pipe.Get(ctx, key+":last")

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("get violations: %w", err)
	}

	record := &ViolationRecord{}

	if count, err := countCmd.Int(); err == nil {
		record.Count = count
	}
	if first, err := firstCmd.Int64(); err == nil {
		record.FirstViolation = first
	}
	if last, err := lastCmd.Int64(); err == nil {
		record.LastViolation = last
	}

	if record.FirstViolation > 0 {
		windowExpiry := record.FirstViolation + int64(windowSec)
		if time.Now().Unix() > windowExpiry {
			c.ResetViolations(ctx, userID)
			return &ViolationRecord{}, nil
		}
	}

	return record, nil
}

func (c *Client) IncrementViolation(ctx context.Context, userID string, windowSec int) (*ViolationRecord, error) {
	key := fmt.Sprintf("user:%s:violations", userID)
	now := time.Now().Unix()
	ttl := time.Duration(windowSec) * time.Second

	pipe := c.rdb.Pipeline()

	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)

	pipe.SetNX(ctx, key+":first", now, ttl)
	pipe.Expire(ctx, key+":first", ttl)

	pipe.Set(ctx, key+":last", now, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("increment violation: %w", err)
	}

	count, _ := incrCmd.Result()

	return &ViolationRecord{
		Count:         int(count),
		LastViolation: now,
	}, nil
}

func (c *Client) ResetViolations(ctx context.Context, userID string) error {
	key := fmt.Sprintf("user:%s:violations", userID)
	pipe := c.rdb.Pipeline()
	pipe.Del(ctx, key)
	pipe.Del(ctx, key+":first")
	pipe.Del(ctx, key+":last")
	_, err := pipe.Exec(ctx)
	return err
}

func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

func (c *Client) Close() error {
	return c.rdb.Close()
}

func splitMember(s string) []string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}
