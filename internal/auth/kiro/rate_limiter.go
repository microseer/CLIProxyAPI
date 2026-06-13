package kiro

import (
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMinTokenInterval  = 1 * time.Second
	DefaultMaxTokenInterval  = 2 * time.Second
	DefaultDailyMaxRequests  = 500
	DefaultJitterPercent     = 0.3
	DefaultBackoffBase       = 30 * time.Second
	DefaultBackoffMax        = 5 * time.Minute
	DefaultBackoffMultiplier = 1.5
	DefaultSuspendCooldown   = 1 * time.Hour
)

// TokenState represents the state of a token for rate limiting.
type TokenState struct {
	LastRequest    time.Time
	RequestCount   int
	CooldownEnd    time.Time
	FailCount      int
	DailyRequests  int
	DailyResetTime time.Time
	IsSuspended    bool
	SuspendedAt    time.Time
	SuspendReason  string
}

// RateLimiter is a frequency-based rate limiter.
type RateLimiter struct {
	mu                sync.RWMutex
	states            map[string]*TokenState
	minTokenInterval  time.Duration
	maxTokenInterval  time.Duration
	dailyMaxRequests  int
	jitterPercent     float64
	backoffBase       time.Duration
	backoffMax        time.Duration
	backoffMultiplier float64
	suspendCooldown   time.Duration
	rng               *rand.Rand
}

// NewRateLimiter creates a rate limiter with default configuration.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		states:            make(map[string]*TokenState),
		minTokenInterval:  DefaultMinTokenInterval,
		maxTokenInterval:  DefaultMaxTokenInterval,
		dailyMaxRequests:  DefaultDailyMaxRequests,
		jitterPercent:     DefaultJitterPercent,
		backoffBase:       DefaultBackoffBase,
		backoffMax:        DefaultBackoffMax,
		backoffMultiplier: DefaultBackoffMultiplier,
		suspendCooldown:   DefaultSuspendCooldown,
		rng:               rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// RateLimiterConfig holds configuration for the rate limiter.
type RateLimiterConfig struct {
	MinTokenInterval  time.Duration
	MaxTokenInterval  time.Duration
	DailyMaxRequests  int
	JitterPercent     float64
	BackoffBase       time.Duration
	BackoffMax        time.Duration
	BackoffMultiplier float64
	SuspendCooldown   time.Duration
}

// NewRateLimiterWithConfig creates a rate limiter with custom configuration.
func NewRateLimiterWithConfig(cfg RateLimiterConfig) *RateLimiter {
	rl := NewRateLimiter()
	if cfg.MinTokenInterval > 0 {
		rl.minTokenInterval = cfg.MinTokenInterval
	}
	if cfg.MaxTokenInterval > 0 {
		rl.maxTokenInterval = cfg.MaxTokenInterval
	}
	if cfg.DailyMaxRequests > 0 {
		rl.dailyMaxRequests = cfg.DailyMaxRequests
	}
	if cfg.JitterPercent > 0 {
		rl.jitterPercent = cfg.JitterPercent
	}
	if cfg.BackoffBase > 0 {
		rl.backoffBase = cfg.BackoffBase
	}
	if cfg.BackoffMax > 0 {
		rl.backoffMax = cfg.BackoffMax
	}
	if cfg.BackoffMultiplier > 0 {
		rl.backoffMultiplier = cfg.BackoffMultiplier
	}
	if cfg.SuspendCooldown > 0 {
		rl.suspendCooldown = cfg.SuspendCooldown
	}
	return rl
}

// getOrCreateState retrieves or creates a Token state entry.
func (rl *RateLimiter) getOrCreateState(tokenKey string) *TokenState {
	state, exists := rl.states[tokenKey]
	if !exists {
		state = &TokenState{
			DailyResetTime: time.Now().Truncate(24 * time.Hour).Add(24 * time.Hour),
		}
		rl.states[tokenKey] = state
	}
	return state
}

// resetDailyIfNeeded resets the daily counter if needed.
func (rl *RateLimiter) resetDailyIfNeeded(state *TokenState) {
	now := time.Now()
	if now.After(state.DailyResetTime) {
		state.DailyRequests = 0
		state.DailyResetTime = now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	}
}

// calculateInterval computes a random interval with jitter.
func (rl *RateLimiter) calculateInterval() time.Duration {
	baseInterval := rl.minTokenInterval + time.Duration(rl.rng.Int63n(int64(rl.maxTokenInterval-rl.minTokenInterval)))
	jitter := time.Duration(float64(baseInterval) * rl.jitterPercent * (rl.rng.Float64()*2 - 1))
	return baseInterval + jitter
}

// WaitForToken blocks until the token is available (random interval with jitter).
func (rl *RateLimiter) WaitForToken(tokenKey string) {
	rl.mu.Lock()
	state := rl.getOrCreateState(tokenKey)
	rl.resetDailyIfNeeded(state)

	now := time.Now()

	// Check if in cooldown period
	if now.Before(state.CooldownEnd) {
		waitTime := state.CooldownEnd.Sub(now)
		rl.mu.Unlock()
		time.Sleep(waitTime)
		rl.mu.Lock()
		state = rl.getOrCreateState(tokenKey)
		now = time.Now()
	}

	// Calculate interval since last request
	interval := rl.calculateInterval()
	nextAllowedTime := state.LastRequest.Add(interval)

	if now.Before(nextAllowedTime) {
		waitTime := nextAllowedTime.Sub(now)
		rl.mu.Unlock()
		time.Sleep(waitTime)
		rl.mu.Lock()
		state = rl.getOrCreateState(tokenKey)
	}

	state.LastRequest = time.Now()
	state.RequestCount++
	state.DailyRequests++
	rl.mu.Unlock()
}

// MarkTokenFailed marks a token as failed.
func (rl *RateLimiter) MarkTokenFailed(tokenKey string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	state := rl.getOrCreateState(tokenKey)
	state.FailCount++
	state.CooldownEnd = time.Now().Add(rl.calculateBackoff(state.FailCount))
}

// MarkTokenSuccess marks a token as successful.
func (rl *RateLimiter) MarkTokenSuccess(tokenKey string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	state := rl.getOrCreateState(tokenKey)
	state.FailCount = 0
	state.CooldownEnd = time.Time{}
}

// CheckAndMarkSuspended detects suspension errors and marks the token accordingly.
func (rl *RateLimiter) CheckAndMarkSuspended(tokenKey string, errorMsg string) bool {
	suspendKeywords := []string{
		"suspended",
		"banned",
		"disabled",
		"account has been",
		"access denied",
		"rate limit exceeded",
		"too many requests",
		"quota exceeded",
	}

	lowerMsg := strings.ToLower(errorMsg)
	for _, keyword := range suspendKeywords {
		if strings.Contains(lowerMsg, keyword) {
			rl.mu.Lock()
			defer rl.mu.Unlock()

			state := rl.getOrCreateState(tokenKey)
			state.IsSuspended = true
			state.SuspendedAt = time.Now()
			state.SuspendReason = errorMsg
			state.CooldownEnd = time.Now().Add(rl.suspendCooldown)
			return true
		}
	}
	return false
}

// IsTokenAvailable checks whether a token is available.
func (rl *RateLimiter) IsTokenAvailable(tokenKey string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	state, exists := rl.states[tokenKey]
	if !exists {
		return true
	}

	now := time.Now()

	// Check if suspended
	if state.IsSuspended {
		if now.After(state.SuspendedAt.Add(rl.suspendCooldown)) {
			return true
		}
		return false
	}

	// Check if in cooldown period
	if now.Before(state.CooldownEnd) {
		return false
	}

	// Check daily request limit
	rl.mu.RUnlock()
	rl.mu.Lock()
	rl.resetDailyIfNeeded(state)
	dailyRequests := state.DailyRequests
	dailyMax := rl.dailyMaxRequests
	rl.mu.Unlock()
	rl.mu.RLock()

	if dailyRequests >= dailyMax {
		return false
	}

	return true
}

// calculateBackoff computes exponential backoff duration.
func (rl *RateLimiter) calculateBackoff(failCount int) time.Duration {
	if failCount <= 0 {
		return 0
	}

	backoff := float64(rl.backoffBase) * math.Pow(rl.backoffMultiplier, float64(failCount-1))

	// Add jitter
	jitter := backoff * rl.jitterPercent * (rl.rng.Float64()*2 - 1)
	backoff += jitter

	if time.Duration(backoff) > rl.backoffMax {
		return rl.backoffMax
	}
	return time.Duration(backoff)
}

// GetTokenState returns a read-only copy of the token state.
func (rl *RateLimiter) GetTokenState(tokenKey string) *TokenState {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	state, exists := rl.states[tokenKey]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modification
	stateCopy := *state
	return &stateCopy
}

// ClearTokenState clears the token state.
func (rl *RateLimiter) ClearTokenState(tokenKey string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.states, tokenKey)
}

// ResetSuspension resets the suspension state of a token.
func (rl *RateLimiter) ResetSuspension(tokenKey string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	state, exists := rl.states[tokenKey]
	if exists {
		state.IsSuspended = false
		state.SuspendedAt = time.Time{}
		state.SuspendReason = ""
		state.CooldownEnd = time.Time{}
		state.FailCount = 0
	}
}
