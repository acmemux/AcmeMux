package httpapi

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	defaultPerClientCapacity = 5
	defaultPerClientRefill   = 30 * time.Second
	defaultGlobalCapacity    = 20
	defaultGlobalRefill      = 3 * time.Second
	defaultMaximumClients    = 1024
	defaultClientIdleExpiry  = 15 * time.Minute
	defaultMaximumKDFWorkers = 2
)

type loginLimiterConfig struct {
	perClientCapacity int
	perClientRefill   time.Duration
	globalCapacity    int
	globalRefill      time.Duration
	maximumClients    int
	clientIdleExpiry  time.Duration
	maximumKDFWorkers int
}

// LoginLimiter bounds password-verification admission globally and per
// normalized client identity. Its state is deliberately process-local.
type LoginLimiter struct {
	mutex      sync.Mutex
	config     loginLimiterConfig
	global     tokenBucket
	clients    map[string]*clientLimit
	overflow   clientLimit
	kdfWorkers chan struct{}
}

type clientLimit struct {
	bucket   tokenBucket
	lastSeen time.Time
}

type tokenBucket struct {
	tokens      float64
	lastRefill  time.Time
	initialized bool
}

// NewLoginLimiter returns the production login limiter.
func NewLoginLimiter() *LoginLimiter {
	limiter, err := newLoginLimiter(loginLimiterConfig{
		perClientCapacity: defaultPerClientCapacity,
		perClientRefill:   defaultPerClientRefill,
		globalCapacity:    defaultGlobalCapacity,
		globalRefill:      defaultGlobalRefill,
		maximumClients:    defaultMaximumClients,
		clientIdleExpiry:  defaultClientIdleExpiry,
		maximumKDFWorkers: defaultMaximumKDFWorkers,
	})
	if err != nil {
		panic(err)
	}
	return limiter
}

func newLoginLimiter(config loginLimiterConfig) (*LoginLimiter, error) {
	if config.perClientCapacity <= 0 || config.perClientRefill <= 0 || config.globalCapacity <= 0 || config.globalRefill <= 0 || config.maximumClients <= 0 || config.clientIdleExpiry <= 0 || config.maximumKDFWorkers <= 0 {
		return nil, errors.New("login limiter configuration values must be positive")
	}
	return &LoginLimiter{
		config:     config,
		clients:    make(map[string]*clientLimit, config.maximumClients),
		kdfWorkers: make(chan struct{}, config.maximumKDFWorkers),
	}, nil
}

// Allow consumes one global and one per-client token. It returns a bounded
// wait when either bucket has no token. A clock rollback never refills tokens.
func (limiter *LoginLimiter) Allow(clientIP netip.Addr, now time.Time) (bool, time.Duration) {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()

	limiter.expireIdleClients(now)
	client := limiter.clientBucket(clientIP, now)
	globalTokens, globalWait := limiter.global.available(now, limiter.config.globalCapacity, limiter.config.globalRefill)
	clientTokens, clientWait := client.bucket.available(now, limiter.config.perClientCapacity, limiter.config.perClientRefill)
	client.lastSeen = monotonicLatest(client.lastSeen, now)
	if globalTokens < 1 || clientTokens < 1 {
		if clientWait > globalWait {
			globalWait = clientWait
		}
		if globalWait < time.Second {
			globalWait = time.Second
		}
		return false, globalWait
	}
	limiter.global.tokens--
	client.bucket.tokens--
	return true, 0
}

// TryAcquireKDF reserves one of the bounded concurrent password-verification
// slots. The returned release function is safe to call more than once.
func (limiter *LoginLimiter) TryAcquireKDF() (func(), bool) {
	select {
	case limiter.kdfWorkers <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-limiter.kdfWorkers })
		}, true
	default:
		return nil, false
	}
}

func (limiter *LoginLimiter) clientBucket(clientIP netip.Addr, now time.Time) *clientLimit {
	key := loginClientKey(clientIP)
	if client, exists := limiter.clients[key]; exists {
		return client
	}
	if len(limiter.clients) >= limiter.config.maximumClients {
		limiter.overflow.lastSeen = monotonicLatest(limiter.overflow.lastSeen, now)
		return &limiter.overflow
	}
	client := &clientLimit{lastSeen: now}
	limiter.clients[key] = client
	return client
}

func (limiter *LoginLimiter) expireIdleClients(now time.Time) {
	for key, client := range limiter.clients {
		if !now.Before(client.lastSeen) && now.Sub(client.lastSeen) >= limiter.config.clientIdleExpiry {
			delete(limiter.clients, key)
		}
	}
	if !limiter.overflow.lastSeen.IsZero() && !now.Before(limiter.overflow.lastSeen) && now.Sub(limiter.overflow.lastSeen) >= limiter.config.clientIdleExpiry {
		limiter.overflow = clientLimit{}
	}
}

func (bucket *tokenBucket) available(now time.Time, capacity int, refillInterval time.Duration) (float64, time.Duration) {
	if !bucket.initialized {
		bucket.tokens = float64(capacity)
		bucket.lastRefill = now
		bucket.initialized = true
	}
	if now.After(bucket.lastRefill) {
		bucket.tokens += float64(now.Sub(bucket.lastRefill)) / float64(refillInterval)
		if bucket.tokens > float64(capacity) {
			bucket.tokens = float64(capacity)
		}
		bucket.lastRefill = now
	}
	if bucket.tokens >= 1 {
		return bucket.tokens, 0
	}
	missing := 1 - bucket.tokens
	wait := time.Duration(missing * float64(refillInterval))
	if wait <= 0 {
		wait = time.Nanosecond
	}
	return bucket.tokens, wait
}

func loginClientKey(address netip.Addr) string {
	if !address.IsValid() {
		return "unknown"
	}
	address = address.Unmap()
	if address.Is6() && address.IsGlobalUnicast() {
		return netip.PrefixFrom(address, 64).Masked().String()
	}
	return address.String()
}

func monotonicLatest(previous, candidate time.Time) time.Time {
	if previous.IsZero() || candidate.After(previous) {
		return candidate
	}
	return previous
}
