package httpapi

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func limiterForTest(t *testing.T, mutate func(*loginLimiterConfig)) *LoginLimiter {
	t.Helper()
	config := loginLimiterConfig{
		perClientCapacity: 2,
		perClientRefill:   10 * time.Second,
		globalCapacity:    100,
		globalRefill:      time.Second,
		maximumClients:    8,
		clientIdleExpiry:  time.Minute,
		maximumKDFWorkers: 2,
	}
	if mutate != nil {
		mutate(&config)
	}
	limiter, err := newLoginLimiter(config)
	if err != nil {
		t.Fatalf("newLoginLimiter() error = %v", err)
	}
	return limiter
}

func TestLoginLimiterEnforcesPerClientBurstAndRefill(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, nil)
	client := netip.MustParseAddr("198.51.100.10")
	now := time.Unix(1_700_000_000, 0)
	for attempt := 0; attempt < 2; attempt++ {
		if allowed, wait := limiter.Allow(client, now); !allowed || wait != 0 {
			t.Fatalf("attempt %d = (%v, %v), want allowed", attempt, allowed, wait)
		}
	}
	if allowed, wait := limiter.Allow(client, now); allowed || wait != 10*time.Second {
		t.Fatalf("exhausted attempt = (%v, %v), want false and 10s", allowed, wait)
	}
	if allowed, wait := limiter.Allow(client, now.Add(5*time.Second)); allowed || wait != 5*time.Second {
		t.Fatalf("half refill = (%v, %v), want false and 5s", allowed, wait)
	}
	if allowed, wait := limiter.Allow(client, now.Add(10*time.Second)); !allowed || wait != 0 {
		t.Fatalf("full refill = (%v, %v), want allowed", allowed, wait)
	}
}

func TestLoginLimiterEnforcesGlobalBoundAcrossClients(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, func(config *loginLimiterConfig) {
		config.globalCapacity = 2
		config.globalRefill = 3 * time.Second
	})
	now := time.Unix(1_700_000_000, 0)
	for _, address := range []string{"198.51.100.1", "198.51.100.2"} {
		if allowed, _ := limiter.Allow(netip.MustParseAddr(address), now); !allowed {
			t.Fatalf("Allow(%s) = false", address)
		}
	}
	if allowed, wait := limiter.Allow(netip.MustParseAddr("198.51.100.3"), now); allowed || wait != 3*time.Second {
		t.Fatalf("global exhaustion = (%v, %v), want false and 3s", allowed, wait)
	}
}

func TestLoginLimiterNormalizesIPv6ClientsToPrefix(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, func(config *loginLimiterConfig) { config.perClientCapacity = 1 })
	now := time.Unix(1_700_000_000, 0)
	if allowed, _ := limiter.Allow(netip.MustParseAddr("2001:db8:1:2::1"), now); !allowed {
		t.Fatal("first IPv6 address was not allowed")
	}
	if allowed, _ := limiter.Allow(netip.MustParseAddr("2001:db8:1:2::ffff"), now); allowed {
		t.Fatal("same IPv6 /64 received a separate bucket")
	}
	if allowed, _ := limiter.Allow(netip.MustParseAddr("2001:db8:1:3::1"), now); !allowed {
		t.Fatal("different IPv6 /64 did not receive a separate bucket")
	}
}

func TestLoginLimiterUsesBoundedConservativeOverflow(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, func(config *loginLimiterConfig) {
		config.maximumClients = 1
		config.perClientCapacity = 1
	})
	now := time.Unix(1_700_000_000, 0)
	if allowed, _ := limiter.Allow(netip.MustParseAddr("198.51.100.1"), now); !allowed {
		t.Fatal("first client was not allowed")
	}
	if allowed, _ := limiter.Allow(netip.MustParseAddr("198.51.100.2"), now); !allowed {
		t.Fatal("first overflow client was not allowed")
	}
	if allowed, _ := limiter.Allow(netip.MustParseAddr("198.51.100.3"), now); allowed {
		t.Fatal("overflow clients did not share a conservative bucket")
	}
	if len(limiter.clients) != 1 {
		t.Fatalf("client map size = %d, want 1", len(limiter.clients))
	}
}

func TestLoginLimiterExpiresOnlyIdleClients(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, func(config *loginLimiterConfig) {
		config.maximumClients = 1
		config.clientIdleExpiry = 20 * time.Second
	})
	now := time.Unix(1_700_000_000, 0)
	first := netip.MustParseAddr("198.51.100.1")
	second := netip.MustParseAddr("198.51.100.2")
	if allowed, _ := limiter.Allow(first, now); !allowed {
		t.Fatal("first client was not allowed")
	}
	if allowed, _ := limiter.Allow(second, now.Add(20*time.Second)); !allowed {
		t.Fatal("new client was not admitted after idle expiry")
	}
	if _, exists := limiter.clients[loginClientKey(second)]; !exists {
		t.Fatalf("new client was not stored after idle expiry: %v", limiter.clients)
	}
}

func TestLoginLimiterClockRollbackDoesNotRefill(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, func(config *loginLimiterConfig) { config.perClientCapacity = 1 })
	client := netip.MustParseAddr("198.51.100.10")
	now := time.Unix(1_700_000_000, 0)
	if allowed, _ := limiter.Allow(client, now); !allowed {
		t.Fatal("first attempt was not allowed")
	}
	if allowed, _ := limiter.Allow(client, now.Add(-time.Hour)); allowed {
		t.Fatal("clock rollback refilled a client bucket")
	}
}

func TestLoginLimiterBoundsConcurrentPasswordVerification(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, nil)
	firstRelease, firstAllowed := limiter.TryAcquireKDF()
	secondRelease, secondAllowed := limiter.TryAcquireKDF()
	if !firstAllowed || !secondAllowed {
		t.Fatal("expected two KDF worker admissions")
	}
	if release, allowed := limiter.TryAcquireKDF(); allowed || release != nil {
		t.Fatal("third KDF worker was admitted")
	}
	firstRelease()
	firstRelease()
	if thirdRelease, allowed := limiter.TryAcquireKDF(); !allowed {
		t.Fatal("KDF worker was not admitted after release")
	} else {
		thirdRelease()
	}
	secondRelease()
}

func TestLoginLimiterConcurrentAdmissionCannotExceedBurst(t *testing.T) {
	t.Parallel()

	limiter := limiterForTest(t, func(config *loginLimiterConfig) {
		config.perClientCapacity = 5
		config.globalCapacity = 5
	})
	client := netip.MustParseAddr("198.51.100.10")
	now := time.Unix(1_700_000_000, 0)
	var admitted atomic.Int32
	var workers sync.WaitGroup
	for range 50 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if allowed, _ := limiter.Allow(client, now); allowed {
				admitted.Add(1)
			}
		}()
	}
	workers.Wait()
	if got := admitted.Load(); got != 5 {
		t.Fatalf("admitted = %d, want 5", got)
	}
}

func TestLoginLimiterRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := newLoginLimiter(loginLimiterConfig{}); err == nil {
		t.Fatal("newLoginLimiter(zero config) error = nil")
	}
}
