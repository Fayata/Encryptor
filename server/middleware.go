package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════
//  SECURITY HEADERS MIDDLEWARE (A05)
// ═══════════════════════════════════════════════

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME-type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// Legacy XSS filter
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Disable dangerous browser features
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		
		// Prevent caching of sensitive pages
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
		}

		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Token, X-CSRF-Token")
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        next.ServeHTTP(w, r)
    })
}

// ═══════════════════════════════════════════════
//  RATE LIMITER (A04, A07)
// ═══════════════════════════════════════════════

type rateLimitEntry struct {
	count    int
	firstHit time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
	limit   int
	window  time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		entries: make(map[string]*rateLimitEntry),
		limit:   limit,
		window:  window,
	}
	// Background cleanup of stale entries every 10 minutes
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for key, entry := range rl.entries {
		if now.Sub(entry.firstHit) > rl.window {
			delete(rl.entries, key)
		}
	}
}

func (rl *rateLimiter) isAllowed(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.entries[key]

	if !exists || now.Sub(entry.firstHit) > rl.window {
		rl.entries[key] = &rateLimitEntry{count: 1, firstHit: now}
		return true
	}

	entry.count++
	return entry.count <= rl.limit
}

// Rate limit middleware for specific endpoints
func rateLimitMiddleware(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
		key := fmt.Sprintf("%s:%s", ip, r.URL.Path)

		if !rl.isAllowed(key) {
			logSecurityEvent("WARN", EventRateLimited, ip, fmt.Sprintf("path=%s", r.URL.Path))
			http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ═══════════════════════════════════════════════
//  REQUEST BODY SIZE LIMITER (A04)
// ═══════════════════════════════════════════════

const maxBodySize = 1 << 20 // 1 MB

func limitBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		}
		next(w, r)
	}
}

// ═══════════════════════════════════════════════
//  CSRF PROTECTION (A01, A08)
// ═══════════════════════════════════════════════

type csrfManager struct {
	mu     sync.RWMutex
	tokens map[string]time.Time // token -> expiry
}

func newCSRFManager() *csrfManager {
	cm := &csrfManager{
		tokens: make(map[string]time.Time),
	}
	// Cleanup expired tokens every 15 minutes
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cm.cleanup()
		}
	}()
	return cm
}

func (cm *csrfManager) cleanup() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	now := time.Now()
	for token, expiry := range cm.tokens {
		if now.After(expiry) {
			delete(cm.tokens, token)
		}
	}
}

func (cm *csrfManager) generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	cm.mu.Lock()
	cm.tokens[token] = time.Now().Add(2 * time.Hour) // 2-hour validity
	cm.mu.Unlock()

	return token
}

func (cm *csrfManager) validateToken(token string) bool {
	if token == "" {
		return false
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	expiry, exists := cm.tokens[token]
	if !exists {
		return false
	}

	// Token is single-use: delete after validation
	delete(cm.tokens, token)

	return time.Now().Before(expiry)
}
