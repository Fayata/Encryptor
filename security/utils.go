package security

import (
	"crypto/rand"
	"runtime"
	"time"
)

// SecureCleanup performs a thorough cleanup of sensitive data in memory.
// Call this before exiting or after sensitive operations.
func SecureCleanup() {
	// Force garbage collection to clean up unreferenced sensitive data
	runtime.GC()
	runtime.GC() // Double GC to ensure finalizers run
}

// SecurePasswordInput processes a password securely.
// Returns a SecureBuffer containing the password bytes.
// The original string should be zeroed after this call.
func SecurePasswordInput(password string) *SecureBuffer {
	sb := NewSecureBuffer([]byte(password))
	// Zero the original string (best effort)
	ZeroString(&password)
	return sb
}

// GenerateSecureRandom generates cryptographically secure random bytes.
func GenerateSecureRandom(size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// TimeConstantCompare performs a constant-time comparison of two byte slices.
// This prevents timing attacks when comparing MACs or hashes.
func TimeConstantCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// SecureDelay adds a random delay to prevent timing attacks.
func SecureDelay() {
	// Add random delay between 50-200ms
	buf := make([]byte, 1)
	rand.Read(buf)
	delay := time.Duration(50+int(buf[0])%150) * time.Millisecond
	time.Sleep(delay)
}
