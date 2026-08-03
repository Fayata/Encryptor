package security

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SecureBuffer holds sensitive data (keys, passwords) in protected memory.
// It locks the memory to prevent swapping to disk, and zeros it on destroy.
type SecureBuffer struct {
	data    []byte
	size    int
	locked  bool
	mu      sync.Mutex
	destroyed bool
}

// NewSecureBuffer creates a new secure buffer with the given data.
// The data is copied into the buffer and the original should be zeroed by the caller.
func NewSecureBuffer(data []byte) *SecureBuffer {
	sb := &SecureBuffer{
		data: make([]byte, len(data)),
		size: len(data),
	}
	copy(sb.data, data)

	// Lock the memory to prevent it from being swapped to disk
	sb.lockMemory()

	// Set a finalizer to ensure the buffer is destroyed when garbage collected
	runtime.SetFinalizer(sb, func(b *SecureBuffer) {
		b.Destroy()
	})

	return sb
}

// NewSecureBufferSize creates an empty secure buffer of the given size.
func NewSecureBufferSize(size int) *SecureBuffer {
	sb := &SecureBuffer{
		data: make([]byte, size),
		size: size,
	}
	sb.lockMemory()
	runtime.SetFinalizer(sb, func(b *SecureBuffer) {
		b.Destroy()
	})
	return sb
}

// Bytes returns the raw bytes. Use with caution — do not store references.
func (sb *SecureBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.destroyed {
		return nil
	}
	return sb.data
}

// Size returns the buffer size.
func (sb *SecureBuffer) Size() int {
	return sb.size
}

// Destroy securely wipes and unlocks the buffer.
func (sb *SecureBuffer) Destroy() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.destroyed {
		return
	}

	// Overwrite with random data first, then zeros (defense in depth)
	if len(sb.data) > 0 {
		rand.Read(sb.data)
		for i := range sb.data {
			sb.data[i] = 0
		}
	}

	// Unlock the memory
	sb.unlockMemory()

	sb.data = nil
	sb.destroyed = true
}

// lockMemory locks the buffer's memory pages to prevent swapping to disk.
func (sb *SecureBuffer) lockMemory() {
	if len(sb.data) == 0 {
		return
	}

	err := windows.VirtualLock(uintptr(unsafe.Pointer(&sb.data[0])), uintptr(len(sb.data)))
	if err == nil {
		sb.locked = true
	}
	// If VirtualLock fails (e.g., insufficient privileges), we continue without it
}

// unlockMemory unlocks previously locked memory pages.
func (sb *SecureBuffer) unlockMemory() {
	if !sb.locked || len(sb.data) == 0 {
		return
	}

	windows.VirtualUnlock(uintptr(unsafe.Pointer(&sb.data[0])), uintptr(len(sb.data)))
	sb.locked = false
}

// ZeroBytes securely zeros a byte slice in place.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Prevent compiler from optimizing away the zeroing
	runtime.KeepAlive(b)
}

// ZeroString attempts to zero a string's underlying bytes.
// Note: Go strings are immutable, so this uses unsafe to modify the underlying data.
// This is a best-effort approach — the GC may have already copied the string.
func ZeroString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}

	// Get the underlying byte array of the string using unsafe
	strHeader := (*[2]uintptr)(unsafe.Pointer(s))
	if strHeader[0] == 0 || strHeader[1] == 0 {
		return
	}

	dataPtr := strHeader[0]
	dataLen := strHeader[1]

	// Create a slice header pointing to the string's data
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), dataLen)
	for i := range bytes {
		bytes[i] = 0
	}
	runtime.KeepAlive(s)

	*s = ""
}

// SecureDeriveKey derives a key and returns it in a SecureBuffer.
// The intermediate key material is zeroed after being copied to the secure buffer.
func SecureDeriveKey(deriveFunc func() []byte) *SecureBuffer {
	key := deriveFunc()
	sb := NewSecureBuffer(key)
	ZeroBytes(key) // Zero the original key
	return sb
}

// String returns a masked representation for logging (never shows actual data).
func (sb *SecureBuffer) String() string {
	if sb.destroyed {
		return "[DESTROYED]"
	}
	return fmt.Sprintf("[SECURE:%d bytes]", sb.size)
}
