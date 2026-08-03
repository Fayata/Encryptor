package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Algorithm IDs for the encrypted file header
const (
	AlgoAESGCM    byte = 0x00
	AlgoAESCBC    byte = 0x01
	AlgoChaCha20  byte = 0x02
	AlgoTripleDES byte = 0x03
	AlgoFayCipher byte = 0x04
)

// Argon2id parameters
const (
	Argon2Time    = 1
	Argon2Memory  = 64 * 1024 // 64 MB
	Argon2Threads = 4
	SaltSize      = 16
)

// Encryptor defines the interface for all encryption algorithms.
type Encryptor interface {
	// Encrypt encrypts plaintext using the provided key.
	// Returns ciphertext with nonce/IV prepended.
	Encrypt(plaintext, key []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the provided key.
	// Expects nonce/IV prepended to ciphertext.
	Decrypt(ciphertext, key []byte) ([]byte, error)

	// Name returns the human-readable name of the algorithm.
	Name() string

	// KeySize returns the required key size in bytes.
	KeySize() int

	// AlgorithmID returns the byte ID for the file header.
	AlgorithmID() byte
}

// AlgorithmInfo holds display information about an algorithm.
type AlgorithmInfo struct {
	ID          string
	Name        string
	Description string
	Warning     string
	AlgoID      byte
}

// SupportedAlgorithms returns information about all supported algorithms.
func SupportedAlgorithms() []AlgorithmInfo {
	return []AlgorithmInfo{
		{
			ID:          "faycipher",
			Name:        "FayCipher (DAG Multi-Layer)",
			Description: "🔥 Custom — DAG chaining + 8-round SPN + AES-GCM",
			AlgoID:      AlgoFayCipher,
		},
		{
			ID:          "aes-gcm",
			Name:        "AES-256-GCM",
			Description: "⭐ Recommended — Fast, secure, authenticated encryption",
			AlgoID:      AlgoAESGCM,
		},
		{
			ID:          "chacha20",
			Name:        "XChaCha20-Poly1305",
			Description: "Excellent alternative — Great on all hardware",
			AlgoID:      AlgoChaCha20,
		},
		{
			ID:          "aes-cbc",
			Name:        "AES-256-CBC",
			Description: "Classic block cipher with HMAC integrity",
			AlgoID:      AlgoAESCBC,
		},
		{
			ID:          "3des",
			Name:        "Triple DES (3DES)",
			Description: "⚠️  Legacy — Not recommended for new data",
			Warning:     "3DES is deprecated by NIST. Use for educational purposes only.",
			AlgoID:      AlgoTripleDES,
		},
	}
}

// NewEncryptor creates an Encryptor for the given algorithm ID string.
func NewEncryptor(algorithm string) (Encryptor, error) {
	switch algorithm {
	case "faycipher":
		return &FayCipher{}, nil
	case "aes-gcm":
		return &AESGCM{}, nil
	case "aes-cbc":
		return &AESCBC{}, nil
	case "chacha20":
		return &ChaCha20{}, nil
	case "3des":
		return &TripleDES{}, nil
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
}

// NewEncryptorByID creates an Encryptor for the given algorithm byte ID.
func NewEncryptorByID(id byte) (Encryptor, error) {
	switch id {
	case AlgoFayCipher:
		return &FayCipher{}, nil
	case AlgoAESGCM:
		return &AESGCM{}, nil
	case AlgoAESCBC:
		return &AESCBC{}, nil
	case AlgoChaCha20:
		return &ChaCha20{}, nil
	case AlgoTripleDES:
		return &TripleDES{}, nil
	default:
		return nil, fmt.Errorf("unknown algorithm ID: %d", id)
	}
}

// DeriveKey derives an encryption key from a password and salt using Argon2id.
func DeriveKey(password string, salt []byte, keyLen int) []byte {
	return argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, uint32(keyLen))
}

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
