package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20 implements Encryptor using XChaCha20-Poly1305.
// Excellent alternative to AES-GCM, especially on hardware without AES acceleration.
type ChaCha20 struct{}

func (c *ChaCha20) Name() string      { return "XChaCha20-Poly1305" }
func (c *ChaCha20) KeySize() int      { return chacha20poly1305.KeySize } // 32 bytes
func (c *ChaCha20) AlgorithmID() byte { return AlgoChaCha20 }

func (c *ChaCha20) Encrypt(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20: failed to create AEAD: %w", err)
	}

	// Generate random nonce (24 bytes for XChaCha20)
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("chacha20: failed to generate nonce: %w", err)
	}

	// Seal prepends the nonce to the ciphertext
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c *ChaCha20) Decrypt(ciphertext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20: failed to create AEAD: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("chacha20: ciphertext too short")
	}

	nonce, encData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, encData, nil)
	if err != nil {
		return nil, fmt.Errorf("chacha20: decryption failed (wrong password?): %w", err)
	}

	return plaintext, nil
}
