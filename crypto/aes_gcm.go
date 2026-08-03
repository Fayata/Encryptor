package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AESGCM implements Encryptor using AES-256-GCM.
// This is the recommended algorithm — provides both confidentiality and authenticity.
type AESGCM struct{}

func (a *AESGCM) Name() string      { return "AES-256-GCM" }
func (a *AESGCM) KeySize() int      { return 32 }
func (a *AESGCM) AlgorithmID() byte { return AlgoAESGCM }

func (a *AESGCM) Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: failed to create GCM: %w", err)
	}

	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("aes-gcm: failed to generate nonce: %w", err)
	}

	// Seal prepends the nonce to the ciphertext
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (a *AESGCM) Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("aes-gcm: ciphertext too short")
	}

	nonce, encData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, encData, nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: decryption failed (wrong password?): %w", err)
	}

	return plaintext, nil
}
