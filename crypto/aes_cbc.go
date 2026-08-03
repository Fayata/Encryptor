package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// AESCBC implements Encryptor using AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC).
type AESCBC struct{}

func (a *AESCBC) Name() string      { return "AES-256-CBC" }
func (a *AESCBC) KeySize() int      { return 32 }
func (a *AESCBC) AlgorithmID() byte { return AlgoAESCBC }

// pkcs7Pad pads data to a multiple of blockSize using PKCS7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padBytes := make([]byte, padding)
	for i := range padBytes {
		padBytes[i] = byte(padding)
	}
	return append(data, padBytes...)
}

// pkcs7Unpad removes PKCS7 padding.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padding: data length %d is not a multiple of block size %d", len(data), blockSize)
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("invalid padding value: %d", padding)
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return data[:len(data)-padding], nil
}

// computeHMAC computes HMAC-SHA256 over the given data.
// Uses the second half of the key for MAC to separate encryption and MAC keys.
func computeHMAC(data, key []byte) []byte {
	// Derive a MAC key from the encryption key using SHA-256
	macKeyHash := sha256.Sum256(append(key, []byte("mac-key")...))
	mac := hmac.New(sha256.New, macKeyHash[:])
	mac.Write(data)
	return mac.Sum(nil)
}

func (a *AESCBC) Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: failed to create cipher: %w", err)
	}

	// PKCS7 pad the plaintext
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	// Generate random IV (16 bytes)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("aes-cbc: failed to generate IV: %w", err)
	}

	// Encrypt
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Format: IV + Ciphertext + HMAC
	result := make([]byte, 0, len(iv)+len(ciphertext)+sha256.Size)
	result = append(result, iv...)
	result = append(result, ciphertext...)

	// Compute HMAC over IV + Ciphertext (Encrypt-then-MAC)
	mac := computeHMAC(result, key)
	result = append(result, mac...)

	return result, nil
}

func (a *AESCBC) Decrypt(data, key []byte) ([]byte, error) {
	// Minimum: IV (16) + 1 block (16) + HMAC (32) = 64 bytes
	if len(data) < aes.BlockSize+aes.BlockSize+sha256.Size {
		return nil, fmt.Errorf("aes-cbc: ciphertext too short")
	}

	// Split: data = IV + Ciphertext + HMAC
	macStart := len(data) - sha256.Size
	ivAndCiphertext := data[:macStart]
	receivedMAC := data[macStart:]

	// Verify HMAC first (Encrypt-then-MAC)
	expectedMAC := computeHMAC(ivAndCiphertext, key)
	if !hmac.Equal(receivedMAC, expectedMAC) {
		return nil, fmt.Errorf("aes-cbc: HMAC verification failed (wrong password?)")
	}

	iv := ivAndCiphertext[:aes.BlockSize]
	ciphertext := ivAndCiphertext[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: failed to create cipher: %w", err)
	}

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: %w", err)
	}

	return plaintext, nil
}
