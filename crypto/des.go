package crypto

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// TripleDES implements Encryptor using Triple DES in CBC mode with HMAC-SHA256.
// LEGACY: Not recommended for new data. Provided for educational/compatibility purposes.
type TripleDES struct{}

func (t *TripleDES) Name() string      { return "Triple DES (3DES)" }
func (t *TripleDES) KeySize() int      { return 24 } // 3 × 8 bytes
func (t *TripleDES) AlgorithmID() byte { return AlgoTripleDES }

// pkcs5Pad pads data to a multiple of blockSize using PKCS5 (same as PKCS7 for 8-byte blocks).
func pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padBytes := make([]byte, padding)
	for i := range padBytes {
		padBytes[i] = byte(padding)
	}
	return append(data, padBytes...)
}

// pkcs5Unpad removes PKCS5 padding.
func pkcs5Unpad(data []byte, blockSize int) ([]byte, error) {
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

// computeHMAC3DES computes HMAC-SHA256 for 3DES integrity.
func computeHMAC3DES(data, key []byte) []byte {
	macKeyHash := sha256.Sum256(append(key, []byte("3des-mac-key")...))
	mac := hmac.New(sha256.New, macKeyHash[:])
	mac.Write(data)
	return mac.Sum(nil)
}

func (t *TripleDES) Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("3des: failed to create cipher: %w", err)
	}

	// PKCS5 pad the plaintext
	padded := pkcs5Pad(plaintext, des.BlockSize)

	// Generate random IV (8 bytes for DES)
	iv := make([]byte, des.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("3des: failed to generate IV: %w", err)
	}

	// Encrypt
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Format: IV + Ciphertext + HMAC
	result := make([]byte, 0, len(iv)+len(ciphertext)+sha256.Size)
	result = append(result, iv...)
	result = append(result, ciphertext...)

	// Compute HMAC over IV + Ciphertext
	mac := computeHMAC3DES(result, key)
	result = append(result, mac...)

	return result, nil
}

func (t *TripleDES) Decrypt(data, key []byte) ([]byte, error) {
	// Minimum: IV (8) + 1 block (8) + HMAC (32) = 48 bytes
	if len(data) < des.BlockSize+des.BlockSize+sha256.Size {
		return nil, fmt.Errorf("3des: ciphertext too short")
	}

	// Split: data = IV + Ciphertext + HMAC
	macStart := len(data) - sha256.Size
	ivAndCiphertext := data[:macStart]
	receivedMAC := data[macStart:]

	// Verify HMAC first
	expectedMAC := computeHMAC3DES(ivAndCiphertext, key)
	if !hmac.Equal(receivedMAC, expectedMAC) {
		return nil, fmt.Errorf("3des: HMAC verification failed (wrong password?)")
	}

	iv := ivAndCiphertext[:des.BlockSize]
	ciphertext := ivAndCiphertext[des.BlockSize:]

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("3des: failed to create cipher: %w", err)
	}

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS5 padding
	plaintext, err = pkcs5Unpad(plaintext, des.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("3des: %w", err)
	}

	return plaintext, nil
}
