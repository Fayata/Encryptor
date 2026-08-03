package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestFayCipherEncryptDecrypt(t *testing.T) {
	fc := &FayCipher{}

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("Hello FayCipher!")},
		{"exact block", make([]byte, fayBlockSize)},
		{"multi block", make([]byte, fayBlockSize*5+17)},
		{"large", make([]byte, 1024*64)},
	}

	key := make([]byte, 32)
	rand.Read(key)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill with some data if not empty
			if len(tt.data) > 0 && tt.data[0] == 0 {
				rand.Read(tt.data)
			}

			original := make([]byte, len(tt.data))
			copy(original, tt.data)

			// Encrypt
			ciphertext, err := fc.Encrypt(tt.data, key)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Ciphertext should be different from plaintext (unless empty)
			if len(original) > 0 && bytes.Equal(ciphertext, original) {
				t.Fatal("Ciphertext equals plaintext")
			}

			// Decrypt
			plaintext, err := fc.Decrypt(ciphertext, key)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Should match original
			if !bytes.Equal(plaintext, original) {
				t.Fatalf("Decrypted data doesn't match original.\nExpected %d bytes, got %d bytes", len(original), len(plaintext))
			}
		})
	}
}

func TestFayCipherWrongKey(t *testing.T) {
	fc := &FayCipher{}

	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	plaintext := []byte("This is secret data that should not be decryptable with wrong key")

	ciphertext, err := fc.Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with wrong key should fail
	_, err = fc.Decrypt(ciphertext, key2)
	if err == nil {
		t.Fatal("Decrypt with wrong key should have failed")
	}
}

func TestFayCipherDAGParents(t *testing.T) {
	seeds := [4]uint64{12345, 67890, 11111, 22222}

	// Block 0 should have no parents
	parents := getDAGParents(0, 10, seeds)
	if len(parents) != 0 {
		t.Fatalf("Block 0 should have no parents, got %d", len(parents))
	}

	// Block 1 should have 1 parent (block 0)
	parents = getDAGParents(1, 10, seeds)
	if len(parents) < 1 {
		t.Fatal("Block 1 should have at least 1 parent")
	}
	if parents[0] != 0 {
		t.Fatalf("Block 1's first parent should be 0, got %d", parents[0])
	}

	// Higher blocks should have multiple parents (non-linear DAG)
	parents = getDAGParents(8, 10, seeds)
	if len(parents) < 2 {
		t.Fatalf("Block 8 should have multiple parents (DAG), got %d", len(parents))
	}

	// Verify no parent index >= block index
	for _, p := range parents {
		if p >= 8 {
			t.Fatalf("Parent %d >= block index 8", p)
		}
	}
}

func TestKeyDependentSBox(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	ks1 := expandKey(key1)
	ks2 := expandKey(key2)

	// Different keys should produce different S-Boxes
	different := false
	for i := 0; i < 256; i++ {
		if ks1.sBox[i] != ks2.sBox[i] {
			different = true
			break
		}
	}
	if !different {
		t.Fatal("Different keys produced identical S-Boxes")
	}

	// S-Box should be a valid permutation (all values 0-255 present)
	seen := make(map[byte]bool)
	for _, v := range ks1.sBox {
		seen[v] = true
	}
	if len(seen) != 256 {
		t.Fatalf("S-Box is not a valid permutation: %d unique values", len(seen))
	}

	// Inverse S-Box should correctly reverse substitution
	for i := 0; i < 256; i++ {
		substituted := ks1.sBox[byte(i)]
		restored := ks1.sBoxInv[substituted]
		if restored != byte(i) {
			t.Fatalf("S-Box inverse failed: sBoxInv[sBox[%d]] = %d", i, restored)
		}
	}
}
