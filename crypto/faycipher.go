package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// FayCipher implements a custom multi-layer DAG-inspired cipher.
//
// Architecture:
//   Layer 1: Key Expansion — Master key expanded into multiple sub-keys via cascaded hashing
//   Layer 2: Key-Dependent S-Box — 256-byte substitution table generated from key
//   Layer 3: Block Permutation — Key-dependent byte-level permutation (P-Box)
//   Layer 4: DAG Block Chaining — Each block depends on multiple parent blocks (non-linear)
//   Layer 5: Multi-Round Transformation — Multiple rounds of substitution + diffusion
//   Layer 6: AES-256-GCM — Final authenticated encryption for integrity
//
// The DAG structure means that unlike CBC (linear chain), each encrypted block
// depends on 2-3 other blocks in a graph pattern determined by the key.
// This makes it significantly harder to analyze block relationships.

const (
	fayBlockSize   = 64          // 64 bytes per block for internal processing
	fayRounds      = 8           // Number of transformation rounds
	faySubKeys     = 16          // Number of derived sub-keys
	fayMaxParents  = 3           // Maximum parent blocks in DAG
)

type FayCipher struct{}

func (f *FayCipher) Name() string      { return "FayCipher (DAG Multi-Layer)" }
func (f *FayCipher) KeySize() int      { return 32 }
func (f *FayCipher) AlgorithmID() byte { return AlgoFayCipher }

// fayKeySchedule holds expanded key material for the cipher.
type fayKeySchedule struct {
	subKeys   [faySubKeys][32]byte // Derived sub-keys
	sBox      [256]byte            // Key-dependent substitution box
	sBoxInv   [256]byte            // Inverse S-Box for decryption
	pBox      [fayBlockSize]byte   // Key-dependent permutation box
	pBoxInv   [fayBlockSize]byte   // Inverse P-Box
	dagSeeds  [4]uint64            // Seeds for DAG topology generation
	diffusion [fayBlockSize]byte   // Diffusion constants
}

// expandKey performs key expansion to generate all cipher parameters.
// It uses HMAC for domain separation to ensure the DAG keys and AES keys are mathematically independent.
func expandKey(masterKey []byte) *fayKeySchedule {
	ks := &fayKeySchedule{}

	// ═══════════════════════════════════════════
	// Phase 1: Sub-key derivation via cascaded hashing with Domain Separation
	// ═══════════════════════════════════════════
	
	// Derive an independent root key for the DAG layer to prevent related-key attacks with AES
	hDag := hmac.New(sha256.New, []byte("faycipher-dag-domain"))
	hDag.Write(masterKey)
	dagRootKey := hDag.Sum(nil)

	current := sha256.Sum256(dagRootKey)
	for i := 0; i < faySubKeys; i++ {
		// Mix in the round number and master key
		roundData := make([]byte, len(masterKey)+32+8)
		copy(roundData, masterKey)
		copy(roundData[len(masterKey):], current[:])
		binary.LittleEndian.PutUint64(roundData[len(masterKey)+32:], uint64(i)*0x9E3779B97F4A7C15) // Golden ratio constant
		
		hash := sha512.Sum512(roundData)
		copy(ks.subKeys[i][:], hash[:32])
		current = sha256.Sum256(hash[:])
	}

	// ═══════════════════════════════════════════
	// Phase 2: Generate key-dependent S-Box (Substitution Box)
	// ═══════════════════════════════════════════
	// Uses Fisher-Yates shuffle seeded by the key to create a random permutation
	// This makes the substitution layer unique per key

	for i := 0; i < 256; i++ {
		ks.sBox[i] = byte(i)
	}

	// Use sub-key as seed for deterministic shuffle
	sboxSeed := sha256.Sum256(append(ks.subKeys[0][:], ks.subKeys[1][:]...))
	seedIdx := 0
	getSeedByte := func() byte {
		if seedIdx >= 32 {
			sboxSeed = sha256.Sum256(sboxSeed[:])
			seedIdx = 0
		}
		b := sboxSeed[seedIdx]
		seedIdx++
		return b
	}

	for i := 255; i > 0; i-- {
		j := int(getSeedByte()) % (i + 1)
		ks.sBox[i], ks.sBox[j] = ks.sBox[j], ks.sBox[i]
	}

	// Build inverse S-Box
	for i := 0; i < 256; i++ {
		ks.sBoxInv[ks.sBox[i]] = byte(i)
	}

	// ═══════════════════════════════════════════
	// Phase 3: Generate key-dependent P-Box (Permutation Box)
	// ═══════════════════════════════════════════
	// Byte-level permutation within each block

	for i := 0; i < fayBlockSize; i++ {
		ks.pBox[i] = byte(i)
	}

	pboxSeed := sha256.Sum256(append(ks.subKeys[2][:], ks.subKeys[3][:]...))
	seedIdx = 0
	getPboxByte := func() byte {
		if seedIdx >= 32 {
			pboxSeed = sha256.Sum256(pboxSeed[:])
			seedIdx = 0
		}
		b := pboxSeed[seedIdx]
		seedIdx++
		return b
	}

	for i := fayBlockSize - 1; i > 0; i-- {
		j := int(getPboxByte()) % (i + 1)
		ks.pBox[i], ks.pBox[j] = ks.pBox[j], ks.pBox[i]
	}

	// Build inverse P-Box
	for i := 0; i < fayBlockSize; i++ {
		ks.pBoxInv[ks.pBox[i]] = byte(i)
	}

	// ═══════════════════════════════════════════
	// Phase 4: Generate DAG topology seeds
	// ═══════════════════════════════════════════
	dagSeedData := sha256.Sum256(append(ks.subKeys[4][:], ks.subKeys[5][:]...))
	for i := 0; i < 4; i++ {
		ks.dagSeeds[i] = binary.LittleEndian.Uint64(dagSeedData[i*8 : (i+1)*8])
	}

	// ═══════════════════════════════════════════
	// Phase 5: Generate diffusion constants
	// ═══════════════════════════════════════════
	diffHash := sha256.Sum256(append(ks.subKeys[6][:], ks.subKeys[7][:]...))
	for i := 0; i < fayBlockSize; i++ {
		ks.diffusion[i] = diffHash[i%32]
		if ks.diffusion[i] == 0 {
			ks.diffusion[i] = 0x1B // Avoid zero for diffusion
		}
	}

	return ks
}

// getDAGParents returns the parent block indices for a given block index.
// This creates the DAG topology where each block depends on multiple parents.
func getDAGParents(blockIndex int, totalBlocks int, seeds [4]uint64) []int {
	if blockIndex == 0 || totalBlocks <= 1 {
		return nil // First block has no parents
	}

	parents := make([]int, 0, fayMaxParents)

	// Parent 1: Always the immediately previous block (like CBC)
	parents = append(parents, blockIndex-1)

	if blockIndex >= 2 {
		// Parent 2: A block determined by the key-derived seed
		// Uses modular arithmetic with the seed to pick a non-linear parent
		p2 := int((seeds[0]*uint64(blockIndex) + seeds[1]) % uint64(blockIndex))
		if p2 != blockIndex-1 { // Avoid duplicate
			parents = append(parents, p2)
		}
	}

	if blockIndex >= 4 {
		// Parent 3: Another key-derived parent for even more cross-linking
		p3 := int((seeds[2]*uint64(blockIndex*blockIndex) + seeds[3]) % uint64(blockIndex))
		// Ensure no duplicates
		isDuplicate := false
		for _, p := range parents {
			if p == p3 {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			parents = append(parents, p3)
		}
	}

	return parents
}

// computeDAGChainValue computes the chaining value from parent blocks.
// This is the hash that gets mixed into the current block before encryption.
func computeDAGChainValue(parentBlocks [][]byte, blockIndex int, subKey [32]byte) []byte {
	h := hmac.New(sha256.New, subKey[:])

	// Mix in block index
	indexBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(indexBytes, uint64(blockIndex))
	h.Write(indexBytes)

	// Mix in all parent block data
	for i, parent := range parentBlocks {
		// Add parent index for ordering
		parentIdx := make([]byte, 4)
		binary.LittleEndian.PutUint32(parentIdx, uint32(i))
		h.Write(parentIdx)
		h.Write(parent)
	}

	result := h.Sum(nil)

	// Expand to block size if needed
	if len(result) < fayBlockSize {
		expanded := make([]byte, fayBlockSize)
		for i := 0; i < fayBlockSize; i++ {
			expanded[i] = result[i%len(result)] ^ byte(i)
		}
		return expanded
	}
	return result[:fayBlockSize]
}

// substituteBytes applies the key-dependent S-Box substitution.
func (ks *fayKeySchedule) substituteBytes(block []byte) {
	for i := range block {
		block[i] = ks.sBox[block[i]]
	}
}

// inverseSubstituteBytes applies the inverse S-Box substitution.
func (ks *fayKeySchedule) inverseSubstituteBytes(block []byte) {
	for i := range block {
		block[i] = ks.sBoxInv[block[i]]
	}
}

// permuteBytes applies the key-dependent P-Box permutation.
func (ks *fayKeySchedule) permuteBytes(block []byte) {
	temp := make([]byte, len(block))
	copy(temp, block)
	for i := 0; i < len(block) && i < fayBlockSize; i++ {
		block[ks.pBox[i]] = temp[i]
	}
}

// inversePermuteBytes applies the inverse P-Box permutation.
func (ks *fayKeySchedule) inversePermuteBytes(block []byte) {
	temp := make([]byte, len(block))
	copy(temp, block)
	for i := 0; i < len(block) && i < fayBlockSize; i++ {
		block[ks.pBoxInv[i]] = temp[i]
	}
}

// diffuseBlock applies diffusion — each byte influences its neighbors.
func (ks *fayKeySchedule) diffuseBlock(block []byte) {
	n := len(block)
	if n < 2 {
		return
	}
	// Forward diffusion pass
	for i := 1; i < n; i++ {
		block[i] ^= galoisMultiply(block[i-1], ks.diffusion[i%fayBlockSize])
	}
	// Backward diffusion pass
	for i := n - 2; i >= 0; i-- {
		block[i] ^= galoisMultiply(block[i+1], ks.diffusion[(i+1)%fayBlockSize])
	}
}

// inverseDiffuseBlock reverses the diffusion operation.
func (ks *fayKeySchedule) inverseDiffuseBlock(block []byte) {
	n := len(block)
	if n < 2 {
		return
	}
	// Reverse backward pass first
	for i := 0; i < n-1; i++ {
		block[i] ^= galoisMultiply(block[i+1], ks.diffusion[(i+1)%fayBlockSize])
	}
	// Reverse forward pass
	for i := n - 1; i >= 1; i-- {
		block[i] ^= galoisMultiply(block[i-1], ks.diffusion[i%fayBlockSize])
	}
}

// galoisMultiply performs multiplication in GF(2^8) with the AES irreducible polynomial.
func galoisMultiply(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hiBit := a & 0x80
		a <<= 1
		if hiBit != 0 {
			a ^= 0x1B // x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return p
}

// transformBlock applies one round of the FayCipher transformation.
func (ks *fayKeySchedule) transformBlock(block []byte, round int) {
	roundKey := ks.subKeys[round%faySubKeys]

	// Step 1: XOR with round key
	for i := range block {
		block[i] ^= roundKey[i%32]
	}

	// Step 2: S-Box substitution
	ks.substituteBytes(block)

	// Step 3: P-Box permutation
	ks.permuteBytes(block)

	// Step 4: Diffusion
	ks.diffuseBlock(block)

	// Step 5: XOR with rotated round key (additional mixing)
	rotation := int(roundKey[0]) % 32
	for i := range block {
		block[i] ^= roundKey[(i+rotation)%32]
	}
}

// inverseTransformBlock reverses one round of transformation.
func (ks *fayKeySchedule) inverseTransformBlock(block []byte, round int) {
	roundKey := ks.subKeys[round%faySubKeys]

	// Inverse Step 5: XOR with rotated round key
	rotation := int(roundKey[0]) % 32
	for i := range block {
		block[i] ^= roundKey[(i+rotation)%32]
	}

	// Inverse Step 4: Diffusion
	ks.inverseDiffuseBlock(block)

	// Inverse Step 3: P-Box permutation
	ks.inversePermuteBytes(block)

	// Inverse Step 2: S-Box substitution
	ks.inverseSubstituteBytes(block)

	// Inverse Step 1: XOR with round key
	for i := range block {
		block[i] ^= roundKey[i%32]
	}
}

// padData pads data to a multiple of fayBlockSize using a custom padding scheme.
// Format: data + random_padding + [original_length as 8 bytes]
func padData(data []byte) []byte {
	origLen := len(data)
	// Calculate padding needed (must fit original length at the end)
	paddedLen := ((origLen + 8) / fayBlockSize + 1) * fayBlockSize
	padded := make([]byte, paddedLen)

	copy(padded, data)

	// Fill padding with random bytes (not zeros — harder to identify)
	if paddedLen-origLen-8 > 0 {
		rand.Read(padded[origLen : paddedLen-8])
	}

	// Store original length in the last 8 bytes
	binary.LittleEndian.PutUint64(padded[paddedLen-8:], uint64(origLen))

	return padded
}

// unpadData removes the custom padding and restores original data.
func unpadData(padded []byte) ([]byte, error) {
	if len(padded) < 8 {
		return nil, fmt.Errorf("faycipher: padded data too short")
	}

	// Read original length from last 8 bytes
	origLen := binary.LittleEndian.Uint64(padded[len(padded)-8:])
	if origLen > uint64(len(padded)-8) {
		return nil, fmt.Errorf("faycipher: invalid original length in padding")
	}

	return padded[:origLen], nil
}

func (f *FayCipher) Encrypt(plaintext, key []byte) ([]byte, error) {
	// ═══════════════════════════════════════════
	// Phase 1: Key Expansion
	// ═══════════════════════════════════════════
	ks := expandKey(key)

	// ═══════════════════════════════════════════
	// Phase 2: Pad and split into blocks
	// ═══════════════════════════════════════════
	padded := padData(plaintext)
	numBlocks := len(padded) / fayBlockSize
	blocks := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		blocks[i] = make([]byte, fayBlockSize)
		copy(blocks[i], padded[i*fayBlockSize:(i+1)*fayBlockSize])
	}

	// ═══════════════════════════════════════════
	// Phase 3: DAG Block Chaining + Multi-Round Transformation
	// ═══════════════════════════════════════════
	encryptedBlocks := make([][]byte, numBlocks)

	for i := 0; i < numBlocks; i++ {
		block := blocks[i]

		// Get parent blocks and compute DAG chain value
		parentIndices := getDAGParents(i, numBlocks, ks.dagSeeds)
		if len(parentIndices) > 0 {
			parentData := make([][]byte, len(parentIndices))
			for j, pi := range parentIndices {
				parentData[j] = encryptedBlocks[pi]
			}
			chainValue := computeDAGChainValue(parentData, i, ks.subKeys[i%faySubKeys])

			// XOR block with chain value (DAG dependency)
			for j := range block {
				block[j] ^= chainValue[j%len(chainValue)]
			}
		}

		// Apply multiple rounds of transformation
		for round := 0; round < fayRounds; round++ {
			ks.transformBlock(block, round+i)
		}

		encryptedBlocks[i] = block
	}

	// ═══════════════════════════════════════════
	// Phase 4: Reassemble and apply final AES-256-GCM layer
	// ═══════════════════════════════════════════
	transformed := make([]byte, 0, numBlocks*fayBlockSize)
	for _, block := range encryptedBlocks {
		transformed = append(transformed, block...)
	}

	// Store number of blocks for decryption
	blockCountBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(blockCountBytes, uint32(numBlocks))

	// Final layer: AES-256-GCM for authenticated encryption
	// Use HMAC domain separation to ensure AES key is mathematically independent from DAG keys
	hAes := hmac.New(sha256.New, []byte("faycipher-aes-domain"))
	hAes.Write(key)
	aesKey := hAes.Sum(nil)
	
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("faycipher: AES init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("faycipher: GCM init failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("faycipher: nonce generation failed: %w", err)
	}

	// Prepend block count to the data before GCM sealing
	dataToSeal := append(blockCountBytes, transformed...)

	// Seal: nonce + ciphertext + GCM tag
	ciphertext := gcm.Seal(nonce, nonce, dataToSeal, nil)

	return ciphertext, nil
}

func (f *FayCipher) Decrypt(ciphertext, key []byte) ([]byte, error) {
	// ═══════════════════════════════════════════
	// Phase 1: Key Expansion (same as encrypt)
	// ═══════════════════════════════════════════
	ks := expandKey(key)

	// ═══════════════════════════════════════════
	// Phase 2: Remove AES-256-GCM layer
	// ═══════════════════════════════════════════
	hAes := hmac.New(sha256.New, []byte("faycipher-aes-domain"))
	hAes.Write(key)
	aesKey := hAes.Sum(nil)
	
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("faycipher: AES init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("faycipher: GCM init failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("faycipher: ciphertext too short")
	}

	nonce, encData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, encData, nil)
	if err != nil {
		return nil, fmt.Errorf("faycipher: decryption failed (wrong password?): %w", err)
	}

	// Extract block count
	if len(decrypted) < 4 {
		return nil, fmt.Errorf("faycipher: decrypted data too short")
	}
	numBlocks := int(binary.LittleEndian.Uint32(decrypted[:4]))
	transformed := decrypted[4:]

	if len(transformed) != numBlocks*fayBlockSize {
		return nil, fmt.Errorf("faycipher: block count mismatch")
	}

	// ═══════════════════════════════════════════
	// Phase 3: Split into blocks
	// ═══════════════════════════════════════════
	blocks := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		blocks[i] = make([]byte, fayBlockSize)
		copy(blocks[i], transformed[i*fayBlockSize:(i+1)*fayBlockSize])
	}

	// ═══════════════════════════════════════════
	// Phase 4: Inverse DAG Block Processing (reverse order!)
	// ═══════════════════════════════════════════
	// Must process in reverse order because of DAG dependencies
	for i := numBlocks - 1; i >= 0; i-- {
		block := blocks[i]

		// Inverse multi-round transformation (reverse round order)
		for round := fayRounds - 1; round >= 0; round-- {
			ks.inverseTransformBlock(block, round+i)
		}

		// Reverse DAG chaining
		parentIndices := getDAGParents(i, numBlocks, ks.dagSeeds)
		if len(parentIndices) > 0 {
			// For decryption, we need the encrypted parent blocks
			// Since we process in reverse, blocks after i are already decrypted
			// But blocks before i are still in encrypted form — which is what we need!
			parentData := make([][]byte, len(parentIndices))
			for j, pi := range parentIndices {
				if pi < i {
					// Parent blocks that haven't been decrypted yet still contain
					// the encrypted data — but we stored the originals
					parentData[j] = make([]byte, fayBlockSize)
					copy(parentData[j], transformed[pi*fayBlockSize:(pi+1)*fayBlockSize])
				}
			}
			chainValue := computeDAGChainValue(parentData, i, ks.subKeys[i%faySubKeys])

			for j := range block {
				block[j] ^= chainValue[j%len(chainValue)]
			}
		}

		blocks[i] = block
	}

	// ═══════════════════════════════════════════
	// Phase 5: Reassemble and unpad
	// ═══════════════════════════════════════════
	padded := make([]byte, 0, numBlocks*fayBlockSize)
	for _, block := range blocks {
		padded = append(padded, block...)
	}

	plaintext, err := unpadData(padded)
	if err != nil {
		return nil, fmt.Errorf("faycipher: unpad failed: %w", err)
	}

	return plaintext, nil
}

// Complexity returns a human-readable description of the cipher's complexity.
func (f *FayCipher) Complexity(dataSize int) string {
	numBlocks := int(math.Ceil(float64(dataSize) / float64(fayBlockSize)))
	totalOps := numBlocks * fayRounds * 5 // 5 operations per round per block

	dagEdges := 0
	for i := 0; i < numBlocks; i++ {
		dagEdges += len(getDAGParents(i, numBlocks, [4]uint64{1, 2, 3, 4}))
	}

	return fmt.Sprintf(
		"%d blocks × %d rounds × 5 ops = %d transformations, %d DAG edges",
		numBlocks, fayRounds, totalOps, dagEdges,
	)
}
