package fileops

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"encryptor/crypto"
	"encryptor/security"
)

// Magic bytes to identify encrypted files
var MagicBytes = [4]byte{'E', 'N', 'C', 'R'}

// File format version
const FormatVersion byte = 0x01

// Encrypted file extension
const EncryptedExt = ".enc"

// FileHeader represents the header of an encrypted file.
type FileHeader struct {
	Magic       [4]byte // "ENCR"
	Version     byte    // Format version
	AlgorithmID byte    // Encryption algorithm used
	FileNameLen uint16  // Length of original filename
	FileName    string  // Original filename (UTF-8)
	Salt        [16]byte // Salt for key derivation
}

// EncryptResult holds the result of a single file encryption.
type EncryptResult struct {
	FilePath string
	Success  bool
	Error    error
}

// ScanFolder recursively scans a folder and returns all file paths.
func ScanFolder(rootPath string) ([]string, error) {
	var files []string

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !strings.HasSuffix(info.Name(), EncryptedExt) {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan folder: %w", err)
	}
	return files, nil
}

// ScanEncryptedFiles recursively scans a folder for .enc files.
func ScanEncryptedFiles(rootPath string) ([]string, error) {
	var files []string

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), EncryptedExt) {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan folder: %w", err)
	}
	return files, nil
}

// writeHeader writes the file header to the encrypted file.
func writeHeader(file *os.File, header *FileHeader) error {
	// Write magic bytes
	if _, err := file.Write(header.Magic[:]); err != nil {
		return err
	}
	// Write version
	if _, err := file.Write([]byte{header.Version}); err != nil {
		return err
	}
	// Write algorithm ID
	if _, err := file.Write([]byte{header.AlgorithmID}); err != nil {
		return err
	}
	// Write filename length (2 bytes, little-endian)
	lenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBytes, header.FileNameLen)
	if _, err := file.Write(lenBytes); err != nil {
		return err
	}
	// Write filename
	if _, err := file.Write([]byte(header.FileName)); err != nil {
		return err
	}
	// Write salt
	if _, err := file.Write(header.Salt[:]); err != nil {
		return err
	}
	return nil
}

// readHeader reads the file header from an encrypted file.
func readHeader(file *os.File) (*FileHeader, error) {
	header := &FileHeader{}

	// Read magic bytes
	if _, err := file.Read(header.Magic[:]); err != nil {
		return nil, fmt.Errorf("failed to read magic bytes: %w", err)
	}
	if header.Magic != MagicBytes {
		return nil, fmt.Errorf("not a valid encrypted file (invalid magic bytes)")
	}

	// Read version
	versionBuf := make([]byte, 1)
	if _, err := file.Read(versionBuf); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	header.Version = versionBuf[0]

	if header.Version != FormatVersion {
		return nil, fmt.Errorf("unsupported format version: %d", header.Version)
	}

	// Read algorithm ID
	algoBuf := make([]byte, 1)
	if _, err := file.Read(algoBuf); err != nil {
		return nil, fmt.Errorf("failed to read algorithm ID: %w", err)
	}
	header.AlgorithmID = algoBuf[0]

	// Read filename length
	lenBuf := make([]byte, 2)
	if _, err := file.Read(lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read filename length: %w", err)
	}
	header.FileNameLen = binary.LittleEndian.Uint16(lenBuf)

	// Read filename
	fileNameBuf := make([]byte, header.FileNameLen)
	if _, err := file.Read(fileNameBuf); err != nil {
		return nil, fmt.Errorf("failed to read filename: %w", err)
	}
	header.FileName = string(fileNameBuf)

	// Read salt
	if _, err := file.Read(header.Salt[:]); err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}

	return header, nil
}

// EncryptFile encrypts a single file and writes it as a .enc file.
func EncryptFile(filePath string, enc crypto.Encryptor, key, salt []byte, secureWipe bool) error {
	// Read the original file
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Encrypt the data
	ciphertext, err := enc.Encrypt(plaintext, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// Create the encrypted file
	originalName := filepath.Base(filePath)
	encFilePath := filePath + EncryptedExt

	outFile, err := os.Create(encFilePath)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %w", err)
	}
	defer outFile.Close()

	// Build and write header
	header := &FileHeader{
		Magic:       MagicBytes,
		Version:     FormatVersion,
		AlgorithmID: enc.AlgorithmID(),
		FileNameLen: uint16(len(originalName)),
		FileName:    originalName,
	}
	copy(header.Salt[:], salt)

	if err := writeHeader(outFile, header); err != nil {
		os.Remove(encFilePath)
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write encrypted data
	if _, err := outFile.Write(ciphertext); err != nil {
		os.Remove(encFilePath)
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	// Remove the original file
	if secureWipe {
		if err := SecureRemove(filePath); err != nil {
			return fmt.Errorf("encrypted file created, but failed to securely remove original: %w", err)
		}
	} else {
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("encrypted file created, but failed to remove original: %w", err)
		}
	}

	// Lock the encrypted file (Read-Only) to prevent accidental modification
	if err := os.Chmod(encFilePath, 0444); err != nil {
		// Just log or ignore, not critical if it fails on some filesystems
	}

	return nil
}

// SecureRemove overwrites the file with 0s before removing it.
func SecureRemove(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	size := info.Size()

	zeros := make([]byte, 4096)
	var written int64
	for written < size {
		n := int64(4096)
		if size-written < n {
			n = size - written
		}
		_, err := f.Write(zeros[:n])
		if err != nil {
			f.Close()
			return err
		}
		written += n
	}
	f.Sync()
	f.Close()
	return os.Remove(path)
}

// DecryptFile decrypts a single .enc file and restores the original file.
func DecryptFile(filePath string, password string) error {
	// Open the encrypted file
	inFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %w", err)
	}
	defer inFile.Close()

	// Read header
	header, err := readHeader(inFile)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Create the encryptor based on algorithm ID
	enc, err := crypto.NewEncryptorByID(header.AlgorithmID)
	if err != nil {
		return fmt.Errorf("unsupported algorithm: %w", err)
	}

	// Derive key from password and salt
	key := crypto.DeriveKey(password, header.Salt[:], enc.KeySize())
	// SECURITY: Ensure key is zeroed from memory after decryption
	defer security.ZeroBytes(key)

	// Read the rest of the file (encrypted data)
	stat, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	currentPos, err := inFile.Seek(0, 1) // Get current position
	if err != nil {
		return fmt.Errorf("failed to get file position: %w", err)
	}

	ciphertext := make([]byte, stat.Size()-currentPos)
	if _, err := inFile.Read(ciphertext); err != nil {
		return fmt.Errorf("failed to read ciphertext: %w", err)
	}
	inFile.Close()

	// Decrypt
	plaintext, err := enc.Decrypt(ciphertext, key)
	if err != nil {
		return err
	}

	// Write the decrypted file with original name
	dir := filepath.Dir(filePath)
	originalPath := filepath.Join(dir, header.FileName)

	// If file already exists, add a suffix to avoid overwriting
	if _, err := os.Stat(originalPath); err == nil {
		ext := filepath.Ext(header.FileName)
		name := strings.TrimSuffix(header.FileName, ext)
		originalPath = filepath.Join(dir, name+"_decrypted"+ext)
	}

	if err := os.WriteFile(originalPath, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	// Remove the Read-Only lock before attempting to delete
	_ = os.Chmod(filePath, 0666)

	// Remove the encrypted file
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("decrypted file created, but failed to remove encrypted file: %w", err)
	}

	return nil
}

// EncryptFolder encrypts all files in a folder recursively.
// Returns the number of successful and failed operations.
func EncryptFolder(folderPath string, enc crypto.Encryptor, password string, progressFn func(current, total int, fileName string), secureWipe bool) (int, int, []error) {
	files, err := ScanFolder(folderPath)
	if err != nil {
		return 0, 0, []error{err}
	}

	if len(files) == 0 {
		return 0, 0, nil
	}

	// Generate salt and derive key
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return 0, 0, []error{err}
	}

	key := crypto.DeriveKey(password, salt, enc.KeySize())
	// SECURITY: Ensure key is zeroed from memory after all files are processed
	defer security.ZeroBytes(key)

	var (
		success int
		failed  int
		errors  []error
	)

	for i, filePath := range files {
		if progressFn != nil {
			progressFn(i+1, len(files), filepath.Base(filePath))
		}

		if err := EncryptFile(filePath, enc, key, salt, secureWipe); err != nil {
			failed++
			errors = append(errors, fmt.Errorf("%s: %w", filepath.Base(filePath), err))
		} else {
			success++
		}
	}

	return success, failed, errors
}

// DecryptFolder decrypts all .enc files in a folder recursively.
// Returns the number of successful and failed operations.
func DecryptFolder(folderPath string, password string, progressFn func(current, total int, fileName string)) (int, int, []error) {
	files, err := ScanEncryptedFiles(folderPath)
	if err != nil {
		return 0, 0, []error{err}
	}

	if len(files) == 0 {
		return 0, 0, nil
	}

	var (
		success int
		failed  int
		errors  []error
	)

	for i, filePath := range files {
		if progressFn != nil {
			progressFn(i+1, len(files), filepath.Base(filePath))
		}

		if err := DecryptFile(filePath, password); err != nil {
			failed++
			errors = append(errors, fmt.Errorf("%s: %w", filepath.Base(filePath), err))
		} else {
			success++
		}
	}

	return success, failed, errors
}

// EncryptFileToMemory encrypts a file and returns it as a byte slice with header.
func EncryptFileToMemory(filePath string, enc crypto.Encryptor, key, salt []byte) ([]byte, error) {
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	ciphertext, err := enc.Encrypt(plaintext, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	originalName := filepath.Base(filePath)

	header := &FileHeader{
		Magic:       MagicBytes,
		Version:     FormatVersion,
		AlgorithmID: enc.AlgorithmID(),
		FileNameLen: uint16(len(originalName)),
		FileName:    originalName,
	}
	copy(header.Salt[:], salt)

	var buf []byte
	buf = append(buf, header.Magic[:]...)
	buf = append(buf, header.Version)
	buf = append(buf, header.AlgorithmID)
	lenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBytes, header.FileNameLen)
	buf = append(buf, lenBytes...)
	buf = append(buf, []byte(header.FileName)...)
	buf = append(buf, header.Salt[:]...)

	buf = append(buf, ciphertext...)
	return buf, nil
}

// DecryptFileFromMemory parses the header and decrypts the ciphertext.
func DecryptFileFromMemory(data []byte, key []byte, enc crypto.Encryptor) ([]byte, error) {
	if len(data) < 4+1+1+2+16 {
		return nil, fmt.Errorf("data too short")
	}

	var magic [4]byte
	copy(magic[:], data[0:4])
	if magic != MagicBytes {
		return nil, fmt.Errorf("not a valid encrypted file (invalid magic bytes)")
	}

	version := data[4]
	if version != FormatVersion {
		return nil, fmt.Errorf("unsupported format version: %d", version)
	}

	algoID := data[5]
	if enc.AlgorithmID() != algoID {
		return nil, fmt.Errorf("mismatched algorithm ID")
	}

	fileNameLen := binary.LittleEndian.Uint16(data[6:8])
	if len(data) < 8+int(fileNameLen)+16 {
		return nil, fmt.Errorf("data too short for filename and salt")
	}

	offset := 8 + int(fileNameLen)
	// skip salt
	ciphertext := data[offset+16:]

	plaintext, err := enc.Decrypt(ciphertext, key)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
