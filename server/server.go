package server

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"encryptor/crypto"
	"encryptor/db"
	"encryptor/fileops"
	"encryptor/security"

	"golang.org/x/crypto/argon2"
)

type Server struct {
	db           *db.DB
	port         string
	csrf         *csrfManager
	loginLimiter *rateLimiter
	apiLimiter   *rateLimiter
	shareLimiter *rateLimiter
}

func NewServer(database *db.DB, port string) (*Server, error) {
	if port == "" {
		port = "8080"
	}

	// Initialize security logger
	initSecurityLogger()

	s := &Server{
		db:           database,
		port:         port,
		csrf:         newCSRFManager(),
		loginLimiter: newRateLimiter(5, 1*time.Minute),  // 5 attempts/min for login
		apiLimiter:   newRateLimiter(30, 1*time.Minute), // 30 req/min for API
		shareLimiter: newRateLimiter(5, 15*time.Minute), // 5 attempts per 15 mins for share password
	}

	return s, nil
}

func (s *Server) Start() {
	go func() {
		mux := http.NewServeMux()

		// Auth
		mux.HandleFunc("/api/auth/login", limitBody(rateLimitMiddleware(s.loginLimiter, s.handleLogin)))
		mux.HandleFunc("/api/auth/register", limitBody(rateLimitMiddleware(s.loginLimiter, s.handleRegister)))

		// Status
		mux.HandleFunc("/api/status", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleStatus)))

		// Local Operations
		mux.HandleFunc("/api/local/encrypt", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleLocalEncrypt)))
		mux.HandleFunc("/api/local/decrypt", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleLocalDecrypt)))
		mux.HandleFunc("/api/local/kdf", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleKDF)))

		// Key Vault
		mux.HandleFunc("/api/vault/upload", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleVaultUpload)))
		mux.HandleFunc("/api/vault/download", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleVaultDownload)))
		mux.HandleFunc("/api/files", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleAPIKeys)))
		mux.HandleFunc("/api/files/", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleAPIKeyByID)))
		mux.HandleFunc("/api/keys", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleAPIKeys)))
		mux.HandleFunc("/api/keys/", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleAPIKeyByID)))

		// Organizations
		mux.HandleFunc("/api/orgs", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleOrgs)))
		mux.HandleFunc("/api/orgs/", limitBody(rateLimitMiddleware(s.apiLimiter, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/leave") {
				s.handleLeaveOrg(w, r)
			} else {
				s.handleOrgMembers(w, r)
			}
		})))

		// Connections & User Search
		mux.HandleFunc("/api/users/search", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleSearchUsers)))
		mux.HandleFunc("/api/connections/request", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleConnectionRequest)))
		mux.HandleFunc("/api/connections/accept", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleConnectionAccept)))
		mux.HandleFunc("/api/connections/reject", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleConnectionReject)))
		mux.HandleFunc("/api/connections/remove", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleConnectionRemove)))
		mux.HandleFunc("/api/connections", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleConnections)))

		// Notifications
		mux.HandleFunc("/api/notifications", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleNotifications)))
		mux.HandleFunc("/api/notifications/stream", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleNotifications)))
		mux.HandleFunc("/api/notifications/read", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleNotificationsRead)))

		// File Shares
		mux.HandleFunc("/api/share", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleShare)))

		// Serve React Web frontend from web/dist
		fs := http.FileServer(http.Dir("web/dist"))
		mux.Handle("/", fs)

		// Wrap all routes with security headers and CORS
		handler := corsMiddleware(securityHeaders(mux))

		if err := http.ListenAndServe("127.0.0.1:"+s.port, handler); err != nil {
			fmt.Printf("Web Server Listen error: %v\n", err)
		}
	}()
}

// ═══════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) getAuthenticatedUser(r *http.Request) *db.User {
	apiToken := r.Header.Get("X-API-Token")
	if apiToken == "" {
		apiToken = r.URL.Query().Get("token")
	}
	if apiToken != "" {
		u, err := s.db.GetUserByToken(apiToken)
		if err == nil {
			return u
		}
	}
	return nil
}

// ═══════════════════════════════════════════════
//  API HANDLERS
// ═══════════════════════════════════════════════

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"))

	var req struct {
		UsernameOrEmail string `json:"username_or_email"`
		Password        string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	user, err := s.db.AuthenticateUser(req.UsernameOrEmail, req.Password)
	if err != nil {
		logSecurityEvent("WARN", EventLoginFailed, ip, fmt.Sprintf("login user=%s", req.UsernameOrEmail))
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	logSecurityEvent("INFO", EventLoginSuccess, ip, fmt.Sprintf("login user=%s", user.Username))

	newToken := "enc_" + generateToken()
	if err := s.db.UpdateUserToken(user.ID, newToken); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate session token"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
		"api_token": newToken,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"))

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(req.Username)
	email := strings.TrimSpace(req.Email)

	apiToken := "enc_" + generateToken()

	salt := []byte(email)
	masterKey := argon2.IDKey([]byte(req.Password), salt, 1, 64*1024, 4, 32)

	pubPEM, privPEM, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate keypair"})
		return
	}

	aesGCM := &crypto.AESGCM{}
	wrappedPriv, err := aesGCM.Encrypt([]byte(privPEM), masterKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to encrypt private key"})
		return
	}
	privEncHex := hex.EncodeToString(wrappedPriv)

	user, err := s.db.CreateUser(username, email, req.Password, apiToken, pubPEM, privEncHex)
	if err != nil {
		logSecurityEvent("WARN", EventInvalidInput, ip, fmt.Sprintf("register_failed user=%s reason=%s", username, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	logSecurityEvent("INFO", EventRegister, ip, fmt.Sprintf("user=%s email=%s", user.Username, user.Email))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
		"api_token": user.APIToken,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	keys, _ := s.db.GetKeysByUserID(user.ID)
	algos := make(map[string]bool)
	for _, k := range keys {
		algos[k.Algorithm] = true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user": map[string]string{
			"username": user.Username,
			"email":    user.Email,
		},
		"key_count":    len(keys),
		"algo_count":   len(algos),
		"vault_status": "online",
	})
}

func (s *Server) handleLocalEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	var req struct {
		FolderPath  string `json:"folder_path"`
		Algorithm   string `json:"algorithm"`
		Password    string `json:"password"`
		SyncToVault bool   `json:"sync_to_vault"`
		SecureWipe  bool   `json:"secure_wipe"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	masterKeyHex := r.Header.Get("X-Master-Key")
	if masterKeyHex == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Missing X-Master-Key header"})
		return
	}
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil || len(masterKey) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid X-Master-Key header"})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if _, err := os.Stat(req.FolderPath); os.IsNotExist(err) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Folder does not exist"})
		return
	}

	files, err := fileops.ScanFolder(req.FolderPath)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}

	enc, err := crypto.NewEncryptor(req.Algorithm)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid algorithm"})
		return
	}

	// Envelope Encryption: generate a random file key instead of using Password directly
	fileKey := make([]byte, 32)
	rand.Read(fileKey)
	fileKeyHex := hex.EncodeToString(fileKey)

	// Encrypt using fileKey
	success, failed, errs := fileops.EncryptFolder(req.FolderPath, enc, fileKeyHex, nil, req.SecureWipe)

	if req.SyncToVault {
		// Encrypt fileKey using X-Master-Key
		aesGCM := &crypto.AESGCM{}
		wrappedKey, err := aesGCM.Encrypt(fileKey, masterKey)
		if err == nil {
			wrappedKeyHex := hex.EncodeToString(wrappedKey)

			// Encrypt user's password with masterKey before storing — only owner can decrypt it
			var encPasswordHex string
			if req.Password != "" {
				encPassBytes, encErr := aesGCM.Encrypt([]byte(req.Password), masterKey)
				if encErr == nil {
					encPasswordHex = hex.EncodeToString(encPassBytes)
				}
			}

			s.db.CreateKey(user.ID, enc.Name()+" - "+filepath.Base(req.FolderPath), enc.Name(), wrappedKeyHex, req.FolderPath, user.Username, encPasswordHex)
		}
	}

	var errStrs []string
	for _, e := range errs {
		errStrs = append(errStrs, e.Error())
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       success,
		"failed":        failed,
		"errors":        errStrs,
		"files_scanned": len(files),
	})
}

func (s *Server) handleLocalDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	var req struct {
		FolderPath string `json:"folder_path"`
		Password   string `json:"password"` // Kept for backwards compatibility if no vault key, but normally unused with envelope
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	masterKeyHex := r.Header.Get("X-Master-Key")
	if masterKeyHex == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Missing X-Master-Key header"})
		return
	}
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil || len(masterKey) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid X-Master-Key header"})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Normalize path: if path is an original file (e.g. file.pdf) that no longer
	// exists but file.pdf.enc does, use the .enc version directly.
	targetPath := req.FolderPath
	info, statErr := os.Stat(targetPath)

	if os.IsNotExist(statErr) {
		// Maybe the original file was encrypted — try appending .enc
		encPath := targetPath + fileops.EncryptedExt
		if _, err2 := os.Stat(encPath); err2 == nil {
			targetPath = encPath
			info, statErr = os.Stat(targetPath)
		} else {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "Path tidak ditemukan: " + req.FolderPath})
			return
		}
	}

	if statErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": statErr.Error()})
		return
	}

	// Auto-mark matching key in vault as decrypted and find the file key
	keys, _ := s.db.GetKeysByUserID(user.ID)

	// Default to request password if not using vault
	actualKeyToUse := req.Password

	// The Vault DB stores the original file path (e.g., test.txt).
	// But targetPath might be test.txt.fay. We need to strip .fay for matching.
	dbLookupPath := targetPath
	if strings.HasSuffix(dbLookupPath, fileops.EncryptedExt) {
		dbLookupPath = strings.TrimSuffix(dbLookupPath, fileops.EncryptedExt)
	}

	for _, k := range keys {
		if k.FilePath == req.FolderPath || k.FilePath == dbLookupPath {
			wrappedKey, err := hex.DecodeString(k.WrappedFileKeyOwner)
			if err == nil {
				aesGCM := &crypto.AESGCM{}
				fileKey, err := aesGCM.Decrypt(wrappedKey, masterKey)
				if err == nil {
					actualKeyToUse = string(fileKey)
					s.db.MarkKeyDecrypted(k.ID, user.ID)
					break
				}
			}
		}
	}

	var success, failed int
	var errs []error

	if !info.IsDir() {
		// Single file decrypt
		if err := fileops.DecryptFile(targetPath, actualKeyToUse); err != nil {
			failed = 1
			errs = []error{err}
		} else {
			success = 1
		}
	} else {
		// Folder decrypt
		success, failed, errs = fileops.DecryptFolder(targetPath, actualKeyToUse, nil)
	}

	if success > 0 {
		s.db.LogAudit(user.ID, "DECRYPT", targetPath)
	}

	var errStrs []string
	for _, e := range errs {
		errStrs = append(errStrs, e.Error())
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": success,
		"failed":  failed,
		"errors":  errStrs,
	})
}

func (s *Server) handleVaultUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	masterKeyHex := r.Header.Get("X-Master-Key")
	if masterKeyHex == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Missing X-Master-Key header"})
		return
	}
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil || len(masterKey) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid X-Master-Key header"})
		return
	}

	var req struct {
		FilePath  string `json:"file_path"`
		Algorithm string `json:"algorithm"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if _, err := os.Stat(req.FilePath); os.IsNotExist(err) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "File does not exist"})
		return
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "aes-gcm"
	}

	enc, err := crypto.NewEncryptor(algorithm)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid algorithm"})
		return
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Failed to generate salt"})
		return
	}

	fileKey := make([]byte, 32)
	rand.Read(fileKey)
	fileKeyStr := hex.EncodeToString(fileKey)
	actualKey := crypto.DeriveKey(fileKeyStr, salt, enc.KeySize())

	encBytes, err := fileops.EncryptFileToMemory(req.FilePath, enc, actualKey, salt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Failed to encrypt file: " + err.Error()})
		return
	}

	aesGCM := &crypto.AESGCM{}
	wrappedKey, err := aesGCM.Encrypt([]byte(fileKeyStr), masterKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Failed to wrap key"})
		return
	}
	wrappedKeyHex := hex.EncodeToString(wrappedKey)

	vaultFilePath := "db://vault"
	originalName := filepath.Base(req.FilePath)
	vaultKeyName := fmt.Sprintf("%d-%s-%s", time.Now().Unix(), user.Username, originalName)

	// Encrypt user's password with masterKey before storing — only owner can decrypt it
	var encPasswordHex string
	if req.Password != "" {
		aesGCMCipher := &crypto.AESGCM{}
		encPassBytes, encErr := aesGCMCipher.Encrypt([]byte(req.Password), masterKey)
		if encErr == nil {
			encPasswordHex = hex.EncodeToString(encPassBytes)
		}
	}

	keyObj, err := s.db.CreateKey(user.ID, vaultKeyName, algorithm, wrappedKeyHex, vaultFilePath, user.Username, encPasswordHex)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Failed to store key in db"})
		return
	}

	if err := s.db.SaveVaultFile(keyObj.ID, encBytes); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Failed to save file to db"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "File uploaded to vault successfully",
	})
}

func (s *Server) handleVaultDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	var req struct {
		KeyID         int64  `json:"key_id"`
		SharePassword string `json:"share_password"`
		Password      string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	masterKeyHex := r.Header.Get("X-Master-Key")
	if masterKeyHex == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Missing X-Master-Key header"})
		return
	}
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil || len(masterKey) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid X-Master-Key header"})
		return
	}

	k, err := s.db.GetKeyByID(req.KeyID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Key not found"})
		return
	}

	if k.UserID != user.ID && !s.db.HasSharedAccess(k.ID, user.ID) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Access denied"})
		return
	}

	if k.FilePath != "db://vault" && !strings.Contains(filepath.ToSlash(k.FilePath), "storage/vault/") {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Not a vault file"})
		return
	}

	var fileKeyBytes []byte
	var activeShare *db.FileShare

	if k.UserID == user.ID {
		// Validasi password enkripsi jika file belum berstatus 'decrypted'
		if k.Status != "decrypted" {
			if k.EncryptionPassword != "" && req.Password != "" {
				encPassHex, _ := hex.DecodeString(k.EncryptionPassword)
				if len(encPassHex) > 0 {
					aesGCM := &crypto.AESGCM{}
					actualPass, err := aesGCM.Decrypt(encPassHex, masterKey)
					if err == nil && req.Password != string(actualPass) {
						w.WriteHeader(http.StatusForbidden)
						json.NewEncoder(w).Encode(map[string]interface{}{"error": "Password enkripsi salah. Masukkan password yang Anda buat saat mengenkripsi file ini."})
						return
					}
				}
			} else if k.EncryptionPassword != "" && req.Password == "" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Password enkripsi diperlukan."})
				return
			}
		} else {
			// Jika sudah 'decrypted', jika user menyertakan password maka verifikasi (opsional)
			if k.EncryptionPassword != "" && req.Password != "" {
				encPassHex, _ := hex.DecodeString(k.EncryptionPassword)
				if len(encPassHex) > 0 {
					aesGCM := &crypto.AESGCM{}
					actualPass, err := aesGCM.Decrypt(encPassHex, masterKey)
					if err == nil && req.Password != string(actualPass) {
						w.WriteHeader(http.StatusForbidden)
						json.NewEncoder(w).Encode(map[string]interface{}{"error": "Password enkripsi salah."})
						return
					}
				}
			}
		}

		wrappedKey, err := hex.DecodeString(k.WrappedFileKeyOwner)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid key data"})
			return
		}
		aesGCM := &crypto.AESGCM{}
		fileKeyBytes, err = aesGCM.Decrypt(wrappedKey, masterKey)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "Failed to unwrap key with master key"})
			return
		}
	} else {
		fs, err := s.db.GetActiveShare(k.ID, user.ID)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "No active share found"})
			return
		}
		activeShare = fs

		if fs.AccessMethod == "password" {
			shareIDStr := strconv.FormatInt(fs.ID, 10)
			if !s.shareLimiter.isAllowed(shareIDStr) {
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Terlalu banyak percobaan pada share ini. Coba lagi nanti."})
				return
			}
			if req.SharePassword == "" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Password required for this share", "require_password": true})
				return
			}

			salt, err := hex.DecodeString(fs.PasswordSalt)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid salt data in share"})
				return
			}
			wrapKey := argon2.IDKey([]byte(req.SharePassword), salt, 1, 64*1024, 4, 32)
			wrappedForMe, _ := hex.DecodeString(fs.WrappedKeyForPassword)

			aesGCM := &crypto.AESGCM{}
			fileKeyBytes, err = aesGCM.Decrypt(wrappedForMe, wrapKey)
			if err != nil {
				s.db.LogAudit(user.ID, "SHARE_ACCESS_FAILED", "Failed attempt on share "+shareIDStr)
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Password share salah"})
				return
			}
		} else {
			privEnc, err := hex.DecodeString(user.PrivateKeyEnc)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid private key data"})
				return
			}

			aesGCM := &crypto.AESGCM{}
			privPEM, err := aesGCM.Decrypt(privEnc, masterKey)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Failed to unwrap private key"})
				return
			}

			wrappedForMe, err := hex.DecodeString(fs.WrappedKeyForRecipient)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid wrapped key for recipient"})
				return
			}

			fileKeyBytes, err = crypto.DecryptRSA(string(privPEM), wrappedForMe)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "Failed to decrypt file key"})
				return
			}
		}
	}
	fileKeyStr := string(fileKeyBytes)

	encBytes, err := s.db.GetVaultFile(k.ID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Vault file data not found"})
		return
	}

	if len(encBytes) < 6 {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid encrypted file data"})
		return
	}
	algoID := encBytes[5]

	enc, err := crypto.NewEncryptorByID(algoID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Unsupported algorithm"})
		return
	}

	fileNameLen := binary.LittleEndian.Uint16(encBytes[6:8])
	saltOffset := 8 + int(fileNameLen)
	if len(encBytes) < saltOffset+16 {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid encrypted file data (salt)"})
		return
	}
	salt := encBytes[saltOffset : saltOffset+16]

	key := crypto.DeriveKey(fileKeyStr, salt, enc.KeySize())
	defer security.ZeroBytes(key)

	plaintext, err := fileops.DecryptFileFromMemory(encBytes, key, enc)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Decryption failed: " + err.Error()})
		return
	}
	security.ZeroBytes(key)

	// Update status di DB jadi 'decrypted'
	if err := s.db.MarkKeyDecrypted(k.ID, user.ID); err != nil {
		fmt.Println("Warning: Failed to mark key as decrypted:", err)
	}

	if activeShare != nil && activeShare.OneTimeView {
		_ = s.db.RevokeFileShare(activeShare.ID)
		s.db.LogAudit(user.ID, "SHARE_BURNED", fmt.Sprintf("File share ID %d otomatis dihancurkan setelah 1x dibuka oleh %s", activeShare.ID, user.Username))
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", k.KeyName))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(plaintext)))
	w.Write(plaintext)
}

func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		var keys []db.Key
		var err error
		if r.URL.Query().Get("mine") == "true" || r.URL.Query().Get("author_only") == "true" {
			keys, err = s.db.GetOwnedKeysByUserID(user.ID)
		} else {
			keys, err = s.db.GetKeysByUserID(user.ID)
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "An internal error occurred"})
			return
		}
		json.NewEncoder(w).Encode(keys)

	case http.MethodPost:
		var req struct {
			KeyName   string `json:"key_name"`
			Algorithm string `json:"algorithm"`
			KeyValue  string `json:"key_value"`
			FilePath  string `json:"file_path"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
			return
		}

		if req.KeyName == "" || req.KeyValue == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "key_name and key_value are required"})
			return
		}

		if len(req.KeyName) > 200 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "key_name exceeds maximum length (200 chars)"})
			return
		}
		if len(req.KeyValue) > 1000 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "key_value exceeds maximum length (1000 chars)"})
			return
		}
		if len(req.FilePath) > 500 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "file_path exceeds maximum length (500 chars)"})
			return
		}

		if req.Algorithm == "" {
			req.Algorithm = "AES-256-GCM"
		}

		key, err := s.db.CreateKey(user.ID, req.KeyName, req.Algorithm, req.KeyValue, req.FilePath, user.Username, "")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to store key"})
			return
		}

		json.NewEncoder(w).Encode(key)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPIKeyByID(w http.ResponseWriter, r *http.Request) {
	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/keys/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Key ID"})
		return
	}

	keyID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Key ID format"})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodPut:
		var req struct {
			KeyName            string  `json:"key_name"`
			KeyValue           string  `json:"key_value"`
			Password           *string `json:"password"`
			EncryptionPassword *string `json:"encryption_password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
			return
		}

		if len(req.KeyName) > 200 || len(req.KeyValue) > 1000 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Input exceeds maximum allowed length"})
			return
		}

		if req.Password != nil {
			var encPasswordHex string
			if *req.Password != "" {
				masterKeyHex := r.Header.Get("X-Master-Key")
				if masterKeyHex == "" {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{"error": "Missing X-Master-Key header"})
					return
				}
				masterKey, err := hex.DecodeString(masterKeyHex)
				if err != nil || len(masterKey) != 32 {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{"error": "Invalid X-Master-Key header"})
					return
				}
				aesGCMCipher := &crypto.AESGCM{}
				encPassBytes, encErr := aesGCMCipher.Encrypt([]byte(*req.Password), masterKey)
				if encErr != nil {
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": "Failed to encrypt password"})
					return
				}
				encPasswordHex = hex.EncodeToString(encPassBytes)
			}
			if err := s.db.UpdateKeyPassword(keyID, user.ID, encPasswordHex); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			s.db.LogAudit(user.ID, "UPDATE_KEY_PASSWORD", fmt.Sprintf("Password encryption untuk Key ID %d diperbarui oleh %s", keyID, user.Username))
		} else if req.EncryptionPassword != nil {
			if err := s.db.UpdateKeyPassword(keyID, user.ID, *req.EncryptionPassword); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			s.db.LogAudit(user.ID, "UPDATE_KEY_PASSWORD", fmt.Sprintf("Password encryption untuk Key ID %d diperbarui oleh %s", keyID, user.Username))
		}

		if req.KeyName != "" || req.KeyValue != "" {
			if err := s.db.UpdateKey(keyID, user.ID, req.KeyName, req.KeyValue); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]string{"status": "success"})

	case http.MethodDelete:
		if err := s.db.DeleteOrRemoveKey(keyID, user.ID); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		s.db.LogAudit(user.ID, "DELETE_FILE", fmt.Sprintf("File/Key ID %d dihapus oleh %s", keyID, user.Username))
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleOrgs(w http.ResponseWriter, r *http.Request) {
	user := s.getAuthenticatedUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		orgs, err := s.db.GetUserOrganizations(user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(orgs)

	case http.MethodPost:
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		org, err := s.db.CreateOrganization(req.Name, req.Description, user.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(org)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleOrgMembers(w http.ResponseWriter, r *http.Request) {
	user := s.getAuthenticatedUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/orgs/"), "/")
	if len(parts) != 2 || parts[1] != "members" {
		http.Error(w, "Invalid route", http.StatusBadRequest)
		return
	}

	orgID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "Invalid Org ID", http.StatusBadRequest)
		return
	}

	members, err := s.db.GetOrganizationMembers(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(members)
}

func (s *Server) handleLeaveOrg(w http.ResponseWriter, r *http.Request) {
	user := s.getAuthenticatedUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/orgs/"), "/")
	if len(parts) != 2 || parts[1] != "leave" {
		http.Error(w, "Invalid route", http.StatusBadRequest)
		return
	}

	orgID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "Invalid Org ID", http.StatusBadRequest)
		return
	}

	if err := s.db.LeaveOrganization(orgID, user.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleSearchUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		json.NewEncoder(w).Encode([]db.UserSearchResult{})
		return
	}

	if len(query) > 50 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Query too long"})
		return
	}

	results, err := s.db.SearchUsers(query, user.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to search users"})
		return
	}

	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleConnectionRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}
	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON format"})
		return
	}
	recipient, err := s.db.GetUserByUsername(req.Username)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Pengguna dengan username '" + req.Username + "' tidak ditemukan"})
		return
	}
	if err := s.db.RequestConnection(user.ID, recipient.ID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	s.db.CreateNotification(recipient.ID, "connection_request", "Permintaan Pertemanan", fmt.Sprintf("%s mengirimkan permintaan pertemanan kepada Anda", user.Username), user.ID)

	json.NewEncoder(w).Encode(map[string]string{"status": "requested"})
}

func (s *Server) handleConnectionAccept(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}
	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}
	var req struct {
		ConnectionID int64 `json:"connection_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	// Cari requester_id untuk dikirimi notifikasi
	var requesterID int64
	conns, _ := s.db.GetConnections(user.ID)
	for _, c := range conns {
		if c.ID == req.ConnectionID {
			if c.RequesterID == user.ID {
				requesterID = c.RecipientID
			} else {
				requesterID = c.RequesterID
			}
			break
		}
	}

	if err := s.db.AcceptConnection(req.ConnectionID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if requesterID > 0 {
		_ = s.db.CreateNotification(requesterID, "connection_accepted", "Permintaan Pertemanan Diterima", fmt.Sprintf("%s telah menerima permintaan pertemanan Anda", user.Username), user.ID)
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

func (s *Server) handleConnectionReject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}
	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}
	var req struct {
		ConnectionID int64 `json:"connection_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if err := s.db.RejectConnection(req.ConnectionID, user.ID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "rejected"})
}

func (s *Server) handleConnectionRemove(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}
	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}
	var req struct {
		ConnectionID int64 `json:"connection_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if err := s.db.RemoveConnection(req.ConnectionID, user.ID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user := s.getAuthenticatedUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	conns, err := s.db.GetConnections(user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conns)
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	// Jika SSE stream
	isSSE := strings.Contains(r.URL.Path, "/stream") || r.Header.Get("Accept") == "text/event-stream"
	if isSSE {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Kirim data awal notifikasi langsung
		initialNotifs, _ := s.db.GetNotifications(user.ID)
		var lastNotifID int64
		for _, n := range initialNotifs {
			if n.ID > lastNotifID {
				lastNotifID = n.ID
			}
		}
		if initialNotifs != nil {
			data, _ := json.Marshal(map[string]interface{}{"notifications": initialNotifs})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}

		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				notifs, err := s.db.GetNotifications(user.ID)
				if err != nil {
					continue
				}

				var newNotifs []db.Notification
				var maxID int64
				for _, n := range notifs {
					if n.ID > lastNotifID {
						newNotifs = append(newNotifs, n)
						if n.ID > maxID {
							maxID = n.ID
						}
					}
				}

				if len(newNotifs) > 0 {
					if maxID > lastNotifID {
						lastNotifID = maxID
					}
					// Kirim full list notifikasi terbaru agar UI selalu sinkron
					data, _ := json.Marshal(map[string]interface{}{"notifications": notifs})
					fmt.Fprintf(w, "data: %s\n\n", data)
					flusher.Flush()
				}
			}
		}
	}

	// Regular GET JSON
	notifs, err := s.db.GetNotifications(user.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifs)
}

func (s *Server) handleNotificationsRead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}
	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	var req struct {
		ID  int64 `json:"id"`
		All bool  `json:"all"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.ID > 0 {
		if err := s.db.MarkNotificationReadByID(req.ID, user.ID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
	} else if req.All {
		if err := s.db.MarkNotificationsRead(user.ID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Field 'id' atau 'all': true diperlukan"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "marked read"})
}

func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}
	user := s.getAuthenticatedUser(r)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}
	masterKeyHex := r.Header.Get("X-Master-Key")
	if masterKeyHex == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing X-Master-Key header"})
		return
	}
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil || len(masterKey) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid X-Master-Key header"})
		return
	}

	var req struct {
		KeyID             int64      `json:"key_id"`
		RecipientUsername string     `json:"recipient_username"`
		Scope             string     `json:"scope"`
		MaxForwardCount   int        `json:"max_forward_count"`
		ExpiresInSeconds  int64      `json:"expires_in_seconds"`
		ExpiresAt         *time.Time `json:"expires_at"`
		OneTimeView       bool       `json:"one_time_view"`
		ShareID           int64      `json:"share_id"` // if forwarding an existing share
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON format"})
		return
	}
	recipient, err := s.db.GetUserByUsername(req.RecipientUsername)
	if err != nil {
		// Fallback jika dikirim berupa user ID
		if uid, convErr := strconv.ParseInt(req.RecipientUsername, 10, 64); convErr == nil {
			recipient, err = s.db.GetUserByID(uid)
		}
	}
	if err != nil || recipient == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Penerima tidak ditemukan: " + req.RecipientUsername})
		return
	}

	keyObj, err := s.db.GetKeyByID(req.KeyID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Key not found in vault"})
		return
	}

	maxForwardCount := req.MaxForwardCount
	scope := req.Scope
	expiresAt := req.ExpiresAt
	if req.ExpiresInSeconds > 0 {
		exp := time.Now().Add(time.Duration(req.ExpiresInSeconds) * time.Second)
		expiresAt = &exp
	}

	var rawFileKey []byte

	// Chain of Custody logic for forwarding
	if req.ShareID > 0 {
		fs, err := s.db.GetFileShare(req.ShareID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Original share not found"})
			return
		}
		if fs.RecipientID != user.ID {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized to forward this share"})
			return
		}
		if fs.RevokedAt != nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Share has been revoked"})
			return
		}
		if fs.ExpiresAt != nil && fs.ExpiresAt.Before(time.Now()) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Share has expired"})
			return
		}
		if fs.CurrentForwardCount >= fs.MaxForwardCount {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Maximum forward count reached"})
			return
		}

		privEnc, _ := hex.DecodeString(user.PrivateKeyEnc)
		aesGCM := &crypto.AESGCM{}
		privPEM, err := aesGCM.Decrypt(privEnc, masterKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to unwrap private key"})
			return
		}

		wrappedForMe, _ := hex.DecodeString(fs.WrappedKeyForRecipient)
		rawFileKey, err = crypto.DecryptRSA(string(privPEM), wrappedForMe)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to decrypt file key"})
			return
		}

		// Increment forward count
		s.db.IncrementForwardCount(fs.ID)

		// Inherit constraints, reduce max forward
		maxForwardCount = fs.MaxForwardCount - fs.CurrentForwardCount - 1
		if maxForwardCount < 0 {
			maxForwardCount = 0
		}
		scope = fs.Scope
		expiresAt = fs.ExpiresAt
	} else {
		if keyObj.UserID != user.ID {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized to share this key"})
			return
		}

		wrappedFileKey, _ := hex.DecodeString(keyObj.WrappedFileKeyOwner)
		aesGCM := &crypto.AESGCM{}
		rawFileKey, err = aesGCM.Decrypt(wrappedFileKey, masterKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to unwrap file key"})
			return
		}
	}

	accessMethod := "password" // Default to password as requested
	var wrappedForRecipientHex, wrappedKeyForPasswordHex, passwordSaltHex string
	var sharePassword string

	if accessMethod == "password" {
		// Generate 12-char random alphanumeric password
		const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate password"})
			return
		}
		for i := range b {
			b[i] = letters[b[i]%byte(len(letters))]
		}
		sharePassword = string(b)

		// Generate 16-byte salt
		salt := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate salt"})
			return
		}
		passwordSaltHex = hex.EncodeToString(salt)

		// Derive wrapping key using Argon2id
		wrapKey := argon2.IDKey([]byte(sharePassword), salt, 1, 64*1024, 4, 32)

		// Wrap the rawFileKey using AES-GCM
		aesGCM := &crypto.AESGCM{}
		wrapped, err := aesGCM.Encrypt(rawFileKey, wrapKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to wrap key with password"})
			return
		}
		wrappedKeyForPasswordHex = hex.EncodeToString(wrapped)
	} else {
		wrappedForRecipient, err := crypto.EncryptRSA(recipient.PublicKey, rawFileKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to re-wrap file key for recipient"})
			return
		}
		wrappedForRecipientHex = hex.EncodeToString(wrappedForRecipient)
	}

	if _, err := s.db.CreateFileShare(req.KeyID, user.ID, recipient.ID, maxForwardCount, scope, accessMethod, req.OneTimeView, wrappedForRecipientHex, wrappedKeyForPasswordHex, passwordSaltHex, expiresAt); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to store share: " + err.Error()})
		return
	}
	// NO password in notification message!
	s.db.CreateNotification(recipient.ID, "file_share", "New File Shared", fmt.Sprintf("%s shared a file with you", user.Username), req.KeyID)

	s.db.LogAudit(user.ID, "SHARE", fmt.Sprintf("Shared key %d with %s (method: %s, one_time_view: %v)", req.KeyID, req.RecipientUsername, accessMethod, req.OneTimeView))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "shared",
		"share_password": sharePassword,
		"one_time_view":  req.OneTimeView,
		"expires_at":     expiresAt,
	})
}

func (s *Server) handleKDF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Password string `json:"password"`
		Salt     string `json:"salt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Argon2id parameters
	timeParam := uint32(1)
	memory := uint32(64 * 1024)
	threads := uint8(4)
	keyLen := uint32(32)

	hashBytes := argon2.IDKey([]byte(req.Password), []byte(req.Salt), timeParam, memory, threads, keyLen)
	hashHex := hex.EncodeToString(hashBytes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"master_key": hashHex})
}
