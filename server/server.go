package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"encryptor/crypto"
	"encryptor/db"
	"encryptor/fileops"
)

type Server struct {
	db           *db.DB
	port         string
	csrf         *csrfManager
	loginLimiter *rateLimiter
	apiLimiter   *rateLimiter
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

		// Key Vault
		mux.HandleFunc("/api/keys", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleAPIKeys)))
		mux.HandleFunc("/api/keys/", limitBody(rateLimitMiddleware(s.apiLimiter, s.handleAPIKeyByID)))

		// Serve React Web frontend from web/dist
		fs := http.FileServer(http.Dir("web/dist"))
		mux.Handle("/", fs)

		// Wrap all routes with security headers and CORS
		handler := corsMiddleware(securityHeaders(mux))

		if err := http.ListenAndServe(":"+s.port, handler); err != nil {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":  user.Username,
		"email":     user.Email,
		"api_token": user.APIToken,
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

	user, err := s.db.CreateUser(username, email, req.Password, apiToken)
	if err != nil {
		logSecurityEvent("WARN", EventInvalidInput, ip, fmt.Sprintf("register_failed user=%s reason=%s", username, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	logSecurityEvent("INFO", EventRegister, ip, fmt.Sprintf("user=%s email=%s", user.Username, user.Email))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":  user.Username,
		"email":     user.Email,
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
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
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

	success, failed, errs := fileops.EncryptFolder(req.FolderPath, enc, req.Password, nil)

	if req.SyncToVault {
		s.db.CreateKey(user.ID, enc.Name()+" - "+filepath.Base(req.FolderPath), enc.Name(), req.Password, req.FolderPath)
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
		Password   string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
    
    w.Header().Set("Content-Type", "application/json")

	files, err := fileops.ScanEncryptedFiles(req.FolderPath)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
        return
    }

	success, failed, errs := fileops.DecryptFolder(req.FolderPath, req.Password, nil)

	// Auto-delete matching key from vault (compare password)
	keys, _ := s.db.GetKeysByUserID(user.ID)
	for _, k := range keys {
		if k.KeyValue == req.Password {
			s.db.DeleteKey(k.ID, user.ID)
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
		keys, err := s.db.GetKeysByUserID(user.ID)
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

		key, err := s.db.CreateKey(user.ID, req.KeyName, req.Algorithm, req.KeyValue, req.FilePath)
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
			KeyName  string `json:"key_name"`
			KeyValue string `json:"key_value"`
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

		if err := s.db.UpdateKey(keyID, user.ID, req.KeyName, req.KeyValue); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"status": "success"})

	case http.MethodDelete:
		if err := s.db.DeleteKey(keyID, user.ID); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"status": "success"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
