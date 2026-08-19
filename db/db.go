package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"unicode"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash  string    `json:"-"`
	PublicKey     string    `json:"public_key"`
	PrivateKeyEnc string    `json:"-"`
	APIToken      string    `json:"api_token"`
	CreatedAt     time.Time `json:"created_at"`
}

type Key struct {
	ID                  int64      `json:"id"`
	UserID              int64      `json:"user_id"`
	KeyName             string     `json:"key_name"`
	Algorithm           string     `json:"algorithm"`
	WrappedFileKeyOwner string     `json:"wrapped_file_key_owner"`
	EncryptionPassword  string     `json:"encryption_password"`
	FilePath            string     `json:"file_path"`
	Author              string     `json:"author"`       // username of who encrypted
	Status              string     `json:"status"`       // "encrypted" or "decrypted"
	DecryptedAt         *time.Time `json:"decrypted_at"` // nullable
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type Organization struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedBy   int64     `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

type Connection struct {
	ID          int64     `json:"id"`
	RequesterID int64     `json:"requester_id"`
	RecipientID int64     `json:"recipient_id"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type Notification struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	RelatedID int64     `json:"related_id"`
	IsRead    bool      `json:"is_read"`
	CreatedAt time.Time `json:"created_at"`
}

type FileShare struct {
	ID                  int64      `json:"id"`
	KeyID               int64      `json:"key_id"`
	SenderID            int64      `json:"sender_id"`
	RecipientID         int64      `json:"recipient_id"`
	MaxForwardCount     int        `json:"max_forward_count"`
	CurrentForwardCount int        `json:"current_forward_count"`
	Scope                  string     `json:"scope"`
	AccessMethod           string     `json:"access_method"` // 'password' or 'keypair'
	WrappedKeyForRecipient string     `json:"wrapped_key_for_recipient"`
	WrappedKeyForPassword  string     `json:"wrapped_key_for_password"`
	PasswordSalt           string     `json:"password_salt"`
	ExpiresAt              *time.Time `json:"expires_at"`
	RevokedAt           *time.Time `json:"revoked_at"`
	CreatedAt           time.Time  `json:"created_at"`
}

type DB struct {
	conn *sql.DB
}

var instance *DB

// InitDB initializes the SQLite database
func InitDB(dbPath string) (*DB, error) {
	if dbPath == "" {
		dbPath = "encryptor_vault.db"
	}

	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	d := &DB{conn: conn}
	if err := d.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	instance = d
	return d, nil
}

func GetDB() *DB {
	return instance
}

func (d *DB) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

func (d *DB) createTables() error {
	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		public_key TEXT,
		private_key_enc TEXT,
		api_token TEXT UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	keysTable := `
	CREATE TABLE IF NOT EXISTS keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		key_name TEXT NOT NULL,
		algorithm TEXT NOT NULL,
		wrapped_file_key_owner TEXT NOT NULL,
		encryption_password TEXT DEFAULT '',
		file_path TEXT DEFAULT '',
		author TEXT DEFAULT '',
		status TEXT DEFAULT 'encrypted',
		decrypted_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);`

	organizationsTable := `
	CREATE TABLE IF NOT EXISTS organizations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	orgMembersTable := `
	CREATE TABLE IF NOT EXISTS organization_members (
		org_id INTEGER,
		user_id INTEGER,
		role TEXT,
		joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY(org_id, user_id)
	);`

	connectionsTable := `
	CREATE TABLE IF NOT EXISTS connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		requester_id INTEGER,
		recipient_id INTEGER,
		status TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	notificationsTable := `
	CREATE TABLE IF NOT EXISTS notifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		type TEXT,
		title TEXT,
		message TEXT,
		related_id INTEGER,
		is_read BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	fileSharesTable := `
	CREATE TABLE IF NOT EXISTS file_shares (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key_id INTEGER,
		sender_id INTEGER,
		recipient_id INTEGER,
		max_forward_count INTEGER DEFAULT 0,
		current_forward_count INTEGER DEFAULT 0,
		scope TEXT,
		access_method TEXT DEFAULT 'password',
		wrapped_key_for_recipient TEXT,
		wrapped_key_for_password TEXT,
		password_salt TEXT,
		expires_at DATETIME,
		revoked_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	auditLogsTable := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		action TEXT,
		details TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	vaultFilesTable := `
	CREATE TABLE IF NOT EXISTS vault_files (
		key_id INTEGER PRIMARY KEY,
		file_data BLOB NOT NULL,
		FOREIGN KEY(key_id) REFERENCES keys(id) ON DELETE CASCADE
	);`

	for _, q := range []string{userTable, keysTable, organizationsTable, orgMembersTable, connectionsTable, notificationsTable, fileSharesTable, auditLogsTable, vaultFilesTable} {
		if _, err := d.conn.Exec(q); err != nil {
			return err
		}
	}
	// Migration: add columns if they don't exist (SQLite safe approach)
	_ = d.conn.QueryRow("SELECT author FROM keys LIMIT 1").Scan(new(string))
	for _, col := range []string{
		"ALTER TABLE keys ADD COLUMN author TEXT DEFAULT ''",
		"ALTER TABLE keys ADD COLUMN status TEXT DEFAULT 'encrypted'",
		"ALTER TABLE keys ADD COLUMN decrypted_at DATETIME",
	} {
		_, _ = d.conn.Exec(col) // ignore errors (column may already exist)
	}
	for _, col := range []string{
		"ALTER TABLE keys RENAME COLUMN key_value TO wrapped_file_key_owner",
	} {
		_, _ = d.conn.Exec(col)
	}
	for _, col := range []string{
		"ALTER TABLE users ADD COLUMN public_key TEXT",
		"ALTER TABLE users ADD COLUMN private_key_enc TEXT",
		"ALTER TABLE file_shares ADD COLUMN wrapped_key_for_recipient TEXT",
		"ALTER TABLE file_shares ADD COLUMN max_forward_count INTEGER DEFAULT 0",
		"ALTER TABLE file_shares ADD COLUMN current_forward_count INTEGER DEFAULT 0",
		"ALTER TABLE file_shares ADD COLUMN scope TEXT",
		"ALTER TABLE file_shares ADD COLUMN expires_at DATETIME",
		"ALTER TABLE file_shares ADD COLUMN revoked_at DATETIME",
		"ALTER TABLE keys ADD COLUMN encryption_password TEXT DEFAULT ''",
		"ALTER TABLE file_shares ADD COLUMN access_method TEXT DEFAULT 'password'",
		"ALTER TABLE file_shares ADD COLUMN wrapped_key_for_password TEXT",
		"ALTER TABLE file_shares ADD COLUMN password_salt TEXT",
	} {
		_, _ = d.conn.Exec(col) // ignore errors
	}
	return nil
}

// ═══════════════════════════════════════════════
//  INPUT VALIDATION (OWASP A03, A07)
// ═══════════════════════════════════════════════

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// validateUsername checks username format: 3-30 chars, alphanumeric + underscores
func validateUsername(username string) error {
	if len(username) < 3 || len(username) > 30 {
		return errors.New("username must be between 3 and 30 characters")
	}
	if !usernameRegex.MatchString(username) {
		return errors.New("username can only contain letters, numbers, and underscores")
	}
	return nil
}

// validateEmail checks email format using net/mail
func validateEmail(email string) error {
	if len(email) > 254 {
		return errors.New("email address is too long")
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("invalid email address format")
	}
	return nil
}

// validatePassword enforces password strength: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit
func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	if len(password) > 128 {
		return errors.New("password exceeds maximum length (128 characters)")
	}
	var hasUpper, hasLower, hasDigit bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return errors.New("password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number")
	}
	return nil
}

// User methods

func (d *DB) CreateUser(username, email, password, apiToken, publicKey, privateKeyEnc string) (*User, error) {
	// Validate inputs (A03, A07)
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if err := validateEmail(email); err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	// Argon2id hash (fixed params: time=1, mem=64*1024, threads=4, keyLen=32)
	salt := []byte(email) // simple deterministic salt based on email
	hashBytes := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	hash := hex.EncodeToString(hashBytes)

	// SHA-256 for api_token
	tokenHashBytes := sha256.Sum256([]byte(apiToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	now := time.Now()
	res, err := d.conn.Exec(
		`INSERT INTO users (username, email, password_hash, public_key, private_key_enc, api_token, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		username, email, string(hash), publicKey, privateKeyEnc, tokenHash, now,
	)
	if err != nil {
		return nil, fmt.Errorf("username or email already exists")
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &User{
		ID:            id,
		Username:      username,
		Email:         email,
		PublicKey:     publicKey,
		PrivateKeyEnc: privateKeyEnc,
		APIToken:      apiToken,
		CreatedAt:     now,
	}, nil
}

func (d *DB) AuthenticateUser(usernameOrEmail, password string) (*User, error) {
	var u User
	err := d.conn.QueryRow(
		`SELECT id, username, email, password_hash, COALESCE(public_key, ''), COALESCE(private_key_enc, ''), api_token, created_at FROM users WHERE username = ? OR email = ?`,
		usernameOrEmail, usernameOrEmail,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.PublicKey, &u.PrivateKeyEnc, &u.APIToken, &u.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid username/email or password")
		}
		return nil, err
	}

	// verify with Argon2id
	salt := []byte(u.Email)
	hashBytes := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	expectedHash := hex.EncodeToString(hashBytes)
	
	if u.PasswordHash != expectedHash {
		// fallback to bcrypt just in case migrating? Let's just do Argon2id
		if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
			return nil, errors.New("invalid username/email or password")
		}
	}

	return &u, nil
}

func (d *DB) GetUserByToken(token string) (*User, error) {
	tokenHashBytes := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	var u User
	err := d.conn.QueryRow(
		`SELECT id, username, email, COALESCE(public_key, ''), COALESCE(private_key_enc, ''), api_token, created_at FROM users WHERE api_token = ?`,
		tokenHash,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PublicKey, &u.PrivateKeyEnc, &u.APIToken, &u.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &u, nil
}

func (d *DB) GetUserByID(id int64) (*User, error) {
	var u User
	err := d.conn.QueryRow(
		`SELECT id, username, email, COALESCE(public_key, ''), COALESCE(private_key_enc, ''), api_token, created_at FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PublicKey, &u.PrivateKeyEnc, &u.APIToken, &u.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &u, nil
}

// Key methods

func (d *DB) CreateKey(userID int64, keyName, algorithm, wrappedFileKeyOwner, filePath, author, encryptionPassword string) (*Key, error) {
	now := time.Now()
	res, err := d.conn.Exec(
		`INSERT INTO keys (user_id, key_name, algorithm, wrapped_file_key_owner, encryption_password, file_path, author, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'encrypted', ?, ?)`,
		userID, keyName, algorithm, wrappedFileKeyOwner, encryptionPassword, filePath, author, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &Key{
		ID:                  id,
		UserID:              userID,
		KeyName:             keyName,
		Algorithm:           algorithm,
		WrappedFileKeyOwner: wrappedFileKeyOwner,
		EncryptionPassword:  encryptionPassword,
		FilePath:            filePath,
		Author:              author,
		Status:              "encrypted",
		CreatedAt:           now,
		UpdatedAt:           now,
	}, nil
}

func (d *DB) MarkKeyDecrypted(keyID, userID int64) error {
	now := time.Now()
	_, err := d.conn.Exec(
		`UPDATE keys SET status='decrypted', decrypted_at=?, updated_at=? WHERE id=? AND user_id=?`,
		now, now, keyID, userID,
	)
	return err
}

func (d *DB) GetKeysByUserID(userID int64) ([]Key, error) {
	rows, err := d.conn.Query(
		`SELECT id, user_id, key_name, algorithm, wrapped_file_key_owner, COALESCE(encryption_password,'') as encryption_password, file_path, COALESCE(author,'') as author, COALESCE(status,'encrypted') as status, decrypted_at, created_at, updated_at 
		 FROM keys WHERE user_id = ? 
		 UNION 
		 SELECT k.id, k.user_id, k.key_name, k.algorithm, '' as wrapped_file_key_owner, '' as encryption_password, k.file_path, (SELECT username FROM users WHERE id = k.user_id) as author, 'encrypted' as status, NULL as decrypted_at, fs.created_at, fs.created_at as updated_at 
		 FROM keys k 
		 JOIN file_shares fs ON k.id = fs.key_id 
		 WHERE fs.recipient_id = ? AND (fs.expires_at IS NULL OR fs.expires_at > CURRENT_TIMESTAMP) AND fs.revoked_at IS NULL 
		 ORDER BY updated_at DESC`,
		userID, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.ID, &k.UserID, &k.KeyName, &k.Algorithm, &k.WrappedFileKeyOwner, &k.EncryptionPassword, &k.FilePath, &k.Author, &k.Status, &k.DecryptedAt, &k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}

	if keys == nil {
		keys = []Key{}
	}
	return keys, nil
}

func (d *DB) GetKeyByID(keyID int64) (*Key, error) {
	var k Key
	err := d.conn.QueryRow(
		`SELECT id, user_id, key_name, algorithm, wrapped_file_key_owner, COALESCE(encryption_password,'') as encryption_password, file_path, COALESCE(author,'') as author, COALESCE(status,'encrypted') as status, decrypted_at, created_at, updated_at FROM keys WHERE id = ?`,
		keyID,
	).Scan(&k.ID, &k.UserID, &k.KeyName, &k.Algorithm, &k.WrappedFileKeyOwner, &k.EncryptionPassword, &k.FilePath, &k.Author, &k.Status, &k.DecryptedAt, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (d *DB) HasSharedAccess(keyID, recipientID int64) bool {
	var id int64
	err := d.conn.QueryRow("SELECT id FROM file_shares WHERE key_id = ? AND recipient_id = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) AND revoked_at IS NULL LIMIT 1", keyID, recipientID).Scan(&id)
	return err == nil
}

func (d *DB) GetActiveShare(keyID, recipientID int64) (*FileShare, error) {
	var fs FileShare
	err := d.conn.QueryRow("SELECT id, key_id, sender_id, recipient_id, max_forward_count, current_forward_count, scope, COALESCE(access_method, 'keypair'), COALESCE(wrapped_key_for_recipient, ''), COALESCE(wrapped_key_for_password, ''), COALESCE(password_salt, ''), expires_at, revoked_at, created_at FROM file_shares WHERE key_id = ? AND recipient_id = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1", keyID, recipientID).Scan(&fs.ID, &fs.KeyID, &fs.SenderID, &fs.RecipientID, &fs.MaxForwardCount, &fs.CurrentForwardCount, &fs.Scope, &fs.AccessMethod, &fs.WrappedKeyForRecipient, &fs.WrappedKeyForPassword, &fs.PasswordSalt, &fs.ExpiresAt, &fs.RevokedAt, &fs.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &fs, nil
}

func (d *DB) UpdateKey(keyID, userID int64, newKeyName, newKeyValue string) error {
	now := time.Now()
	res, err := d.conn.Exec(
		`UPDATE keys SET key_name = ?, wrapped_file_key_owner = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
		newKeyName, newKeyValue, now, keyID, userID,
	)
	if err != nil {
		return err
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("key not found or unauthorized")
	}
	return nil
}

func (d *DB) DeleteKey(keyID, userID int64) error {
	res, err := d.conn.Exec(`DELETE FROM keys WHERE id = ? AND user_id = ?`, keyID, userID)
	if err != nil {
		return err
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("key not found or unauthorized")
	}
	return nil
}

func (d *DB) UpdateUserToken(userID int64, newToken string) error {
	tokenHashBytes := sha256.Sum256([]byte(newToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	_, err := d.conn.Exec(`UPDATE users SET api_token = ? WHERE id = ?`, tokenHash, userID)
	return err
}

func (d *DB) GetUserByUsername(username string) (*User, error) {
	var u User
	err := d.conn.QueryRow(
		`SELECT id, username, email, COALESCE(public_key, ''), COALESCE(private_key_enc, ''), api_token, created_at FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PublicKey, &u.PrivateKeyEnc, &u.APIToken, &u.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &u, nil
}

func (d *DB) CreateOrganization(name, description string, creatorID int64) (*Organization, error) {
	res, err := d.conn.Exec("INSERT INTO organizations (name, description, created_by) VALUES (?, ?, ?)", name, description, creatorID)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	_, err = d.conn.Exec("INSERT INTO organization_members (org_id, user_id, role) VALUES (?, ?, 'admin')", id, creatorID)
	if err != nil {
		return nil, err
	}
	return &Organization{ID: id, Name: name, Description: description, CreatedBy: creatorID, CreatedAt: time.Now()}, nil
}

func (d *DB) GetUserOrganizations(userID int64) ([]Organization, error) {
	rows, err := d.conn.Query("SELECT o.id, o.name, o.description, o.created_by, o.created_at FROM organizations o JOIN organization_members om ON o.id = om.org_id WHERE om.user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Description, &o.CreatedBy, &o.CreatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	if orgs == nil {
		orgs = []Organization{}
	}
	return orgs, nil
}

func (d *DB) LeaveOrganization(orgID, userID int64) error {
	_, err := d.conn.Exec("DELETE FROM organization_members WHERE org_id = ? AND user_id = ?", orgID, userID)
	return err
}

func (d *DB) GetOrganizationMembers(orgID int64) ([]map[string]interface{}, error) {
	rows, err := d.conn.Query("SELECT u.id, u.username, om.role FROM users u JOIN organization_members om ON u.id = om.user_id WHERE om.org_id = ?", orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []map[string]interface{}
	for rows.Next() {
		var id int64
		var username, role string
		if err := rows.Scan(&id, &username, &role); err != nil {
			return nil, err
		}
		members = append(members, map[string]interface{}{"id": id, "username": username, "role": role})
	}
	if members == nil {
		members = []map[string]interface{}{}
	}
	return members, nil
}

func (d *DB) RequestConnection(requesterID, recipientID int64) error {
	_, err := d.conn.Exec("INSERT INTO connections (requester_id, recipient_id, status) VALUES (?, ?, 'pending')", requesterID, recipientID)
	return err
}

func (d *DB) AcceptConnection(connectionID int64) error {
	_, err := d.conn.Exec("UPDATE connections SET status = 'accepted' WHERE id = ?", connectionID)
	return err
}

func (d *DB) GetConnections(userID int64) ([]Connection, error) {
	rows, err := d.conn.Query("SELECT id, requester_id, recipient_id, status, created_at FROM connections WHERE requester_id = ? OR recipient_id = ?", userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var conns []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.RequesterID, &c.RecipientID, &c.Status, &c.CreatedAt); err != nil {
			return nil, err
		}
		conns = append(conns, c)
	}
	if conns == nil {
		conns = []Connection{}
	}
	return conns, nil
}

func (d *DB) CreateNotification(userID int64, ntype, title, message string, relatedID int64) error {
	_, err := d.conn.Exec("INSERT INTO notifications (user_id, type, title, message, related_id) VALUES (?, ?, ?, ?, ?)", userID, ntype, title, message, relatedID)
	return err
}

func (d *DB) GetNotifications(userID int64) ([]Notification, error) {
	rows, err := d.conn.Query("SELECT id, user_id, type, title, message, related_id, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var notifs []Notification
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.UserID, &n.Type, &n.Title, &n.Message, &n.RelatedID, &n.IsRead, &n.CreatedAt); err != nil {
			return nil, err
		}
		notifs = append(notifs, n)
	}
	if notifs == nil {
		notifs = []Notification{}
	}
	return notifs, nil
}

func (d *DB) MarkNotificationsRead(userID int64) error {
	_, err := d.conn.Exec("UPDATE notifications SET is_read = 1 WHERE user_id = ?", userID)
	return err
}

func (d *DB) CreateFileShare(keyID, senderID, recipientID int64, maxForwardCount int, scope, accessMethod, wrappedKeyForRecipient, wrappedKeyForPassword, passwordSalt string, expiresAt *time.Time) (*FileShare, error) {
	res, err := d.conn.Exec("INSERT INTO file_shares (key_id, sender_id, recipient_id, max_forward_count, current_forward_count, scope, access_method, wrapped_key_for_recipient, wrapped_key_for_password, password_salt, expires_at) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)", keyID, senderID, recipientID, maxForwardCount, scope, accessMethod, wrappedKeyForRecipient, wrappedKeyForPassword, passwordSalt, expiresAt)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &FileShare{
		ID: id,
		KeyID: keyID,
		SenderID: senderID,
		RecipientID: recipientID,
		MaxForwardCount:        maxForwardCount,
		CurrentForwardCount:    0,
		Scope:                  scope,
		AccessMethod:           accessMethod,
		WrappedKeyForRecipient: wrappedKeyForRecipient,
		WrappedKeyForPassword:  wrappedKeyForPassword,
		PasswordSalt:           passwordSalt,
		ExpiresAt:              expiresAt,
		CreatedAt:              time.Now(),
	}, nil
}

func (d *DB) GetFileShare(shareID int64) (*FileShare, error) {
	var fs FileShare
	err := d.conn.QueryRow("SELECT id, key_id, sender_id, recipient_id, max_forward_count, current_forward_count, scope, COALESCE(access_method, 'keypair'), COALESCE(wrapped_key_for_recipient, ''), COALESCE(wrapped_key_for_password, ''), COALESCE(password_salt, ''), expires_at, revoked_at, created_at FROM file_shares WHERE id = ?", shareID).Scan(&fs.ID, &fs.KeyID, &fs.SenderID, &fs.RecipientID, &fs.MaxForwardCount, &fs.CurrentForwardCount, &fs.Scope, &fs.AccessMethod, &fs.WrappedKeyForRecipient, &fs.WrappedKeyForPassword, &fs.PasswordSalt, &fs.ExpiresAt, &fs.RevokedAt, &fs.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &fs, nil
}

func (d *DB) IncrementForwardCount(shareID int64) error {
	_, err := d.conn.Exec("UPDATE file_shares SET current_forward_count = current_forward_count + 1 WHERE id = ?", shareID)
	return err
}

func (d *DB) RevokeFileShare(shareID int64) error {
	_, err := d.conn.Exec("UPDATE file_shares SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?", shareID)
	return err
}

func (d *DB) LogAudit(userID int64, action, details string) error {
	_, err := d.conn.Exec("INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)", userID, action, details)
	return err
}

func (d *DB) SaveVaultFile(keyID int64, data []byte) error {
	_, err := d.conn.Exec("INSERT OR REPLACE INTO vault_files (key_id, file_data) VALUES (?, ?)", keyID, data)
	return err
}

func (d *DB) GetVaultFile(keyID int64) ([]byte, error) {
	var data []byte
	err := d.conn.QueryRow("SELECT file_data FROM vault_files WHERE key_id = ?", keyID).Scan(&data)
	if err != nil {
		return nil, err
	}
	return data, nil
}
