package db

import (
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"unicode"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	APIToken     string    `json:"api_token"`
	CreatedAt    time.Time `json:"created_at"`
}

type Key struct {
	ID            int64     `json:"id"`
	UserID        int64     `json:"user_id"`
	KeyName       string    `json:"key_name"`
	Algorithm     string    `json:"algorithm"`
	KeyValue      string    `json:"key_value"`
	FilePath      string    `json:"file_path"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
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
		api_token TEXT UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	keysTable := `
	CREATE TABLE IF NOT EXISTS keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		key_name TEXT NOT NULL,
		algorithm TEXT NOT NULL,
		key_value TEXT NOT NULL,
		file_path TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);`

	if _, err := d.conn.Exec(userTable); err != nil {
		return err
	}
	if _, err := d.conn.Exec(keysTable); err != nil {
		return err
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

func (d *DB) CreateUser(username, email, password, apiToken string) (*User, error) {
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

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	res, err := d.conn.Exec(
		`INSERT INTO users (username, email, password_hash, api_token, created_at) VALUES (?, ?, ?, ?, ?)`,
		username, email, string(hash), apiToken, now,
	)
	if err != nil {
		return nil, fmt.Errorf("username or email already exists")
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &User{
		ID:        id,
		Username:  username,
		Email:     email,
		APIToken:  apiToken,
		CreatedAt: now,
	}, nil
}

func (d *DB) AuthenticateUser(usernameOrEmail, password string) (*User, error) {
	var u User
	err := d.conn.QueryRow(
		`SELECT id, username, email, password_hash, api_token, created_at FROM users WHERE username = ? OR email = ?`,
		usernameOrEmail, usernameOrEmail,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.APIToken, &u.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid username/email or password")
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("invalid username/email or password")
	}

	return &u, nil
}

func (d *DB) GetUserByToken(token string) (*User, error) {
	var u User
	err := d.conn.QueryRow(
		`SELECT id, username, email, api_token, created_at FROM users WHERE api_token = ?`,
		token,
	).Scan(&u.ID, &u.Username, &u.Email, &u.APIToken, &u.CreatedAt)

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
		`SELECT id, username, email, api_token, created_at FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.APIToken, &u.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &u, nil
}

// Key methods

func (d *DB) CreateKey(userID int64, keyName, algorithm, keyValue, filePath string) (*Key, error) {
	now := time.Now()
	res, err := d.conn.Exec(
		`INSERT INTO keys (user_id, key_name, algorithm, key_value, file_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, keyName, algorithm, keyValue, filePath, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &Key{
		ID:        id,
		UserID:    userID,
		KeyName:   keyName,
		Algorithm: algorithm,
		KeyValue:  keyValue,
		FilePath:  filePath,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (d *DB) GetKeysByUserID(userID int64) ([]Key, error) {
	rows, err := d.conn.Query(
		`SELECT id, user_id, key_name, algorithm, key_value, file_path, created_at, updated_at FROM keys WHERE user_id = ? ORDER BY updated_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.ID, &k.UserID, &k.KeyName, &k.Algorithm, &k.KeyValue, &k.FilePath, &k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}

	if keys == nil {
		keys = []Key{}
	}
	return keys, nil
}

func (d *DB) UpdateKey(keyID, userID int64, newKeyName, newKeyValue string) error {
	now := time.Now()
	res, err := d.conn.Exec(
		`UPDATE keys SET key_name = ?, key_value = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
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
