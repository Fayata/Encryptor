package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Session struct {
	ServerURL string `json:"server_url"`
	Username  string `json:"username"`
	APIToken  string `json:"api_token"`
}

type RemoteKey struct {
	ID        int64  `json:"id"`
	KeyName   string `json:"key_name"`
	Algorithm string `json:"algorithm"`
	KeyValue  string `json:"key_value"`
	FilePath  string `json:"file_path"`
}

func getSessionFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".encryptor_session.json")
}

func LoadSession() (*Session, error) {
	path := getSessionFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func SaveSession(sess *Session) error {
	path := getSessionFilePath()
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func Logout() error {
	path := getSessionFilePath()
	return os.Remove(path)
}

func Login(serverURL, usernameOrEmail, password string) (*Session, error) {
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	client := &http.Client{Timeout: 5 * time.Second}

	reqBody, _ := json.Marshal(map[string]string{
		"username_or_email": usernameOrEmail,
		"password":          password,
	})

	resp, err := client.Post(serverURL+"/api/auth/cli-login", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		if msg, ok := errData["error"]; ok {
			return nil, fmt.Errorf("%s", msg)
		}
		return nil, fmt.Errorf("login failed with status: %s", resp.Status)
	}

	var resData struct {
		Username string `json:"username"`
		APIToken string `json:"api_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&resData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	sess := &Session{
		ServerURL: serverURL,
		Username:  resData.Username,
		APIToken:  resData.APIToken,
	}

	if err := SaveSession(sess); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}

	return sess, nil
}

func UploadKey(algoName, passwordOrKey, targetPath string) error {
	sess, err := LoadSession()
	if err != nil || sess == nil || sess.APIToken == "" {
		// Session not active, skip uploading silently or return error
		return fmt.Errorf("no active web account session found")
	}

	keyName := fmt.Sprintf("%s Encryption - %s", algoName, filepath.Base(targetPath))

	reqBody, _ := json.Marshal(map[string]string{
		"key_name":  keyName,
		"algorithm": algoName,
		"key_value": passwordOrKey,
		"file_path": targetPath,
	})

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, sess.ServerURL+"/api/keys", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Token", sess.APIToken)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send key to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server responded with status: %s", resp.Status)
	}

	return nil
}

func FetchRemoteKeys() ([]RemoteKey, error) {
	sess, err := LoadSession()
	if err != nil || sess == nil || sess.APIToken == "" {
		return nil, fmt.Errorf("no active web account session found")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, sess.ServerURL+"/api/keys", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-API-Token", sess.APIToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keys from server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server error: %s", resp.Status)
	}

	var keys []RemoteKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func DeleteKey(id int64) error {
	sess, err := LoadSession()
	if err != nil || sess == nil || sess.APIToken == "" {
		return fmt.Errorf("no active web account session found")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("%s/api/keys/%d", sess.ServerURL, id)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("X-API-Token", sess.APIToken)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete key on server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server error: %s", resp.Status)
	}

	return nil
}
