package db

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) (*DB, func()) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_encryptor.db")

	database, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	cleanup := func() {
		database.Close()
		os.RemoveAll(tempDir)
	}

	return database, cleanup
}

func TestGetOwnedKeysByUserID_Isolation(t *testing.T) {
	d, cleanup := setupTestDB(t)
	defer cleanup()

	// Create user1 (Alice) and user2 (Bob)
	alice, err := d.CreateUser("alice", "alice@example.com", "Password123", "token_alice", "pub_alice", "priv_alice")
	if err != nil {
		t.Fatalf("CreateUser alice failed: %v", err)
	}
	bob, err := d.CreateUser("bob", "bob@example.com", "Password123", "token_bob", "pub_bob", "priv_bob")
	if err != nil {
		t.Fatalf("CreateUser bob failed: %v", err)
	}

	// Alice creates a key
	aliceKey, err := d.CreateKey(alice.ID, "alice_secret.txt", "AES-256-GCM", "wrapped_alice", "db://vault", alice.Username, "enc_pass_alice")
	if err != nil {
		t.Fatalf("CreateKey alice failed: %v", err)
	}

	// Bob creates a key
	bobKey, err := d.CreateKey(bob.ID, "bob_secret.txt", "AES-256-GCM", "wrapped_bob", "db://vault", bob.Username, "enc_pass_bob")
	if err != nil {
		t.Fatalf("CreateKey bob failed: %v", err)
	}

	// Bob shares his file with Alice
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = d.CreateFileShare(bobKey.ID, bob.ID, alice.ID, 0, "personal", "password", false, "", "wrapped_share_pw", "salt", &expiresAt)
	if err != nil {
		t.Fatalf("CreateFileShare failed: %v", err)
	}

	// Verify GetKeysByUserID for Alice (should include both aliceKey and bobKey via share)
	allAliceKeys, err := d.GetKeysByUserID(alice.ID)
	if err != nil {
		t.Fatalf("GetKeysByUserID failed: %v", err)
	}
	if len(allAliceKeys) != 2 {
		t.Errorf("Expected 2 keys in GetKeysByUserID for Alice, got %d", len(allAliceKeys))
	}

	// Verify GetOwnedKeysByUserID for Alice (should ONLY include aliceKey, NOT bobKey)
	ownedAliceKeys, err := d.GetOwnedKeysByUserID(alice.ID)
	if err != nil {
		t.Fatalf("GetOwnedKeysByUserID failed: %v", err)
	}
	if len(ownedAliceKeys) != 1 {
		t.Fatalf("Expected 1 key in GetOwnedKeysByUserID for Alice, got %d", len(ownedAliceKeys))
	}
	if ownedAliceKeys[0].ID != aliceKey.ID {
		t.Errorf("Expected key ID %d, got %d", aliceKey.ID, ownedAliceKeys[0].ID)
	}
	if ownedAliceKeys[0].Author != alice.Username {
		t.Errorf("Expected author %s, got %s", alice.Username, ownedAliceKeys[0].Author)
	}
}

func TestUpdateKeyPassword_And_Delete(t *testing.T) {
	d, cleanup := setupTestDB(t)
	defer cleanup()

	alice, err := d.CreateUser("alice", "alice@example.com", "Password123", "token_alice", "pub_alice", "priv_alice")
	if err != nil {
		t.Fatalf("CreateUser alice failed: %v", err)
	}
	bob, err := d.CreateUser("bob", "bob@example.com", "Password123", "token_bob", "pub_bob", "priv_bob")
	if err != nil {
		t.Fatalf("CreateUser bob failed: %v", err)
	}

	key, err := d.CreateKey(alice.ID, "file.txt", "AES-256-GCM", "wrapped", "db://vault", alice.Username, "old_pass_hex")
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// Update password as Alice (Owner)
	err = d.UpdateKeyPassword(key.ID, alice.ID, "new_pass_hex")
	if err != nil {
		t.Fatalf("UpdateKeyPassword failed: %v", err)
	}

	// Check updated key
	updatedKey, err := d.GetKeyByID(key.ID)
	if err != nil {
		t.Fatalf("GetKeyByID failed: %v", err)
	}
	if updatedKey.EncryptionPassword != "new_pass_hex" {
		t.Errorf("Expected encryption_password 'new_pass_hex', got '%s'", updatedKey.EncryptionPassword)
	}

	// Bob attempts to update Alice's key password (should fail unauthorized)
	err = d.UpdateKeyPassword(key.ID, bob.ID, "hacked_pass_hex")
	if err == nil {
		t.Errorf("Expected unauthorized error when Bob updates Alice's key, got nil")
	}

	// Delete key as Alice
	err = d.DeleteOrRemoveKey(key.ID, alice.ID)
	if err != nil {
		t.Fatalf("DeleteOrRemoveKey failed: %v", err)
	}

	// Verify key is gone
	owned, err := d.GetOwnedKeysByUserID(alice.ID)
	if err != nil {
		t.Fatalf("GetOwnedKeysByUserID failed: %v", err)
	}
	if len(owned) != 0 {
		t.Errorf("Expected 0 keys after deletion, got %d", len(owned))
	}
}

func TestSearchUsers(t *testing.T) {
	d, cleanup := setupTestDB(t)
	defer cleanup()

	alice, _ := d.CreateUser("alice", "alice@example.com", "Password123", "token_alice", "pub_alice", "priv_alice")
	bob, _ := d.CreateUser("bob_marley", "bob@example.com", "Password123", "token_bob", "pub_bob", "priv_bob")
	charlie, _ := d.CreateUser("charlie_b", "charlie@example.com", "Password123", "token_charlie", "pub_charlie", "priv_charlie")
	_, _ = d.CreateUser("daffa", "daffa@example.com", "Password123", "token_daffa", "pub_daffa", "priv_daffa")

	// Alice sends request to Bob
	_ = d.RequestConnection(alice.ID, bob.ID)

	// Charlie sends request to Alice and Alice accepts
	_ = d.RequestConnection(charlie.ID, alice.ID)
	// Find connection ID to accept
	conns, _ := d.GetConnections(alice.ID)
	for _, c := range conns {
		if c.RequesterID == charlie.ID || c.RecipientID == charlie.ID {
			_ = d.AcceptConnection(c.ID)
		}
	}

	// Search "b" from Alice's perspective
	// Expected: bob_marley (pending_sent), charlie_b (accepted)
	// alice herself should be excluded
	res, err := d.SearchUsers("b", alice.ID)
	if err != nil {
		t.Fatalf("SearchUsers failed: %v", err)
	}

	if len(res) < 2 {
		t.Fatalf("Expected at least 2 results for query 'b', got %d", len(res))
	}

	statusMap := make(map[string]string)
	for _, r := range res {
		statusMap[r.Username] = r.ConnectionStatus
	}

	if statusMap["bob_marley"] != "pending_sent" {
		t.Errorf("Expected bob_marley status 'pending_sent', got '%s'", statusMap["bob_marley"])
	}
	if statusMap["charlie_b"] != "accepted" {
		t.Errorf("Expected charlie_b status 'accepted', got '%s'", statusMap["charlie_b"])
	}

	// Search "daf" from Alice's perspective -> daffa should be "none"
	resDaf, err := d.SearchUsers("daf", alice.ID)
	if err != nil {
		t.Fatalf("SearchUsers 'daf' failed: %v", err)
	}
	if len(resDaf) != 1 || resDaf[0].ConnectionStatus != "none" {
		t.Errorf("Expected daffa with status 'none', got %+v", resDaf)
	}
}

func TestKeyScopeFiltering(t *testing.T) {
	d, cleanup := setupTestDB(t)
	defer cleanup()

	alice, err := d.CreateUser("alice_scope", "alice_scope@example.com", "Password123", "tok1", "pub1", "priv1")
	if err != nil {
		t.Fatalf("CreateUser alice failed: %v", err)
	}
	bob, err := d.CreateUser("bob_scope", "bob_scope@example.com", "Password123", "tok2", "pub2", "priv2")
	if err != nil {
		t.Fatalf("CreateUser bob failed: %v", err)
	}

	// Alice's own key
	_, _ = d.CreateKey(alice.ID, "alice_file.txt", "AES-GCM", "wrapA", "db://vault", "alice", "passA")

	// Bob's key shared to Alice with scope 'organization'
	bobKeyOrg, _ := d.CreateKey(bob.ID, "bob_org_file.txt", "AES-GCM", "wrapB1", "db://vault", "bob", "passB1")
	_, _ = d.CreateFileShare(bobKeyOrg.ID, bob.ID, alice.ID, 0, "organization", "password", false, "", "", "", nil)

	// Bob's key shared to Alice with scope 'personal' (connection)
	bobKeyConn, _ := d.CreateKey(bob.ID, "bob_conn_file.txt", "AES-GCM", "wrapB2", "db://vault", "bob", "passB2")
	_, _ = d.CreateFileShare(bobKeyConn.ID, bob.ID, alice.ID, 0, "personal", "password", false, "", "", "", nil)

	// Query keys for Alice
	keys, err := d.GetKeysByUserID(alice.ID)
	if err != nil {
		t.Fatalf("GetKeysByUserID failed: %v", err)
	}

	if len(keys) != 3 {
		t.Fatalf("Expected 3 keys for Alice, got %d", len(keys))
	}

	scopeMap := make(map[string]string)
	for _, k := range keys {
		scopeMap[k.KeyName] = k.Scope
	}

	if scopeMap["alice_file.txt"] != "mine" {
		t.Errorf("Expected alice_file.txt scope 'mine', got '%s'", scopeMap["alice_file.txt"])
	}
	if scopeMap["bob_org_file.txt"] != "organization" {
		t.Errorf("Expected bob_org_file.txt scope 'organization', got '%s'", scopeMap["bob_org_file.txt"])
	}
	if scopeMap["bob_conn_file.txt"] != "personal" {
		t.Errorf("Expected bob_conn_file.txt scope 'personal', got '%s'", scopeMap["bob_conn_file.txt"])
	}
}

