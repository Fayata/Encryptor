package main

import (
	"fmt"
	"os"

	"encryptor/crypto"
	"encryptor/fileops"
	"encryptor/security"
	"encryptor/ui"
)

func main() {
	// ═══════════════════════════════════════════════
	//  SECURITY INITIALIZATION
	// ═══════════════════════════════════════════════

	// Check for debuggers before doing anything sensitive
	security.CheckDebuggerAndExit()

	// Apply process-level protections (anti-dump, DEP, DLL injection prevention)
	security.ProtectProcess()
	security.SecureProcessHandle()

	// Start background anti-debug monitoring
	quitAntiDebug := make(chan struct{})
	go security.AntiDebugLoop(quitAntiDebug)
	defer close(quitAntiDebug)

	// Ensure secure cleanup on exit
	defer security.SecureCleanup()

	// ═══════════════════════════════════════════════
	//  APPLICATION START
	// ═══════════════════════════════════════════════

	// Clear screen and show banner
	fmt.Print("\033[2J\033[H")
	ui.ShowBanner()
	ui.ShowInfo("Security protections active")

	for {
		choice, err := ui.ShowMainMenu()
		if err != nil {
			ui.ShowError(fmt.Sprintf("Menu error: %v", err))
			os.Exit(1)
		}

		switch choice {
		case "encrypt":
			handleEncrypt()
		case "decrypt":
			handleDecrypt()
		case "about":
			ui.ShowAbout()
		case "exit":
			fmt.Println()
			security.SecureCleanup()
			ui.ShowInfo("Thank you for using Faycryptor! Goodbye 👋")
			fmt.Println()
			os.Exit(0)
		}
	}
}

func handleEncrypt() {
	// Step 1: Get folder path
	folderPath, err := ui.InputFolderPath("encrypt")
	if err != nil {
		ui.ShowError(fmt.Sprintf("Input error: %v", err))
		return
	}

	// Step 2: Scan files
	files, err := fileops.ScanFolder(folderPath)
	if err != nil {
		ui.ShowError(fmt.Sprintf("Scan error: %v", err))
		return
	}

	if len(files) == 0 {
		ui.ShowWarning("No files found in the specified folder (encrypted files are skipped).")
		return
	}

	// Step 3: Select algorithm
	algoID, err := ui.SelectAlgorithm()
	if err != nil {
		ui.ShowError(fmt.Sprintf("Selection error: %v", err))
		return
	}

	enc, err := crypto.NewEncryptor(algoID)
	if err != nil {
		ui.ShowError(fmt.Sprintf("Algorithm error: %v", err))
		return
	}

	// Show warning for 3DES
	for _, algo := range crypto.SupportedAlgorithms() {
		if algo.ID == algoID && algo.Warning != "" {
			ui.ShowWarning(algo.Warning)
		}
	}

	// Step 4: Get password (secured in memory)
	password, err := ui.InputPasswordWithConfirm()
	if err != nil {
		ui.ShowError(fmt.Sprintf("Password error: %v", err))
		return
	}

	// Store password in secure buffer
	securePassword := security.SecurePasswordInput(password)
	security.ZeroString(&password) // Zero the original string
	defer securePassword.Destroy() // Auto-zero when done

	// Step 5: Show summary and confirm
	ui.ShowEncryptSummary(enc.Name(), folderPath, len(files))

	confirmed, err := ui.ConfirmAction("Proceed with encryption?")
	if err != nil {
		ui.ShowError(fmt.Sprintf("Confirm error: %v", err))
		return
	}
	if !confirmed {
		ui.ShowInfo("Encryption cancelled.")
		return
	}

	// Step 6: Encrypt (password retrieved from secure buffer)
	fmt.Println()
	ui.ShowInfo(fmt.Sprintf("Encrypting %d files with %s...", len(files), enc.Name()))
	fmt.Println()

	passwordStr := string(securePassword.Bytes())
	success, failed, errors := fileops.EncryptFolder(folderPath, enc, passwordStr, func(current, total int, fileName string) {
		ui.ShowProgress(current, total, fileName)
	})
	security.ZeroString(&passwordStr)

	// Step 7: Show results
	fmt.Println()
	if success > 0 {
		ui.ShowSuccess(fmt.Sprintf("%d file(s) encrypted successfully!", success))
	}
	if failed > 0 {
		ui.ShowError(fmt.Sprintf("%d file(s) failed to encrypt:", failed))
		for _, e := range errors {
			fmt.Printf("     • %v\n", e)
		}
	}
	fmt.Println()
}

func handleDecrypt() {
	// Step 1: Get folder path
	folderPath, err := ui.InputFolderPath("decrypt")
	if err != nil {
		ui.ShowError(fmt.Sprintf("Input error: %v", err))
		return
	}

	// Step 2: Scan encrypted files
	files, err := fileops.ScanEncryptedFiles(folderPath)
	if err != nil {
		ui.ShowError(fmt.Sprintf("Scan error: %v", err))
		return
	}

	if len(files) == 0 {
		ui.ShowWarning("No .enc files found in the specified folder.")
		return
	}

	// Step 3: Get password (secured in memory)
	password, err := ui.InputPassword("Enter decryption password")
	if err != nil {
		ui.ShowError(fmt.Sprintf("Password error: %v", err))
		return
	}

	// Store password in secure buffer
	securePassword := security.SecurePasswordInput(password)
	security.ZeroString(&password)
	defer securePassword.Destroy()

	// Step 4: Show summary and confirm
	ui.ShowDecryptSummary(folderPath, len(files))

	confirmed, err := ui.ConfirmAction("Proceed with decryption?")
	if err != nil {
		ui.ShowError(fmt.Sprintf("Confirm error: %v", err))
		return
	}
	if !confirmed {
		ui.ShowInfo("Decryption cancelled.")
		return
	}

	// Step 5: Decrypt (password retrieved from secure buffer)
	fmt.Println()
	ui.ShowInfo(fmt.Sprintf("Decrypting %d file(s)...", len(files)))
	fmt.Println()

	passwordStr := string(securePassword.Bytes())
	success, failed, errors := fileops.DecryptFolder(folderPath, passwordStr, func(current, total int, fileName string) {
		ui.ShowProgress(current, total, fileName)
	})
	security.ZeroString(&passwordStr)

	// Step 6: Show results
	fmt.Println()
	if success > 0 {
		ui.ShowSuccess(fmt.Sprintf("%d file(s) decrypted successfully!", success))
	}
	if failed > 0 {
		ui.ShowError(fmt.Sprintf("%d file(s) failed to decrypt:", failed))
		for _, e := range errors {
			fmt.Printf("     • %v\n", e)
		}
	}
	fmt.Println()
}
