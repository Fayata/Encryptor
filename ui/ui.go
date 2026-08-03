package ui

import (
	"fmt"
	"os"
	"strings"

	"encryptor/crypto"

	"github.com/charmbracelet/huh"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorMagenta = "\033[35m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
)

// ShowBanner displays the application banner.
func ShowBanner() {
	banner := `
` + colorCyan + colorBold + `
  ███████╗ █████╗ ██╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██████╗
  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
  █████╗  ███████║ ╚████╔╝ ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██████╔╝
  ██╔══╝  ██╔══██║  ╚██╔╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██╔══██╗
  ██║     ██║  ██║   ██║   ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║  ██║
  ╚═╝     ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
` + colorReset + `
` + colorDim + `  ──────────────────────────────────────────────────────────────────────────────────` + colorReset + `
` + colorYellow + `Faycryptor CLI` + colorReset + ` — Encrypt & Decrypt your files with ease
` + colorDim + `  Supports: AES-256-GCM │ AES-256-CBC │ XChaCha20-Poly1305 │ 3DES
  ─────────────────────────────────────────────────────────────────────────────` + colorReset + `
`
	fmt.Print(banner)
}

// ShowMainMenu displays the main menu and returns the user's choice.
func ShowMainMenu() (string, error) {
	var choice string

	err := huh.NewSelect[string]().
		Title(" Main Menu — What would you like to do?").
		Options(
			huh.NewOption(" Encrypt Folder", "encrypt"),
			huh.NewOption(" Decrypt Folder", "decrypt"),
			huh.NewOption(" About", "about"),
			huh.NewOption(" Exit", "exit"),
		).
		Value(&choice).
		Run()

	return choice, err
}

// SelectAlgorithm displays the algorithm selection menu.
func SelectAlgorithm() (string, error) {
	algorithms := crypto.SupportedAlgorithms()
	options := make([]huh.Option[string], len(algorithms))

	for i, algo := range algorithms {
		label := fmt.Sprintf("%s — %s", algo.Name, algo.Description)
		options[i] = huh.NewOption(label, algo.ID)
	}

	var choice string
	err := huh.NewSelect[string]().
		Title(" Select Encryption Algorithm").
		Options(options...).
		Value(&choice).
		Run()

	return choice, err
}

// InputFolderPath prompts the user to enter a folder path.
func InputFolderPath(action string) (string, error) {
	var folderPath string

	err := huh.NewInput().
		Title(fmt.Sprintf(" Enter the folder path to %s", action)).
		Placeholder("C:\\path\\to\\your\\folder").
		Validate(func(s string) error {
			s = strings.TrimSpace(s)
			if s == "" {
				return fmt.Errorf("folder path cannot be empty")
			}
			info, err := os.Stat(s)
			if os.IsNotExist(err) {
				return fmt.Errorf("folder does not exist: %s", s)
			}
			if err != nil {
				return fmt.Errorf("cannot access folder: %w", err)
			}
			if !info.IsDir() {
				return fmt.Errorf("path is not a directory: %s", s)
			}
			return nil
		}).
		Value(&folderPath).
		Run()

	return strings.TrimSpace(folderPath), err
}

// InputPassword prompts the user to enter a password (masked).
func InputPassword(prompt string) (string, error) {
	var password string

	err := huh.NewInput().
		Title(prompt).
		EchoMode(huh.EchoModePassword).
		Validate(func(s string) error {
			if len(s) < 4 {
				return fmt.Errorf("password must be at least 4 characters")
			}
			return nil
		}).
		Value(&password).
		Run()

	return password, err
}

// InputPasswordWithConfirm prompts the user to enter and confirm a password.
func InputPasswordWithConfirm() (string, error) {
	var password string
	var confirm string

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Enter encryption password").
				EchoMode(huh.EchoModePassword).
				Validate(func(s string) error {
					if len(s) < 4 {
						return fmt.Errorf("password must be at least 4 characters")
					}
					return nil
				}).
				Value(&password),

			huh.NewInput().
				Title("Confirm password").
				EchoMode(huh.EchoModePassword).
				Value(&confirm),
		),
	).Run()

	if err != nil {
		return "", err
	}

	if password != confirm {
		return "", fmt.Errorf("passwords do not match")
	}

	return password, nil
}

func ConfirmAction(message string) (bool, error) {
	var confirmed bool

	err := huh.NewConfirm().
		Title(message).
		Affirmative("Yes").
		Negative("No").
		Value(&confirmed).
		Run()

	return confirmed, err
}

// ShowProgress displays progress information.
func ShowProgress(current, total int, fileName string) {
	percentage := float64(current) / float64(total) * 100
	barWidth := 30
	filled := int(float64(barWidth) * float64(current) / float64(total))

	bar := strings.Repeat("", filled) + strings.Repeat("░", barWidth-filled)

	fmt.Printf("\r  %s[%s]%s %s%.0f%%%s (%d/%d) %s%s%s",
		colorCyan, bar, colorReset,
		colorBold, percentage, colorReset,
		current, total,
		colorDim, truncateName(fileName, 30), colorReset,
	)

	if current == total {
		fmt.Println()
	}
}

// ShowSuccess displays a success message.
func ShowSuccess(message string) {
	fmt.Printf("\n  %s%s✅ %s%s\n", colorGreen, colorBold, message, colorReset)
}

// ShowError displays an error message.
func ShowError(message string) {
	fmt.Printf("\n  %s%s❌ %s%s\n", colorRed, colorBold, message, colorReset)
}

// ShowWarning displays a warning message.
func ShowWarning(message string) {
	fmt.Printf("\n  %s%s⚠️  %s%s\n", colorYellow, colorBold, message, colorReset)
}

// ShowInfo displays an info message.
func ShowInfo(message string) {
	fmt.Printf("\n  %s%sℹ️  %s%s\n", colorCyan, colorBold, message, colorReset)
}

// ShowAbout displays information about the application.
func ShowAbout() {
	about := `
` + colorCyan + colorBold + `  ╔══════════════════════════════════════════════════════════════╗
  ║                     ABOUT FAYCRYPTOR                       ║
  ╚══════════════════════════════════════════════════════════════╝` + colorReset + `

` + colorBold + `   Version:` + colorReset + ` 1.0.0
` + colorBold + `   Description:` + colorReset + ` A terminal-based file encryption tool.
                   Encrypt and decrypt entire folders with
                   military-grade encryption algorithms.

` + colorBold + `   Supported Algorithms:` + colorReset + `

  ┌─────────────────────────┬──────────┬──────────────────────────┐
  │ Algorithm               │ Key Size │ Status                   │
  ├─────────────────────────┼──────────┼──────────────────────────┤
  │ FayCipher (DAG)         │ 256-bit  │ ` + colorMagenta + `Multi-Layer Encryption` + colorReset + `    │
  │ AES-256-GCM             │ 256-bit  │ ` + colorGreen + `Recommended` + colorReset + `           │
  │ XChaCha20-Poly1305      │ 256-bit  │ ` + colorGreen + `Excellent` + colorReset + `             │
  │ AES-256-CBC             │ 256-bit  │ ` + colorYellow + `Classic` + colorReset + `               │
  │ Triple DES (3DES)       │ 192-bit  │ ` + colorRed + `Legacy (not recommended)` + colorReset + `│
  └─────────────────────────┴──────────┴──────────────────────────┘

` + colorBold + `   Key Derivation:` + colorReset + ` Argon2id (PHC winner, GPU/ASIC resistant)
` + colorBold + `   File Format:` + colorReset + `    Custom .enc format with embedded metadata
` + colorBold + `    Integrity:` + colorReset + `     AEAD (GCM/Poly1305) or HMAC-SHA256

` + colorBold + `   Security Features:` + colorReset + `

  ┌──────────────────────────────────────────────────────────────┐
  │ ` + colorGreen + `✔` + colorReset + ` Secure Memory     — Keys locked in RAM, never swapped    │
  │ ` + colorGreen + `✔` + colorReset + ` Auto Key Zeroing  — Keys wiped from memory after use     │
  │ ` + colorGreen + `✔` + colorReset + ` Anti-Debugging    — Detects & blocks debugger attachment  │
  │ ` + colorGreen + `✔` + colorReset + ` Anti-Dump         — Prevents process memory dumps         │
  │ ` + colorGreen + `✔` + colorReset + ` DLL Protection    — Blocks unsigned DLL injection         │
  │ ` + colorGreen + `✔` + colorReset + ` DEP Enabled       — Prevents code execution from heap     │
  │ ` + colorGreen + `✔` + colorReset + ` Timing Protection — Random delays against timing attacks  │
  └──────────────────────────────────────────────────────────────┘

` + colorDim + `  ─────────────────────────────────────────────────────────────────` + colorReset + `
`
	fmt.Print(about)

	// Wait for user to press enter
	fmt.Print(colorDim + "  Press Enter to return to main menu..." + colorReset)
	fmt.Scanln()
}

// ShowEncryptSummary displays the encryption summary.
func ShowEncryptSummary(algorithm string, folderPath string, fileCount int) {
	fmt.Printf(`
%s%s  ╔══════════════════════════════════════════════════════════════╗
  ║                   ENCRYPTION SUMMARY                       ║
  ╚══════════════════════════════════════════════════════════════╝%s

  %s Folder:%s    %s
  %s Algorithm:%s %s
  %s Files:%s     %d file(s) to encrypt

`, colorCyan, colorBold, colorReset,
		colorBold, colorReset, folderPath,
		colorBold, colorReset, algorithm,
		colorBold, colorReset, fileCount,
	)
}

// ShowDecryptSummary displays the decryption summary.
func ShowDecryptSummary(folderPath string, fileCount int) {
	fmt.Printf(`
%s%s  ╔══════════════════════════════════════════════════════════════╗
  ║                   DECRYPTION SUMMARY                       ║
  ╚══════════════════════════════════════════════════════════════╝%s

  %s Folder:%s %s
  %s Files:%s  %d .enc file(s) to decrypt

`, colorCyan, colorBold, colorReset,
		colorBold, colorReset, folderPath,
		colorBold, colorReset, fileCount,
	)
}

// truncateName truncates a filename to maxLen characters.
func truncateName(name string, maxLen int) string {
	if len(name) <= maxLen {
		return name + strings.Repeat(" ", maxLen-len(name))
	}
	return name[:maxLen-3] + "..."
}
