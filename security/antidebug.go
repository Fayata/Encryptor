package security

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	ntdll              = syscall.NewLazyDLL("ntdll.dll")

	procIsDebuggerPresent    = kernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebugger  = kernel32.NewProc("CheckRemoteDebuggerPresent")
	procOutputDebugStringW   = kernel32.NewProc("OutputDebugStringW")
	procGetTickCount         = kernel32.NewProc("GetTickCount")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
)

// IsDebuggerAttached checks if a debugger is currently attached to the process.
// Uses multiple detection techniques for defense in depth.
func IsDebuggerAttached() bool {
	// Method 1: IsDebuggerPresent API
	ret, _, _ := procIsDebuggerPresent.Call()
	if ret != 0 {
		return true
	}

	// Method 2: CheckRemoteDebuggerPresent (detects remote debuggers too)
	var debuggerPresent int32
	ret, _, _ = procCheckRemoteDebugger.Call(
		uintptr(0xFFFFFFFFFFFFFFFF), // Current process handle (-1)
		uintptr(unsafe.Pointer(&debuggerPresent)),
	)
	if ret != 0 && debuggerPresent != 0 {
		return true
	}

	// Method 3: NtQueryInformationProcess - DebugPort (class 7)
	var debugPort uintptr
	ret, _, _ = procNtQueryInformationProcess.Call(
		uintptr(0xFFFFFFFFFFFFFFFF), // Current process handle
		7,                           // ProcessDebugPort
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		0,
	)
	if ret == 0 && debugPort != 0 {
		return true
	}

	// Method 4: Timing-based detection
	// Debuggers cause significant slowdowns in execution
	tick1, _, _ := procGetTickCount.Call()
	// Do some dummy work
	dummy := 0
	for i := 0; i < 1000000; i++ {
		dummy += i
	}
	_ = dummy
	tick2, _, _ := procGetTickCount.Call()
	// If this simple loop takes more than 100ms, likely being debugged
	if tick2-tick1 > 100 {
		return true
	}

	return false
}

// CheckDebuggerAndExit checks for debuggers and exits if one is found.
func CheckDebuggerAndExit() {
	if IsDebuggerAttached() {
		fmt.Println("\n  \033[31m\033[1m🚫 Security Alert: Debugger detected!\033[0m")
		fmt.Println("  \033[31mFaycryptor cannot run under a debugger for security reasons.\033[0m")
		fmt.Println("  \033[31mPlease close the debugger and try again.\033[0m")
		os.Exit(1)
	}
}

// AntiDebugLoop runs periodic debugger checks in the background.
// Call this as a goroutine: go AntiDebugLoop()
func AntiDebugLoop(quit <-chan struct{}) {
	for {
		select {
		case <-quit:
			return
		default:
			if IsDebuggerAttached() {
				fmt.Println("\n  \033[31m\033[1m🚫 Security Alert: Debugger detected! Terminating...\033[0m")

				// Zero any global sensitive state here if needed

				os.Exit(1)
			}
			// Check every ~2 seconds (use a busy loop to avoid timer-based evasion)
			dummy := 0
			for i := 0; i < 50000000; i++ {
				dummy += i % 7
			}
			_ = dummy
		}
	}
}
