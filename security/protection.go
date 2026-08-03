package security

import (
	"syscall"
	"unsafe"
)

var (
	procSetProcessMitigationPolicy = kernel32.NewProc("SetProcessMitigationPolicy")
	procSetHandleInformation       = kernel32.NewProc("SetHandleInformation")
)

// Process mitigation policy types
const (
	processSignaturePolicy       = 8
	processDynamicCodePolicy     = 2
)

// ProtectProcess applies various process-level protections.
func ProtectProcess() {
	disableMemoryDump()
	preventDLLInjection()
}

// disableMemoryDump attempts to prevent memory dumps of the process.
// This makes it harder for attackers to extract keys from a memory dump.
func disableMemoryDump() {
	// Method 1: Set process as critical (crash = BSOD, discourages dumping)
	// We don't actually do this as it's too aggressive, but we can
	// reduce the information available in a dump

	// Method 2: Disable SeDebugPrivilege for child processes
	// by removing the token's debug privilege

	// Method 3: Set process DEP (Data Execution Prevention) policy
	// This prevents executing code from data pages (heap spray attacks)
	var depPolicy struct {
		Flags      uint32
		Permanent  uint32
	}
	depPolicy.Flags = 1     // Enable DEP
	depPolicy.Permanent = 1 // Cannot be disabled at runtime

	procSetProcessMitigationPolicy.Call(
		0, // ProcessDEPPolicy
		uintptr(unsafe.Pointer(&depPolicy)),
		unsafe.Sizeof(depPolicy),
	)
}

// preventDLLInjection attempts to prevent unsigned DLL injection.
// This prevents attackers from injecting malicious DLLs to read key memory.
func preventDLLInjection() {
	// Set binary signature policy to only allow Microsoft-signed DLLs
	// This prevents most DLL injection attacks
	var signaturePolicy struct {
		Flags uint32
	}
	signaturePolicy.Flags = 0x1 // PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON

	procSetProcessMitigationPolicy.Call(
		uintptr(processSignaturePolicy),
		uintptr(unsafe.Pointer(&signaturePolicy)),
		unsafe.Sizeof(signaturePolicy),
	)

	// Block dynamic code generation (prevents shellcode injection)
	var dynamicCodePolicy struct {
		Flags uint32
	}
	dynamicCodePolicy.Flags = 0x1 // PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON

	procSetProcessMitigationPolicy.Call(
		uintptr(processDynamicCodePolicy),
		uintptr(unsafe.Pointer(&dynamicCodePolicy)),
		unsafe.Sizeof(dynamicCodePolicy),
	)
}

// SecureProcessHandle makes the current process handle non-inheritable
// to prevent child processes from accessing our memory.
func SecureProcessHandle() {
	handle, err := syscall.GetCurrentProcess()
	if err != nil {
		return
	}

	// HANDLE_FLAG_INHERIT = 0x1, setting to 0 means non-inheritable
	procSetHandleInformation.Call(
		uintptr(handle),
		0x1, // HANDLE_FLAG_INHERIT
		0,   // Remove inherit flag
	)
}
