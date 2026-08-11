package server

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Security event types
const (
	EventLoginFailed    = "FAILED_LOGIN"
	EventLoginSuccess   = "LOGIN_SUCCESS"
	EventRateLimited    = "RATE_LIMITED"
	EventCSRFFailed     = "CSRF_FAILURE"
	EventRegister       = "REGISTRATION"
	EventInvalidInput   = "INVALID_INPUT"
)

type secLogger struct {
	mu      sync.Mutex
	logFile *os.File
}

var secLog *secLogger

func initSecurityLogger() {
	f, err := os.OpenFile("security.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Warning: Could not open security.log: %v\n", err)
		return
	}
	secLog = &secLogger{logFile: f}
}

func logSecurityEvent(level, event, ip, detail string) {
	if secLog == nil || secLog.logFile == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("[%s] [%s] %s ip=%s %s\n", timestamp, level, event, ip, detail)

	secLog.mu.Lock()
	defer secLog.mu.Unlock()
	secLog.logFile.WriteString(entry)
}

func getClientIP(r interface{ Header() interface{ Get(string) string }; RemoteAddr() string }) string {
	return ""
}

// getIP extracts client IP from an http.Request
func getIP(remoteAddr string, fwdFor string) string {
	if fwdFor != "" {
		return fwdFor
	}
	// Strip port from RemoteAddr
	for i := len(remoteAddr) - 1; i >= 0; i-- {
		if remoteAddr[i] == ':' {
			return remoteAddr[:i]
		}
	}
	return remoteAddr
}
