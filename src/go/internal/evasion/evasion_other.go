//go:build !windows

package evasion

// Init runs evasion techniques at agent startup.
// On non-Windows platforms this is a no-op.
func Init() {
	// Anti-sandbox and anti-debug checks still run on Unix
	AntiSandbox()
	AntiDebug()
}

// UnhookNtdll is a no-op on non-Windows.
func UnhookNtdll() {}
