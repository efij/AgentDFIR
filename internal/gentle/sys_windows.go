package gentle

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procSetPriorityClass    = kernel32.NewProc("SetPriorityClass")
	procGlobalMemoryStatus  = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpaceExW = kernel32.NewProc("GetDiskFreeSpaceExW")
)

const (
	belowNormalPriorityClass   = 0x00004000
	processModeBackgroundBegin = 0x00100000
)

func setPriority(m Mode) error {
	cls := uintptr(0)
	switch m {
	case Gentle:
		cls = belowNormalPriorityClass
	case Background:
		cls = processModeBackgroundBegin
	default:
		return nil
	}
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	if r, _, e := procSetPriorityClass.Call(uintptr(h), cls); r == 0 {
		return e
	}
	return nil
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func memStatus() (memoryStatusEx, bool) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&m)))
	return m, r != 0
}

// loadAverage does not exist on Windows; memory load stands in for it
// (see memoryPressure).
func loadAverage() (float64, bool) { return 0, false }

func totalMemory() int64 {
	if m, ok := memStatus(); ok {
		return int64(m.TotalPhys)
	}
	return 0
}

// memoryPressure: 90% or more of physical memory in use.
func memoryPressure() bool {
	m, ok := memStatus()
	return ok && m.MemoryLoad >= 90
}

func diskSpace(path string) (free, total int64, err error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var avail, tot, totalFree uint64
	r, _, e := procGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&avail)), uintptr(unsafe.Pointer(&tot)), uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return 0, 0, e
	}
	return int64(avail), int64(tot), nil
}

// FreeBytes is the space available to this user on the volume holding path.
func FreeBytes(path string) (int64, error) {
	f, _, err := diskSpace(path)
	return f, err
}

// TotalBytes is the size of the volume holding path.
func TotalBytes(path string) (int64, error) {
	_, t, err := diskSpace(path)
	return t, err
}
