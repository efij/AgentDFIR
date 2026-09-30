package gentle

import (
	"encoding/binary"
	"syscall"
)

const (
	prioDarwinProcess = 4      // PRIO_DARWIN_PROCESS
	prioDarwinBG      = 0x1000 // PRIO_DARWIN_BG: background CPU and throttled I/O
)

func setPriority(m Mode) error {
	switch m {
	case Gentle:
		return syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
	case Background:
		if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10); err != nil {
			return err
		}
		return syscall.Setpriority(prioDarwinProcess, 0, prioDarwinBG)
	}
	return nil
}

// sysctlRaw returns a sysctl's bytes. syscall.Sysctl drops one trailing
// NUL, which in a binary value is a zero high byte; pad it back.
func sysctlRaw(name string, size int) ([]byte, bool) {
	s, err := syscall.Sysctl(name)
	if err != nil {
		return nil, false
	}
	b := []byte(s)
	for len(b) < size {
		b = append(b, 0)
	}
	return b, len(b) == size
}

// loadAverage is the 1-minute load average (struct loadavg: three
// fixed-point values and their scale).
func loadAverage() (float64, bool) {
	b, ok := sysctlRaw("vm.loadavg", 24)
	if !ok {
		return 0, false
	}
	l := binary.LittleEndian.Uint32(b[0:4])
	scale := binary.LittleEndian.Uint64(b[16:24])
	if scale == 0 {
		return 0, false
	}
	return float64(l) / float64(scale), true
}

func totalMemory() int64 {
	b, ok := sysctlRaw("hw.memsize", 8)
	if !ok {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(b))
}

// memoryPressure is left to the load average on macOS: the kernel's own
// pressure level needs a dispatch source, not a syscall.
func memoryPressure() bool { return false }
