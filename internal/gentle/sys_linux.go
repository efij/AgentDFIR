package gentle

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	ioprioWhoProcess = 1
	ioprioClassBE    = 2
	ioprioClassIdle  = 3
	ioprioShift      = 13
)

// setPriority applies to every thread: on Linux, nice and I/O priority are
// per thread, and the Go runtime has already started several. Threads
// created later inherit from the one that creates them.
func setPriority(m Mode) error {
	if m == Normal {
		return nil
	}
	io := uintptr(ioprioClassBE<<ioprioShift | 7)
	if m == Background {
		io = uintptr(ioprioClassIdle << ioprioShift)
	}
	tids := []int{0}
	if ents, err := os.ReadDir("/proc/self/task"); err == nil {
		tids = tids[:0]
		for _, e := range ents {
			if id, err := strconv.Atoi(e.Name()); err == nil {
				tids = append(tids, id)
			}
		}
	}
	var first error
	for _, id := range tids {
		if err := syscall.Setpriority(syscall.PRIO_PROCESS, id, 10); err != nil && first == nil {
			first = err
		}
		if _, _, e := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(id), io); e != 0 && first == nil {
			first = e
		}
	}
	return first
}

func loadAverage() (float64, bool) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil
}

func totalMemory() int64 {
	var si syscall.Sysinfo_t
	if syscall.Sysinfo(&si) != nil {
		return 0
	}
	return int64(si.Totalram) * int64(si.Unit)
}

// memoryPressure: less than 10% of memory available.
func memoryPressure() bool {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return false
	}
	var total, avail int64
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	return total > 0 && avail > 0 && avail*10 < total
}
