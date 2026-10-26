//go:build darwin

package endpoint

import (
	"strconv"
	"strings"
	"syscall"
)

// macOSMajor reads the running macOS major version, 0 when unknown.
func macOSMajor() int {
	v, err := syscall.Sysctl("kern.osproductversion")
	if err != nil {
		return 0
	}
	major, _ := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	return major
}
