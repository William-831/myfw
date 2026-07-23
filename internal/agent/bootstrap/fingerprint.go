package bootstrap

import (
	"net"
	"os"
	"runtime"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// MachineFingerprint gathers stable identifying information about the host.
// It's cheap and safe to call at any time.
func MachineFingerprint() *myfwv1.MachineFingerprint {
	host, _ := os.Hostname()
	fp := &myfwv1.MachineFingerprint{
		MachineId: readMachineID(),
		Hostname:  host,
		Arch:      runtime.GOARCH,
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fp
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.HardwareAddr == nil {
			continue
		}
		if mac := ifc.HardwareAddr.String(); mac != "" {
			fp.MacAddresses = append(fp.MacAddresses, mac)
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			// a.String() looks like "192.168.1.5/24" — trim the mask.
			s := a.String()
			if i := indexByte(s, '/'); i >= 0 {
				s = s[:i]
			}
			fp.IpAddresses = append(fp.IpAddresses, s)
		}
	}
	return fp
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
