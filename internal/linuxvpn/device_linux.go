//go:build linux

package linuxvpn

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
)

func OpenTUN(name string) (Device, error) {
	if !InterfaceName(name) {
		return nil, ErrConfig
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, ErrNetwork
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrNetwork
	}
	req, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, ErrConfig
	}
	req.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if unix.IoctlIfreq(fd, unix.TUNSETIFF, req) != nil {
		unix.Close(fd)
		return nil, ErrNetwork
	}
	return os.NewFile(uintptr(fd), name), nil
}
