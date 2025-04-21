package tunnel

import (
	"net"
	"sync/atomic"
	"time"
	"unsafe"
)

type AtomicSwitchableRegularTunnel struct {
	tun unsafe.Pointer
}

func (a *AtomicSwitchableRegularTunnel) resolve() *RegularOutTunnel {
	return (*RegularOutTunnel)(atomic.LoadPointer(&a.tun))
}

func (a *AtomicSwitchableRegularTunnel) SwitchTo(tun *RegularOutTunnel) {
	atomic.StorePointer(&a.tun, unsafe.Pointer(tun))
}

func (a *AtomicSwitchableRegularTunnel) Current() *RegularOutTunnel {
	return a.resolve()
}

func (a *AtomicSwitchableRegularTunnel) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return a.resolve().ReadFrom(p)
}

func (a *AtomicSwitchableRegularTunnel) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return a.resolve().WriteTo(p, addr)
}

func (a *AtomicSwitchableRegularTunnel) Close() error {
	return a.resolve().Close()
}

func (a *AtomicSwitchableRegularTunnel) LocalAddr() net.Addr {
	return a.resolve().LocalAddr()
}

func (a *AtomicSwitchableRegularTunnel) SetDeadline(t time.Time) error {
	return a.resolve().SetDeadline(t)
}

func (a *AtomicSwitchableRegularTunnel) SetReadDeadline(t time.Time) error {
	return a.resolve().SetReadDeadline(t)
}

func (a *AtomicSwitchableRegularTunnel) SetWriteDeadline(t time.Time) error {
	return a.resolve().SetWriteDeadline(t)
}
