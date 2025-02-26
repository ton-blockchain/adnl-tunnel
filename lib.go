package main

/*
#include <stdint.h>
#include <sys/socket.h>

typedef struct {
	size_t index;
	int ip;
	int port;
} Tunnel;

// next - is pointer to class instance or callback to call method from node code
typedef void (*RecvCallback)(void* next, uint8_t* data, size_t num);

typedef void (*ReinitCallback)(void* next, struct sockaddr* data);


// we need it because we cannot call C func by pointer directly from go
static inline void on_recv_batch_ready(RecvCallback cb, void* next, void* data, size_t num) {
	cb(next, (uint8_t*)data, num);
}

static inline void on_reinit(ReinitCallback cb, void* next, void* data) {
	cb(next, (struct sockaddr*)data);
}
*/
import "C"
import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/rs/zerolog/log"
	"github.com/ton-blockchain/adnl-tunnel/config"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/liteclient"
	"net"
	"time"
	"unsafe"
)

var _gcAliveHolder []*tunnel.RegularOutTunnel

// 16 bytes
func writeSockAddr(at []byte, addr *net.UDPAddr) {
	at[0], at[1] = 2, 0 // AF_INET

	// port
	at[2] = byte(addr.Port >> 8)
	at[3] = byte(addr.Port & 0xff)

	copy(at[4:], addr.IP.To4())
}

func parseSockAddr(at []byte) (*net.UDPAddr, error) {
	if len(at) < 16 {
		return nil, errors.New("length too short")
	}

	if at[0] != 2 || at[1] != 0 {
		return nil, errors.New("only supports AF_INET addr")
	}

	return &net.UDPAddr{IP: at[4:8], Port: int(at[2])<<8 + int(at[3])}, nil
}

//export PrepareTunnel
//goland:noinspection ALL
func PrepareTunnel(onRecv C.RecvCallback, onReinit C.ReinitCallback, nextOnRecv, nextOnReinit unsafe.Pointer, configJson *C.char, configJsonLen C.int, networkConfigJson *C.char, networkConfigJsonLen C.int) C.Tunnel {
	var cfg config.ClientConfig
	if err := json.Unmarshal(C.GoBytes(unsafe.Pointer(configJson), configJsonLen), &cfg); err != nil {
		println("failed to parse tunnel config: " + err.Error())
		return C.Tunnel{}
	}

	var netCfg liteclient.GlobalConfig
	if err := json.Unmarshal(C.GoBytes(unsafe.Pointer(networkConfigJson), networkConfigJsonLen), &netCfg); err != nil {
		println("failed to parse network config: " + err.Error())
		return C.Tunnel{}
	}

	tun, port, ip, err := tunnel.PrepareTunnel(&cfg, &netCfg)
	if err != nil {
		log.Error().Err(err).Msg("failed to prepare tunnel")
		return C.Tunnel{}
	}

	tun.SetOutAddressChangedHandler(func(addr *net.UDPAddr) {
		var buf [16]byte
		writeSockAddr(buf[:], addr)

		C.on_reinit((C.RecvCallback)(onReinit), nextOnReinit, unsafe.Pointer(&buf[0]))
	})

	// to not collect by gc
	_gcAliveHolder = append(_gcAliveHolder, tun)

	go func() {
		off, num := 0, 0
		buf := make([]byte, (16+2+adnl.MaxMTU)*100)
		sinceLastBatch := time.Now()
		ctx, _ := context.WithTimeout(context.Background(), 20*time.Millisecond)

		for {
			n, addr, err := tun.ReadFromWithTimeout(ctx, buf[off+18:])
			if err != nil {
				if !errors.Is(err, context.DeadlineExceeded) {
					log.Debug().Err(err).Msg("failed to read from tunnel")
					time.Sleep(10 * time.Millisecond)
					continue
				}
				// we reinit it when done to not create it for each packet read
				// we need it to not lock batch for long time when there is no packets
				ctx, _ = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}

			if n > adnl.MaxMTU {
				log.Debug().Msg("skip message bigger than max mtu")
				continue
			}

			if n > 0 {
				writeSockAddr(buf[off:], addr.(*net.UDPAddr))
				buf[off+16] = byte(n >> 8)
				buf[off+17] = byte(n & 0xff)

				off += 18 + n
				num++
			}

			if num >= 100 || (num > 0 && time.Since(sinceLastBatch) >= 10*time.Millisecond) {
				C.on_recv_batch_ready((C.RecvCallback)(onRecv), nextOnRecv, unsafe.Pointer(&buf[0]), C.size_t(num))
				num, off = 0, 0
				sinceLastBatch = time.Now()
			}
		}
	}()

	log.Info().Uint16("port", port).IPAddr("ip", ip).Msg("using tunnel")
	return C.Tunnel{
		index: C.size_t(len(_gcAliveHolder)),
		ip:    C.int(binary.BigEndian.Uint32(ip.To4())),
		port:  C.int(port),
	}
}

//export WriteTunnel
func WriteTunnel(tunIdx C.size_t, data *C.uint8_t, num C.size_t) C.int {
	if int(tunIdx) <= 0 || int(tunIdx) > len(_gcAliveHolder) {
		return 0
	}

	log.Debug().Int("num", int(num)).Msg("batch write to tunnel")

	tun := _gcAliveHolder[int(tunIdx)-1]

	// convert to go slice but without copy, we don't cate about actual len so set it big
	buf := unsafe.Slice((*byte)(unsafe.Pointer(data)), 1<<31)
	off := 0

	t := time.Now()
	for i := 0; i < int(num); i++ {
		addr, err := parseSockAddr(buf[off:])
		if err != nil {
			log.Error().Err(err).Msg("invalid sock addr when trying to send")

			return 0
		}

		sz := int(buf[off+16])<<8 + int(buf[off+17])

		if _, err = tun.WriteTo(buf[off+18:off+18+sz], addr); err != nil {
			log.Debug().Err(err).Msg("failed to write to tunnel")
			return -1
		}

		off += 18 + sz
	}

	log.Debug().Int("num", int(num)).Dur("took", time.Since(t)).Msg("batch write to tunnel done")

	return 1
}

func main() {}
