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

typedef void (*Logger)(const char *text, const size_t len, const int level);


// we need it because we cannot call C func by pointer directly from go
static inline void on_recv_batch_ready(RecvCallback cb, void* next, void* data, size_t num) {
	cb(next, (uint8_t*)data, num);
}

static inline void on_reinit(ReinitCallback cb, void* next, void* data) {
	cb(next, (struct sockaddr*)data);
}

static inline void write_log(Logger log, const char *text, const size_t len, const int level) {
	log(text, len, level);
}
*/
import "C"
import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ton-blockchain/adnl-tunnel/config"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/liteclient"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var indexMatch []unsafe.Pointer

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

type LogWriter struct {
	logger C.Logger
}

func (l *LogWriter) Write(p []byte) (n int, err error) {
	if len(p) < 2 {
		return 0, errors.New("invalid message")
	}

	msg := string(p[2:])
	C.write_log(l.logger, C.CString(msg), C.size_t(len(p)-2), C.int(p[0]-0x30))
	return len(p), nil
}

//export PrepareTunnel
//goland:noinspection ALL
func PrepareTunnel(logger C.Logger, onRecv C.RecvCallback, onReinit C.ReinitCallback, nextOnRecv, nextOnReinit unsafe.Pointer, configPath *C.char, configPathLen C.int, networkConfigJson *C.char, networkConfigJsonLen C.int) C.Tunnel {
	path := string(C.GoBytes(unsafe.Pointer(configPath), configPathLen))

	log.Logger = zerolog.New(zerolog.NewConsoleWriter(
		func(w *zerolog.ConsoleWriter) {
			w.NoColor = true
			w.FormatTimestamp = func(i interface{}) string { return "" }
			w.FormatLevel = func(i interface{}) string {
				switch i.(string) {
				case zerolog.LevelFatalValue:
					return "0"
				case zerolog.LevelErrorValue:
					return "1"
				case zerolog.LevelWarnValue:
					return "2"
				case zerolog.LevelInfoValue:
					return "3"
				default:
					return "4"
				}
			}
			w.Out = &LogWriter{
				logger: logger,
			}
		})).With().Timestamp().Logger().Level(zerolog.DebugLevel)

	log.Info().Str("path", path).Msg("using config")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg, err := config.GenerateClientConfig()
			if err != nil {
				log.Error().Err(err).Msg("Failed to generate tunnel config")
				os.Exit(1)
			}
			if err = config.SaveConfig(cfg, path); err != nil {
				log.Error().Err(err).Msg("Failed to save tunnel config")
				os.Exit(1)
			}
			log.Info().Msg("Generated tunnel config; fill it with the desired settings and nodes pool config path, then restart")
			os.Exit(0)
		}
		log.Fatal().Err(err).Msg("Failed to load tunnel config")
	}

	var cfg config.ClientConfig
	if err = json.Unmarshal(data, &cfg); err != nil {
		log.Fatal().Err(err).Msg("Failed to parse tunnel config")
	}

	if cfg.NodesPoolConfigPath == "" {
		log.Fatal().Msg("nodes pool config path is empty")
	}

	data, err = os.ReadFile(cfg.NodesPoolConfigPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", cfg.NodesPoolConfigPath).Msg("Failed to load tunnel shared config (nodes pool)")
	}

	var sharedCfg config.SharedConfig
	if err = json.Unmarshal(data, &sharedCfg); err != nil {
		log.Fatal().Err(err).Msg("Failed to parse tunnel shared config")
	}

	var netCfg liteclient.GlobalConfig
	if err := json.Unmarshal(C.GoBytes(unsafe.Pointer(networkConfigJson), networkConfigJsonLen), &netCfg); err != nil {
		log.Error().Err(err).Msg("failed to parse network config")
		return C.Tunnel{}
	}

	events := make(chan any, 1)
	go tunnel.RunTunnel(context.Background(), &cfg, &sharedCfg, &netCfg, log.Logger, events)

	indexMatch = []unsafe.Pointer{nil}

	initUpd := make(chan tunnel.UpdatedEvent, 1)
	once := sync.Once{}
	go func() {
		for event := range events {
			switch e := event.(type) {
			case tunnel.StoppedEvent:
				log.Info().Msg("tunnel stopped")
				return
			case tunnel.UpdatedEvent:
				log.Info().Msg("tunnel updated")

				e.Tunnel.SetOutAddressChangedHandler(func(addr *net.UDPAddr) {
					var buf [16]byte
					writeSockAddr(buf[:], addr)

					C.on_reinit((C.RecvCallback)(onReinit), nextOnReinit, unsafe.Pointer(&buf[0]))
				})

				once.Do(func() {
					initUpd <- e
				})

				atomic.StorePointer(&indexMatch[0], unsafe.Pointer(e.Tunnel))
			case tunnel.ConfigurationErrorEvent:
				log.Err(e.Err).Msg("tunnel configuration error, will retry...")
			case error:
				log.Fatal().Err(e).Msg("tunnel failed")
			}
		}
	}()
	upd := <-initUpd

	go func() {
		off, num := 0, 0
		buf := make([]byte, (16+2+adnl.MaxMTU)*100)
		sinceLastBatch := time.Now()
		ctx, _ := context.WithTimeout(context.Background(), 20*time.Millisecond)

		for {
			tun := (*tunnel.RegularOutTunnel)(atomic.LoadPointer(&indexMatch[0]))
			n, addr, err := tun.ReadFromWithTimeout(ctx, buf[off+18:])
			if err != nil {
				if !errors.Is(err, context.DeadlineExceeded) {
					log.Trace().Err(err).Msg("failed to read from tunnel")
					time.Sleep(10 * time.Millisecond)
					continue
				}
				// we reinit it when done to not create it for each packet read
				// we need it to not lock batch for long time when there is no packets
				ctx, _ = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}

			if n > adnl.MaxMTU {
				log.Trace().Msg("skip message bigger than max mtu")
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
				C.on_recv_batch_ready(onRecv, nextOnRecv, unsafe.Pointer(&buf[0]), C.size_t(num))
				num, off = 0, 0
				sinceLastBatch = time.Now()
			}
		}
	}()

	log.Info().Uint16("port", upd.ExtPort).IPAddr("ip", upd.ExtIP).Msg("using tunnel")
	return C.Tunnel{
		index: C.size_t(len(indexMatch)),
		ip:    C.int(binary.BigEndian.Uint32(upd.ExtIP.To4())),
		port:  C.int(upd.ExtPort),
	}
}

//export WriteTunnel
func WriteTunnel(tunIdx C.size_t, data *C.uint8_t, num C.size_t) C.int {
	if int(tunIdx) <= 0 || int(tunIdx) > len(indexMatch) {
		return 0
	}

	// log.Debug().Int("num", int(num)).Msg("batch write to tunnel")

	tun := (*tunnel.RegularOutTunnel)(atomic.LoadPointer(&indexMatch[int(tunIdx)-1]))

	// convert to go slice but without copy, we don't cate about actual len so set it big
	buf := unsafe.Slice((*byte)(unsafe.Pointer(data)), 1<<31)
	off := 0

	// t := time.Now()
	for i := 0; i < int(num); i++ {
		addr, err := parseSockAddr(buf[off:])
		if err != nil {
			log.Trace().Err(err).Msg("invalid sock addr when trying to send")

			return 0
		}

		sz := int(buf[off+16])<<8 + int(buf[off+17])

		if _, err = tun.WriteTo(buf[off+18:off+18+sz], addr); err != nil {
			log.Trace().Err(err).Msg("failed to write to tunnel")
			return -1
		}

		off += 18 + sz
	}

	// log.Debug().Int("num", int(num)).Dur("took", time.Since(t)).Msg("batch write to tunnel done")

	return 1
}

func main() {}
