package main

/*
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
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ton-blockchain/adnl-tunnel/config"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/tonpayments"
	"github.com/xssnick/ton-payment-network/tonpayments/chain"
	configPayments "github.com/xssnick/ton-payment-network/tonpayments/config"
	"github.com/xssnick/ton-payment-network/tonpayments/db"
	"github.com/xssnick/ton-payment-network/tonpayments/db/leveldb"
	"github.com/xssnick/ton-payment-network/tonpayments/transport"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"math/big"
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

	tun, port, ip, err := prepareTun(&cfg, &netCfg)
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
				// t := time.Now()
				C.on_recv_batch_ready((C.RecvCallback)(onRecv), nextOnRecv, unsafe.Pointer(&buf[0]), C.size_t(num))
				// println("BATCH READ PROCESS TOOK", time.Since(t).String(), num)
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

	tun := _gcAliveHolder[int(tunIdx)-1]

	// convert to go slice but without copy, we don't cate about actual len so set it big
	buf := unsafe.Slice((*byte)(unsafe.Pointer(data)), 1<<31)
	off := 0

	// t := time.Now()
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

	// println("BATCH WRITTEN", num, time.Since(t).String())

	return 1
}

func prepareTun(cfg *config.ClientConfig, netCfg *liteclient.GlobalConfig) (*tunnel.RegularOutTunnel, uint16, net.IP, error) {

	lsClient := liteclient.NewConnectionPool()
	if err := lsClient.AddConnectionsFromConfig(context.Background(), netCfg); err != nil {
		return nil, 0, nil, fmt.Errorf("failed to connect to liteservers: %w", err)
	}

	apiClient := ton.NewAPIClient(lsClient, ton.ProofCheckPolicyFast).WithRetry().WithTimeout(10 * time.Second)

	_, dhtKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to generate DHT key: %w", err)
	}

	_, tunKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to generate TUN key: %w", err)
	}

	gate := adnl.NewGateway(tunKey)
	if err = gate.StartClient(8); err != nil {
		return nil, 0, nil, fmt.Errorf("start gateway as client failed: %w", err)
	}

	dhtGate := adnl.NewGateway(dhtKey)
	if err = dhtGate.StartClient(); err != nil {
		return nil, 0, nil, fmt.Errorf("start dht gateway failed: %w", err)
	}

	dhtClient, err := dht.NewClientFromConfig(dhtGate, netCfg)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to create DHT client: %w", err)
	}

	var chainTo, chainFrom []*tunnel.SectionInfo

	for i, s := range cfg.RouteOut {
		si, err := paymentConfigToSections(&s, cfg.PaymentsEnabled)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("convert config to section %d in `out` route failed: %w", i, err)
		}

		chainTo = append(chainTo, si)
	}

	for i, s := range cfg.RouteIn {
		si, err := paymentConfigToSections(&s, cfg.PaymentsEnabled)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("convert config to section %d in `in` route failed: %w", i, err)
		}

		chainFrom = append(chainFrom, si)
	}

	siGate, err := paymentConfigToSections(&cfg.OutGateway, cfg.PaymentsEnabled)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("convert config to section out gateway failed: %w", err)
	}

	chainTo = append(chainTo, siGate)

	toUs, err := tunnel.GenerateEncryptionKeys(tunKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("generate us encryption keys failed: %w", err)
	}
	chainFrom = append(chainFrom, &tunnel.SectionInfo{
		Keys: toUs,
	})

	zLogger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	log.Logger = zLogger

	var pay *tonpayments.Service
	if cfg.PaymentsEnabled {
		pay, err = preparePayerPayments(context.Background(), apiClient, dhtClient, cfg, zLogger)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("prepare payments failed: %w", err)
		}
	}

	tGate := tunnel.NewGateway(gate, dhtClient, tunKey, zLogger.With().Str("component", "gateway").Logger(), tunnel.PaymentConfig{
		Service: pay,
	})
	go func() {
		if err = tGate.Start(); err != nil {
			log.Fatal().Err(err).Msg("tunnel gateway failed")
			return
		}
	}()

	zLogger.Info().Msg("creating adnl tunnel...")

	tun, err := tGate.CreateRegularOutTunnel(context.Background(), chainTo, chainFrom, zLogger.With().Str("component", "tunnel").Logger())
	if err != nil {
		return nil, 0, nil, fmt.Errorf("create regular out tunnel failed: %w", err)
	}

	extIP, extPort, err := tun.WaitForInit(context.Background())
	if err != nil {
		return nil, 0, nil, fmt.Errorf("wait for tunnel init failed: %w", err)
	}

	zLogger.Info().Msg("adnl tunnel is ready")

	return tun, extPort, extIP, nil
}

func preparePayerPayments(ctx context.Context, apiClient ton.APIClientWrapped, dhtClient *dht.Client, cfg *config.ClientConfig, logger zerolog.Logger) (*tonpayments.Service, error) {
	nodePrv := ed25519.NewKeyFromSeed(cfg.Payments.PaymentsServerKey)
	gate := adnl.NewGateway(nodePrv)

	if err := gate.StartClient(); err != nil {
		return nil, fmt.Errorf("failed to init adnl gateway: %w", err)
	}

	walletPrv := ed25519.NewKeyFromSeed(cfg.Payments.WalletPrivateKey)
	fdb, err := leveldb.NewDB(cfg.Payments.DBPath, walletPrv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to init leveldb: %w", err)
	}

	tr := transport.NewServer(dhtClient, gate, nodePrv, walletPrv, false)

	var seqno uint32
	if bo, err := fdb.GetBlockOffset(ctx); err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return nil, fmt.Errorf("failed to load block offset: %w", err)
		}
	} else {
		seqno = bo.Seqno
	}

	inv := make(chan any)
	sc := chain.NewScanner(apiClient, payments.AsyncPaymentChannelCodeHash, seqno, logger)
	if err = sc.Start(context.Background(), inv); err != nil {
		return nil, fmt.Errorf("failed to start chain scanner: %w", err)
	}

	w, err := wallet.FromPrivateKey(apiClient, walletPrv, wallet.ConfigHighloadV3{
		MessageTTL: 3*60 + 30,
		MessageBuilder: func(ctx context.Context, subWalletId uint32) (id uint32, createdAt int64, err error) {
			createdAt = time.Now().Unix() - 30 // something older than last master block, to pass through LS external's time validation
			id = uint32(createdAt) % (1 << 23) // TODO: store seqno in db
			return
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init wallet: %w", err)
	}
	logger.Info().Msg("wallet initialized with address: " + w.WalletAddress().String())

	svc := tonpayments.NewService(apiClient, fdb, tr, w, inv, walletPrv, configPayments.ChannelConfig(cfg.Payments.ChannelConfig))
	tr.SetService(svc)
	logger.Info().Msg("payment node initialized with public key: " + base64.StdEncoding.EncodeToString(walletPrv.Public().(ed25519.PublicKey)))

	go svc.Start()
	if _, err = preparePayerPaymentChannel(ctx, svc, nil); err != nil {
		return nil, fmt.Errorf("failed to prepare payment channel: %w", err)
	}

	return svc, nil
}

func preparePayerPaymentChannel(ctx context.Context, pmt *tonpayments.Service, ch []byte) ([]byte, error) {
	list, err := pmt.ListChannels(ctx, nil, db.ChannelStateActive)
	if err != nil {
		return nil, fmt.Errorf("failed to list channels: %w", err)
	}

	var best []byte
	var bestAmount = big.NewInt(0)
	for _, channel := range list {
		if len(ch) > 0 {
			if bytes.Equal(channel.TheirOnchain.Key, ch) {
				// we have specified channel already deployed
				return channel.TheirOnchain.Key, nil
			}
			continue
		}

		balance, err := channel.CalcBalance(false)
		if err != nil {
			continue
		}

		if balance.Cmp(tlb.MustFromTON("0.1").Nano()) < 0 {
			// skip if balance too low
			continue
		}

		// if specific channel not defined we select the channel with the biggest deposit
		if balance.Cmp(bestAmount) >= 0 {
			bestAmount = balance
			best = channel.TheirOnchain.Key
		}
	}

	if best != nil {
		return best, nil
	}

	var inp string

	// if no channels (or specified channel) are nod deployed, we deploy
	if len(ch) == 0 {
		log.Info().Msg("No active onchain payment channel found, please input payment node id (pub key) in hex format, to deploy channel with:")
		if _, err = fmt.Scanln(&inp); err != nil {
			return nil, fmt.Errorf("failed to read input: %w", err)
		}

		ch, err = hex.DecodeString(inp)
		if err != nil {
			return nil, fmt.Errorf("invalid id formet: %w", err)
		}
	}

	if len(ch) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid channel id length")
	}

	log.Info().Msg("Please input amount in TON to reserve in channel:")
	if _, err = fmt.Scanln(&inp); err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	amt, err := tlb.FromTON(inp)
	if err != nil {
		return nil, fmt.Errorf("incorrect format of amount: %w", err)
	}

	ctxTm, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	addr, err := pmt.DeployChannelWithNode(ctxTm, amt, ch, nil)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("failed to deploy channel with node: %w", err)
	}
	log.Info().Msg("Onchain channel deployed at address: " + addr.String())

	return ch, nil
}

func paymentConfigToSections(s *config.TunnelRouteSection, paymentsEnabled bool) (*tunnel.SectionInfo, error) {
	if len(s.Key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid `in` route node key size")
	}

	k, err := tunnel.GenerateEncryptionKeys(s.Key)
	if err != nil {
		return nil, fmt.Errorf("generate to encryption keys failed: %w", err)
	}

	var payer *tunnel.Payer
	if s.Payment != nil {
		if !paymentsEnabled {
			return nil, fmt.Errorf("node payment is enabled but payments are disabled in config")
		}

		var ptn []tunnel.PaymentTunnelSection

		for _, paymentChain := range s.Payment.Chain {
			if len(paymentChain.NodeKey) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid payment node key size")
			}

			cFee, err := tlb.FromTON(paymentChain.Fee)
			if err != nil {
				return nil, fmt.Errorf("invalid payment fee: %w", err)
			}

			cCap, err := tlb.FromTON(paymentChain.MaxCapacity)
			if err != nil {
				return nil, fmt.Errorf("invalid payment capacity: %w", err)
			}

			ptn = append(ptn, tunnel.PaymentTunnelSection{
				Key:         paymentChain.NodeKey,
				Fee:         cFee.Nano(),
				MaxCapacity: cCap.Nano(),
			})
		}

		payer = &tunnel.Payer{
			PaymentTunnel:  ptn,
			PricePerPacket: s.Payment.PricePerPacketNano,
		}
	}

	return &tunnel.SectionInfo{
		Keys:        k,
		PaymentInfo: payer,
	}, nil
}

func main() {}
