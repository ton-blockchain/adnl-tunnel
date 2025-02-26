package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ton-blockchain/adnl-tunnel/config"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/tonpayments"
	"github.com/xssnick/ton-payment-network/tonpayments/chain"
	pConfig "github.com/xssnick/ton-payment-network/tonpayments/config"
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
	"runtime"
	"time"
)

import _ "net/http/pprof"

var ConfigPath = flag.String("config", "config.json", "Config path")
var PaymentNodeWith = flag.String("payment-node", "", "Payment node to open channel with")
var Verbosity = flag.Int("v", 2, "verbosity")

func init() {
	flag.Parse()
}

func main() {
	log.Logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	adnl.Logger = func(v ...any) {}

	if *Verbosity >= 5 {
		dht.Logger = func(v ...any) {
			log.Logger.Debug().Msg(fmt.Sprintln(v...))
		}
	}

	if *Verbosity >= 4 {
		adnl.Logger = func(v ...any) {
			log.Logger.Debug().Msg(fmt.Sprintln(v...))
		}
	}

	if *Verbosity >= 3 {
		log.Logger = log.Logger.Level(zerolog.DebugLevel).With().Logger()
	} else if *Verbosity == 2 {
		log.Logger = log.Logger.Level(zerolog.InfoLevel).With().Logger()
	} else if *Verbosity == 1 {
		log.Logger = log.Logger.Level(zerolog.WarnLevel).With().Logger()
	} else if *Verbosity == 0 {
		log.Logger = log.Logger.Level(zerolog.ErrorLevel).With().Logger()
	} else {
		log.Logger = log.Logger.Level(zerolog.FatalLevel).With().Logger()
	}

	cfg, err := config.LoadConfig(*ConfigPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
		return
	}

	_, dhtKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate DHT key")
		return
	}

	/*runtime.SetMutexProfileFraction(1)
	go func() {
		http.ListenAndServe(":6065", nil)
	}()*/

	threads := int(cfg.TunnelThreads)
	if threads == 0 {
		threads = runtime.NumCPU()
	}

	tunKey := ed25519.NewKeyFromSeed(cfg.TunnelServerKey)
	gate := adnl.NewGateway(tunKey)
	if cfg.ExternalIP != "" {
		ip := net.ParseIP(cfg.ExternalIP)
		if ip == nil {
			log.Fatal().Msg("Invalid external IP address")
			return
		}
		gate.SetExternalIP(ip)
	}

	if err = gate.StartServer(cfg.TunnelListenAddr, threads); err != nil {
		log.Fatal().Err(err).Msg("start gateway as server failed")
		return
	}

	dhtGate := adnl.NewGateway(dhtKey)
	if err = dhtGate.StartClient(); err != nil {
		log.Fatal().Err(err).Msg("start dht gateway failed")
		return
	}

	gCfg, err := liteclient.GetConfigFromUrl(context.Background(), cfg.NetworkConfigUrl)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get global config")
	}

	dhtClient, err := dht.NewClientFromConfig(dhtGate, gCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create DHT client")
		return
	}

	var pmt tunnel.PaymentConfig
	if cfg.PaymentsEnabled {
		log.Info().Msg("Initializing payment node ")
		pm := preparePayments(context.Background(), gCfg, dhtClient, cfg)
		go pm.Start()

		var ch []byte
		if *PaymentNodeWith != "" {
			ch, err = hex.DecodeString(*PaymentNodeWith)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to parse payment node key")
				return
			}
			if len(ch) != ed25519.PublicKeySize {
				log.Fatal().Msg("Invalid payment node key size")
				return
			}
		}

		chId, err := preparePaymentChannel(context.Background(), pm, ch)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to prepare payment channels")
		}
		log.Info().Hex("payment-pub-key", chId).Msg("prioritized channel for payments is active")

		pmt = tunnel.PaymentConfig{
			Service:                pm,
			MinPricePerPacketRoute: cfg.Payments.MinPricePerPacketRoute,
			MinPricePerPacketInOut: cfg.Payments.MinPricePerPacketInOut,
		}
	}

	tGate := tunnel.NewGateway(gate, dhtClient, tunKey, log.With().Str("component", "gateway").Logger(), pmt)
	go func() {
		if err = tGate.Start(); err != nil {
			log.Fatal().Err(err).Msg("tunnel gateway failed")
			return
		}
	}()

	speedPrinterCtx, cancelSp := context.WithCancel(context.Background())
	cancelSp()

	log.Info().Msg("Tunnel started, listening on " + cfg.TunnelListenAddr + " ADNL id is: " + base64.StdEncoding.EncodeToString(tunKey.Public().(ed25519.PublicKey)))
	for {
		log.Info().Msg("Input a command:")
		var val string
		if _, err = fmt.Scanln(&val); err != nil {
			log.Error().Err(err).Msg("input failure")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		switch val {
		case "speed":
			select {
			case <-speedPrinterCtx.Done():
				speedPrinterCtx, cancelSp = context.WithCancel(context.Background())

				go func() {
					prev := tGate.GetPacketsStats()
					for {
						select {
						case <-speedPrinterCtx.Done():
							return
						case <-time.After(time.Second * 1):
							stats := tGate.GetPacketsStats()
							for s, st := range stats {
								if p := prev[s]; p != nil {
									log.Info().Hex("section", []byte(s)).
										Str("routed", formatNum(st.Routed-p.Routed)+"/s").
										Str("sent", formatNum(st.Sent-p.Sent)+"/s").
										Str("received", formatNum(st.Received-p.Received)+"/s").
										Msg("per second")
								}
							}
							prev = stats
						}
					}
				}()

			default:
				cancelSp()
			}
		case "stats":
			stats := tGate.GetPacketsStats()
			for s, st := range stats {
				log.Info().Hex("section", []byte(s)).
					Str("routed", formatNum(st.Routed)).
					Str("sent", formatNum(st.Sent)).
					Str("received", formatNum(st.Received)).
					Msg("stats summarized")
			}
		case "balance", "capacity":
			if pmt.Service == nil {
				log.Error().Msg("payments are not enabled")
				continue
			}

			list, err := pmt.Service.ListChannels(context.Background(), nil, db.ChannelStateActive)
			if err != nil {
				log.Error().Err(err).Msg("Failed to list channels")
				continue
			}

			amount := big.NewInt(0)
			for _, channel := range list {
				v, err := channel.CalcBalance(val == "capacity")
				if err != nil {
					log.Error().Err(err).Msg("Failed to calc channel balance")
					continue
				}
				amount = amount.Add(amount, v)
			}

			if val == "balance" {
				log.Info().Msg("Summarized balance: " + tlb.FromNanoTON(amount).String() + " TON")
			} else {
				log.Info().Msg("Capacity left: " + tlb.FromNanoTON(amount).String() + " TON")
			}
			continue
		}

	}
}

func formatNum(packets uint64) string {
	sizes := []string{"", " K", " M", " B"}

	sizeIndex := 0
	sizeFloat := float64(packets)

	for sizeFloat >= 1000 && sizeIndex < len(sizes)-1 {
		sizeFloat /= 1000
		sizeIndex++
	}

	return fmt.Sprintf("%.2f%s", sizeFloat, sizes[sizeIndex])
}

func preparePayments(ctx context.Context, gCfg *liteclient.GlobalConfig, dhtClient *dht.Client, cfg *config.Config) *tonpayments.Service {
	client := liteclient.NewConnectionPool()

	log.Info().Msg("initializing ton client with verified proof chain...")

	// connect to lite servers
	if err := client.AddConnectionsFromConfig(ctx, gCfg); err != nil {
		log.Fatal().Err(err).Msg("ton connect err")
		return nil
	}

	policy := ton.ProofCheckPolicyFast
	if cfg.Payments.SecureProofPolicy {
		policy = ton.ProofCheckPolicySecure
	}

	// initialize ton api lite connection wrapper
	apiClient := ton.NewAPIClient(client, policy).WithRetry(2).WithTimeout(5 * time.Second)
	if cfg.Payments.SecureProofPolicy {
		apiClient.SetTrustedBlockFromConfig(gCfg)
	}

	nodePrv := ed25519.NewKeyFromSeed(cfg.Payments.PaymentsServerKey)
	gate := adnl.NewGateway(nodePrv)

	if err := gate.StartClient(); err != nil {
		log.Fatal().Err(err).Msg("failed to init adnl payments gateway")
		return nil
	}

	walletPrv := ed25519.NewKeyFromSeed(cfg.Payments.WalletPrivateKey)
	fdb, err := leveldb.NewDB(cfg.Payments.DBPath, walletPrv.Public().(ed25519.PublicKey))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init leveldb")
		return nil
	}

	tr := transport.NewServer(dhtClient, gate, nodePrv, walletPrv, cfg.ExternalIP != "")

	var seqno uint32
	if bo, err := fdb.GetBlockOffset(ctx); err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			log.Fatal().Err(err).Msg("failed to load block offset")
			return nil
		}
	} else {
		seqno = bo.Seqno
	}

	scanLog := log.Logger
	if *Verbosity >= 4 {
		scanLog = scanLog.Level(zerolog.DebugLevel).With().Logger()
	}

	inv := make(chan any)
	sc := chain.NewScanner(apiClient, payments.AsyncPaymentChannelCodeHash, seqno, scanLog)
	if err = sc.Start(context.Background(), inv); err != nil {
		log.Fatal().Err(err).Msg("failed to start chain scanner")
		return nil
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
		log.Fatal().Err(err).Msg("failed to init wallet")
		return nil
	}
	log.Info().Str("addr", w.WalletAddress().String()).Msg("wallet initialized")

	svc := tonpayments.NewService(apiClient, fdb, tr, w, inv, walletPrv, pConfig.ChannelConfig(cfg.Payments.ChannelConfig))
	tr.SetService(svc)
	log.Info().Hex("pubkey", walletPrv.Public().(ed25519.PublicKey)).Msg("node initialized")

	return svc
}

func preparePaymentChannel(ctx context.Context, pmt *tonpayments.Service, ch []byte) ([]byte, error) {
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

		// if specific channel not defined we select the channel with the biggest deposit
		if channel.TheirOnchain.Deposited.Cmp(bestAmount) >= 0 {
			bestAmount = channel.TheirOnchain.Deposited
			best = channel.TheirOnchain.Key
		}
	}

	if best != nil {
		return best, nil
	}

	var inp string

	// if no channels (or specified channel) are nod deployed, we deploy
	if len(ch) == 0 {
		log.Warn().Msg("No active onchain payment channel found, please input payment node id (pub key) in hex format, to deploy channel with:")
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

	log.Warn().Msg("Please input amount in TON to reserve in channel:")
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
	log.Info().Str("address", addr.String()).Msg("onchain channel deployed")

	return ch, nil
}

/*
func test() {
	nodes, err := tGate.DiscoverNodes(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("discover nodes failed")
		return
	}

	if len(nodes) == 0 {
		log.Fatal().Msg("no nodes found")
		return
	}

	nodes = nodes[:1]

	var chainTo, chainFrom []*tunnel.SectionInfo
	for i, node := range nodes {
		k, err := tunnel.GenerateEncryptionKeys(node)
		if err != nil {
			log.Fatal().Err(err).Int("i", i).Msg("generate to encryption keys failed")
			return
		}
		chainTo = append(chainTo, &tunnel.SectionInfo{
			Keys: k,
		})
	}

	toUs, err := tunnel.GenerateEncryptionKeys(tunKey.Public().(ed25519.PublicKey))
	if err != nil {
		log.Fatal().Err(err).Msg("generate us encryption keys failed")
		return
	}
	chainFrom = append(chainFrom, &tunnel.SectionInfo{
		Keys: toUs,
	})

	tun, err := tGate.CreateRegularOutTunnel(context.Background(), chainTo, chainFrom, log.With().Str("component", "tunnel").Logger())
	if err != nil {
		log.Fatal().Err(err).Msg("create regular out tunnel failed")
		return
	}

	extIP, _, err := tun.WaitForInit(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("wait for tunnel init failed")
		return
	}

	_, gKey, _ := ed25519.GenerateKey(nil)
	tgw := adnl.NewGatewayWithListener(gKey, func(addr string) (net.PacketConn, error) {
		println("TUN ADDR VIA: ", addr)
		return tun, nil
	})
	if extIP != nil {
		tgw.SetExternalIP(extIP)
	}

	/*tgw := adnl.NewGatewayWithListener(gKey, func(addr string) (net.PacketConn, error) {
		println("TUN ADDR VIA: ", addr)
		return tun, nil
	})*/
/*
	if err = tgw.StartClient(); err != nil {
		log.Fatal().Err(err).Msg("start tunnel client failed")
		return
	}

	tunDhtClient, err := dht.NewClientFromConfigUrl(context.Background(), tgw, "https://ton-blockchain.github.io/global.config.json")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create TUN DHT client")
		return
	}

	for {
		time.Sleep(3 * time.Second)

		overlayKey, _ := tl.Hash(tunnel.OverlayKey{
			PaymentNode: make([]byte, 32),
		})
		println("SEARCHING VIA TUN", hex.EncodeToString(overlayKey))

		nodesList, _, err := tunDhtClient.FindOverlayNodes(context.Background(), overlayKey)
		if err != nil {
			log.Error().Err(err).Msg("find overlay nodes failed")
			continue
		}

		println("FOUND VIA TUN:", len(nodesList.List))
	}

	/*go func() {
		var x uint32
		for {
			time.Sleep(3 * time.Second)

			x++
			var buf = make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, x)

			_, err := tun.WriteTo(buf, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("5.0.0.1:7777")))
			if err != nil {
				log.Fatal().Err(err).Msg("write to tunnel failed")
			}

			log.Info().Uint32("x", x).Msg("wrote to tunnel")
		}
	}()

	for {
		buf := make([]byte, 2048)
		n, from, err := tun.ReadFrom(buf)
		if err != nil {
			log.Fatal().Err(err).Msg("read from tunnel failed")
			return
		}

		log.Info().Str("data", string(buf[:n])).Str("from", from.String()).Msg("read from tunnel")
	}*/
//}
