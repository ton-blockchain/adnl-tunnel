package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ton-blockchain/adnl-tunnel/config"
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
)

func PrepareTunnel(cfg *config.ClientConfig, netCfg *liteclient.GlobalConfig) (*RegularOutTunnel, uint16, net.IP, error) {
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

	var chainTo, chainFrom []*SectionInfo

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

	toUs, err := GenerateEncryptionKeys(tunKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("generate us encryption keys failed: %w", err)
	}
	chainFrom = append(chainFrom, &SectionInfo{
		Keys: toUs,
	})

	zLogger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	log.Logger = zLogger

	var pay *tonpayments.Service
	if cfg.PaymentsEnabled {
		lsClient := liteclient.NewConnectionPool()
		if err := lsClient.AddConnectionsFromConfig(context.Background(), netCfg); err != nil {
			return nil, 0, nil, fmt.Errorf("failed to connect to liteservers: %w", err)
		}

		apiClient := ton.NewAPIClient(lsClient, ton.ProofCheckPolicyFast).WithRetry().WithTimeout(10 * time.Second)

		pay, err = preparePayerPayments(context.Background(), apiClient, dhtClient, cfg, zLogger)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("prepare payments failed: %w", err)
		}
	}

	tGate := NewGateway(gate, dhtClient, tunKey, zLogger.With().Str("component", "gateway").Logger(), PaymentConfig{
		Service: pay,
	})
	go func() {
		if err = tGate.Start(); err != nil {
			log.Fatal().Err(err).Msg("tunnel gateway failed")
			return
		}
	}()

	zLogger.Info().Msg("creating adnl...")

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

func paymentConfigToSections(s *config.TunnelRouteSection, paymentsEnabled bool) (*SectionInfo, error) {
	if len(s.Key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid `in` route node key size")
	}

	k, err := GenerateEncryptionKeys(s.Key)
	if err != nil {
		return nil, fmt.Errorf("generate to encryption keys failed: %w", err)
	}

	var payer *Payer
	if s.Payment != nil && paymentsEnabled {
		var ptn []PaymentTunnelSection

		for _, paymentChain := range s.Payment.Chain {
			if len(paymentChain.NodeKey) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid payment node key size")
			}

			cFee, err := tlb.FromTON(paymentChain.FeePerVirtualChannel)
			if err != nil {
				return nil, fmt.Errorf("invalid payment fee: %w", err)
			}

			ptn = append(ptn, PaymentTunnelSection{
				Key: paymentChain.NodeKey,
				Fee: cFee.Nano(),
			})
		}

		payer = &Payer{
			PaymentTunnel:  ptn,
			PricePerPacket: s.Payment.PricePerPacketNano,
		}
	}

	return &SectionInfo{
		Keys:        k,
		PaymentInfo: payer,
	}, nil
}
