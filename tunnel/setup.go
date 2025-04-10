package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ton-blockchain/adnl-tunnel/config"
	"github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/tonpayments"
	"github.com/xssnick/ton-payment-network/tonpayments/chain"
	"github.com/xssnick/ton-payment-network/tonpayments/db"
	"github.com/xssnick/ton-payment-network/tonpayments/db/leveldb"
	"github.com/xssnick/ton-payment-network/tonpayments/transport"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"math/big"
	"math/rand"
	"net"
	"time"

	cRand "crypto/rand"
)

func PrepareTunnel(cfg *config.ClientConfig, sharedCfg *config.SharedConfig, netCfg *liteclient.GlobalConfig, logger zerolog.Logger) (*RegularOutTunnel, uint16, net.IP, error) {
	if len(sharedCfg.NodesPool) == 0 {
		return nil, 0, nil, fmt.Errorf("no nodes pool provided, please specify at least one node in config file")
	}

	if uint(len(sharedCfg.NodesPool)) < cfg.TunnelSectionsNum {
		return nil, 0, nil, fmt.Errorf("not enough nodes in pool to have desired tunnel sections number")
	}

	_, dhtKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to generate DHT key: %w", err)
	}

	_, tunKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to generate TUN key: %w", err)
	}

	conn, err := adnl.DefaultListener(":")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to bind listener: %w", err)
	}

	ml := adnl.NewMultiNetReader(conn)

	gate := adnl.NewGatewayWithNetManager(tunKey, ml)
	if err = gate.StartClient(8); err != nil {
		return nil, 0, nil, fmt.Errorf("start gateway as client failed: %w", err)
	}

	dhtGate := adnl.NewGatewayWithNetManager(dhtKey, ml)
	if err = dhtGate.StartClient(); err != nil {
		return nil, 0, nil, fmt.Errorf("start dht gateway failed: %w", err)
	}

	dhtClient, err := dht.NewClientFromConfig(dhtGate, netCfg)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to create DHT client: %w", err)
	}

	var pay *tonpayments.Service
	if cfg.PaymentsEnabled {
		lsClient := liteclient.NewConnectionPool()
		if err := lsClient.AddConnectionsFromConfig(context.Background(), netCfg); err != nil {
			return nil, 0, nil, fmt.Errorf("failed to connect to liteservers: %w", err)
		}

		apiClient := ton.NewAPIClient(lsClient, ton.ProofCheckPolicyFast).WithRetry().WithTimeout(10 * time.Second)

		pay, err = preparePayerPayments(context.Background(), apiClient, dhtClient, cfg, sharedCfg, logger, ml)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("prepare payments failed: %w", err)
		}
	}

	tGate := NewGateway(gate, dhtClient, tunKey, logger.With().Str("component", "gateway").Logger(), PaymentConfig{
		Service: pay,
	})
	go func() {
		if err = tGate.Start(); err != nil {
			log.Fatal().Err(err).Msg("tunnel gateway failed")
			return
		}
	}()

	logger.Info().Msg("initializing adnl tunnel...")

	var chainTo, chainFrom []*SectionInfo

	var rndInt = make([]byte, 8)
	if _, err = cRand.Read(rndInt); err != nil {
		return nil, 0, nil, fmt.Errorf("failed to generate random number: %w", err)
	}
	rnd := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(rndInt))))

	rnd.Shuffle(len(sharedCfg.NodesPool), func(i, j int) {
		sharedCfg.NodesPool[i], sharedCfg.NodesPool[j] = sharedCfg.NodesPool[j], sharedCfg.NodesPool[i]
	})

	out := sharedCfg.NodesPool[0]
	pool := sharedCfg.NodesPool[1:]

	var siBack *SectionInfo
	if cfg.TunnelSectionsNum > 1 {
		for i := uint(0); i < cfg.TunnelSectionsNum-1; i++ {
			si, err := paymentConfigToSections(&pool[i], false, pay)
			if err != nil {
				return nil, 0, nil, fmt.Errorf("convert config to section %d in `out` route failed: %w", i, err)
			}

			if siBack == nil {
				siBack, err = paymentConfigToSections(&pool[i], false, pay)
				if err != nil {
					return nil, 0, nil, fmt.Errorf("convert config to section %d in `out` route failed: %w", i, err)
				}
			}

			chainTo = append(chainTo, si)
		}

		rnd.Shuffle(len(pool), func(i, j int) {
			pool[i], pool[j] = pool[j], pool[i]
		})

		for i := uint(0); i < cfg.TunnelSectionsNum-1; i++ {
			si, err := paymentConfigToSections(&pool[i], false, pay)
			if err != nil {
				return nil, 0, nil, fmt.Errorf("convert config to section %d in `in` route failed: %w", i, err)
			}

			chainFrom = append(chainFrom, si)
		}
	}

	siGate, err := paymentConfigToSections(&out, true, pay)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("convert config to section out gateway failed: %w", err)
	}

	chainTo = append(chainTo, siGate)

	if len(chainFrom) > 0 && siBack != nil {
		// we need same first node to be able to connect to users with
		chainFrom[len(chainFrom)-1] = siBack
	}

	var strTo string
	strTo += "we -> "
	for _, node := range chainTo {
		strTo += base64.StdEncoding.EncodeToString(node.Keys.ReceiverPubKey) + " -> "
	}

	for _, node := range chainFrom {
		strTo += base64.StdEncoding.EncodeToString(node.Keys.ReceiverPubKey) + " -> "
	}
	strTo += "we"

	logger.Info().Str("route", strTo).Msgf("configuring route...")

	toUs, err := GenerateEncryptionKeys(tunKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("generate us encryption keys failed: %w", err)
	}
	chainFrom = append(chainFrom, &SectionInfo{
		Keys: toUs,
	})

	tun, err := tGate.CreateRegularOutTunnel(context.Background(), chainTo, chainFrom, logger.With().Str("component", "tunnel").Logger())
	if err != nil {
		return nil, 0, nil, fmt.Errorf("create regular out tunnel failed: %w", err)
	}

	logger.Info().Msg("waiting adnl tunnel confirmation...")

	extIP, extPort, err := tun.WaitForInit(context.Background())
	if err != nil {
		return nil, 0, nil, fmt.Errorf("wait for tunnel init failed: %w", err)
	}

	logger.Info().Msg("adnl tunnel is ready")

	return tun, extPort, extIP, nil
}

func preparePayerPayments(ctx context.Context, apiClient ton.APIClientWrapped, dhtClient *dht.Client, cfg *config.ClientConfig, sharedCfg *config.SharedConfig, logger zerolog.Logger, manager adnl.NetManager) (*tonpayments.Service, error) {
	nodePrv := ed25519.NewKeyFromSeed(cfg.Payments.PaymentsNodeKey)
	serverPrv := ed25519.NewKeyFromSeed(cfg.Payments.ADNLServerKey)
	gate := adnl.NewGatewayWithNetManager(serverPrv, manager)

	if err := gate.StartClient(); err != nil {
		return nil, fmt.Errorf("failed to init adnl gateway: %w", err)
	}

	walletPrv := ed25519.NewKeyFromSeed(cfg.Payments.WalletPrivateKey)
	fdb, err := leveldb.NewDB(cfg.Payments.DBPath, nodePrv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to init leveldb: %w", err)
	}

	tr := transport.NewServer(dhtClient, gate, serverPrv, nodePrv, false)

	var seqno uint32
	if bo, err := fdb.GetBlockOffset(ctx); err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return nil, fmt.Errorf("failed to load block offset: %w", err)
		}
	} else {
		seqno = bo.Seqno
	}

	inv := make(chan any)
	sc := chain.NewScanner(apiClient, payments.PaymentChannelCodeHash, seqno, logger)
	if err = sc.StartSmall(inv); err != nil {
		return nil, fmt.Errorf("failed to start account scanner: %w", err)
	}
	fdb.SetOnChannelUpdated(sc.OnChannelUpdate)

	chList, err := fdb.GetChannels(context.Background(), nil, db.ChannelStateAny)
	if err != nil {
		return nil, fmt.Errorf("failed to load channels: %w", err)
	}

	for _, channel := range chList {
		if channel.Status != db.ChannelStateInactive {
			sc.OnChannelUpdate(context.Background(), channel, true)
		}
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

	svc, err := tonpayments.NewService(apiClient, fdb, tr, w, inv, nodePrv, cfg.Payments.ChannelsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to init tonpayments: %w", err)
	}

	tr.SetService(svc)
	logger.Info().Msg("payment node initialized with public key: " + base64.StdEncoding.EncodeToString(nodePrv.Public().(ed25519.PublicKey)))

	go svc.Start()

	var requiredChannels = map[string]bool{}
	for _, sec := range sharedCfg.NodesPool {
		if len(sec.Payment.Chain) == 0 {
			return nil, fmt.Errorf("no payment nodes chain specified in config for node " + base64.StdEncoding.EncodeToString(sec.Key))
		}

		if sec.Payment != nil {
			var jetton *address.Address
			var key = base64.StdEncoding.EncodeToString(sec.Payment.Chain[0].NodeKey)
			if sec.Payment.ExtraCurrencyID != 0 {
				key += ", EC: " + fmt.Sprint(sec.Payment.ExtraCurrencyID)
			}
			if sec.Payment.JettonMaster != nil {
				key += ", jetton: " + *sec.Payment.JettonMaster
				jetton = address.MustParseAddr(*sec.Payment.JettonMaster)
			}

			if _, ok := requiredChannels[key]; !ok {
				requiredChannels[key] = true
			} else {
				continue
			}

			log.Info().Str("key", key).Msg("checking required channel for payment node...")

			if _, err = preparePayerPaymentChannel(ctx, svc, sec.Payment.Chain[0].NodeKey, jetton, sec.Payment.ExtraCurrencyID); err != nil {
				return nil, fmt.Errorf("failed to prepare payment channel for %s: %w", key, err)
			}
		}
	}

	return svc, nil
}

func preparePayerPaymentChannel(ctx context.Context, pmt *tonpayments.Service, ch []byte, jetton *address.Address, ecID uint32) ([]byte, error) {
	list, err := pmt.ListChannels(ctx, nil, db.ChannelStateActive)
	if err != nil {
		return nil, fmt.Errorf("failed to list channels: %w", err)
	}

	for _, channel := range list {
		if bytes.Equal(channel.TheirOnchain.Key, ch) {
			// we have specified channel already deployed
			return channel.TheirOnchain.Key, nil
		}
	}

	ctxTm, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	addr, err := pmt.DeployChannelWithNode(ctxTm, ch, jetton, ecID)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("failed to deploy channel with node: %w", err)
	}
	log.Info().Msg("Onchain channel deployed at address: " + addr.String() + " waiting for states exchange...")

	for {
		channel, err := pmt.GetChannel(context.Background(), addr.String())
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("failed to get channel: %w", err)
		}

		if !channel.Our.IsReady() || !channel.Their.IsReady() {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		break
	}
	log.Info().Str("address", addr.String()).Msg("Channel states exchange completed")

	return ch, nil
}

func paymentConfigToSections(s *config.TunnelRouteSection, isOut bool, pay *tonpayments.Service) (*SectionInfo, error) {
	if len(s.Key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid `in` route node key size")
	}

	k, err := GenerateEncryptionKeys(s.Key)
	if err != nil {
		return nil, fmt.Errorf("generate to encryption keys failed: %w", err)
	}

	var payer *Payer
	if s.Payment != nil && pay != nil {
		var ptn []PaymentTunnelSection

		var jetton *address.Address
		var jettonStr string
		if s.Payment.JettonMaster != nil {
			if jetton, err = address.ParseAddr(*s.Payment.JettonMaster); err != nil {
				return nil, fmt.Errorf("invalid jetton master address: %w", err)
			}
			jettonStr = jetton.Bounce(true).String()
		}

		cc, err := pay.ResolveCoinConfig(jettonStr, s.Payment.ExtraCurrencyID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve coin config: %w", err)
		}

		for _, paymentChain := range s.Payment.Chain {
			if len(paymentChain.NodeKey) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid payment node key size")
			}

			minFee, err := tlb.FromDecimal(paymentChain.MinFeePerVirtualChannel, int(cc.Decimals))
			if err != nil {
				return nil, fmt.Errorf("invalid payment fee: %w", err)
			}

			maxCap, err := tlb.FromDecimal(paymentChain.MaxCapacityPerVirtualChannel, int(cc.Decimals))
			if err != nil {
				return nil, fmt.Errorf("invalid payment cap: %w", err)
			}

			ptn = append(ptn, PaymentTunnelSection{
				Key:         paymentChain.NodeKey,
				MinFee:      minFee.Nano(),
				PercentFee:  big.NewFloat(paymentChain.PercentFeePerVirtualChannel),
				MaxCapacity: maxCap.Nano(),
			})
		}

		price := s.Payment.PricePerPacketRouteNano
		if isOut {
			price = s.Payment.PricePerPacketOutNano
		}

		payer = &Payer{
			PaymentTunnel:   ptn,
			PricePerPacket:  price,
			JettonMaster:    jetton,
			ExtraCurrencyID: s.Payment.ExtraCurrencyID,
		}
	}

	return &SectionInfo{
		Keys:        k,
		PaymentInfo: payer,
	}, nil
}
