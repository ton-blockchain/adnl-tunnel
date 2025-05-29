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

const (
	AcceptorDecisionCancel = iota
	AcceptorDecisionAccept
	AcceptorDecisionReject
)

var Acceptor = func(to, from []*SectionInfo) int {
	return AcceptorDecisionAccept
}

var AskReroute = func() bool {
	return false
}

type UpdatedEvent struct {
	Tunnel  *RegularOutTunnel
	ExtIP   net.IP
	ExtPort uint16
}

type ConfigurationErrorEvent struct {
	Err error
}

type MsgEvent struct {
	Msg string
}

type StoppedEvent struct{}

func RunTunnel(stopCtx context.Context, cfg *config.ClientConfig, sharedCfg *config.SharedConfig, netCfg *liteclient.GlobalConfig, logger zerolog.Logger, events chan any) {
	defer func() {
		events <- StoppedEvent{}
	}()

	var nodes []config.TunnelRouteSection

	closerCtx, cancel := context.WithCancel(stopCtx)
	defer cancel()

	if !cfg.PaymentsEnabled {
		for i, section := range sharedCfg.NodesPool {
			if section.Payment == nil {
				nodes = append(nodes, sharedCfg.NodesPool[i])
			}
		}
	} else {
		nodes = sharedCfg.NodesPool
	}

	if len(nodes) == 0 {
		events <- fmt.Errorf("no nodes pool provided, please specify at least one node that match your payment settings in config file")
		return
	}

	if uint(len(nodes)) < cfg.TunnelSectionsNum {
		events <- fmt.Errorf("not enough nodes that match your payment settings in pool to have desired tunnel sections number")
		return
	}

	_, dhtKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		events <- fmt.Errorf("failed to generate DHT key: %w", err)
		return
	}

	_, tunKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		events <- fmt.Errorf("failed to generate TUN key: %w", err)
		return
	}

	conn, err := adnl.DefaultListener(":")
	if err != nil {
		events <- fmt.Errorf("failed to bind listener: %w", err)
		return
	}
	defer conn.Close()

	ml := adnl.NewMultiNetReader(conn)
	defer ml.Close()

	gate := adnl.NewGatewayWithNetManager(tunKey, ml)
	if err = gate.StartClient(8); err != nil {
		events <- fmt.Errorf("start gateway as client failed: %w", err)
		return
	}
	defer gate.Close()

	dhtGate := adnl.NewGatewayWithNetManager(dhtKey, ml)
	if err = dhtGate.StartClient(); err != nil {
		events <- fmt.Errorf("start dht gateway failed: %w", err)
		return
	}
	defer dhtGate.Close()

	dhtClient, err := dht.NewClientFromConfig(dhtGate, netCfg)
	if err != nil {
		events <- fmt.Errorf("failed to create DHT client: %w", err)
		return
	}
	defer dhtClient.Close()

	var apiClient ton.APIClientWrapped
	var pay *tonpayments.Service
	if cfg.PaymentsEnabled {
		lsClient := liteclient.NewConnectionPool()
		if err := lsClient.AddConnectionsFromConfig(closerCtx, netCfg); err != nil {
			events <- fmt.Errorf("failed to connect to liteservers: %w", err)
			return
		}

		apiClient = ton.NewAPIClient(lsClient, ton.ProofCheckPolicyFast).WithRetry(3).WithTimeout(5 * time.Second)

		events <- MsgEvent{Msg: "Preparing tunnel payments..."}
		var onCloseExec []func()
		pay, onCloseExec, err = preparePayerPayments(closerCtx, apiClient, dhtClient, cfg, logger, ml, events)
		if err != nil {
			events <- fmt.Errorf("prepare payments failed: %w", err)
			return
		}
		defer func() {
			for _, f := range onCloseExec {
				f()
			}
		}()
	}

	tGate := NewGateway(gate, dhtClient, tunKey, logger.With().Str("component", "gateway").Logger(), PaymentConfig{
		Service: pay,
	})
	go func() {
		if err = tGate.Start(); err != nil {
			events <- fmt.Errorf("tunnel gateway failed: %w", err)
			return
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
		defer cancel()

		if err := tGate.Stop(ctx); err != nil {
			log.Error().Err(err).Msg("tunnel gateway graceful stop failed")
		}
	}()

	attempts := map[string]bool{}
reinit:
	for {
		events <- MsgEvent{Msg: "Configuring tunnel route..."}

		var lastAsk int64
		ctxInit, cancel := context.WithTimeout(closerCtx, 60*time.Second)
		tun, port, ip, err, retryable := configureRoute(ctxInit, cfg, apiClient, tGate, nodes, attempts, events)
		cancel()
		if err != nil {
			if errors.Is(err, ErrNoMoreRoutes) {
				attempts = map[string]bool{}
			}

			if !retryable {
				events <- fmt.Errorf("failed to configure route: %w", err)
				return
			}

			events <- ConfigurationErrorEvent{err}
			time.Sleep(300 * time.Millisecond)
			continue
		}

		events <- UpdatedEvent{
			Tunnel:  tun,
			ExtIP:   ip,
			ExtPort: port,
		}

		for {
			select {
			case <-tGate.closerCtx.Done():
				return
			case <-closerCtx.Done():
				return
			case <-time.After(5 * time.Second):
				now := time.Now().Unix()
				if now-tun.lastFullyCheckedAt > 45 && now-lastAsk > 60 {
					tGate.log.Warn().Msg("tunnel is stalled for too long, asking about rerouting...")
					if AskReroute() {
						_ = tun.Stop(closerCtx)
						continue reinit
					} else {
						tGate.log.Warn().Msg("rerouting denied, waiting 60 seconds before next ask")

						lastAsk = time.Now().Unix()
					}
				}
			}
		}
	}
}

var ErrRouteCanceled = errors.New("route canceled")
var ErrRouteIsNotAccepted = errors.New("route is not accepted")
var ErrNoMoreRoutes = errors.New("no more routes to try")

func configureRoute(ctx context.Context, cfg *config.ClientConfig, apiClient ton.APIClientWrapped, tGate *Gateway, nodes []config.TunnelRouteSection, attempts map[string]bool, events chan any) (*RegularOutTunnel, uint16, net.IP, error, bool) {
	tGate.log.Info().Msg("initializing adnl tunnel...")

	var tries int
reassemble:
	if tries > 50 {
		return nil, 0, nil, ErrNoMoreRoutes, true
	}

	tries++

	var chainTo, chainFrom []*SectionInfo

	var rndInt = make([]byte, 8)
	if _, err := cRand.Read(rndInt); err != nil {
		return nil, 0, nil, fmt.Errorf("failed to generate random number: %w", err), false
	}
	rnd := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(rndInt))))

	rnd.Shuffle(len(nodes), func(i, j int) {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	})

	out := nodes[0]
	pool := nodes[1:]

	var siBack *SectionInfo
	if cfg.TunnelSectionsNum > 1 {
		for i := uint(0); i < cfg.TunnelSectionsNum-1; i++ {
			si, err := paymentConfigToSections(&pool[i], false, tGate.payments.Service)
			if err != nil {
				return nil, 0, nil, fmt.Errorf("convert config to section %d in `out` route failed: %w", i, err), false
			}

			if siBack == nil {
				siBack, err = paymentConfigToSections(&pool[i], false, tGate.payments.Service)
				if err != nil {
					return nil, 0, nil, fmt.Errorf("convert config to section %d in `out` route failed: %w", i, err), false
				}
			}

			chainTo = append(chainTo, si)
		}

		rnd.Shuffle(len(pool), func(i, j int) {
			pool[i], pool[j] = pool[j], pool[i]
		})

		for i := uint(0); i < cfg.TunnelSectionsNum-1; i++ {
			si, err := paymentConfigToSections(&pool[i], false, tGate.payments.Service)
			if err != nil {
				return nil, 0, nil, fmt.Errorf("convert config to section %d in `in` route failed: %w", i, err), false
			}

			chainFrom = append(chainFrom, si)
		}
	}

	siGate, err := paymentConfigToSections(&out, true, tGate.payments.Service)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("convert config to section out gateway failed: %w", err), false
	}

	chainTo = append(chainTo, siGate)

	if len(chainFrom) > 0 && siBack != nil {
		// we need same first node to be able to connect to users with
		found := false
		for i, node := range chainFrom {
			if bytes.Equal(node.Keys.ReceiverPubKey, siBack.Keys.ReceiverPubKey) {
				// swap the found node with the last node in the chainFrom
				chainFrom[i], chainFrom[len(chainFrom)-1] = chainFrom[len(chainFrom)-1], node
				found = true
				break
			}
		}

		if !found {
			// not there, replace last with it
			chainFrom[len(chainFrom)-1] = siBack
		}
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

	if attempts[strTo] {
		goto reassemble
	}

	tGate.log.Info().Str("route", strTo).Msgf("configuring route...")

	attempts[strTo] = true
	if den := Acceptor(chainTo, chainFrom); den != AcceptorDecisionAccept {

		if den == AcceptorDecisionCancel {
			tGate.log.Info().Str("route", strTo).Msgf("route canceled")
			return nil, 0, nil, ErrRouteCanceled, false
		}
		tGate.log.Info().Str("route", strTo).Msgf("route denied")

		return nil, 0, nil, ErrRouteIsNotAccepted, true
	}

	toUs, err := GenerateEncryptionKeys(tGate.key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("generate us encryption keys failed: %w", err), false
	}
	chainFrom = append(chainFrom, &SectionInfo{
		Keys: toUs,
	})

	if tGate.payments.Service != nil {
		if err = checkAndDeployPaymentChannels(ctx, apiClient, tGate.payments.Service, nodes, events); err != nil {
			return nil, 0, nil, fmt.Errorf("failed to check payment channels: %w", err), false
		}
	}

	tun, err := tGate.CreateRegularOutTunnel(ctx, chainTo, chainFrom, tGate.log.With().Str("component", "tunnel").Logger())
	if err != nil {
		return nil, 0, nil, fmt.Errorf("create regular out tunnel failed: %w", err), true
	}

	tGate.log.Info().Str("route", strTo).Msg("waiting adnl tunnel confirmation...")

	extIP, extPort, err := tun.WaitForInit(ctx, func(s string) {
		events <- MsgEvent{Msg: s}
	})
	if err != nil {
		_ = tun.Stop(ctx)
		return nil, 0, nil, fmt.Errorf("wait for tunnel init failed: %w", err), true
	}

	tGate.log.Info().Str("route", strTo).Msg("adnl tunnel is ready")

	return tun, extPort, extIP, nil, true
}

func preparePayerPayments(ctx context.Context, apiClient ton.APIClientWrapped, dhtClient *dht.Client, cfg *config.ClientConfig, logger zerolog.Logger, manager adnl.NetManager, events chan any) (svc *tonpayments.Service, onCloseExec []func(), err error) {
	nodePrv := ed25519.NewKeyFromSeed(cfg.Payments.PaymentsNodeKey)
	serverPrv := ed25519.NewKeyFromSeed(cfg.Payments.ADNLServerKey)
	gate := adnl.NewGatewayWithNetManager(serverPrv, manager)

	initOk := false
	onEnd := func(f func()) {
		if !initOk {
			f()
			return
		}
		// we need this to gracefully close backgrounds on error or after exec when ctx is done (on service stop)
		onCloseExec = append([]func(){f}, onCloseExec...)
	}

	if err := gate.StartClient(); err != nil {
		return nil, nil, fmt.Errorf("failed to init adnl gateway: %w", err)
	}
	defer onEnd(func() {
		_ = gate.Close()
	})

	walletPrv := ed25519.NewKeyFromSeed(cfg.Payments.WalletPrivateKey)
	fdb, freshDb, err := leveldb.NewDB(cfg.Payments.DBPath, nodePrv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init leveldb: %w", err)
	}
	defer onEnd(fdb.Close)

	if freshDb {
		if err = fdb.SetMigrationVersion(ctx, len(db.Migrations)); err != nil {
			return nil, nil, fmt.Errorf("failed to set migration version: %w", err)
		}
	} else {
		if err = db.RunMigrations(fdb); err != nil {
			return nil, nil, fmt.Errorf("failed to run migrations: %w", err)
		}
	}

	tr := transport.NewServer(dhtClient, gate, serverPrv, nodePrv, false)
	defer onEnd(tr.Stop)

	var seqno uint32
	if bo, err := fdb.GetBlockOffset(ctx); err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return nil, nil, fmt.Errorf("failed to load block offset: %w", err)
		}
	} else {
		seqno = bo.Seqno
	}

	inv := make(chan any)
	sc := chain.NewScanner(apiClient, seqno, logger)
	if err = sc.StartSmall(inv); err != nil {
		return nil, nil, fmt.Errorf("failed to start account scanner: %w", err)
	}
	defer onEnd(sc.Stop)
	fdb.SetOnChannelUpdated(sc.OnChannelUpdate)

	chList, err := fdb.GetChannels(ctx, nil, db.ChannelStateAny)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load channels: %w", err)
	}

	for _, channel := range chList {
		if channel.Status != db.ChannelStateInactive {
			sc.OnChannelUpdate(ctx, channel, true)
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
		return nil, nil, fmt.Errorf("failed to init wallet: %w", err)
	}
	logger.Info().Msg("wallet initialized with address: " + w.WalletAddress().String())

	svc, err = tonpayments.NewService(apiClient, fdb, tr, w, inv, nodePrv, cfg.Payments.ChannelsConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init tonpayments: %w", err)
	}

	tr.SetService(svc)
	logger.Info().Msg("payment node initialized with public key: " + base64.StdEncoding.EncodeToString(nodePrv.Public().(ed25519.PublicKey)))

	go svc.Start()
	defer onEnd(svc.Stop)

	initOk = true
	return
}

func checkAndDeployPaymentChannels(ctx context.Context, apiClient ton.APIClientWrapped, svc *tonpayments.Service, nodes []config.TunnelRouteSection, events chan any) error {
	var requiredChannels = map[string]bool{}
	for _, sec := range nodes {
		if sec.Payment == nil {
			continue
		}
		
		if len(sec.Payment.Chain) == 0 {
			return fmt.Errorf("no payment nodes chain specified in config for node " + base64.StdEncoding.EncodeToString(sec.Key))
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

			events <- MsgEvent{Msg: "Preparing payment channel for tunnel..."}

			if _, err := preparePayerPaymentChannel(ctx, apiClient, svc, sec.Payment.Chain[0].NodeKey, jetton, sec.Payment.ExtraCurrencyID, events); err != nil {
				return fmt.Errorf("failed to prepare payment channel for %s: %w", key, err)
			}
		}
	}
	return nil
}

func preparePayerPaymentChannel(ctx context.Context, api ton.APIClientWrapped, pmt *tonpayments.Service, ch []byte, jetton *address.Address, ecID uint32, events chan any) ([]byte, error) {
	list, err := pmt.ListChannels(ctx, nil, db.ChannelStateActive)
	if err != nil {
		return nil, fmt.Errorf("failed to list channels: %w", err)
	}

	for _, channel := range list {
		if bytes.Equal(channel.TheirOnchain.Key, ch) {
			addr := address.MustParseAddr(channel.Address)

			block, err := api.CurrentMasterchainInfo(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get current block: %w", err)
			}

			acc, err := api.GetAccount(ctx, block, addr)
			if err != nil {
				return nil, fmt.Errorf("failed to get account %s: %w", addr.String(), err)
			}

			if acc.State == nil || !acc.IsActive {
				continue
			}

			on, err := payments.NewPaymentChannelClient(api).ParseAsyncChannel(addr, acc.Code, acc.Data, true)
			if err != nil {
				log.Warn().Err(err).Str("address", addr.String()).Msg("failed to parse payment channel")
				continue
			}

			// check is channel is really alive, in case we have outdated status in db
			if on.Status == payments.ChannelStatusOpen {
				return channel.TheirOnchain.Key, nil
			}
		}
	}

	events <- MsgEvent{Msg: "Deploying payment channel for tunnel..."}

	ctxTm, cancel := context.WithTimeout(ctx, 150*time.Second)
	addr, err := pmt.DeployChannelWithNode(ctxTm, ch, jetton, ecID)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("failed to deploy channel with node: %w", err)
	}
	log.Info().Msg("onchain channel deployed at address: " + addr.String() + " waiting for states exchange...")

	for {
		channel, err := pmt.GetChannel(ctx, addr.String())
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

		cc, err := pay.ResolveCoinConfig(jettonStr, s.Payment.ExtraCurrencyID, true)
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
