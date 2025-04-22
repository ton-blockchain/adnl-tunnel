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
	"github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/tonpayments/db"
	"github.com/xssnick/ton-payment-network/tonpayments/transport"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/tlb"
	"math"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	StateTypeConfiguring uint32 = iota
	StateTypeOptimizingRoutes
	StateTypeOptimized
)

type VirtualPaymentChannel struct {
	Key          ed25519.PrivateKey
	LastAmount   *big.Int
	Capacity     *big.Int
	SafeDeadline time.Time
}

type PaymentTunnelSection struct {
	Key         ed25519.PublicKey
	MinFee      *big.Int
	PercentFee  *big.Float
	MaxCapacity *big.Int
}

type Payer struct {
	PaymentTunnel   []PaymentTunnelSection
	PricePerPacket  uint64
	JettonMaster    *address.Address
	ExtraCurrencyID uint32

	PaidPackets    int64
	CurrentChannel *VirtualPaymentChannel
	PaidChannelFee *big.Int

	LatestChannelDeadline time.Time
	LatestPaidOnSeqno     uint64
	LatestInstruction     *PaymentInstruction
	LatestPacketsPaid     int64

	feeMx sync.RWMutex
}

type SectionInfo struct {
	Keys        *EncryptionKeys
	PaymentInfo *Payer
}

type RegularOutTunnel struct {
	localID           uint32
	gateway           *Gateway
	peer              *Peer
	usePayments       bool
	paymentsConfirmed int32

	tunnelState       uint32
	tunnelInitialized bool
	initSignal        chan struct{}
	paySignal         chan struct{}
	externalAddr      net.IP
	externalPort      uint16

	onOutAddressChanged func(addr *net.UDPAddr)

	chainTo     []*SectionInfo
	chainFrom   []*SectionInfo
	payloadKeys *EncryptionKeys

	read chan DeliverUDPPayload

	currentSendInstructions []byte
	seqnoSend               uint64
	seqnoRecv               uint64
	packetsRecv             uint64
	packetsRecvPaidConsumed uint64
	packetsDropped          uint64
	packetsSent             uint64

	controlSeqno             uint64
	controlSeqnoReceived     uint64
	controlPaidSeqnoReceived uint64
	controlSeqnoReinitAt     uint64

	packetsToPrepay int64

	packetsConsumedIn  int64
	packetsConsumedOut int64
	packetsMinPaidIn   int64
	packetsMinPaidOut  int64

	lastFullyCheckedAt int64

	seqnoForward uint32

	wDeadline time.Time
	rDeadline time.Time

	localAddr net.Addr

	log zerolog.Logger

	closerCtx context.Context
	close     context.CancelFunc

	mx sync.RWMutex
}

var initAddr = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("0.0.0.1:123"))

var ChannelCapacityForNumPayments int64 = 30
var ChannelPacketsToPrepay int64 = 200000

func (g *Gateway) CreateRegularOutTunnel(ctx context.Context, chainTo, chainFrom []*SectionInfo, log zerolog.Logger) (*RegularOutTunnel, error) {
	if len(chainTo) == 0 || len(chainFrom) == 0 {
		return nil, fmt.Errorf("chains should have at least one node")
	}

	if !bytes.Equal(chainFrom[len(chainFrom)-1].Keys.ReceiverPubKey, g.key.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("last 'chain from' should be our gateway")
	}

	// TODO: generate based on key (ipv6 form)
	ap, _ := netip.ParseAddrPort("255.0.0.0:1")

	pec, err := GenerateEncryptionKeys(chainTo[len(chainTo)-1].Keys.ReceiverPubKey)
	if err != nil {
		return nil, fmt.Errorf("generate payload key failed: %w", err)
	}

	id, err := tl.Hash(adnl.PublicKeyED25519{Key: chainTo[0].Keys.ReceiverPubKey})
	if err != nil {
		return nil, fmt.Errorf("calc receiver adnl id failed: %w", err)
	}

	closerCtx, closer := context.WithCancel(g.closerCtx)
	rt := &RegularOutTunnel{
		localID:            binary.LittleEndian.Uint32(pec.SectionPubKey), // first 4 bytes
		gateway:            g,
		peer:               g.addPeer(id, nil),
		chainTo:            chainTo,
		chainFrom:          chainFrom,
		payloadKeys:        pec,
		initSignal:         make(chan struct{}, 1),
		paySignal:          make(chan struct{}, 1),
		read:               make(chan DeliverUDPPayload, 512*1024),
		localAddr:          net.UDPAddrFromAddrPort(ap),
		tunnelState:        StateTypeConfiguring,
		log:                log,
		closerCtx:          closerCtx,
		close:              closer,
		packetsToPrepay:    ChannelPacketsToPrepay,
		lastFullyCheckedAt: time.Now().Unix(),
	}
	rt.peer.AddReference()

	list := append([]*SectionInfo{}, chainTo...)
	list = append(list, chainFrom...)

	for _, info := range list {
		if info.PaymentInfo != nil {
			if g.payments.Service == nil {
				return nil, fmt.Errorf("payments are not enabled")
			}
			rt.usePayments = true
			break
		}
	}

	go rt.startControlSender()

	if err = rt.prepareInstructions(StateTypeConfiguring); err != nil {
		return nil, fmt.Errorf("prepare initial instructions failed: %w", err)
	}

	g.mx.Lock()
	g.tunnels[binary.LittleEndian.Uint32(rt.payloadKeys.SectionPubKey)] = rt
	g.mx.Unlock()

	return rt, nil
}

func buildRoute(initial bool, msg *EncryptedMessage, cur, next *SectionInfo, prepareSystemTunnel bool) error {
	id, err := tl.Hash(adnl.PublicKeyED25519{Key: next.Keys.ReceiverPubKey})
	if err != nil {
		return fmt.Errorf("calc receiver adnl id failed: %w", err)
	}

	var instructions []tl.Serializable

	routeId := binary.LittleEndian.Uint32(next.Keys.SectionPubKey)
	if initial {
		var price uint64
		if cur.PaymentInfo != nil {
			price = cur.PaymentInfo.PricePerPacket
		}

		instructions = append(instructions, BuildRouteInstruction{
			TargetADNL:          id,
			TargetSectionPubKey: next.Keys.SectionPubKey,
			RouteID:             routeId,
			PricePerPacket:      price,
		}, CacheInstruction{
			Version: uint32(time.Now().Unix()),
			Instructions: []any{
				RouteInstruction{
					RouteID: routeId,
				},
			},
		})

		if prepareSystemTunnel {
			// we prepare another tunnel for system messages and payments,
			// to be sure limits are not consumed by main traffic,
			// and we always can pay and send low rate messages for free
			instructions = append(instructions, BuildRouteInstruction{
				TargetADNL:          id,
				TargetSectionPubKey: next.Keys.SectionPubKey,
				RouteID:             ^routeId, // xor id for system tunnel
				PricePerPacket:      price,
			})
		}
	}

	instructions = append(instructions, RouteInstruction{
		RouteID: routeId,
	})

	if err = cur.Keys.EncryptInstructionsMessage(msg, instructions...); err != nil {
		return fmt.Errorf("encrypt failed: %w", err)
	}

	return nil
}

func (t *RegularOutTunnel) SetOutAddressChangedHandler(f func(addr *net.UDPAddr)) {
	t.onOutAddressChanged = f
}

func (t *RegularOutTunnel) startControlSender() {
	select {
	case <-t.closerCtx.Done():
		return
	case <-t.initSignal:
	}

	const CheckEvery = 1 * time.Second

	ticker := time.NewTicker(CheckEvery)

	lastTry := time.Time{}

	for {
		ticker.Reset(CheckEvery)

		select {
		case <-t.closerCtx.Done():
			return
		case <-t.paySignal:
		case <-ticker.C:
		}

		if since := time.Since(lastTry); since < 200*time.Millisecond {
			// to not overflow free limit of system route
			time.Sleep(200*time.Millisecond - since)
		}
		lastTry = time.Now()

		var paidRecvLoss float64
		var attachPayments = false
		if t.usePayments {
			received := atomic.LoadUint64(&t.packetsRecv)
			paidUsed := atomic.LoadUint64(&t.packetsRecvPaidConsumed)

			// attaching payments only after checking that tunnel works
			attachPayments = t.controlSeqno > 0 && t.controlSeqno == t.controlSeqnoReceived
			if attachPayments {
				const LossNumAcceptable = 5000 // + 33%
				if paidUsed > received+received/3+LossNumAcceptable {
					attachPayments = false
					// TODO: reinit something instead, with a new tunnel
					t.log.Warn().Uint64("seqno", atomic.LoadUint64(&t.seqnoRecv)).Uint64("received", received).Msg("more than 33% incoming packets lost according to seqno, very unstable network or tunnel seems trying to cheat to get more payments")
				}
			}

			paidRecvLoss = float64(paidUsed-received) / float64(paidUsed)
		}

		lastMsg, _, err := t.prepareTunnelControlMessage(attachPayments, atomic.LoadInt32(&t.paymentsConfirmed) == 0)
		if err != nil {
			t.log.Error().Err(err).Msg("prepare tunnel pings failed")
			continue
		}

		if time.Now().Unix()-atomic.LoadInt64(&t.lastFullyCheckedAt) > 15 {
			t.log.Info().Msg("tunnel looks disconnected, trying to reconfigure...")

			// try to reconfigure tunnel in case server restart on one of the nodes on the way
			if err = t.prepareInstructions(StateTypeConfiguring); err != nil {
				t.log.Error().Err(err).Msg("prepare tunnel reconfigure instructions failed")
				continue
			}

			t.controlSeqnoReinitAt = t.controlSeqno
			atomic.StoreInt32(&t.paymentsConfirmed, 0)

			for {
				t.log.Info().Msg("sending tunnel reinit")

				if _, err := t.WriteTo(nil, initAddr); err != nil {
					t.log.Error().Err(err).Msg("write to reconfigure tunnel failed")
					continue
				}

				select {
				case <-t.closerCtx.Done():
					return
				case <-ticker.C:
				}

				if t.tunnelState > StateTypeConfiguring {
					t.log.Info().Msg("tunnel reinitialized successfully")
					break
				}
			}
			continue
		}

		t.log.Debug().Float64("paid_recv_loss", paidRecvLoss).
			Uint64("seqno_diff", t.controlSeqno-t.controlSeqnoReceived).
			Int64("out_left", atomic.LoadInt64(&t.packetsMinPaidOut)-atomic.LoadInt64(&t.packetsConsumedOut)).
			Int64("in_left", atomic.LoadInt64(&t.packetsMinPaidIn)-atomic.LoadInt64(&t.packetsConsumedIn)).
			Msg("sending control message")

		if err = t.peer.SendCustomMessage(context.Background(), lastMsg); err != nil {
			t.log.Error().Err(err).Msg("send tunnel payments failed, retrying")
			continue
		}
	}
}

func (t *RegularOutTunnel) buildTunnelPaymentsChain(paymentTunnel []PaymentTunnelSection, initialCapacity *big.Int, baseTTL, hopTTL time.Duration) ([]transport.TunnelChainPart, error) {
	n := len(paymentTunnel)

	if n == 0 {
		return nil, errors.New("empty payment tunnel")
	}

	cumulativeFees := make([]*big.Int, n+1)
	fees := make([]*big.Int, n)
	for i := 0; i <= n; i++ {
		cumulativeFees[i] = big.NewInt(0)
	}

	x := new(big.Int).Set(initialCapacity)
	maxIter := 10

	for iter := 0; iter < maxIter; iter++ {
		cumulativeFees[n].SetInt64(0)
		for i := n - 1; i >= 0; i-- {
			R := new(big.Int).Add(x, cumulativeFees[i+1])
			rFloat := new(big.Float).SetInt(R)
			candidateFeeFloat := new(big.Float).Mul(paymentTunnel[i].PercentFee, rFloat)
			candidateFeeFloat = candidateFeeFloat.Quo(candidateFeeFloat, new(big.Float).SetInt(big.NewInt(100)))
			candidateFee := new(big.Int)

			candidateFeeFloat.Int(candidateFee)
			feeI := new(big.Int)
			if candidateFee.Cmp(paymentTunnel[i].MinFee) > 0 {
				feeI.Set(candidateFee)
			} else {
				feeI.Set(paymentTunnel[i].MinFee)
			}
			fees[i] = feeI
			cumulativeFees[i] = new(big.Int).Add(feeI, cumulativeFees[i+1])
		}

		newX := new(big.Int).Set(initialCapacity)
		for i := 0; i < n; i++ {
			allowed := new(big.Int).Sub(paymentTunnel[i].MaxCapacity, cumulativeFees[i+1])
			if allowed.Cmp(newX) < 0 {
				newX.Set(allowed)
			}
		}

		if newX.Cmp(x) == 0 {
			break
		}
		x.Set(newX)
	}

	if x.Sign() < 0 {
		return nil, errors.New("min capacity on the way cannot cover fees")
	}

	requiredCapacities := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		requiredCapacities[i] = new(big.Int).Add(x, cumulativeFees[i+1])
	}

	chain := make([]transport.TunnelChainPart, n)
	base := time.Now().Add(baseTTL)
	for i := 0; i < n; i++ {
		chain[i] = transport.TunnelChainPart{
			Target:   paymentTunnel[i].Key,
			Capacity: new(big.Int).Set(requiredCapacities[i]),
			Fee:      new(big.Int).Set(cumulativeFees[i]),
			Deadline: base.Add(time.Duration(n-i) * hopTTL),
		}
	}

	return chain, nil
}

func (t *RegularOutTunnel) AliveCtx() context.Context {
	return t.closerCtx
}

func (t *RegularOutTunnel) CalcPaidAmount() map[string]tlb.Coins {
	t.mx.RLock()
	defer t.mx.RUnlock()

	paidAmount := make(map[string]tlb.Coins)

	for _, section := range append(t.chainTo, t.chainFrom...) {
		if section.PaymentInfo == nil {
			continue
		}

		var jm string
		if section.PaymentInfo.JettonMaster != nil {
			jm = section.PaymentInfo.JettonMaster.String()
		}

		cc, err := t.gateway.payments.Service.ResolveCoinConfig(jm, section.PaymentInfo.ExtraCurrencyID, true)
		if err != nil {
			continue
		}

		amt := new(big.Int).Mul(new(big.Int).SetInt64(section.PaymentInfo.PaidPackets), new(big.Int).SetUint64(section.PaymentInfo.PricePerPacket))

		section.PaymentInfo.feeMx.RLock()
		amt = amt.Add(amt, section.PaymentInfo.PaidChannelFee)
		section.PaymentInfo.feeMx.RUnlock()

		paidAmount[cc.Symbol] = tlb.MustFromNano(new(big.Int).Add(paidAmount[cc.Symbol].Nano(), amt), int(cc.Decimals))
	}

	return paidAmount
}

func (t *RegularOutTunnel) openVirtualChannel(p *Payer, capacity *big.Int) (*VirtualPaymentChannel, error) {
	t.log.Debug().Uint64("price_per_packet", p.PricePerPacket).Str("capacity", tlb.FromNanoTON(capacity).String()).Msg("opening virtual channel")
	var tunChain = make([]transport.TunnelChainPart, len(p.PaymentTunnel))
	hopTTL := t.gateway.payments.Service.GetMinSafeTTL()

	tunChain, err := t.buildTunnelPaymentsChain(p.PaymentTunnel, capacity, 1*time.Hour, hopTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to build tunnel payments chain: %w", err)
	}

	_, chKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate channel key failed: %w", err)
	}

	vc, firstInstructionKey, tun, err := transport.GenerateTunnel(chKey, tunChain, 5, false)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tunnel: %w", err)
	}

	err = t.gateway.payments.Service.OpenVirtualChannel(context.Background(), tunChain[0].Target, firstInstructionKey, tunChain[len(tunChain)-1].Target, chKey, tun, vc, p.JettonMaster, p.ExtraCurrencyID)
	if err != nil {
		return nil, fmt.Errorf("failed to open virtual channel: %w", err)
	}

	for {
		meta, err := t.gateway.payments.Service.GetVirtualChannelMeta(context.Background(), vc.Key)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				time.Sleep(time.Second)
				continue
			}
			return nil, fmt.Errorf("failed to get virtual channel meta: %w", err)
		}

		if meta.Status == db.VirtualChannelStatePending {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if meta.Status != db.VirtualChannelStateActive {
			return nil, fmt.Errorf("failed to open virtual channel: incorrect state %d", db.VirtualChannelStateActive)
		}
		break
	}

	p.feeMx.Lock()
	if p.PaidChannelFee == nil {
		p.PaidChannelFee = big.NewInt(0)
	}
	p.PaidChannelFee.Add(p.PaidChannelFee, tunChain[0].Fee)
	p.feeMx.Unlock()

	return &VirtualPaymentChannel{
		Key:          chKey,
		LastAmount:   big.NewInt(0),
		Capacity:     tunChain[len(tunChain)-1].Capacity,
		SafeDeadline: tunChain[len(tunChain)-1].Deadline.Add(-hopTTL),
	}, nil
}

func (t *RegularOutTunnel) resolveSection(key ed25519.PublicKey) (*SectionInfo, *SectionInfo) {
	var next *SectionInfo

	for i, info := range t.chainTo {
		if bytes.Equal(info.Keys.SectionPubKey, key) {
			if i+1 < len(t.chainTo) {
				next = t.chainTo[i+1]
			} else if len(t.chainFrom) > 0 {
				next = t.chainFrom[0]
			}
			return t.chainTo[i], next
		}
	}

	for i, info := range t.chainFrom {
		if bytes.Equal(info.Keys.SectionPubKey, key) {
			if i+1 < len(t.chainFrom) {
				next = t.chainFrom[i+1]
			}

			return t.chainFrom[i], next
		}
	}

	return nil, nil
}

func (t *RegularOutTunnel) ReassembleInstructions(msg *EncryptedMessage) (*EncryptedMessage, error) {
	t.mx.Lock()
	defer t.mx.Unlock()

	ln := len(msg.Instructions)

	log.Debug().Int("len", ln).Str("section", base64.StdEncoding.EncodeToString(msg.SectionPubKey)).Msg("reassemble instructions")
	rs, err := t.reassembleInstructions(msg)
	if err != nil {
		return nil, err
	}

	if len(rs.Instructions) != ln {
		panic(fmt.Errorf("reassemble instructions failed, len %d, expected %d", len(rs.Instructions), ln).Error())
	}

	return rs, nil
}

func (t *RegularOutTunnel) reassembleInstructions(msg *EncryptedMessage) (*EncryptedMessage, error) {
	var containers []*InstructionsContainer
	var sections []*SectionInfo

	sectionKey := msg.SectionPubKey
	restInstructions := append([]byte{}, msg.Instructions...)
	for {
		sec, nextSec := t.resolveSection(sectionKey)
		if sec == nil {
			return nil, fmt.Errorf("section %x not found", sectionKey)
		}

		data, err := decryptStream(sec.Keys.CipherKeyCRC, sec.Keys.CipherKey, restInstructions)
		if err != nil {
			return nil, fmt.Errorf("decrypt stream %x failed: %v", sec.Keys.SectionPubKey, err)
		}

		if len(data) < 12 {
			return nil, fmt.Errorf("corrupted instructions, len %d", len(data))
		}

		var container = &InstructionsContainer{}
		restInstructions, err = tl.Parse(container, data, true)
		if err != nil {
			return nil, fmt.Errorf("parse instructions failed: %v", err)
		}
		containers = append(containers, container)
		sections = append(sections, sec)

		more := false
		for y, ins := range container.List {
			switch v := ins.(type) {
			case *RouteInstruction:
				if nextSec != nil {
					more = true
					sectionKey = nextSec.Keys.SectionPubKey
				}
			case *BindOutInstruction:
				inMsg := &EncryptedMessage{
					SectionPubKey: v.InboundSectionPubKey,
					Instructions:  v.InboundInstructions,
				}

				inMsg, err = t.reassembleInstructions(inMsg)
				if err != nil {
					return nil, fmt.Errorf("reassemble instructions failed: %v", err)
				}
				v.InboundInstructions = inMsg.Instructions

				container.List[y] = v
			}
		}

		if !more {
			break
		}
	}

	newMsg := &EncryptedMessage{}
	for i := len(containers) - 1; i >= 0; i-- {
		if err := sections[i].Keys.EncryptInstructionsMessage(newMsg, containers[i].List...); err != nil {
			return nil, fmt.Errorf("encrypt failed: %w", err)
		}
	}
	newMsg.Payload = msg.Payload

	return newMsg, nil
}

func (t *RegularOutTunnel) prepareTunnelControlMessage(withPayments, forcePayments bool) (*EncryptedMessage, time.Time, error) {
	t.mx.Lock()
	defer t.mx.Unlock()

	nodes := append([]*SectionInfo{}, t.chainTo...)
	nodes = append(nodes, t.chainFrom...)

	var consumedOut = atomic.LoadInt64(&t.packetsConsumedOut)
	var consumedIn = atomic.LoadInt64(&t.packetsConsumedIn)
	var consumedMax = consumedOut
	if consumedMax < consumedIn {
		consumedMax = consumedIn
	}

	msg := &EncryptedMessage{}

	debtMoved := false

	var mutations []func()

	for i := len(nodes) - 1; i >= 0; i-- {
		if i == len(nodes)-1 {
			// deliver meta to ourself
			if err := nodes[i].Keys.EncryptInstructionsMessage(msg, DeliverInitiatorInstruction{
				From: t.localID,
				Metadata: PingMeta{
					Seqno:        t.controlSeqno + 1,
					WithPayments: withPayments,
				},
			}); err != nil {
				return nil, time.Time{}, fmt.Errorf("encrypt failed: %w", err)
			}
			continue
		}

		var instructions []tl.Serializable

		routeId := binary.LittleEndian.Uint32(nodes[i+1].Keys.SectionPubKey)
		// check if we need to pay
		if p := nodes[i].PaymentInfo; withPayments && p != nil && p.PricePerPacket > 0 {
			skipNewPayment := false
			if p.LatestInstruction != nil &&
				p.LatestPaidOnSeqno > atomic.LoadUint64(&t.controlPaidSeqnoReceived) {
				// not yet processed payment, will not send a new one, attach old

				if p.LatestChannelDeadline.After(time.Now()) {
					instructions = append(instructions, *p.LatestInstruction)
					skipNewPayment = true
				} else {
					// if channel safe deadline is passed, it cannot be accepted, so we will make new payment
					p.PaidPackets -= p.LatestPacketsPaid
					p.LatestInstruction = nil
				}
			}

			if !skipNewPayment {
				prepay := consumedOut
				if i >= len(t.chainTo) {
					prepay = consumedIn
				} else if i == len(t.chainTo)-1 {
					// out gate
					prepay = consumedMax
				}
				prepay -= p.PaidPackets
				prepay += t.packetsToPrepay

				if prepay > t.packetsToPrepay/2 || forcePayments {
					price := new(big.Int).SetUint64(p.PricePerPacket)
					if p.CurrentChannel == nil || p.CurrentChannel.SafeDeadline.Before(time.Now()) {
						regularAmount := new(big.Int).Mul(big.NewInt(t.packetsToPrepay), price)
						// make capacity enough for ChannelCapacityForNumPayments payments,
						// but in fact it can be less if intermediate nodes not allow this amount
						wantCap := new(big.Int).Mul(regularAmount, big.NewInt(ChannelCapacityForNumPayments))

						var err error
						if p.CurrentChannel, err = t.openVirtualChannel(p, wantCap); err != nil {
							return nil, time.Time{}, fmt.Errorf("open virtual channel failed: %w", err)
						}
					}

					left := new(big.Int).Sub(p.CurrentChannel.Capacity, p.CurrentChannel.LastAmount)

					isFinal := true
					payFor := new(big.Int).Div(left, price).Int64()
					if payFor > prepay {
						isFinal = false
						payFor = prepay
					}

					if debt := prepay - payFor; debt > 0 {
						// we cannot pay for this in single payment channel, amount is too big, will open new one with next payment and pay diff
						debtMoved = true
						t.log.Debug().Int64("packets_num", debt).Str("section_key", base64.StdEncoding.EncodeToString(nodes[i].Keys.SectionPubKey)).Msg("part of the debt moved to pay later, channel is too small")
					}

					amount := new(big.Int).Mul(big.NewInt(payFor), price)
					stateAmount := new(big.Int).Add(p.CurrentChannel.LastAmount, amount)

					st := &payments.VirtualChannelState{
						Amount: tlb.FromNanoTON(stateAmount),
					}
					st.Sign(p.CurrentChannel.Key)

					pcs, err := tlb.ToCell(st)
					if err != nil {
						return nil, time.Time{}, fmt.Errorf("state to cell failed: %w", err)
					}

					pi := PaymentInstruction{
						Key:                 p.CurrentChannel.Key.Public().(ed25519.PublicKey),
						PaymentChannelState: pcs,
						Final:               isFinal,
					}

					if i == len(t.chainTo)-1 {
						pi.Purpose = PaymentPurposeOut << 32
					} else {
						pi.Purpose = (PaymentPurposeRoute << 32) | uint64(routeId)
					}

					if p.LatestInstruction != nil && forcePayments && p.LatestChannelDeadline.After(time.Now()) {
						// attach previous payment, in case they were lost after reinit
						instructions = append(instructions, *p.LatestInstruction)
					}
					instructions = append(instructions, pi)
					t.log.Debug().Str("amount", amount.String()).Str("section_key", base64.StdEncoding.EncodeToString(nodes[i].Keys.SectionPubKey)).Msg("adding virtual channel payment state instruction")

					// We do it this way for atomicity, because some error may happen during iteration,
					// and it will produce double spend otherwise.
					// Channel may still be opened but spend will not happen.
					mutations = append(mutations, func() {
						p.PaidPackets += payFor

						p.LatestPacketsPaid = payFor
						p.LatestInstruction = &pi
						p.LatestChannelDeadline = p.CurrentChannel.SafeDeadline
						p.LatestPaidOnSeqno = t.controlSeqno // incremented before mutation

						if isFinal {
							p.CurrentChannel = nil
						} else {
							p.CurrentChannel.LastAmount.Set(stateAmount)
						}
					})
				}
			}
		}

		instructions = append(instructions, RouteInstruction{
			RouteID: ^routeId, // through system tunnel
		})

		if err := nodes[i].Keys.EncryptInstructionsMessage(msg, instructions...); err != nil {
			return nil, time.Time{}, fmt.Errorf("encrypt failed: %w", err)
		}
	}

	if len(mutations) == 0 {
		t.log.Debug().Msg("payments not needed")
	}

	t.controlSeqno++
	for _, mutation := range mutations {
		mutation()
	}

	var minDeadline time.Time
	var minPaidIn, minPaidOut int64 = math.MaxInt64, math.MaxInt64
	for i, node := range nodes {
		if i == len(nodes)-1 {
			// ourself
			continue
		}

		if node.PaymentInfo == nil {
			continue
		}

		if node.PaymentInfo.CurrentChannel != nil &&
			(minDeadline.IsZero() || node.PaymentInfo.CurrentChannel.SafeDeadline.Before(minDeadline)) {
			minDeadline = node.PaymentInfo.CurrentChannel.SafeDeadline
		}

		if i >= len(t.chainTo) {
			// in
			if minPaidIn > node.PaymentInfo.PaidPackets {
				minPaidIn = node.PaymentInfo.PaidPackets
			}
		} else if i == len(t.chainTo)-1 {
			// out gate
			if minPaidOut > node.PaymentInfo.PaidPackets {
				minPaidOut = node.PaymentInfo.PaidPackets
			}
			if minPaidIn > node.PaymentInfo.PaidPackets {
				minPaidIn = node.PaymentInfo.PaidPackets
			}
		} else {
			// out
			if minPaidOut > node.PaymentInfo.PaidPackets {
				minPaidOut = node.PaymentInfo.PaidPackets
			}
		}
	}

	atomic.StoreInt64(&t.packetsMinPaidIn, minPaidIn)
	atomic.StoreInt64(&t.packetsMinPaidOut, minPaidOut)

	t.log.Debug().Uint64("seqno", t.controlSeqno).Int("size", len(t.currentSendInstructions)).Msg("control instructions prepared")

	if debtMoved {
		t.requestPayment()
	}

	return msg, minDeadline, nil
}

func (t *RegularOutTunnel) prepareInstructions(state uint32) error {
	msg := &EncryptedMessage{}

	for i := len(t.chainTo) - 1; i >= 0; i-- {
		if i == len(t.chainTo)-1 { // last (out gate)

			if state <= StateTypeOptimizingRoutes {
				backMsg := &EncryptedMessage{}

				// encrypting inbound tunnel
				for y := len(t.chainFrom) - 1; y >= 0; y-- {
					if y == len(t.chainFrom)-1 { // last (we)
						ins := DeliverInitiatorInstruction{
							From: t.localID,
							Metadata: StateMeta{
								State: state,
							},
						}

						if err := t.chainFrom[y].Keys.EncryptInstructionsMessage(backMsg, ins, CacheInstruction{
							Version:      uint32(time.Now().Unix()),
							Instructions: []any{ins},
						}); err != nil {
							return fmt.Errorf("encrypt layer %d failed: %w", i, err)
						}

						continue
					}

					if err := buildRoute(state == StateTypeConfiguring, backMsg, t.chainFrom[y], t.chainFrom[y+1], t.usePayments); err != nil {
						return fmt.Errorf("build route %d failed: %w", y, err)
					}
				}

				id, err := tl.Hash(adnl.PublicKeyED25519{Key: t.chainFrom[0].Keys.ReceiverPubKey})
				if err != nil {
					return fmt.Errorf("calc receiver adnl id failed: %w", err)
				}

				var price uint64
				if t.chainTo[i].PaymentInfo != nil {
					price = t.chainTo[i].PaymentInfo.PricePerPacket
				}

				if err = t.chainTo[i].Keys.EncryptInstructionsMessage(msg, BuildRouteInstruction{ // we build route here to route system messages, like tunnel payments
					TargetADNL:          id,
					TargetSectionPubKey: backMsg.SectionPubKey,
					RouteID:             ^binary.LittleEndian.Uint32(backMsg.SectionPubKey),
					PricePerPacket:      price, // we assign price, but free rate is enough for us here, we will not pay actually
				}, BindOutInstruction{
					InboundNodeADNL:      id,
					InboundSectionPubKey: backMsg.SectionPubKey,
					InboundInstructions:  backMsg.Instructions,
					ReceiverPubKey:       t.payloadKeys.SectionPubKey,
					PricePerPacket:       price,
				}, CacheInstruction{
					Version:      uint32(time.Now().Unix()),
					Instructions: []any{SendOutInstruction{}},
				}, SendOutInstruction{}); err != nil {
					return fmt.Errorf("encrypt bind out failed: %w", err)
				}
				continue
			}

			if err := t.chainTo[i].Keys.EncryptInstructionsMessage(msg, CacheInstruction{
				Version:      uint32(time.Now().Unix()),
				Instructions: []any{SendOutInstruction{}},
			}, SendOutInstruction{}); err != nil {
				return fmt.Errorf("encrypt send out failed: %w", err)
			}

			continue
		}

		if err := buildRoute(state == StateTypeConfiguring, msg, t.chainTo[i], t.chainTo[i+1], t.usePayments); err != nil {
			return fmt.Errorf("build route %d failed: %w", i, err)
		}
	}

	t.currentSendInstructions = msg.Instructions
	t.tunnelState = state

	t.log.Debug().Int("size", len(t.currentSendInstructions)).Msg("instructions updated")

	return nil
}

func (t *RegularOutTunnel) Process(payload []byte, meta any) error {
	switch m := meta.(type) {
	case StateMeta:
		data, err := t.payloadKeys.decryptRecvPayload(payload)
		if err != nil {
			return fmt.Errorf("decryptRecvPayload failed: %v", err)
		}

		// optimizing instructions size
		switch m.State {
		case StateTypeConfiguring:
			if t.tunnelState < StateTypeOptimizingRoutes {
				if err = t.prepareInstructions(StateTypeOptimizingRoutes); err != nil {
					return fmt.Errorf("prepare optimized instructions failed: %w", err)
				}

				t.log.Info().Int("size", len(t.currentSendInstructions)).Msg("tunnel configured")
			}
		case StateTypeOptimizingRoutes:
			if t.tunnelState < StateTypeOptimized {
				if err = t.prepareInstructions(StateTypeOptimized); err != nil {
					return fmt.Errorf("prepare optimized instructions failed: %w", err)
				}

				t.log.Info().Int("size", len(t.currentSendInstructions)).Msg("tunnel optimizations completed")
			}
		default:
			return fmt.Errorf("unknown tunnel state: %d", m.State)
		}

		switch p := data.(type) {
		case DeliverUDPPayload:
			if len(p.IP) != net.IPv4len && len(p.IP) != net.IPv6len {
				return fmt.Errorf("invalid ip len %d", len(p.IP))
			}

			if p.Port > math.MaxUint16 {
				return fmt.Errorf("invalid port %d", p.Port)
			}

			atomic.AddUint64(&t.packetsRecv, 1)
			var seqnoDiff uint64
			for {
				if prev := atomic.LoadUint64(&t.seqnoRecv); prev < p.Seqno {
					if !atomic.CompareAndSwapUint64(&t.seqnoRecv, prev, p.Seqno) {
						continue
					}
					seqnoDiff = p.Seqno - prev
				}
				break
			}

			if t.usePayments && seqnoDiff > 0 {
				atomic.AddUint64(&t.packetsRecvPaidConsumed, seqnoDiff)

				paid := atomic.LoadInt64(&t.packetsMinPaidIn)
				if paid-atomic.AddInt64(&t.packetsConsumedIn, int64(seqnoDiff)) < t.packetsToPrepay/2 {
					t.requestPayment()
				}
			}

			select {
			case t.read <- p:
				// t.log.Debug().Uint64("seqno", p.Seqno).Msg("udp delivered")
				return nil
			default:
				atomic.AddUint64(&t.packetsDropped, 1)
				t.log.Warn().Uint64("seqno", p.Seqno).Msg("full, skip")
				return fmt.Errorf("read channel full")
			}
		case OutBindDonePayload:
			t.mx.Lock()
			defer t.mx.Unlock()

			if t.externalAddr.Equal(p.IP) && t.externalPort == uint16(p.Port) {
				return nil
			}

			t.externalAddr = p.IP
			t.externalPort = uint16(p.Port)

			t.log.Info().Str("ip", net.IP(p.IP).String()).Uint32("port", p.Port).Msg("out gateway updated")

			if !t.tunnelInitialized {
				t.tunnelInitialized = true
				close(t.initSignal)
			} else {
				if f := t.onOutAddressChanged; f != nil {
					f(&net.UDPAddr{
						IP:   p.IP,
						Port: int(p.Port),
					})
				}
			}

			return nil
		default:
			return fmt.Errorf("incorrect payload type: %T", p)
		}
	case PingMeta:
		for {
			if sq := atomic.LoadUint64(&t.controlSeqnoReceived); sq < m.Seqno {
				if !atomic.CompareAndSwapUint64(&t.controlSeqnoReceived, sq, m.Seqno) {
					continue
				}
				atomic.StoreInt64(&t.lastFullyCheckedAt, time.Now().Unix())
				if m.WithPayments {
					atomic.StoreInt32(&t.paymentsConfirmed, 1)
					atomic.StoreUint64(&t.controlPaidSeqnoReceived, m.Seqno)
				}
				t.log.Debug().Uint64("seqno", m.Seqno).Msg("control message returned successfully")
			}
			break
		}
		return nil
	default:
		return fmt.Errorf("unknown meta type %T", m)
	}
}

func (t *RegularOutTunnel) WaitForInit(ctx context.Context, events func(string)) (net.IP, uint16, error) {
	var after time.Duration = 0
	for {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-t.closerCtx.Done():
			return nil, 0, t.closerCtx.Err()
		case <-t.initSignal:
			if t.usePayments {
				if events != nil {
					events("Tunnel configured, waiting payments...")
				}

				t.requestPayment()
				log.Info().Msg("adnl tunnel initialized, waiting payment confirmation...")

				for {
					select {
					case <-ctx.Done():
						return nil, 0, ctx.Err()
					case <-t.closerCtx.Done():
						return nil, 0, t.closerCtx.Err()
					case <-time.After(5 * time.Millisecond):
						if atomic.LoadInt32(&t.paymentsConfirmed) == 0 {
							continue
						}
					}

					break
				}
			}

			if events != nil {
				events("Tunnel initialized")
			}
			return t.externalAddr, t.externalPort, nil
		case <-time.After(after):
			if _, err := t.WriteTo(nil, initAddr); err != nil {
				log.Warn().Err(err).Msg("write initial instructions failed, retrying in 1 second...")
			}
			after = 1 * time.Second
		}
	}
}

func (t *RegularOutTunnel) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet := <-t.read
	return copy(p, packet.Payload), &net.UDPAddr{
		IP:   packet.IP,
		Port: int(packet.Port),
	}, nil
}

func (t *RegularOutTunnel) ReadFromWithTimeout(ctx context.Context, p []byte) (n int, addr net.Addr, err error) {
	select {
	case packet := <-t.read:
		return copy(p, packet.Payload), &net.UDPAddr{
			IP:   packet.IP,
			Port: int(packet.Port),
		}, nil
	case <-ctx.Done():
		return -1, nil, ctx.Err()
	}
}

func (t *RegularOutTunnel) requestPayment() {
	select {
	case t.paySignal <- struct{}{}:
	default:
	}
}

func (t *RegularOutTunnel) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(t.currentSendInstructions) == 0 {
		return -1, fmt.Errorf("send instructions is empty")
	}

	if t.usePayments && p != nil {
		paid := atomic.LoadInt64(&t.packetsMinPaidOut)
		consumed := atomic.LoadInt64(&t.packetsConsumedOut)
		if paid < consumed {
			return -1, fmt.Errorf("not enough packets prepaid, paid: %d, consumed: %d", paid, consumed)
		}

		if paid-atomic.AddInt64(&t.packetsConsumedOut, 1) < t.packetsToPrepay/2 {
			t.requestPayment()
		}
	}

	updAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return -1, fmt.Errorf("invalid address type: %T", addr)
	}

	pl := SendOutPayload{
		Seqno:   atomic.AddUint64(&t.seqnoSend, 1),
		IP:      updAddr.IP,
		Port:    uint32(updAddr.Port),
		Payload: p,
	}

	payload, err := tl.Serialize(pl, true)
	if err != nil {
		return -1, fmt.Errorf("SendOutPayload serialization error: %w", err)
	}

	payload, err = t.payloadKeys.EncryptPayload(payload)
	if err != nil {
		return -1, fmt.Errorf("encrypt payload error: %w", err)
	}

	var msg tl.Serializable
	if t.tunnelState >= StateTypeOptimized {
		msg = &EncryptedMessageCached{
			SectionPubKey: t.chainTo[0].Keys.SectionPubKey,
			Seqno:         atomic.AddUint32(&t.seqnoForward, 1),
			Payload:       payload,
		}
	} else if (t.tunnelState > StateTypeConfiguring &&
		(!t.usePayments || atomic.LoadInt32(&t.paymentsConfirmed) == 1)) || p == nil {
		msg, err = t.ReassembleInstructions(&EncryptedMessage{
			SectionPubKey: t.chainTo[0].Keys.SectionPubKey,
			Instructions:  t.currentSendInstructions,
			Payload:       payload,
		})
		if err != nil {
			return -1, fmt.Errorf("reassemble instructions error: %w", err)
		}
	} else {
		return -1, fmt.Errorf("route is not yet configured")
	}

	if err = t.peer.SendCustomMessage(context.Background(), msg); err != nil {
		return -1, fmt.Errorf("send encrypted message error: %w", err)
	}
	atomic.AddUint64(&t.packetsSent, 1)

	return len(p), nil
}

func (t *RegularOutTunnel) Close() error {
	// TODO: add callback onClose, to add option to reopen new channel
	t.close()
	return nil
}

func (t *RegularOutTunnel) LocalAddr() net.Addr {
	return t.localAddr
}

func (t *RegularOutTunnel) SetDeadline(tm time.Time) error {
	t.wDeadline, t.rDeadline = tm, tm
	return nil
}

func (t *RegularOutTunnel) SetReadDeadline(tm time.Time) error {
	t.rDeadline = tm
	return nil
}

func (t *RegularOutTunnel) SetWriteDeadline(tm time.Time) error {
	t.wDeadline = tm
	return nil
}
