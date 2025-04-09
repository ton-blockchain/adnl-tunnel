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
	Key        ed25519.PrivateKey
	LastAmount *big.Int
	Capacity   *big.Int
	Deadline   time.Time
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
}

type SectionInfo struct {
	Keys        *EncryptionKeys
	PaymentInfo *Payer
}

type RegularOutTunnel struct {
	localID     uint32
	gateway     *Gateway
	peer        *Peer
	usePayments bool

	tunnelState       uint32
	tunnelInitialized bool
	markPaidOnce      sync.Once
	initSignal        chan struct{}
	paidSignal        chan struct{}
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

	paymentSeqno         uint64
	paymentSeqnoReceived uint64
	pingSeqno            uint64
	pingSeqnoReceived    uint64
	pingSeqnoReinitAt    uint64

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

	peer, err := g.discoverPeer(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("register peer failed: %w", err)
	}

	closerCtx, closer := context.WithCancel(context.Background())
	rt := &RegularOutTunnel{
		localID:         binary.LittleEndian.Uint32(pec.SectionPubKey), // first 4 bytes
		gateway:         g,
		peer:            peer,
		chainTo:         chainTo,
		chainFrom:       chainFrom,
		payloadKeys:     pec,
		initSignal:      make(chan struct{}, 1),
		paidSignal:      make(chan struct{}, 1),
		paySignal:       make(chan struct{}, 1),
		read:            make(chan DeliverUDPPayload, 512*1024),
		localAddr:       net.UDPAddrFromAddrPort(ap),
		tunnelState:     StateTypeConfiguring,
		log:             log,
		closerCtx:       closerCtx,
		close:           closer,
		packetsToPrepay: 200000,
	}

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

	go rt.startSystemSender()

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

func (t *RegularOutTunnel) startSystemSender() {
	select {
	case <-t.closerCtx.Done():
		return
	case <-t.initSignal:
	}

	const CheckEvery = 2 * time.Second

	ticker := time.NewTicker(CheckEvery)

	lastTry := time.Time{}

	var lastPaymentMsg *EncryptedMessage
	var err error
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

		var lastMsg *EncryptedMessage

		lastMetaAt := atomic.LoadInt64(&t.lastFullyCheckedAt)
		if lastMetaAt+int64((CheckEvery/time.Second)/2)*3 < time.Now().Unix() {
			if t.pingSeqno-atomic.LoadUint64(&t.pingSeqnoReceived) > 3 && t.pingSeqno-t.pingSeqnoReinitAt > 3 {
				if t.tunnelState != StateTypeConfiguring {
					t.log.Info().Msg("tunnel looks disconnected, trying to reconfigure...")

					// try to reconfigure tunnel in case server restart on one of the nodes on the way
					if err = t.prepareInstructions(StateTypeConfiguring); err != nil {
						t.log.Error().Err(err).Msg("prepare tunnel reconfigure instructions failed")
						continue
					}

					t.peer.peer.Reinit()
					t.pingSeqnoReinitAt = t.pingSeqno

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
							// TODO: remove after payments recovery logic, this is temp
							t.packetsConsumedIn = 0
							t.packetsConsumedOut = 0
							t.seqnoRecv = 0
							t.seqnoSend = 0

							t.log.Info().Msg("tunnel reinitialized successfully")
							break
						}
					}
					continue
				}
			}

			lastMsg, err = t.prepareTunnelPings()
			if err != nil {
				t.log.Error().Err(err).Msg("prepare tunnel pings failed")
				continue
			}
		}

		if t.usePayments && lastMsg == nil {
			received := atomic.LoadUint64(&t.packetsRecv)
			paidUsed := atomic.LoadUint64(&t.packetsRecvPaidConsumed)

			if t.paymentSeqnoReceived >= t.paymentSeqno {
				// we're paying for seqno, because packets arrive asynchronously, and we cannot know what is lost on the way
				// so we trust seqno here, but validating it against received packets num, we agree for up to 33% loss
				// if loss is higher we cannot trust this tunnel and will notify user and stop payments until normalization
				const LossNumAcceptable = 5000 // + 33%
				if paidUsed > received+received/3+LossNumAcceptable {
					// TODO: reinit something instead, with a new tunnel
					t.log.Warn().Uint64("seqno", atomic.LoadUint64(&t.seqnoRecv)).Uint64("received", received).Msg("more than 33% incoming packets lost according to seqno, very unstable network or tunnel seems trying to cheat to get more payments")
					continue
				}

				lastMsg, err = t.prepareTunnelPayments()
				if err != nil {
					t.log.Error().Err(err).Msg("prepare tunnel payments failed")
					continue
				}
				lastPaymentMsg = lastMsg
			} else {
				lastMsg = lastPaymentMsg
			}

			if lastMsg != nil {
				t.log.Debug().Uint64("seqno", t.paymentSeqno).Msg("sending payment")
			}

			loss := float64(paidUsed-received) / float64(paidUsed)
			t.log.Debug().Float64("loss", loss).
				Uint64("payments_seqno_diff", t.paymentSeqno-t.paymentSeqnoReceived).
				Int64("consumed_out", atomic.LoadInt64(&t.packetsConsumedOut)).
				Int64("consumed_in", atomic.LoadInt64(&t.packetsConsumedIn)).
				Msg("tunnel stats")
		}

		if lastMsg == nil {
			continue
		}
		lastMsg.Seqno = atomic.AddUint32(&t.seqnoForward, 1)

		for {
			if err = t.peer.SendCustomMessage(context.Background(), lastMsg); err != nil {
				t.log.Error().Err(err).Msg("send tunnel payments failed, retrying")

				select {
				case <-t.closerCtx.Done():
					return
				case <-ticker.C:
				}

				continue
			}
			break
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
			Fee:      new(big.Int).Set(fees[i]),
			Deadline: base.Add(time.Duration(n-i) * hopTTL),
		}
	}

	return chain, nil
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

	return &VirtualPaymentChannel{
		Key:        chKey,
		LastAmount: big.NewInt(0),
		Capacity:   tunChain[len(tunChain)-1].Capacity,
		Deadline:   tunChain[len(tunChain)-1].Deadline,
	}, nil
}

const ChannelCapacityForNumPayments = 50

func (t *RegularOutTunnel) prepareTunnelPings() (*EncryptedMessage, error) {
	t.mx.Lock()
	defer t.mx.Unlock()

	msg := &EncryptedMessage{}

	nodes := append([]*SectionInfo{}, t.chainTo...)
	nodes = append(nodes, t.chainFrom...)

	for i := len(nodes) - 1; i >= 0; i-- {
		if i == len(nodes)-1 {
			// we don't need to pay ourselves, just deliver meta about payments received
			if err := nodes[i].Keys.EncryptInstructionsMessage(msg, DeliverInitiatorInstruction{
				From: t.localID,
				Metadata: PingMeta{
					Seqno: t.pingSeqno + 1,
				},
			}); err != nil {
				return nil, fmt.Errorf("encrypt failed: %w", err)
			}
			continue
		}

		var instructions []tl.Serializable

		routeId := binary.LittleEndian.Uint32(nodes[i+1].Keys.SectionPubKey)
		instructions = append(instructions, RouteInstruction{
			RouteID: ^routeId, // through system tunnel
		})

		if err := nodes[i].Keys.EncryptInstructionsMessage(msg, instructions...); err != nil {
			return nil, fmt.Errorf("encrypt failed: %w", err)
		}
	}

	t.pingSeqno++

	t.log.Debug().Int("size", len(t.currentSendInstructions)).Msg("ping instructions prepared")
	return msg, nil
}

func (t *RegularOutTunnel) prepareTunnelPayments() (*EncryptedMessage, error) {
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
			// we don't need to pay ourselves, just deliver meta about payments received
			if err := nodes[i].Keys.EncryptInstructionsMessage(msg, DeliverInitiatorInstruction{
				From: t.localID,
				Metadata: PaymentMeta{
					Seqno: t.paymentSeqno + 1,
				},
			}); err != nil {
				return nil, fmt.Errorf("encrypt failed: %w", err)
			}
			continue
		}

		var instructions []tl.Serializable

		routeId := binary.LittleEndian.Uint32(nodes[i+1].Keys.SectionPubKey)
		// check if we need to pay
		if p := nodes[i].PaymentInfo; p != nil && p.PricePerPacket > 0 {
			prepay := consumedOut
			if i >= len(t.chainTo) {
				prepay = consumedIn
			} else if i == len(t.chainTo)-1 {
				// out gate
				prepay = consumedMax
			}
			prepay -= p.PaidPackets
			prepay += t.packetsToPrepay

			if prepay <= 0 {
				continue
			}

			price := new(big.Int).SetUint64(p.PricePerPacket)
			if p.CurrentChannel == nil {
				regularAmount := new(big.Int).Mul(big.NewInt(t.packetsToPrepay), price)
				// make capacity enough for ChannelCapacityForNumPayments payments,
				// but in fact it can be less if intermediate nodes not allow this amount
				wantCap := new(big.Int).Mul(regularAmount, big.NewInt(ChannelCapacityForNumPayments))

				var err error
				if p.CurrentChannel, err = t.openVirtualChannel(p, wantCap); err != nil {
					return nil, fmt.Errorf("open virtual channel failed: %w", err)
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
				return nil, fmt.Errorf("state to cell failed: %w", err)
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

			instructions = append(instructions, pi)
			t.log.Debug().Str("amount", amount.String()).Str("section_key", base64.StdEncoding.EncodeToString(nodes[i].Keys.SectionPubKey)).Msg("adding virtual channel payment state instruction")

			// We do it this way for atomicity, because some error may happen during iteration,
			// and it will produce double spend otherwise.
			// Channel may still be opened but spend will not happen.
			mutations = append(mutations, func() {
				p.PaidPackets += payFor

				if isFinal {
					p.CurrentChannel = nil
				} else {
					p.CurrentChannel.LastAmount.Set(stateAmount)
				}
			})
		}

		instructions = append(instructions, RouteInstruction{
			RouteID: ^routeId, // through system tunnel
		})

		if err := nodes[i].Keys.EncryptInstructionsMessage(msg, instructions...); err != nil {
			return nil, fmt.Errorf("encrypt failed: %w", err)
		}
	}

	if len(mutations) == 0 {
		t.log.Debug().Msg("payments not needed")

		return nil, nil
	}

	t.paymentSeqno++
	for _, mutation := range mutations {
		mutation()
	}

	var minPaidIn, minPaidOut int64 = math.MaxInt64, math.MaxInt64
	for i, node := range nodes {
		if i == len(nodes)-1 {
			// ourself
			continue
		}

		if node.PaymentInfo == nil {
			continue
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

	t.log.Debug().Uint64("seqno", t.paymentSeqno).Int("size", len(t.currentSendInstructions)).Msg("payment instructions prepared")

	if debtMoved {
		t.requestPayment()
	}

	return msg, nil
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
					UseCacheForPayload:   true,
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
	atomic.StoreInt64(&t.lastFullyCheckedAt, time.Now().Unix())

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
		if m.Seqno > atomic.LoadUint64(&t.pingSeqnoReceived) {
			atomic.StoreUint64(&t.pingSeqnoReceived, m.Seqno)
		}
		return nil
	case PaymentMeta:
		for {
			if sq := atomic.LoadUint64(&t.paymentSeqnoReceived); sq < m.Seqno {
				if !atomic.CompareAndSwapUint64(&t.paymentSeqnoReceived, sq, m.Seqno) {
					continue
				}
				t.log.Debug().Uint64("seqno", t.paymentSeqnoReceived).Msg("payment confirmed for every node in tunnel")
			}
			break
		}
		t.markPaidOnce.Do(func() {
			close(t.paidSignal)
		})
		return nil
	default:
		return fmt.Errorf("unknown meta type %T", m)
	}
}

func (t *RegularOutTunnel) WaitForInit(ctx context.Context) (net.IP, uint16, error) {
	var after time.Duration = 0
	for {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-t.initSignal:
			if t.usePayments {
				t.requestPayment()
				log.Info().Msg("adnl tunnel initialized, waiting payment confirmation...")

				select {
				case <-ctx.Done():
					return nil, 0, ctx.Err()
				case <-t.paidSignal:
					// wait for payments to happen
				}
			}
			return t.externalAddr, t.externalPort, nil
		case <-time.After(after):
			if _, err := t.WriteTo(nil, initAddr); err != nil {
				return nil, 0, fmt.Errorf("write initial instructions failed: %w", err)
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

	if t.usePayments {
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
	} else {
		msg = &EncryptedMessage{
			SectionPubKey: t.chainTo[0].Keys.SectionPubKey,
			Seqno:         atomic.AddUint32(&t.seqnoForward, 1),
			Instructions:  t.currentSendInstructions,
			Payload:       payload,
		}
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
