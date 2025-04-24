package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/kevinms/leakybucket-go"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/tonpayments/db"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/tl"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"hash/crc64"
	"math"
	"math/big"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"time"
	"unsafe"
)

var instructionOpcodes = map[uint32]reflect.Type{}

func init() {
	tl.Register(EncryptedMessage{}, "adnlTunnel.encryptedMessage tunnelPubKey:int256 seqno:int instructions:bytes payload:bytes = adnlTunnel.EncryptedMessage")
	tl.Register(EncryptedMessageCached{}, "adnlTunnel.encryptedMessageCached tunnelPubKey:int256 seqno:int payload:bytes = adnlTunnel.EncryptedMessage")
	tl.Register(InstructionsContainer{}, "adnlTunnel.instructionsContainer seqno:int list:(vector adnlTunnel.Instruction) = adnlTunnel.InstructionsContainer")

	tl.Register(StateMeta{}, "adnlTunnel.stateMeta state:int = adnlTunnel.StateMeta")
	tl.Register(PingMeta{}, "adnlTunnel.pingMeta seqno:long withPayments:Bool = adnlTunnel.PingMeta")

	tl.Register(SendOutPayload{}, "adnlTunnel.sendOutPayload seqno:long ip:bytes port:int payload:bytes = adnlTunnel.SendOutPayload")
	tl.Register(DeliverUDPPayload{}, "adnlTunnel.deliverUDPPayload seqno:long ip:bytes port:int payload:bytes = adnlTunnel.DeliverUDPPayload")
	tl.Register(DeliverPayload{}, "adnlTunnel.deliverPayload seqno:long payload:bytes = adnlTunnel.DeliverPayload")
	tl.Register(OutBindDonePayload{}, "adnlTunnel.outBindDonePayload seqno:long ip:bytes port:int = adnlTunnel.OutBindDonePayload")

	instructionOpcodes[tl.Register(CacheInstruction{}, "adnlTunnel.cacheInstruction version:int instructions:(vector adnlTunnel.Instruction) = adnlTunnel.Instruction")] = reflect.TypeOf(CacheInstruction{})
	instructionOpcodes[tl.Register(RouteInstruction{}, "adnlTunnel.routeInstruction routeId:int nextChecksum:long = adnlTunnel.Instruction")] = reflect.TypeOf(RouteInstruction{})
	instructionOpcodes[tl.Register(BuildRouteInstruction{}, "adnlTunnel.buildRouteInstruction targetADNL:int256 targetSectionPubKey:int256 routeId:int = adnlTunnel.Instruction")] = reflect.TypeOf(BuildRouteInstruction{})
	instructionOpcodes[tl.Register(PaymentInstruction{}, "adnlTunnel.paymentInstruction paymentChannelState:bytes = adnlTunnel.Instruction")] = reflect.TypeOf(PaymentInstruction{})
	instructionOpcodes[tl.Register(BindOutInstruction{}, "adnlTunnel.bindOutInstruction inboundNodeADNL:int256 inboundSectionPubKey:int256 inboundInstructions:bytes receiverPubKey:int256 = adnlTunnel.Instruction")] = reflect.TypeOf(BindOutInstruction{})
	instructionOpcodes[tl.Register(ReportStatsInstruction{}, "adnlTunnel.reportStatsInstruction inboundNodeADNL:int256 inboundSectionPubKey:int256 inboundInstructions:bytes receiverPubKey:int256 = adnlTunnel.Instruction")] = reflect.TypeOf(ReportStatsInstruction{})
	instructionOpcodes[tl.Register(SendOutInstruction{}, "adnlTunnel.sendOutInstruction = adnlTunnel.Instruction")] = reflect.TypeOf(SendOutInstruction{})
	instructionOpcodes[tl.Register(DeliverInstruction{}, "adnlTunnel.deliverInstruction = adnlTunnel.Instruction")] = reflect.TypeOf(DeliverInstruction{})
	instructionOpcodes[tl.Register(DeliverInitiatorInstruction{}, "adnlTunnel.deliverInitiatorInstruction from:int metadata:bytes = adnlTunnel.Instruction")] = reflect.TypeOf(DeliverInitiatorInstruction{})
}

type PingMeta struct {
	Seqno        uint64 `tl:"long"`
	WithPayments bool   `tl:"bool"`
}

type StateMeta struct {
	State uint32 `tl:"int"`
}

type Instruction interface {
	Execute(ctx context.Context, s *Section, msg *EncryptedMessage, restInstructions []byte) error
}

type CachedAction interface {
	Execute(ctx context.Context, s *Section, msg *EncryptedMessageCached) error
}

// InstructionsContainer list of instructions to process on this node, order is matters
type InstructionsContainer struct {
	Seqno uint32            // to randomize checksum and deny repeats
	List  []tl.Serializable // can be any instruction, for example RouteInstruction + PaymentInstruction
} // min overhead size: 4 + 4 + (instructions count)*4 bytes

// Parse implemented manually for optimization
func (c *InstructionsContainer) Parse(data []byte) ([]byte, error) {
	c.Seqno = binary.LittleEndian.Uint32(data)

	num := int(binary.LittleEndian.Uint32(data[4:]))
	data = data[8:]

	for i := 0; i < num; i++ {
		if len(data) < 4 {
			return nil, fmt.Errorf("corrupted instruction, len %d", len(data))
		}

		op := binary.LittleEndian.Uint32(data)
		typ, ok := instructionOpcodes[op]
		if !ok {
			return nil, fmt.Errorf("unsupported instruction %d", op)
		}

		inst := reflect.New(typ).Interface()

		var err error
		if data, err = tl.Parse(inst, data[4:], false); err != nil {
			return nil, fmt.Errorf("parse instruction %d failed: %v", i, err)
		}

		c.List = append(c.List, inst)
	}

	return data, nil
}

// Serialize implemented manually for optimization
func (c InstructionsContainer) Serialize(buf *bytes.Buffer) error {
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint32(tmp, c.Seqno)
	binary.LittleEndian.PutUint32(tmp[4:], uint32(len(c.List)))
	buf.Write(tmp)

	for i, s := range c.List {
		if _, ok := s.(Instruction); !ok {
			return fmt.Errorf("unsupported instruction %d", i)
		}

		_, err := tl.Serialize(s, true, buf)
		if err != nil {
			return fmt.Errorf("serialize instruction %d failed: %v", i, err)
		}
	}

	return nil
}

// CacheInstruction save instruction to cache, to reduce next packets size
type CacheInstruction struct {
	Version          uint32
	PayloadVerifyKey uint64
	Instructions     []any
}

// Parse implemented manually for optimization
func (ins *CacheInstruction) Parse(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("corrupted instruction, len %d", len(data))
	}

	ins.Version = binary.LittleEndian.Uint32(data)
	ins.PayloadVerifyKey = binary.LittleEndian.Uint64(data[4:])

	num := int(binary.LittleEndian.Uint32(data[12:]))
	data = data[16:]

	for i := 0; i < num; i++ {
		if len(data) < 4 {
			return nil, fmt.Errorf("corrupted instruction, len %d", len(data))
		}

		op := binary.LittleEndian.Uint32(data)
		typ, ok := instructionOpcodes[op]
		if !ok {
			return nil, fmt.Errorf("unsupported instruction %d", op)
		}

		inst := reflect.New(typ).Interface()

		var err error
		if data, err = tl.Parse(inst, data[4:], false); err != nil {
			return nil, fmt.Errorf("parse instruction %d failed: %v", i, err)
		}

		ins.Instructions = append(ins.Instructions, inst)
	}

	return data, nil
}

// Serialize implemented manually for optimization
func (ins CacheInstruction) Serialize(buf *bytes.Buffer) error {
	tmp := make([]byte, 16)
	binary.LittleEndian.PutUint32(tmp, ins.Version)
	binary.LittleEndian.PutUint64(tmp[4:], ins.PayloadVerifyKey)
	binary.LittleEndian.PutUint32(tmp[12:], uint32(len(ins.Instructions)))
	buf.Write(tmp)

	for i, s := range ins.Instructions {
		if _, ok := s.(Instruction); !ok {
			return fmt.Errorf("unsupported instruction %d", i)
		}

		_, err := tl.Serialize(s, true, buf)
		if err != nil {
			return fmt.Errorf("serialize instruction %d failed: %v", i, err)
		}
	}

	return nil
}

func (ins CacheInstruction) Execute(ctx context.Context, s *Section, msg *EncryptedMessage, restInstructions []byte) error {
	s.mx.RLock()
	ver := s.cachedActionsVer
	s.mx.RUnlock()

	if ver >= ins.Version {
		return nil
	}

	var list = make([]CachedAction, 0, len(ins.Instructions))
	for _, instruction := range ins.Instructions {
		switch v := instruction.(type) {
		case *DeliverInitiatorInstruction:
			s.gw.mx.RLock()
			t := s.gw.tunnels[v.From]
			s.gw.mx.RUnlock()

			if t == nil {
				return fmt.Errorf("no tunnel registered for from: %d", v.From)
			}

			list = append(list, &DeliverInitiatorCachedAction{
				Metadata: v.Metadata,
				tun:      t,
			})
		case *SendOutInstruction:
			list = append(list, &SendOutCachedAction{})
		case *RouteInstruction:
			s.mx.RLock()
			route := s.routes[v.RouteID]
			s.mx.RUnlock()

			if route == nil {
				return fmt.Errorf("route %d not exists", v.RouteID)
			}

			list = append(list, &RouteCachedAction{
				Route: route,
			})
		default:
			return fmt.Errorf("unsupported instruction passed in list")
		}
	}

	s.mx.Lock()
	if s.cachedActionsVer < ins.Version {
		s.cachedActions = list
		s.cachedActionsVer = ins.Version
	}
	s.mx.Unlock()

	return nil
}

// BuildRouteInstruction remember route to optimize further packets
type BuildRouteInstruction struct {
	TargetADNL          []byte `tl:"int256"`
	TargetSectionPubKey []byte `tl:"int256"`
	RouteID             uint32 `tl:"int"`
	PricePerPacket      uint64 `tl:"long"`
}

const FreePacketsMaxPS = 10
const FreePacketsMaxPSBurst = FreePacketsMaxPS * 2
const MaxActiveRoutesPerSection = 3

func (ins BuildRouteInstruction) Execute(ctx context.Context, s *Section, msg *EncryptedMessage, restInstructions []byte) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	if !s.gw.allowRouting {
		return fmt.Errorf("instruction is not executable since routing is not allowed")
	}

	if s.gw.payments.MinPricePerPacketRoute > ins.PricePerPacket {
		return fmt.Errorf("too low price per packet route: %d, min is %d", ins.PricePerPacket, s.gw.payments.MinPricePerPacketRoute)
	}

	target := &RouteTarget{
		Peer:           s.gw.addPeer(ins.TargetADNL, nil),
		ADNL:           ins.TargetADNL,
		SectionKey:     ins.TargetSectionPubKey,
		PricePerPacket: ins.PricePerPacket,
	}

	route := s.routes[ins.RouteID]
	if route == nil {
		if len(s.routes) >= MaxActiveRoutesPerSection {
			return fmt.Errorf("too many active routes: %d", len(s.routes))
		}

		route = &Route{
			ID:     ins.RouteID,
			Target: unsafe.Pointer(target),
			// we need some free capacity to configure route, and not create payment channels for not working tunnels
			rate: leakybucket.NewLeakyBucket(FreePacketsMaxPS, FreePacketsMaxPSBurst),
		}
		target.Peer.AddReference()
		s.routes[ins.RouteID] = route
	} else {
		existingTarget := (*RouteTarget)(atomic.LoadPointer(&route.Target))
		adnlChanged := !bytes.Equal(existingTarget.ADNL, target.ADNL)
		if !adnlChanged &&
			bytes.Equal(existingTarget.ADNL, target.ADNL) &&
			bytes.Equal(existingTarget.SectionKey, target.SectionKey) &&
			existingTarget.PricePerPacket == target.PricePerPacket {
			// it is same
			return nil
		}

		if adnlChanged {
			existingTarget.Peer.Dereference()
			target.Peer.AddReference()
		}

		atomic.StorePointer(&route.Target, unsafe.Pointer(target))
	}

	s.log.Info().
		Uint32("id", ins.RouteID).
		Str("target_addr", target.Peer.getAddr()).
		Str("target_key", base64.StdEncoding.EncodeToString(ins.TargetSectionPubKey)).
		Str("target_adnl", base64.StdEncoding.EncodeToString(ins.TargetADNL)).
		Uint64("price_per_packet", ins.PricePerPacket).
		Msg("route configured")

	return nil
}

type RouteCachedAction struct {
	Route *Route
}

func (r *Route) dereferenceTarget() {
	target := (*RouteTarget)(atomic.LoadPointer(&r.Target))
	target.Peer.Dereference()
}

func (r *Route) Route(ctx context.Context, payload []byte, cached bool, instructions []byte, seqno uint32) error {
	target := (*RouteTarget)(atomic.LoadPointer(&r.Target))

	var paid bool
	if target.PricePerPacket > 0 {
		if r.PaymentReceived {
			maxLoss := -int64((r.PacketsRouted/100)*LossAcceptablePercent + LossAcceptableStartup)
			if atomic.LoadInt64(&r.PrepaidPackets) > maxLoss {
				// we not so care about concurrency here, and it is okay to allow couple packets overdraft
				paid = atomic.AddInt64(&r.PrepaidPackets, -1) >= maxLoss
			}
		}

		if !paid && r.rate.Add(1) <= 0 {
			return fmt.Errorf("free packets exceeds rate limit for route %d", r.ID)
		}
	}

	var msg any
	if cached {
		msg = EncryptedMessageCached{
			SectionPubKey: target.SectionKey,
			Seqno:         seqno,
			Payload:       payload,
		}
	} else {
		msg = EncryptedMessage{
			SectionPubKey: target.SectionKey,
			Instructions:  instructions,
			Payload:       payload,
		}
	}

	if err := target.Peer.SendCustomMessage(ctx, msg); err != nil {
		if paid {
			// refund packet
			atomic.AddInt64(&r.PrepaidPackets, 1)
		}
		return fmt.Errorf("route message failed: %w", err)
	}
	atomic.AddUint64(&r.PacketsRouted, 1)

	return nil
}

func (a *RouteCachedAction) Execute(ctx context.Context, s *Section, msg *EncryptedMessageCached) error {
	if !s.gw.allowRouting {
		return fmt.Errorf("instruction is not executable since routing is not allowed")
	}

	return a.Route.Route(ctx, msg.Payload, true, nil, msg.Seqno)
}

// RouteInstruction routes other encrypted instructions and payload to next node saved by BuildRouteInstruction
type RouteInstruction struct {
	RouteID uint32 `tl:"int"`
}

func (ins RouteInstruction) Execute(ctx context.Context, s *Section, msg *EncryptedMessage, restInstructions []byte) error {
	if !s.gw.allowRouting {
		return fmt.Errorf("instruction is not executable since routing is not allowed")
	}

	s.mx.RLock()
	route := s.routes[ins.RouteID]
	s.mx.RUnlock()

	if route == nil {
		return fmt.Errorf("route %d not exists", ins.RouteID)
	}

	return route.Route(ctx, msg.Payload, false, restInstructions, 0)
}

// PaymentInstruction attached virtual payment channel state is used to get money for traffic
type PaymentInstruction struct {
	Key                 ed25519.PublicKey `tl:"int256"`
	PaymentChannelState *cell.Cell        `tl:"cell"`
	Purpose             uint64            `tl:"long"`
	Final               bool              `tl:"bool"`
}

const MinChannelTimeoutSec = 300

func (ins PaymentInstruction) Execute(ctx context.Context, s *Section, _ *EncryptedMessage, _ []byte) error {
	if !s.gw.allowRouting {
		return fmt.Errorf("instruction is not executable since routing is not allowed")
	}

	if s.gw.payments.Service == nil {
		return fmt.Errorf("payments are not enabled")
	}

	// TODO: recover payments after restart

	var st payments.VirtualChannelState
	if err := tlb.LoadFromCell(&st, ins.PaymentChannelState.BeginParse()); err != nil {
		return fmt.Errorf("incorrect state cell: %w", err)
	}

	if st.Amount.Nano().Sign() <= 0 {
		return fmt.Errorf("amount should be positive")
	}

	if !st.Verify(ins.Key) {
		return fmt.Errorf("invalid payment state")
	}

	s.mx.RLock()
	v := s.payments[string(ins.Key)]
	s.mx.RUnlock()

	justLoadedAndCountable := false
	if v == nil {
		vc, err := s.gw.payments.Service.GetVirtualChannelMeta(ctx, ins.Key)
		if err != nil {
			return fmt.Errorf("get virtual %x channel failed: %w", ins.Key, err)
		}

		var last *payments.VirtualChannelState
		if len(vc.LastKnownResolve) > 0 {
			cl, err := cell.FromBOC(vc.LastKnownResolve)
			if err != nil {
				return fmt.Errorf("incorrect latest state cell: %w", err)
			}

			last = &payments.VirtualChannelState{}
			if err = tlb.LoadFromCell(last, cl.BeginParse()); err != nil {
				return fmt.Errorf("incorrect latest state cell: %w", err)
			}
		}

		// TODO: recover paid packets num after restart

		if vc.Incoming == nil {
			return fmt.Errorf("payment channel direction is incorrect")
		}

		if vc.Outgoing != nil {
			return fmt.Errorf("payment channel should not have outgoing direction")
		}

		capacity, err := tlb.FromTON(vc.Incoming.Capacity)
		if err != nil {
			return fmt.Errorf("incorrect capacity: %w", err)
		}

		justLoadedAndCountable = time.Until(vc.Incoming.SafeDeadline) >= MinChannelTimeoutSec*time.Second

		v = &PaymentChannel{
			Key:         ins.Key,
			Active:      vc.Status == db.VirtualChannelStateActive && justLoadedAndCountable,
			Deadline:    vc.Incoming.SafeDeadline.Unix(),
			Capacity:    capacity.Nano(),
			Purpose:     ins.Purpose,
			LatestState: last,
		}

		s.mx.Lock()
		ov := s.payments[string(ins.Key)]
		if ov != nil {
			v = ov
		} else {
			s.payments[string(ins.Key)] = v
		}
		s.mx.Unlock()
	}

	v.mx.Lock()
	defer v.mx.Unlock()

	if v.Purpose != ins.Purpose {
		return fmt.Errorf("purpose change is not allowed")
	}

	var lastAmt *big.Int
	if v.LatestState != nil && !justLoadedAndCountable { // we count first after restart even if it was paid before
		lastAmt = v.LatestState.Amount.Nano()
	} else {
		lastAmt = big.NewInt(0)
	}

	amt := new(big.Int).Sub(st.Amount.Nano(), lastAmt)
	if amt.Sign() <= 0 {
		// already processed payment
		log.Trace().Str("key", base64.StdEncoding.EncodeToString(ins.Key)).Msg("already processed payment")
		return nil
	}

	// even if channel is closed, we accept payment, because we may restart before
	if !v.Active && !justLoadedAndCountable {
		return fmt.Errorf("payment channel is inactive")
	}

	timeLeft := v.Deadline - time.Now().Unix()
	if timeLeft < MinChannelTimeoutSec {
		return fmt.Errorf("payment channel deadline is too short")
	}

	var mutation func()

	switch v.Purpose >> 32 {
	case PaymentPurposeOut:
		s.mx.RLock()
		out := s.out
		s.mx.RUnlock()

		if out == nil {
			return fmt.Errorf("out is not initialized")
		}

		if v.LatestState == nil { // first init
			minCap := new(big.Int).Mul(out.PricePerPacket, big.NewInt(10000))

			if v.Capacity.Cmp(minCap) < 0 {
				return fmt.Errorf("payment channel capacity is too low")
			}
		}

		mutation = func() {
			out.mx.RLock()
			num := amt.Div(amt, out.PricePerPacket)
			x := addPrepaid(&out.PrepaidPacketsOut, num)
			z := addPrepaid(&out.PrepaidPacketsIn, num)
			out.mx.RUnlock()
			s.log.Info().Int64("num", num.Int64()).
				Int64("out_balance", x).
				Int64("in_balance", z).
				Str("payment", st.Amount.String()).
				Int64("payment_ttl_left", timeLeft).
				Msg("packets prepaid for out gateway")
		}

	case PaymentPurposeRoute:
		routeId := uint32(v.Purpose & math.MaxUint32)
		s.mx.RLock()
		route := s.routes[routeId]
		s.mx.RUnlock()
		if route == nil {
			return fmt.Errorf("route %d not exists", routeId)
		}

		target := (*RouteTarget)(atomic.LoadPointer(&route.Target))

		if target.PricePerPacket == 0 {
			return fmt.Errorf("payment is not required for route %d", routeId)
		}

		if v.LatestState == nil { // first init
			minCap := new(big.Int).Mul(new(big.Int).SetUint64(target.PricePerPacket), big.NewInt(500))

			if v.Capacity.Cmp(minCap) < 0 {
				return fmt.Errorf("payment channel capacity is too low")
			}
		}

		num := amt.Div(amt, new(big.Int).SetUint64(target.PricePerPacket))
		mutation = func() {
			route.PaymentReceived = true
			x := addPrepaid(&route.PrepaidPackets, num)
			s.log.Info().Uint32("route", routeId).
				Int64("num", num.Int64()).
				Int64("balance", x).
				Str("payment", st.Amount.String()).
				Int64("payment_ttl_left", timeLeft).
				Msg("packets prepaid for route")
		}
	default:
		return fmt.Errorf("unknown payment purpose: %d", v.Purpose>>32)
	}

	if err := s.gw.payments.Service.AddVirtualChannelResolve(ctx, ins.Key, st); err != nil {
		return fmt.Errorf("add virtual channel resolve failed: %w", err)
	}

	// from this point payment is accepted
	mutation()
	v.LatestState = &st

	if ins.Final {
		go func() { // it locks inside, so we close async
			for i := 1; i <= 5; i++ {
				if err := s.gw.closePaymentChannel(v); err != nil {
					s.log.Warn().Err(err).Int("attempt", i).Msg("close payment channel failed")
					time.Sleep(time.Second)
					continue
				}
				break
			}
		}()
	}

	return nil
}

func addPrepaid(at *int64, num *big.Int) int64 {
	if new(big.Int).Add(num, big.NewInt(atomic.LoadInt64(at))).BitLen() >= 64 {
		// in case of overflow we just set max to not go below zero
		atomic.StoreInt64(at, math.MaxInt64)
		return math.MaxInt64
	}

	return atomic.AddInt64(at, num.Int64())
}

// BindOutInstruction allocate external address and port on this node,
// it will be used by initiator to send and receive ADNL packets from outside.
// Second call in same tunnel replaces inbound route and key, without allocating new port.
type BindOutInstruction struct {
	InboundNodeADNL      []byte `tl:"int256"`
	InboundSectionPubKey []byte `tl:"int256"`
	InboundInstructions  []byte `tl:"bytes"`
	ReceiverPubKey       []byte `tl:"int256"`
	PricePerPacket       uint64 `tl:"long"`
}

func (ins BindOutInstruction) Execute(ctx context.Context, s *Section, _ *EncryptedMessage, _ []byte) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	if !s.gw.allowOut {
		return fmt.Errorf("instruction is not executable since out is not allowed")
	}

	gateAddresses := s.gw.gate.GetAddressList().Addresses
	if len(gateAddresses) == 0 {
		return fmt.Errorf("no external addresses in gate")
	}

	sharedPayloadKey, err := adnl.SharedKey(s.gw.key, ins.ReceiverPubKey)
	if err != nil {
		return fmt.Errorf("calculate shared_payload key for out failed: %w", err)
	}

	if s.gw.payments.Service != nil && s.gw.payments.MinPricePerPacketInOut > ins.PricePerPacket {
		return fmt.Errorf("too low price per packet: %d, min is %d", ins.PricePerPacket, s.gw.payments.MinPricePerPacketInOut)
	}

	if s.gw.payments.Service == nil {
		// if we have no payments enabled, just ignore price
		ins.PricePerPacket = 0
	}

	var port uint16
	if s.out == nil {
		// allocate port automatically
		conn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return fmt.Errorf("allocate addr for out failed: %w", err)
		}

		closer, cancel := context.WithCancel(context.Background())
		s.out = &Out{
			inboundPeer:         s.gw.addPeer(ins.InboundNodeADNL, nil),
			conn:                conn,
			closer:              closer,
			closerClose:         cancel,
			InboundADNL:         ins.InboundNodeADNL,
			PayloadCipherKey:    sharedPayloadKey,
			PayloadCipherKeyCRC: crc64.Checksum(sharedPayloadKey, crcTable),
			InboundSectionKey:   ins.InboundSectionPubKey,
			Instructions:        ins.InboundInstructions,
			PacketsSentOut:      0,
			PacketsSentIn:       0,
			PricePerPacket:      new(big.Int).SetUint64(ins.PricePerPacket),
			log:                 s.log.With().Str("component", "out").Logger(),
		}

		s.out.inboundPeer.AddReference()
		go s.out.Listen(s.gw, 8)

		port = uint16(s.out.conn.LocalAddr().(*net.UDPAddr).Port)
		s.log.Info().
			Str("back_addr", s.out.inboundPeer.getAddr()).
			Uint16("alloc_port", port).
			Str("back_route_adnl", base64.StdEncoding.EncodeToString(ins.InboundNodeADNL)).
			Msg("out addr allocated")
	} else {
		s.out.mx.Lock()
		inADNLChanged := !bytes.Equal(s.out.InboundADNL, ins.InboundNodeADNL)
		changed := inADNLChanged ||
			!bytes.Equal(s.out.PayloadCipherKey, sharedPayloadKey) ||
			s.out.PayloadCipherKeyCRC != crc64.Checksum(sharedPayloadKey, crcTable) ||
			!bytes.Equal(s.out.InboundSectionKey, ins.InboundSectionPubKey) ||
			!bytes.Equal(s.out.Instructions, ins.InboundInstructions) ||
			s.out.PricePerPacket.Cmp(new(big.Int).SetUint64(ins.PricePerPacket)) != 0

		if changed {
			if inADNLChanged {
				s.out.inboundPeer.Dereference()
				s.out.inboundPeer = s.gw.addPeer(ins.InboundNodeADNL, nil)
				s.out.inboundPeer.AddReference()
			}

			s.out.InboundADNL = ins.InboundNodeADNL
			s.out.PayloadCipherKey = sharedPayloadKey
			s.out.PayloadCipherKeyCRC = crc64.Checksum(sharedPayloadKey, crcTable)
			s.out.InboundSectionKey = ins.InboundSectionPubKey
			s.out.Instructions = ins.InboundInstructions
			s.out.PricePerPacket = new(big.Int).SetUint64(ins.PricePerPacket)

			s.log.Info().
				Str("back_addr", s.out.inboundPeer.getAddr()).
				Uint16("port", port).
				Str("back_route_adnl", base64.StdEncoding.EncodeToString(ins.InboundNodeADNL)).
				Int("size", len(ins.InboundInstructions)).
				Uint64("crc", crc64.Checksum(ins.InboundInstructions, crcTable)).
				Msg("out addr reconfigured")
		}
		s.out.mx.Unlock()

		port = uint16(s.out.conn.LocalAddr().(*net.UDPAddr).Port)
	}

	if err = s.out.sendBack(OutBindDonePayload{
		Seqno: atomic.AddUint64(&s.out.PacketsSentIn, 1),
		IP:    gateAddresses[0].IP,
		Port:  uint32(port),
	}, false); err != nil {
		s.log.Warn().Err(err).Msg("send back failed")
	}

	return nil
}

// ReportStatsInstruction is used to get network statistics from some node,
// for example to calc packet loss or align payment amount
type ReportStatsInstruction struct {
	InboundNodeADNL             []byte `tl:"int256"`
	InboundSectionPubKey        []byte `tl:"int256"`
	InboundInstructions         []byte `tl:"bytes"`
	InboundInstructionsChecksum uint64 `tl:"long"`
	ReceiverPubKey              []byte `tl:"int256"`
}

func (ins ReportStatsInstruction) Execute(ctx context.Context, s *Section, msg *EncryptedMessage, restInstructions []byte) error {
	if !s.gw.allowRouting {
		return fmt.Errorf("instruction is not executable since routing is not allowed")
	}

	println(reflect.TypeOf(ins).String())
	return nil
}

type SendOutCachedAction struct{}

func (_ *SendOutCachedAction) Execute(ctx context.Context, s *Section, msg *EncryptedMessageCached) error {
	if !s.gw.allowOut {
		return fmt.Errorf("instruction is not executable since out is not allowed")
	}
	return s.out.Send(msg.Payload)
}

// SendOutInstruction used to send UDP packet by server which already bind port using BindOutInstruction
type SendOutInstruction struct{}

func (ins SendOutInstruction) Execute(ctx context.Context, s *Section, msg *EncryptedMessage, _ []byte) error {
	if !s.gw.allowOut {
		return fmt.Errorf("instruction is not executable since out is not allowed")
	}
	return s.out.Send(msg.Payload)
}

// DeliverInstruction used to identify that node is the destination
// and payload should be processed on this server, to decrypt shared key of private receiver + public tunnel should be used
type DeliverInstruction struct{}

func (ins DeliverInstruction) Execute(ctx context.Context, s *Section, msg *EncryptedMessage, restInstructions []byte) error {
	println(reflect.TypeOf(ins).String())
	return nil
}

type DeliverInitiatorCachedAction struct {
	Metadata any

	tun Tunnel
}

func (d *DeliverInitiatorCachedAction) Execute(ctx context.Context, s *Section, msg *EncryptedMessageCached) error {
	if err := d.tun.Process(msg.Payload, d.Metadata); err != nil {
		return fmt.Errorf("process recv message failed: %w", err)
	}
	return nil
}

// DeliverInitiatorInstruction used to identify that node is the initiator destination
// and payload should be processed on this server, to decrypt shared key of public sender + private tunnel should be used
type DeliverInitiatorInstruction struct {
	From     uint32 `tl:"int"`
	Metadata any    `tl:"struct boxed [adnlTunnel.stateMeta,adnlTunnel.paymentMeta,adnlTunnel.pingMeta]"`
}

func (ins DeliverInitiatorInstruction) Execute(ctx context.Context, s *Section, msg *EncryptedMessage, _ []byte) error {
	s.gw.mx.RLock()
	t := s.gw.tunnels[ins.From]
	s.gw.mx.RUnlock()

	if t == nil {
		return fmt.Errorf("no tunnel registered for from: %d", ins.From)
	}

	if err := t.Process(msg.Payload, ins.Metadata); err != nil {
		return fmt.Errorf("process recv message failed: %w", err)
	}

	return nil
}

type DeliverPayload struct {
	Seqno uint64 `tl:"long"`

	Payload []byte `tl:"bytes"`
}

type DeliverUDPPayload struct {
	Seqno uint64 `tl:"long"`

	IP      []byte `tl:"bytes"`
	Port    uint32 `tl:"int"`
	Payload []byte `tl:"bytes"`
}

type OutBindDonePayload struct {
	Seqno uint64 `tl:"long"`

	IP   []byte `tl:"bytes"`
	Port uint32 `tl:"int"`
}

type SendOutPayload struct {
	Seqno uint64 `tl:"long"`

	IP      []byte `tl:"bytes"`
	Port    uint32 `tl:"int"`
	Payload []byte `tl:"bytes"`
}

func (o *Out) Close() {
	o.closerClose()
	o.conn.Close()
	o.inboundPeer.Dereference()

	o.log.Debug().Msg("closing out")
}

type inPacket struct {
	from net.Addr
	buf  []byte
	n    int
}

func (o *Out) Send(payload []byte) error {
	o.mx.RLock()
	defer o.mx.RUnlock()

	data, err := decryptStream(o.PayloadCipherKeyCRC, o.PayloadCipherKey, payload)
	if err != nil {
		return fmt.Errorf("decrypt payload failed: %w", err)
	}

	var pl SendOutPayload
	if _, err = tl.Parse(&pl, data, true); err != nil {
		return fmt.Errorf("parse payload failed: %w", err)
	}

	if len(pl.Payload) == 0 {
		return nil
	}

	ip, ok := netip.AddrFromSlice(pl.IP)
	if !ok {
		return fmt.Errorf("invalid IP address")
	}
	addr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(pl.Port)))

	if o.PricePerPacket.Sign() > 0 {
		if atomic.LoadInt64(&o.PrepaidPacketsIn) < -int64((o.PacketsSentIn/100)*LossAcceptablePercent+LossAcceptableStartup) {
			return fmt.Errorf("prepaid `in` packets exceeds, cannot send more out messages")
		}

		if prepaid := atomic.LoadInt64(&o.PrepaidPacketsOut); prepaid <= 0 {
			return fmt.Errorf("prepaid packets exceeds limit")
		}
		// we not so care about concurrency here, and it is okay to allow couple packets overdraft
		atomic.AddInt64(&o.PrepaidPacketsOut, -1)
	}

	if _, err = o.conn.WriteTo(pl.Payload, addr); err != nil {
		return fmt.Errorf("write out failed: %w", err)
	}
	atomic.AddUint64(&o.PacketsSentOut, 1)

	return nil
}

const LossAcceptablePercent = 0
const LossAcceptableStartup = 20000

func (o *Out) Listen(g *Gateway, threads int) {
	pks := make(chan inPacket, 256*1024)

	for i := 0; i < threads; i++ {
		go func() {
			var p inPacket
			for {
				select {
				case <-o.closer.Done():
					o.log.Debug().Msg("stopping outbound listener thread")
					return
				case p = <-pks:
				}

				if o.PricePerPacket.Sign() > 0 {
					maxCredit := (atomic.LoadUint64(&o.PacketsSentIn)/100)*LossAcceptablePercent + LossAcceptableStartup
					if prepaid := atomic.LoadInt64(&o.PrepaidPacketsIn); prepaid <= -int64(maxCredit) {
						o.log.Trace().Int64("credit", prepaid).Uint64("sent", atomic.LoadUint64(&o.PacketsSentIn)).Msg("incoming packet was dropped because not paid")
						continue
					}
					// we not so care about concurrency here, and it is okay to allow couple packets overdraft
					atomic.AddInt64(&o.PrepaidPacketsIn, -1)
				}

				src := p.from.(*net.UDPAddr)
				err := o.sendBack(DeliverUDPPayload{
					Seqno:   atomic.AddUint64(&o.PacketsSentIn, 1),
					IP:      src.IP,
					Port:    uint32(src.Port),
					Payload: p.buf[:p.n],
				}, true)
				g.bufPool.Put(p.buf)

				if err != nil {
					o.log.Warn().Err(err).Msg("send back failed")
					continue
				}
			}
		}()
	}

	for {
		buf := g.bufPool.Get().([]byte)
		n, from, err := o.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-o.closer.Done():
				_ = o.conn.Close()
				o.log.Debug().Err(err).Msg("closing outbound connection")
				return
			default:
			}

			continue
		}
		// TODO: filter "from", add bans

		//TODO: verify packets as much as possible

		if n < 64 {
			g.bufPool.Put(buf)
			// too small packet
			continue
		}

		select {
		case pks <- inPacket{
			from: from,
			buf:  buf,
			n:    n,
		}:
		default:
			// overflow
			g.bufPool.Put(buf)
		}
	}
}

func (o *Out) sendBack(obj tl.Serializable, isPayload bool) error {
	pl, err := tl.Serialize(obj, true)
	if err != nil {
		return fmt.Errorf("serialize payload failed: %w", err)
	}

	o.mx.RLock()
	defer o.mx.RUnlock()

	pl, err = encryptStream(o.PayloadCipherKeyCRC, o.PayloadCipherKey, pl)
	if err != nil {
		return fmt.Errorf("encrypt payload failed: %w", err)
	}

	//TODO: add random padding to payload

	var msg tl.Serializable
	if isPayload {
		msg = EncryptedMessageCached{
			SectionPubKey: o.InboundSectionKey,
			Seqno:         atomic.AddUint32(&o.backSeqno, 1),
			Payload:       pl,
		}
	} else {
		msg = EncryptedMessage{
			SectionPubKey: o.InboundSectionKey,
			Instructions:  o.Instructions,
			Payload:       pl,
		}
	}

	if err = o.inboundPeer.SendCustomMessage(o.closer, msg); err != nil {
		return fmt.Errorf("send message to inbound tunnel failed: %w", err)
	}
	return nil
}
