package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/kevinms/leakybucket-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ton-blockchain/adnl-tunnel/metrics"
	"github.com/xssnick/ton-payment-network/pkg/payments"
	"github.com/xssnick/ton-payment-network/tonpayments"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/tl"
	"hash/crc64"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var crcTable = crc64.MakeTable(crc64.ECMA)

func init() {
	tl.Register(Ping{}, "adnlTunnel.ping seqno:long = adnlTunnel.Ping")
	tl.Register(Pong{}, "adnlTunnel.pong seqno:long = adnlTunnel.Pong")
}

type Tunnel interface {
	Process(payload []byte, meta any) error
}

type Ping struct {
	Seqno uint64 `tl:"long"`
}

type Pong struct {
	Seqno uint64 `tl:"long"`
}

type RouteTarget struct {
	Peer           *Peer
	ADNL           []byte
	SectionKey     []byte
	PricePerPacket uint64
}

type Route struct {
	ID            uint32
	Target        unsafe.Pointer // *RouteTarget
	PacketsRouted uint64
	Section       *Section

	PaymentReceived bool
	PrepaidPackets  int64
	rate            *leakybucket.LeakyBucket
}

type Out struct {
	gw          *Gateway
	inboundPeer *Peer
	conn        net.PacketConn

	closer      context.Context
	closerClose func()

	InboundADNL         []byte
	PayloadCipherKey    []byte
	PayloadCipherKeyCRC uint64
	InboundSectionKey   []byte
	Instructions        []byte

	PacketsSentOut uint64
	PacketsSentIn  uint64

	PrepaidPacketsIn  int64
	PrepaidPacketsOut int64

	PricePerPacket *big.Int

	backSeqno uint32

	mx  sync.RWMutex
	log zerolog.Logger
}

const (
	PaymentPurposeRoute = iota + 1
	PaymentPurposeOut
)

type PaymentChannel struct {
	Key         ed25519.PublicKey
	Active      bool
	Deadline    int64
	Capacity    *big.Int
	LatestState *payments.VirtualChannelState

	Purpose uint64

	mx sync.Mutex
}

type SeqnoWindow struct {
	latest uint32
	window [8]uint64 // 512
	mx     sync.Mutex
}

type Section struct {
	gw           *Gateway
	lastPacketAt int64

	key          []byte
	cipherKey    []byte
	cipherKeyCrc uint64
	routes       map[uint32]*Route
	out          *Out

	cachedActions    []CachedAction
	cachedActionsVer uint64

	payments map[string]*PaymentChannel

	seqno       SeqnoWindow
	seqnoCached SeqnoWindow

	lastOnceLogAt int64
	log           zerolog.Logger
	mx            sync.RWMutex
}

type Gateway struct {
	gate         *adnl.Gateway
	key          ed25519.PrivateKey
	dht          *dht.Client
	allowRouting bool
	allowOut     bool
	paymentNode  []byte

	activePeers map[string]*Peer

	signalCheckPeers chan struct{}

	closerCtx context.Context
	close     func()

	tunnels map[uint32]Tunnel

	statsReceived uint64
	statsSent     uint64
	statsRouted   uint64

	payments PaymentConfig

	bufPool sync.Pool

	log             zerolog.Logger
	inboundSections map[string]*Section
	mx              sync.RWMutex
}

// EncryptedMessage tunneled message to decrypt and process, after decryption contains InstructionsContainer
type EncryptedMessage struct {
	// used to generate shared key for decryption
	SectionPubKey []byte `tl:"int256"`

	// instructions are recursively encrypted, each receiver decrypts its own layer
	Instructions []byte `tl:"bytes"`

	// payload encrypted from sender to receiver,
	// just once, only some instructions use payload.
	// payload can contain multiple payloads
	Payload []byte `tl:"bytes"`
} // min overhead size: 60 bytes

type EncryptedMessageCached struct {
	SectionPubKey []byte `tl:"int256"`
	Seqno         uint32 `tl:"int"`
	Payload       []byte `tl:"bytes"`
} // overhead size: 40 bytes

type PaymentConfig struct {
	Service                *tonpayments.Service
	MinPricePerPacketRoute uint64
	MinPricePerPacketInOut uint64
}

func NewGateway(gate *adnl.Gateway, dht *dht.Client, key ed25519.PrivateKey, logger zerolog.Logger, pay PaymentConfig) *Gateway {
	ctx, cancel := context.WithCancel(context.Background())
	g := &Gateway{
		gate:             gate,
		key:              key,
		dht:              dht,
		allowRouting:     true,
		allowOut:         true,
		paymentNode:      nil,
		activePeers:      map[string]*Peer{},
		signalCheckPeers: make(chan struct{}, 1),
		closerCtx:        ctx,
		close:            cancel,
		tunnels:          map[uint32]Tunnel{},
		log:              logger,
		payments:         pay,
		inboundSections:  map[string]*Section{},
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 2048)
			},
		},
	}

	if metrics.Registered {
		go g.speedMetricsUpdater()
	}
	return g
}

type SectionStats struct {
	Routed   uint64
	Sent     uint64
	Received uint64

	PrepaidPacketsRoute []int64
	PrepaidPacketsIn    int64
	PrepaidPacketsOut   int64
}

func (g *Gateway) requestCheckPeers() {
	select {
	case g.signalCheckPeers <- struct{}{}:
	default:
	}
}

func (g *Gateway) speedMetricsUpdater() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var routedPrev, inPrev, outPrev uint64
	for {
		select {
		case <-g.closerCtx.Done():
			return
		case <-ticker.C:
			routed := atomic.LoadUint64(&g.statsRouted) / 1000
			in := atomic.LoadUint64(&g.statsReceived) / 1000
			out := atomic.LoadUint64(&g.statsSent) / 1000

			metrics.PacketsCounter.WithLabelValues("routed").Add(float64(routed - routedPrev))
			metrics.PacketsCounter.WithLabelValues("in").Add(float64(in - inPrev))
			metrics.PacketsCounter.WithLabelValues("out").Add(float64(out - outPrev))

			routedPrev = routed
			inPrev = in
			outPrev = out
		}
	}
}

func (g *Gateway) GetPacketsStats() map[string]*SectionStats {
	tmp := map[string]*Section{}
	res := map[string]*SectionStats{}

	g.mx.RLock()
	for s, section := range g.inboundSections {
		tmp[s] = section
	}
	g.mx.RUnlock()

	for s, section := range tmp {
		stats := &SectionStats{}
		res[s] = stats

		section.mx.RLock()
		if len(section.routes) > 0 {
			for _, route := range section.routes {
				stats.Routed += atomic.LoadUint64(&route.PacketsRouted)
				stats.PrepaidPacketsRoute = append(stats.PrepaidPacketsRoute, atomic.LoadInt64(&route.PrepaidPackets))
			}
		}

		if section.out != nil {
			stats.Sent = atomic.LoadUint64(&section.out.PacketsSentOut)
			stats.Received = atomic.LoadUint64(&section.out.PacketsSentIn)
			stats.PrepaidPacketsIn = atomic.LoadInt64(&section.out.PrepaidPacketsIn)
			stats.PrepaidPacketsOut = atomic.LoadInt64(&section.out.PrepaidPacketsOut)
		}
		section.mx.RUnlock()
	}

	return res
}

func (g *Gateway) Stop(ctx context.Context) error {
	var err error
	g.close()
	if g.payments.Service != nil {
		if err = g.payments.Service.CommitAllOurVirtualChannelsAndWait(ctx); err != nil {
			err = fmt.Errorf("commit virtual channels error: %w", err)
		}
		g.payments.Service.Stop()
	}
	return err
}

func (g *Gateway) Start() error {
	connHandler := func(client adnl.Peer) error {
		p := g.addPeer(client.GetID(), client)

		client.SetDisconnectHandler(func(addr string, key ed25519.PublicKey) {
			p.closeConn(client)
		})

		return nil
	}

	g.gate.SetConnectionHandler(connHandler)
	// process previously connected peers
	for _, peer := range g.gate.GetActivePeers() {
		if err := connHandler(peer); err != nil {
			g.log.Warn().Err(err).Msg("failed to bootstrap already active peer")
			continue
		}
	}

	go func() {
		var after time.Duration = 0
		for {
			select {
			case <-g.closerCtx.Done():
				return
			case <-time.After(after):
				if len(g.gate.GetAddressList().Addresses) > 0 {
					g.log.Debug().Msg("updating dht")
					ctx, cancel := context.WithTimeout(g.closerCtx, 300*time.Second)
					err := g.updateDHT(ctx, 20*60)
					cancel()
					if err != nil {
						g.log.Err(err).Msg("dht update failed")
						after = 10 * time.Second
						continue
					}

					g.log.Debug().Msg("dht updated")

				} else {
					g.log.Debug().Msg("skipping dht because no external address known")
				}

				after = 5 * time.Minute
			}
		}
	}()

	go g.keepAlivePeersAndSections()
	<-g.closerCtx.Done()
	return nil
}

func (g *Gateway) keepAlivePeersAndSections() {
	const SectionMaxInactiveSec = 120
	const PeerMaxInactiveSec = 10

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-g.closerCtx.Done():
			return
		case <-ticker.C:
			tm := time.Now().Unix()
			var sectionsToClose []*Section
			var paymentsToClose []*PaymentChannel

			g.mx.RLock()
			for _, peer := range g.activePeers {
				g.log.Trace().Int64("refs", atomic.LoadInt64(&peer.references)).Str("id", base64.StdEncoding.EncodeToString(peer.id)).Int64("inactive", tm-peer.LastPacketFromAt).Bool("connected", peer.getConn() != nil).Msg("checking peer")

				if atomic.LoadInt64(&peer.references) == 0 && tm-peer.CreatedAt > 10 {
					go peer.kill() // async to not get deadlock
					continue
				}

				if tm-peer.LastPacketFromAt > PeerMaxInactiveSec &&
					tm-atomic.LoadInt64(&peer.DiscoveredAt) > PeerMaxInactiveSec {
					peer.closeConn(nil)
				}

				if conn := peer.getConn(); conn == nil {
					if atomic.LoadInt32(&peer.discoverInProgress) == 0 {
						go func(peer *Peer) {
							g.log.Debug().Str("id", base64.StdEncoding.EncodeToString(peer.id)).Msg("discovering peer")
							ctx, cancel := context.WithTimeout(g.closerCtx, 60*time.Second)
							err := peer.discover(ctx)
							cancel()
							if err != nil {
								g.log.Debug().Err(err).Str("id", base64.StdEncoding.EncodeToString(peer.id)).Msg("peer discovery failed")
							}
						}(peer)
					}
					continue
				}

				if tm-peer.LastPingSentAt > 3 {
					peer.LastPingSentAt = tm
					g.log.Debug().Int64("refs", atomic.LoadInt64(&peer.references)).Str("id", base64.StdEncoding.EncodeToString(peer.id)).Msg("pinging peer")
					err := peer.SendCustomMessage(context.Background(), Ping{
						Seqno: atomic.AddUint64(&peer.pingSeqno, 1),
					})
					if err != nil {
						continue
					}
				}
			}

			for _, section := range g.inboundSections {
				if !section.mx.TryLock() {
					continue
				}

				if atomic.LoadInt64(&section.lastPacketAt) < tm-SectionMaxInactiveSec {
					sectionsToClose = append(sectionsToClose, section)
				} else {
					for k, channel := range section.payments {
						if channel.Deadline < tm {
							if channel.Active {
								paymentsToClose = append(paymentsToClose, channel)
								continue
							}
							delete(section.payments, k)
						}
					}
				}
				section.mx.Unlock()
			}
			g.mx.RUnlock()

			for _, section := range sectionsToClose {
				if section.closeIfNotLocked() {
					g.mx.Lock()
					delete(g.inboundSections, string(section.key))
					g.mx.Unlock()
				}
			}

			for _, channel := range paymentsToClose {
				_ = g.closePaymentChannel(channel)
			}
		}
	}
}

func (g *Gateway) messageHandler(peer *Peer) func(msg *adnl.MessageCustom) error {
	return func(msg *adnl.MessageCustom) error {
		switch m := msg.Data.(type) {
		case Ping:
			if err := peer.SendCustomMessage(context.Background(), Pong{
				Seqno: m.Seqno,
			}); err != nil {
				return fmt.Errorf("send pong failed: %w", err)
			}
			g.log.Trace().Str("peer", base64.StdEncoding.EncodeToString(peer.id)).Str("addr", peer.getAddr()).Msg("ping received")
		case Pong:
			atomic.StoreUint64(&peer.pongSeqno, m.Seqno)
			g.log.Trace().Str("peer", base64.StdEncoding.EncodeToString(peer.id)).Str("addr", peer.getAddr()).Msg("pong received")
		case EncryptedMessageCached:
			g.mx.RLock()
			sec := g.inboundSections[string(m.SectionPubKey)]
			g.mx.RUnlock()

			if sec == nil {
				return fmt.Errorf("section is not exists")
			}

			if !sec.checkSeqno(m.Seqno, true) {
				sec.logOnce().Uint32("seqno", m.Seqno).Uint32("last_seqno", sec.seqnoCached.latest).Msg("repeating cached packet")
				return fmt.Errorf("repeating cached packet")
			}

			if len(sec.cachedActions) == 0 {
				return fmt.Errorf("cache is empty")
			}

			atomic.StoreInt64(&sec.lastPacketAt, time.Now().Unix())
			for i, inst := range sec.cachedActions {
				if err := inst.Execute(g.closerCtx, sec, &m); err != nil {
					sec.logOnce().Type("instruction", inst).Err(err).Msg("execute cached instruction failed")
					return fmt.Errorf("execute cached action %d error: %w", i, err)
				}
			}
		case EncryptedMessage:
			g.mx.RLock()
			sec := g.inboundSections[string(m.SectionPubKey)]
			g.mx.RUnlock()

			// TODO: random tunnel creation ddos protection
			if sec == nil {
				shKey, err := adnl.SharedKey(g.key, m.SectionPubKey)
				if err != nil {
					return fmt.Errorf("shared key calc failed: %v", err)
				}

				sec = &Section{
					key:          m.SectionPubKey,
					gw:           g,
					cipherKey:    shKey,
					cipherKeyCrc: crc64.Checksum(shKey, crcTable),
					routes:       map[uint32]*Route{},
					payments:     map[string]*PaymentChannel{},
					lastPacketAt: time.Now().Unix(),
					log: g.log.With().
						Str("from_addr", peer.getConn().RemoteAddr()).
						Str("from_adnl", base64.StdEncoding.EncodeToString(peer.id)).
						Str("tunnel", base64.StdEncoding.EncodeToString(m.SectionPubKey)).Logger(),
				}
				sec.log.Info().Msg("inbound section created")

				g.mx.Lock()
				g.inboundSections[string(m.SectionPubKey)] = sec
				g.mx.Unlock()

				metrics.ActiveInboundSections.Inc()
			}

			container, restInstructions, err := sec.decryptMessage(&m)
			if err != nil {
				return fmt.Errorf("decrypt failed: %w", err)
			}

			if !sec.checkSeqno(container.Seqno, false) {
				sec.logOnce().Uint32("seqno", container.Seqno).Uint32("last_seqno", sec.seqno.latest).Msg("repeating instructions packet")

				return fmt.Errorf("repeating instructions packet")
			}

			if len(container.List) > 5 {
				return fmt.Errorf("too many instructions")
			}

			atomic.StoreInt64(&sec.lastPacketAt, time.Now().Unix())
			for i, inst := range container.List {
				if err = inst.(Instruction).Execute(g.closerCtx, sec, &m, restInstructions); err != nil {
					sec.logOnce().Int("index", i).Type("instruction", inst).Err(err).Msg("execute instruction failed")
					return fmt.Errorf("execute instruction %d (%T) error: %w", i, inst, err)
				}
			}
		default:
			return fmt.Errorf("unsupported message type %T", msg.Data)
		}

		atomic.StoreInt64(&peer.LastPacketFromAt, time.Now().Unix())

		return nil
	}
}

func (s *Section) logOnce() *zerolog.Event {
	e := s.log.Trace()
	now := time.Now().UnixMilli()
	if v := atomic.LoadInt64(&s.lastOnceLogAt); v < time.Now().UnixMilli()-500 {
		if atomic.CompareAndSwapInt64(&s.lastOnceLogAt, v, now) {
			e = s.log.Debug()
		}
	}
	return e
}

func (s *Section) decryptMessage(m *EncryptedMessage) (*InstructionsContainer, []byte, error) {
	data, err := decryptStream(s.cipherKeyCrc, s.cipherKey, m.Instructions)
	if err != nil {
		return nil, nil, fmt.Errorf("shared key calc failed: %v", err)
	}

	if len(data) < 12 {
		return nil, nil, fmt.Errorf("corrupted instructions, len %d", len(data))
	}

	var container = &InstructionsContainer{}
	restInstructions, err := tl.Parse(container, data, true)
	if err != nil {
		return nil, nil, fmt.Errorf("parse instructions failed: %v", err)
	}

	return container, restInstructions, nil
}

func encryptStream(cipherKeyCrc uint64, cipherKey, data []byte) ([]byte, error) {
	enc := make([]byte, 16+len(data))

	// we are using encrypted crc as part of iv to not let data bruteforce by 3rd party,
	// and reduce message size in the same time
	binary.LittleEndian.PutUint64(enc, crc64.Checksum(data, crcTable)^cipherKeyCrc)
	if _, err := rand.Read(enc[8:16]); err != nil {
		return nil, err
	}

	pl := enc[16:]
	copy(pl, data)

	// binary.LittleEndian.PutUint64(iv, checksum)
	// binary.LittleEndian.PutUint64(iv[8:], crc64.Checksum(cipherKey, crcTable))

	// we build cipher based on shared key of tunnel+node and checksum of decrypted packet
	// checksum is needed here to randomize cipher to make it not repeatable if underlying data is similar
	// checksum always changes because of underlying packet "random" field of InstructionsContainer changes
	crypt, err := adnl.NewCipherCtr(cipherKey, enc[:16])
	if err != nil {
		return nil, fmt.Errorf("new cipher calc failed: %v", err)
	}
	crypt.XORKeyStream(pl, pl)

	return enc, nil
}

func decryptStream(cipherKeyCrc uint64, cipherKey, data []byte) ([]byte, error) {
	if len(data) <= 16 {
		return nil, fmt.Errorf("corrupted data, len %d", len(data))
	}
	pl := data[16:]

	crypt, err := adnl.NewCipherCtr(cipherKey, data[:16])
	if err != nil {
		return nil, fmt.Errorf("new cipher calc failed: %v", err)
	}
	crypt.XORKeyStream(pl, pl)

	crc := crc64.Checksum(pl, crcTable) ^ cipherKeyCrc
	if binary.LittleEndian.Uint64(data[:8]) != crc {
		return nil, fmt.Errorf("corrupted data, checksum not match")
	}

	return pl, nil
}

func (g *Gateway) closePaymentChannel(ch *PaymentChannel) error {
	ch.mx.Lock()
	defer ch.mx.Unlock()

	if !ch.Active {
		return nil
	}

	// we mark it as inactive in any way, because it is complicated to handle closure errors and they are very unlikely
	ch.Active = false

	if ch.LatestState == nil {
		return nil
	}

	log.Info().Str("amount", ch.LatestState.Amount.String()).
		Str("key", base64.StdEncoding.EncodeToString(ch.Key)).Msg("closing payment channel")
	if err := g.payments.Service.CloseVirtualChannel(context.Background(), ch.Key); err != nil {
		g.log.Warn().Err(err).Hex("key", ch.Key).Msg("failed to close virtual payment channel")
	}
	return nil
}

func (s *Section) closeIfNotLocked() bool {
	if !s.mx.TryLock() {
		return false
	}
	defer s.mx.Unlock()

	for _, ch := range s.payments {
		_ = s.gw.closePaymentChannel(ch)
	}

	for _, r := range s.routes {
		r.Close()
	}

	if s.out != nil {
		s.log.Debug().Msg("closing out port")
		s.out.Close()
	}
	s.log.Debug().Msg("section closed")

	metrics.ActiveInboundSections.Dec()

	return true
}
