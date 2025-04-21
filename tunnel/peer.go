package tunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/tl"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type connAtomic struct {
	addr string
	conn adnl.Peer
}

type Peer struct {
	id         []byte
	conn       unsafe.Pointer
	pingSeqno  uint64
	references int64
	gw         *Gateway

	CreatedAt        int64
	DiscoveredAt     int64
	LastPacketFromAt int64
	LastPacketToAt   int64

	wantDiscoverAt     int64
	discoverInProgress int32

	closerCtx context.Context
	closer    context.CancelFunc
	mx        sync.Mutex
}

func (g *Gateway) addPeer(id []byte, conn adnl.Peer) *Peer {
	g.mx.Lock()
	peer := g.activePeers[string(id)]
	if peer == nil {
		ctx, closer := context.WithCancel(g.closerCtx)
		peer = &Peer{
			id:               id,
			gw:               g,
			LastPacketFromAt: time.Now().Unix(),
			CreatedAt:        time.Now().Unix(),
			LastPacketToAt:   0,
			closerCtx:        ctx,
			closer:           closer,
		}
		g.activePeers[string(id)] = peer
		log.Debug().Str("peer", base64.StdEncoding.EncodeToString(id)).Msg("new peer connected")
	}
	g.mx.Unlock()

	peer.mx.Lock()
	if conn != nil {
		conn.SetCustomMessageHandler(g.messageHandler(peer))
		atomic.StorePointer(&peer.conn, unsafe.Pointer(&connAtomic{conn: conn, addr: conn.RemoteAddr()}))
	} else {
		atomic.StoreInt64(&peer.wantDiscoverAt, time.Now().Unix())
	}
	peer.mx.Unlock()

	return peer
}

func (p *Peer) discover(ctx context.Context) error {
	if p.getConn() != nil {
		return nil
	}

	if atomic.CompareAndSwapInt32(&p.discoverInProgress, 0, 1) {
		defer atomic.StoreInt32(&p.discoverInProgress, 0)
	} else {
		return nil
	}

	addresses, key, err := p.gw.dht.FindAddresses(ctx, p.id)
	if err != nil {
		return fmt.Errorf("find peer addresses failed: %w", err)
	}

	if len(addresses.Addresses) == 0 {
		return fmt.Errorf("find peer addresses failed: empty address list")
	}

	addr := addresses.Addresses[0].IP.String() + ":" + fmt.Sprint(uint16(addresses.Addresses[0].Port))
	conn, err := p.gw.gate.RegisterClient(addr, key)
	if err != nil {
		return fmt.Errorf("register peer failed: %w", err)
	}
	conn.Reinit()

	conn.SetCustomMessageHandler(p.gw.messageHandler(p))
	atomic.StorePointer(&p.conn, unsafe.Pointer(&connAtomic{conn: conn, addr: conn.RemoteAddr()}))
	atomic.StoreInt64(&p.DiscoveredAt, time.Now().Unix())
	// TODO: ping?

	log.Info().Str("id", base64.StdEncoding.EncodeToString(p.id)).Str("addr", conn.RemoteAddr()).Msg("peer discovered")

	return nil
}

func (p *Peer) getConn() adnl.Peer {
	c := (*connAtomic)(atomic.LoadPointer(&p.conn))
	if c == nil {
		return nil
	}
	return c.conn
}

func (p *Peer) getAddr() string {
	c := (*connAtomic)(atomic.LoadPointer(&p.conn))
	if c == nil {
		return "empty"
	}
	return c.addr
}

func (p *Peer) closeConn(cmp adnl.Peer) {
	conn := p.getConn()
	if conn != nil && (cmp == nil || conn == cmp) {
		conn.Close()
		atomic.StorePointer(&p.conn, nil)
	}
}

func (p *Peer) AddReference() {
	atomic.AddInt64(&p.references, 1)
}

func (p *Peer) kill() {
	p.closeConn(nil)

	p.gw.mx.Lock()
	delete(p.gw.activePeers, string(p.id))
	p.gw.mx.Unlock()
	p.closer()

	p.gw.log.Debug().Str("id", base64.StdEncoding.EncodeToString(p.id)).Msg("killed peer")
}

func (p *Peer) Dereference() {
	remove := false
	p.mx.Lock()
	if atomic.AddInt64(&p.references, -1) <= 0 {
		p.closeConn(nil)
		remove = true
	}
	p.mx.Unlock()

	if remove {
		p.gw.mx.Lock()
		delete(p.gw.activePeers, string(p.id))
		p.gw.mx.Unlock()
		p.closer()

		p.gw.log.Debug().Str("id", base64.StdEncoding.EncodeToString(p.id)).Msg("removed peer, no references left")
	}
}

func (p *Peer) SendCustomMessage(ctx context.Context, req tl.Serializable) error {
	conn := p.getConn()
	if conn == nil {
		atomic.StoreInt64(&p.wantDiscoverAt, time.Now().Unix())
		return fmt.Errorf("peer is not connected")
	}

	atomic.StoreInt64(&p.LastPacketToAt, time.Now().Unix())
	return conn.SendCustomMessage(ctx, req)
}
