package test_tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	tunnelpkg "github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/xssnick/tonutils-go/adnl"
	adnladdress "github.com/xssnick/tonutils-go/adnl/address"
)

type localTunnelNode struct {
	name          string
	tunnelGateway *tunnelpkg.Gateway
	adnlGateway   *adnl.Gateway
	key           ed25519.PrivateKey
	addr          string
}

func TestLoopbackTwoTunnelsTrafficAndEdgeCases(t *testing.T) {
	muteGlobalLogs(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	outNode, clientNode := startLoopbackTunnelNodes(t)
	echoAddr, closeEcho := startUDPEchoServer(t)
	t.Cleanup(closeEcho)

	tunA, extA := createLoopbackTunnel(t, ctx, clientNode, outNode)
	tunB, extB := createLoopbackTunnel(t, ctx, clientNode, outNode)
	stopTunA := cleanupTunnel(t, tunA)
	stopTunB := cleanupTunnel(t, tunB)

	if extA.Port == extB.Port {
		t.Fatalf("expected two independent out ports, both got %d", extA.Port)
	}

	assertRoundTrip(t, ctx, tunA, echoAddr, testPayload("alpha-through-tunnel-a"))
	assertRoundTrip(t, ctx, tunB, echoAddr, testPayload("bravo-through-tunnel-b"))

	for i := 0; i < 8; i++ {
		assertRoundTrip(t, ctx, tunA, echoAddr, testPayload(fmt.Sprintf("a-burst-%02d", i)))
		assertRoundTrip(t, ctx, tunB, echoAddr, testPayload(fmt.Sprintf("b-burst-%02d", i)))
	}

	if n, err := tunA.WriteTo(nil, echoAddr); err != nil || n != 0 {
		t.Fatalf("empty write = %d, %v; want 0, nil", n, err)
	}

	if _, err := tunA.WriteTo([]byte("bad-addr"), &net.TCPAddr{}); err == nil {
		t.Fatal("expected invalid address error")
	}

	if err := tunA.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	if _, _, err := tunA.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom deadline error = %v, want %v", err, os.ErrDeadlineExceeded)
	}
	if err := tunA.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	if err := tunA.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := tunA.WriteTo([]byte("past-write-deadline"), echoAddr); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("WriteTo deadline error = %v, want %v", err, os.ErrDeadlineExceeded)
	}
	if err := tunA.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := stopTunA(stopCtx); err != nil {
		t.Fatalf("stop tunnel A: %v", err)
	}
	if _, err := tunA.WriteTo([]byte("after-close"), echoAddr); err == nil {
		t.Fatal("expected write error after tunnel close")
	}

	assertRoundTrip(t, ctx, tunB, echoAddr, testPayload("tunnel-b-still-alive"))
	_ = stopTunB(stopCtx)
}

func TestLoopbackAsymmetricMultiHopTunnel(t *testing.T) {
	muteGlobalLogs(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	nodes := startLoopbackTunnelNodeSet(t, "client", "to1", "to2", "out", "from1", "from2", "from3")
	echoAddr, closeEcho := startUDPEchoServer(t)
	t.Cleanup(closeEcho)

	connectPath(t, nodes["client"], nodes["to1"], nodes["to2"], nodes["out"])
	connectPath(t, nodes["out"], nodes["from1"], nodes["from2"], nodes["from3"], nodes["client"])

	tun, ext := createLoopbackTunnelWithChains(t, ctx, nodes["client"], []*localTunnelNode{
		nodes["to1"],
		nodes["to2"],
		nodes["out"],
	}, []*localTunnelNode{
		nodes["from1"],
		nodes["from2"],
		nodes["from3"],
		nodes["client"],
	})
	stopTun := cleanupTunnel(t, tun)

	if ext.Port == 0 || !ext.IP.IsLoopback() {
		t.Fatalf("unexpected external tunnel address: %v", ext)
	}

	for i := 0; i < 12; i++ {
		assertRoundTrip(t, ctx, tun, echoAddr, testPayload(fmt.Sprintf("asymmetric-multihop-%02d", i)))
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	_ = stopTun(stopCtx)
}

func startLoopbackTunnelNodes(t *testing.T) (*localTunnelNode, *localTunnelNode) {
	t.Helper()

	nodes := startLoopbackTunnelNodeSet(t, "out", "client")
	connectADNL(t, nodes["client"], nodes["out"])
	return nodes["out"], nodes["client"]
}

func startLoopbackTunnelNodeSet(t *testing.T, names ...string) map[string]*localTunnelNode {
	t.Helper()

	logger := zerolog.New(io.Discard)
	nodes := make(map[string]*localTunnelNode, len(names))

	for _, name := range names {
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}

		addr := reserveUDPAddr(t)
		adnlGateway := adnl.NewGateway(key)
		if err = adnlGateway.StartServer("0.0.0.0:"+portOf(t, addr), 2); err != nil {
			t.Fatalf("start %s ADNL server: %v", name, err)
		}

		advertised, err := adnladdress.NewAddress(net.IPv4(127, 0, 0, 1), int32(portNum(t, addr)))
		if err != nil {
			t.Fatal(err)
		}
		adnlGateway.SetAddressList([]adnladdress.Address{advertised})

		nodes[name] = &localTunnelNode{
			name:          name,
			tunnelGateway: tunnelpkg.NewGateway(adnlGateway, nil, key, logger.With().Str("node", name).Logger(), tunnelpkg.PaymentConfig{}),
			adnlGateway:   adnlGateway,
			key:           key,
			addr:          addr,
		}
	}

	errCh := make(chan nodeStartResult, len(nodes))
	for _, node := range nodes {
		node := node
		go func() {
			errCh <- nodeStartResult{
				name: node.name,
				err:  node.tunnelGateway.Start(),
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)

	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, node := range nodes {
			_ = node.tunnelGateway.Stop(stopCtx)
		}
		for _, node := range nodes {
			_ = node.adnlGateway.Close()
		}

		deadline := time.After(3 * time.Second)
		for i := 0; i < len(nodes); i++ {
			select {
			case res := <-errCh:
				if res.err != nil && !errors.Is(res.err, context.Canceled) {
					t.Errorf("gateway %s stopped with error: %v", res.name, res.err)
				}
			case <-deadline:
				t.Errorf("timeout waiting for gateway shutdown")
				return
			}
		}
	})

	return nodes
}

type nodeStartResult struct {
	name string
	err  error
}

func muteGlobalLogs(t *testing.T) {
	t.Helper()

	prev := log.Logger
	log.Logger = zerolog.New(io.Discard)
	t.Cleanup(func() {
		log.Logger = prev
	})
}

func createLoopbackTunnel(t *testing.T, ctx context.Context, clientNode, outNode *localTunnelNode) (*tunnelpkg.RegularOutTunnel, *net.UDPAddr) {
	t.Helper()

	return createLoopbackTunnelWithChains(t, ctx, clientNode, []*localTunnelNode{outNode}, []*localTunnelNode{clientNode})
}

func createLoopbackTunnelWithChains(t *testing.T, ctx context.Context, clientNode *localTunnelNode, chainToNodes, chainFromNodes []*localTunnelNode) (*tunnelpkg.RegularOutTunnel, *net.UDPAddr) {
	t.Helper()

	chainTo := sectionInfosForNodes(t, chainToNodes)
	chainFrom := sectionInfosForNodes(t, chainFromNodes)

	tun, err := clientNode.tunnelGateway.CreateRegularOutTunnel(ctx, chainTo, chainFrom, zerolog.New(io.Discard))
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}

	ip, port, err := tun.WaitForInit(ctx, nil)
	if err != nil {
		_ = tun.Stop(context.Background())
		t.Fatalf("wait for tunnel init: %v", err)
	}
	if ip == nil || port == 0 {
		_ = tun.Stop(context.Background())
		t.Fatalf("invalid tunnel out address: %v:%d", ip, port)
	}

	return tun, &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: int(port)}
}

func sectionInfosForNodes(t *testing.T, nodes []*localTunnelNode) []*tunnelpkg.SectionInfo {
	t.Helper()

	sections := make([]*tunnelpkg.SectionInfo, 0, len(nodes))
	for _, node := range nodes {
		keys, err := tunnelpkg.GenerateEncryptionKeys(node.key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		sections = append(sections, &tunnelpkg.SectionInfo{Keys: keys})
	}
	return sections
}

func connectPath(t *testing.T, nodes ...*localTunnelNode) {
	t.Helper()

	for i := 0; i+1 < len(nodes); i++ {
		connectADNL(t, nodes[i], nodes[i+1])
	}
}

func connectADNL(t *testing.T, from, to *localTunnelNode) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := from.adnlGateway.RegisterClient(to.addr, to.key.Public().(ed25519.PublicKey)); err == nil {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("connect %s -> %s: %v", from.name, to.name, err)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

func cleanupTunnel(t *testing.T, tun *tunnelpkg.RegularOutTunnel) func(context.Context) error {
	t.Helper()

	var once sync.Once
	var stopErr error
	stop := func(ctx context.Context) error {
		once.Do(func() {
			stopErr = tun.Stop(ctx)
		})
		return stopErr
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = stop(ctx)
	})
	return stop
}

func testPayload(label string) []byte {
	payload := []byte(label + ":")
	for len(payload) < 96 {
		payload = append(payload, label...)
	}
	return payload[:96]
}

func assertRoundTrip(t *testing.T, ctx context.Context, tun *tunnelpkg.RegularOutTunnel, echoAddr *net.UDPAddr, payload []byte) {
	t.Helper()

	n, err := tun.WriteTo(payload, echoAddr)
	if err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	if n != len(payload) {
		t.Fatalf("write %q bytes = %d, want %d", payload, n, len(payload))
	}

	readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	buf := make([]byte, 2048)
	n, addr, err := tun.ReadFromWithTimeout(readCtx, buf)
	if err != nil {
		t.Fatalf("read response for %q: %v", payload, err)
	}

	want := append([]byte("echo:"), payload...)
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("response = %q, want %q", buf[:n], want)
	}

	gotUDP, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("response addr type = %T, want *net.UDPAddr", addr)
	}
	if !gotUDP.IP.Equal(echoAddr.IP) || gotUDP.Port != echoAddr.Port {
		t.Fatalf("response addr = %v, want %v", gotUDP, echoAddr)
	}
}

func startUDPEchoServer(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}

			resp := append([]byte("echo:"), buf[:n]...)
			_, _ = conn.WriteTo(resp, addr)
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr), func() {
		_ = conn.Close()
		<-done
	}
}

func reserveUDPAddr(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	return conn.LocalAddr().String()
}

func portOf(t *testing.T, addr string) string {
	t.Helper()

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func portNum(t *testing.T, addr string) int {
	t.Helper()

	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	return udpAddr.Port
}
