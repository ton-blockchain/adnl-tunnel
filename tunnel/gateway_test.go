package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"

	"github.com/rs/zerolog"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
	"hash/crc64"
	"reflect"
	"testing"
	"time"
)

func TestGateway_encryptMessage(t1 *testing.T) {
	_, tun1Prv, _ := ed25519.GenerateKey(nil)
	_, tun2Prv, _ := ed25519.GenerateKey(nil)
	_, tun3Prv, _ := ed25519.GenerateKey(nil)

	gate1Pub, gate1Prv, _ := ed25519.GenerateKey(nil)
	gate2Pub, gate2Prv, _ := ed25519.GenerateKey(nil)
	gate3Pub, gate3Prv, _ := ed25519.GenerateKey(nil)

	sh1, _ := keys.SharedKey(gate1Prv, tun1Prv.Public().(ed25519.PublicKey))
	s1 := &Section{
		cipherKey:    sh1,
		cipherKeyCrc: crc64.Checksum(sh1, crcTable),
	}

	sh2, _ := keys.SharedKey(gate2Prv, tun2Prv.Public().(ed25519.PublicKey))
	s2 := &Section{
		cipherKey:    sh2,
		cipherKeyCrc: crc64.Checksum(sh2, crcTable),
	}

	sh3, _ := keys.SharedKey(gate3Prv, tun3Prv.Public().(ed25519.PublicKey))
	s3 := &Section{
		cipherKey:    sh3,
		cipherKeyCrc: crc64.Checksum(sh3, crcTable),
	}

	k3, _ := NewEncryptionKeys(tun3Prv, gate3Pub)
	k2, _ := NewEncryptionKeys(tun2Prv, gate2Pub)
	k1, _ := NewEncryptionKeys(tun1Prv, gate1Pub)

	msg := &EncryptedMessage{}
	if err := k3.EncryptInstructionsMessage(msg, SendOutInstruction{}); err != nil {
		t1.Fatalf("3 encryptMessage() error = %v", err)
	}

	if err := k2.EncryptInstructionsMessage(msg, BuildRouteInstruction{
		TargetADNL:          make([]byte, 32),
		TargetSectionPubKey: k3.SectionPubKey,
		RouteID:             1,
	}, RouteInstruction{RouteID: 1}); err != nil {
		t1.Fatalf("2 encryptMessage() error = %v", err)
	}

	if err := k1.EncryptInstructionsMessage(msg, BuildRouteInstruction{
		TargetADNL:          make([]byte, 32),
		TargetSectionPubKey: k2.SectionPubKey,
		RouteID:             1,
	}, RouteInstruction{RouteID: 1}); err != nil {
		t1.Fatalf("1 encryptMessage() error = %v", err)
	}

	b, _ := tl.Serialize(msg, true)
	println(len(b), hex.EncodeToString(b))

	c, rest, err := s1.decryptMessage(msg)
	if err != nil {
		t1.Fatalf("1 decryptMessage() error = %v", err)
	}

	msg.Instructions = rest
	msg.SectionPubKey = c.List[0].(*BuildRouteInstruction).TargetSectionPubKey

	println(c.Seqno, reflect.TypeOf(c.List[0]).String())

	c2, rest, err := s2.decryptMessage(msg)
	if err != nil {
		t1.Fatalf("2 decryptMessage() error = %v", err)
	}

	msg.Instructions = rest
	msg.SectionPubKey = c2.List[0].(*BuildRouteInstruction).TargetSectionPubKey

	println(c2.Seqno, reflect.TypeOf(c2.List[0]).String())

	c3, _, err := s3.decryptMessage(msg)
	if err != nil {
		t1.Fatalf("3 decryptMessage() error = %v", err)
	}

	println(c3.Seqno, reflect.TypeOf(c3.List[0]).String())
}

func TestCheckSeqno(t *testing.T) {
	var s Section

	// Test 1: The first sequence number should be accepted.
	if !s.checkSeqno(1000, false) {
		t.Error("Expected to accept seqno 1000 as the first number")
	}

	// Test 2: Repeating the same number should return false.
	if s.checkSeqno(1000, false) {
		t.Error("Expected to reject duplicate seqno 1000")
	}

	// Test 3: A sequential number greater than the previous one.
	if !s.checkSeqno(1001, false) {
		t.Error("Expected to accept seqno 1001")
	}

	// Test 4: Repeating an already received older number (1000) should return false.
	if s.checkSeqno(1000, false) {
		t.Error("Expected to reject duplicate seqno 1000 (already received)")
	}

	// Test 5: Receiving an older number that has not been marked.
	// With 100 and 101 received, seqno 99 (diff = 2) is not yet marked, so it should be accepted.
	if !s.checkSeqno(999, false) {
		t.Error("Expected to accept seqno 999 (not yet received)")
	}

	// Test 6: Number outside the window.
	// With current lastSeqno == 101, seqno 37 (diff = 64) is outside the window.
	if s.checkSeqno(37, false) {
		t.Error("Expected to reject seqno 37 as it is outside the window")
	}

	// Test 7: Large jump forward.
	// When transitioning from 101 to 200, the window is reset.
	if !s.checkSeqno(2000, false) {
		t.Error("Expected to accept seqno 2000 (new number, window reset)")
	}
	// Repeating seqno 200 should return false.
	if s.checkSeqno(2000, false) {
		t.Error("Expected to reject duplicate seqno 2000")
	}

	// Test 8: Receiving numbers in increasing order and checking for duplicates.
	if !s.checkSeqno(2001, false) {
		t.Error("Expected to accept seqno 2001")
	}
	if !s.checkSeqno(2002, false) {
		t.Error("Expected to accept seqno 2002")
	}
	// Repeating seqno 201 should return false.
	if s.checkSeqno(2001, false) {
		t.Error("Expected to reject duplicate seqno 201")
	}

	// Test 9: Handling uint32 overflow.
	// Simulate a situation where lastSeqno is near the maximum value.
	s = Section{
		seqno: SeqnoWindow{
			latest: 0xFFFFFFF0,
			window: [8]uint64{1 << 63, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	// In case of overflow, a new small seqno (e.g., 10) should be accepted.
	if !s.checkSeqno(10, false) {
		t.Error("Expected to accept seqno 10 during uint32 overflow")
	}
}

func TestGatewayRejectsInvalidUnknownSectionWithoutAdmission(t *testing.T) {
	g, peer := newTestGatewayWithPeer(t)
	msg := EncryptedMessage{
		SectionPubKey: make([]byte, 32),
		Instructions:  make([]byte, 64),
	}
	if _, err := rand.Read(msg.SectionPubKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(msg.Instructions); err != nil {
		t.Fatal(err)
	}

	err := g.messageHandler(peer)(&adnl.MessageCustom{Data: msg})
	if err == nil {
		t.Fatal("expected invalid encrypted message to be rejected")
	}
	if len(g.inboundSections) != 0 {
		t.Fatalf("invalid unknown section was admitted: %d", len(g.inboundSections))
	}
	if len(g.sectionsByPeer) != 0 {
		t.Fatalf("invalid unknown section affected peer counters: %d", len(g.sectionsByPeer))
	}
}

func TestGatewayInboundSectionPerPeerCap(t *testing.T) {
	g, peer := newTestGatewayWithPeer(t)
	oldMax, oldTTL := MaxInboundSectionsPerPeer, InboundSectionPendingTTL
	MaxInboundSectionsPerPeer = 1
	InboundSectionPendingTTL = time.Hour
	defer func() {
		MaxInboundSectionsPerPeer = oldMax
		InboundSectionPendingTTL = oldTTL
	}()

	handler := g.messageHandler(peer)
	if err := handler(&adnl.MessageCustom{Data: newBuildRouteMessage(t, g, 1)}); err != nil {
		t.Fatalf("first valid section should be admitted: %v", err)
	}
	err := handler(&adnl.MessageCustom{Data: newBuildRouteMessage(t, g, 2)})
	if err == nil || !strings.Contains(err.Error(), "too many inbound sections for peer") {
		t.Fatalf("expected per-peer cap error, got %v", err)
	}
	if len(g.inboundSections) != 1 {
		t.Fatalf("unexpected admitted sections count: %d", len(g.inboundSections))
	}
}

func TestGatewayEvictsPendingSectionForValidAdmission(t *testing.T) {
	g, peer := newTestGatewayWithPeer(t)
	oldMax, oldTTL := MaxInboundSectionsPerPeer, InboundSectionPendingTTL
	MaxInboundSectionsPerPeer = 1
	InboundSectionPendingTTL = time.Hour
	defer func() {
		MaxInboundSectionsPerPeer = oldMax
		InboundSectionPendingTTL = oldTTL
	}()

	pendingKey := make([]byte, 32)
	if _, err := rand.Read(pendingKey); err != nil {
		t.Fatal(err)
	}
	pendingID, err := key32("pending section", pendingKey)
	if err != nil {
		t.Fatal(err)
	}
	ownerPeer, err := key32("peer id", peer.id)
	if err != nil {
		t.Fatal(err)
	}
	pending := &Section{
		gw:           g,
		key:          pendingKey,
		keyID:        pendingID,
		lastPacketAt: time.Now().Unix(),
		admittedAt:   time.Now().Unix(),
		ownerPeer:    ownerPeer,
		log:          g.log,
	}
	if _, inserted, err := g.admitInboundSection(pending); err != nil || !inserted {
		t.Fatalf("pending section setup failed, inserted=%v err=%v", inserted, err)
	}

	if err := g.messageHandler(peer)(&adnl.MessageCustom{Data: newBuildRouteMessage(t, g, 1)}); err != nil {
		t.Fatalf("valid section should evict pending slot: %v", err)
	}
	if len(g.inboundSections) != 1 {
		t.Fatalf("unexpected admitted sections count: %d", len(g.inboundSections))
	}
	if g.inboundSections[pendingID] != nil {
		t.Fatal("pending section was not evicted")
	}
}

func newTestGatewayWithPeer(t *testing.T) (*Gateway, *Peer) {
	t.Helper()
	_, prv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(nil, nil, prv, zerolog.New(io.Discard), PaymentConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	peerID := make([]byte, 32)
	if _, err := rand.Read(peerID); err != nil {
		t.Fatal(err)
	}
	return g, &Peer{
		id:        peerID,
		gw:        g,
		CreatedAt: time.Now().Unix(),
		closerCtx: ctx,
		closer:    cancel,
	}
}

func newBuildRouteMessage(t *testing.T, g *Gateway, routeID uint32) EncryptedMessage {
	t.Helper()
	k, err := GenerateEncryptionKeys(g.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	targetADNL := make([]byte, 32)
	if _, err := rand.Read(targetADNL); err != nil {
		t.Fatal(err)
	}
	targetSection := make([]byte, 32)
	if _, err := rand.Read(targetSection); err != nil {
		t.Fatal(err)
	}
	msg := EncryptedMessage{}
	if err := k.EncryptInstructionsMessage(&msg, BuildRouteInstruction{
		TargetADNL:          targetADNL,
		TargetSectionPubKey: targetSection,
		RouteID:             routeID,
	}); err != nil {
		t.Fatal(err)
	}
	return msg
}

func BenchmarkSeqnoCheck(b *testing.B) {
	var s Section

	for i := 0; i < b.N; i++ {
		s.checkSeqno(uint32(i)-uint32(i)%5, false)
	}
}
