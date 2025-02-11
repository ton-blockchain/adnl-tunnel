package tunnel

import (
	"crypto/ed25519"
	"encoding/hex"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/tl"
	"hash/crc64"
	"reflect"
	"testing"
)

func TestGateway_encryptMessage(t1 *testing.T) {
	_, tun1Prv, _ := ed25519.GenerateKey(nil)
	_, tun2Prv, _ := ed25519.GenerateKey(nil)
	_, tun3Prv, _ := ed25519.GenerateKey(nil)

	gate1Pub, gate1Prv, _ := ed25519.GenerateKey(nil)
	gate2Pub, gate2Prv, _ := ed25519.GenerateKey(nil)
	gate3Pub, gate3Prv, _ := ed25519.GenerateKey(nil)

	sh1, _ := adnl.SharedKey(gate1Prv, tun1Prv.Public().(ed25519.PublicKey))
	s1 := &Section{
		cipherKey:    sh1,
		cipherKeyCrc: crc64.Checksum(sh1, crcTable),
	}

	sh2, _ := adnl.SharedKey(gate2Prv, tun2Prv.Public().(ed25519.PublicKey))
	s2 := &Section{
		cipherKey:    sh2,
		cipherKeyCrc: crc64.Checksum(sh2, crcTable),
	}

	sh3, _ := adnl.SharedKey(gate3Prv, tun3Prv.Public().(ed25519.PublicKey))
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

	println(c.Rand, reflect.TypeOf(c.List[0]).String())

	c2, rest, err := s2.decryptMessage(msg)
	if err != nil {
		t1.Fatalf("2 decryptMessage() error = %v", err)
	}

	msg.Instructions = rest
	msg.SectionPubKey = c2.List[0].(*BuildRouteInstruction).TargetSectionPubKey

	println(c2.Rand, reflect.TypeOf(c2.List[0]).String())

	c3, _, err := s3.decryptMessage(msg)
	if err != nil {
		t1.Fatalf("3 decryptMessage() error = %v", err)
	}

	println(c3.Rand, reflect.TypeOf(c3.List[0]).String())
}
