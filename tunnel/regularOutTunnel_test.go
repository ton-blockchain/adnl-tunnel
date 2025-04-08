package tunnel

import (
	"crypto/ed25519"
	"math/big"
	"testing"
	"time"
)

func TestBuildTunnelPaymentsChain(t *testing.T) {
	publicKey1 := make([]byte, ed25519.PublicKeySize)
	publicKey2 := make([]byte, ed25519.PublicKeySize)
	publicKey3 := make([]byte, ed25519.PublicKeySize)
	publicKey4 := make([]byte, ed25519.PublicKeySize)
	section1 := PaymentTunnelSection{
		Key:         publicKey1,
		MinFee:      big.NewInt(10),
		PercentFee:  big.NewFloat(10), // 10%
		MaxCapacity: big.NewInt(120),
	}
	section2 := PaymentTunnelSection{
		Key:         publicKey2,
		MinFee:      big.NewInt(5),
		PercentFee:  big.NewFloat(20), // 20%
		MaxCapacity: big.NewInt(100),
	}
	section3 := PaymentTunnelSection{
		Key:         publicKey3,
		MinFee:      big.NewInt(1),
		PercentFee:  big.NewFloat(0.05),
		MaxCapacity: big.NewInt(50),
	}
	section4 := PaymentTunnelSection{
		Key:         publicKey4,
		MinFee:      big.NewInt(0),
		PercentFee:  big.NewFloat(0),
		MaxCapacity: big.NewInt(100),
	}
	paymentTunnel := []PaymentTunnelSection{section1, section2, section3, section4}
	initialCapacity := big.NewInt(80)
	initialDeadline := time.Now().Add(30 * time.Minute).Add(4 * 30 * time.Second).Truncate(time.Second)

	tunnel := &RegularOutTunnel{}
	chain, err := tunnel.buildTunnelPaymentsChain(paymentTunnel, initialCapacity, 30*time.Minute, 30*time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(chain) != 4 {
		t.Fatalf("Expected chain length 3, got %d", len(chain))
	}

	expectedFee1 := big.NewInt(10)
	expectedFee2 := big.NewInt(10)
	expectedFee3 := big.NewInt(1)
	expectedFee4 := big.NewInt(0)
	expectedCap1 := big.NewInt(61)
	expectedCap2 := big.NewInt(51)
	expectedCap3 := big.NewInt(50)
	expectedCap4 := big.NewInt(50)

	if chain[0].Fee.Cmp(expectedFee1) != 0 {
		t.Errorf("Section1: expected fee %v, got %v", expectedFee1, chain[0].Fee)
	}
	if chain[1].Fee.Cmp(expectedFee2) != 0 {
		t.Errorf("Section2: expected fee %v, got %v", expectedFee2, chain[1].Fee)
	}
	if chain[2].Fee.Cmp(expectedFee3) != 0 {
		t.Errorf("Section3: expected fee %v, got %v", expectedFee3, chain[2].Fee)
	}
	if chain[3].Fee.Cmp(expectedFee4) != 0 {
		t.Errorf("Section4: expected fee %v, got %v", expectedFee4, chain[3].Fee)
	}
	if chain[0].Capacity.Cmp(expectedCap1) != 0 {
		t.Errorf("Section1: expected capacity %v, got %v", expectedCap1, chain[0].Capacity)
	}
	if chain[1].Capacity.Cmp(expectedCap2) != 0 {
		t.Errorf("Section2: expected capacity %v, got %v", expectedCap2, chain[1].Capacity)
	}
	if chain[2].Capacity.Cmp(expectedCap3) != 0 {
		t.Errorf("Section3: expected capacity %v, got %v", expectedCap3, chain[2].Capacity)
	}
	if chain[3].Capacity.Cmp(expectedCap4) != 0 {
		t.Errorf("Section4: expected capacity %v, got %v", expectedCap4, chain[3].Capacity)
	}
	if !chain[0].Deadline.Truncate(time.Second).Equal(initialDeadline) {
		t.Errorf("Section1: expected deadline %v, got %v", initialDeadline, chain[0].Deadline)
	}
	expectedDeadline2 := initialDeadline.Add(-30 * time.Second)
	if !chain[1].Deadline.Truncate(time.Second).Equal(expectedDeadline2) {
		t.Errorf("Section2: expected deadline %v, got %v", expectedDeadline2, chain[1].Deadline)
	}
	expectedDeadline3 := expectedDeadline2.Add(-30 * time.Second)
	if !chain[2].Deadline.Truncate(time.Second).Equal(expectedDeadline3) {
		t.Errorf("Section3: expected deadline %v, got %v", expectedDeadline3, chain[2].Deadline)
	}
	expectedDeadline4 := expectedDeadline3.Add(-30 * time.Second)
	if !chain[3].Deadline.Truncate(time.Second).Equal(expectedDeadline4) {
		t.Errorf("Section4: expected deadline %v, got %v", expectedDeadline4, chain[3].Deadline)
	}
}
