package tunnel

import (
	"bytes"
	"testing"

	"github.com/xssnick/tonutils-go/tl"
)

func TestPayloadCodecsRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{
		nil,
		[]byte("abc"),
		bytes.Repeat([]byte{0xAA}, 254),
	} {
		send := SendOutPayload{Seqno: 11, IP: []byte{127, 0, 0, 1}, Port: 1234, Payload: payload}
		var gotSend SendOutPayload
		roundTripTL(t, send, &gotSend)
		if gotSend.Seqno != send.Seqno || gotSend.Port != send.Port ||
			!bytes.Equal(gotSend.IP, send.IP) || !bytes.Equal(gotSend.Payload, send.Payload) {
			t.Fatalf("send out payload mismatch: got %+v want %+v", gotSend, send)
		}

		deliver := DeliverUDPPayload{Seqno: 22, IP: []byte{1, 2, 3, 4}, Port: 4321, Payload: payload}
		var gotDeliver DeliverUDPPayload
		roundTripTL(t, deliver, &gotDeliver)
		if gotDeliver.Seqno != deliver.Seqno || gotDeliver.Port != deliver.Port ||
			!bytes.Equal(gotDeliver.IP, deliver.IP) || !bytes.Equal(gotDeliver.Payload, deliver.Payload) {
			t.Fatalf("deliver udp payload mismatch: got %+v want %+v", gotDeliver, deliver)
		}
	}

	bind := OutBindDonePayload{Seqno: 33, IP: []byte{10, 0, 0, 1}, Port: 9999}
	var gotBind OutBindDonePayload
	roundTripTL(t, bind, &gotBind)
	if gotBind.Seqno != bind.Seqno || gotBind.Port != bind.Port || !bytes.Equal(gotBind.IP, bind.IP) {
		t.Fatalf("out bind done payload mismatch: got %+v want %+v", gotBind, bind)
	}
}

func roundTripTL(t *testing.T, src, dst tl.Serializable) {
	t.Helper()
	data, err := tl.Serialize(src, true)
	if err != nil {
		t.Fatal(err)
	}
	rest, err := tl.Parse(dst, data, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected rest after parse: %d bytes", len(rest))
	}
}
