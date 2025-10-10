package secure

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func handshakePair(t *testing.T, pwA, pwB string) (ka, kb []byte, ea, eb error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		ka, ea = Handshake(a, []byte(pwA), true)
		if ea != nil {
			a.Close()
		}
		close(done)
	}()
	kb, eb = Handshake(b, []byte(pwB), false)
	if eb != nil {
		b.Close()
	}
	<-done
	return
}

func TestHandshakeAgrees(t *testing.T) {
	ka, kb, ea, eb := handshakePair(t, "1234-lamp-gold-lake", "1234-lamp-gold-lake")
	if ea != nil || eb != nil || !bytes.Equal(ka, kb) || len(ka) != 32 {
		t.Fatalf("keys differ or errors: %v %v", ea, eb)
	}
	if bytes.Equal(DeriveKey(ka, "session"), DeriveKey(ka, "direct")) {
		t.Fatal("derived keys must differ per purpose")
	}
}

func TestWrongCode(t *testing.T) {
	_, _, ea, eb := handshakePair(t, "1234-lamp-gold-lake", "1234-lamp-gold-iron")
	if !errors.Is(ea, ErrWrongCode) || !errors.Is(eb, ErrWrongCode) {
		t.Fatalf("want ErrWrongCode on both sides, got %v / %v", ea, eb)
	}
}

func TestConnRoundTripAndTamper(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	var wire bytes.Buffer
	s, _ := NewConn(&wire, key, true)
	for _, m := range []string{"hello", "", "world"} {
		if err := s.Send([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	raw := append([]byte(nil), wire.Bytes()...)

	r, _ := NewConn(bytes.NewBuffer(raw), key, false)
	for _, want := range []string{"hello", "", "world"} {
		got, err := r.Recv()
		if err != nil || string(got) != want {
			t.Fatalf("got %q, %v", got, err)
		}
	}

	flipped := append([]byte(nil), raw...)
	flipped[6] ^= 1 // inside the first ciphertext
	r, _ = NewConn(bytes.NewBuffer(flipped), key, false)
	if _, err := r.Recv(); !errors.Is(err, ErrTampered) {
		t.Fatalf("flipped bit: %v", err)
	}

	// Dropping the first frame breaks the nonce sequence.
	first := 4 + int(raw[3])
	r, _ = NewConn(bytes.NewBuffer(raw[first:]), key, false)
	if _, err := r.Recv(); !errors.Is(err, ErrTampered) {
		t.Fatalf("dropped frame: %v", err)
	}

	// A message sent by the receiver can't be reflected back to it.
	var back bytes.Buffer
	rc, _ := NewConn(&back, key, false)
	rc.Send([]byte("from receiver"))
	r2, _ := NewConn(&back, key, false)
	if _, err := r2.Recv(); !errors.Is(err, ErrTampered) {
		t.Fatalf("reflected frame: %v", err)
	}
}

func TestMalformedPAKEMessage(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		readFrame(a, 1<<16)
		writeFrame(a, []byte(`{"Role":1}`)) // no points at all
		a.Close()
	}()
	if _, err := Handshake(b, []byte("x"), true); err == nil {
		t.Fatal("accepted a malformed PAKE message")
	}
}
