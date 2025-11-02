package relay

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func start(t *testing.T, s *Server) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return ln.Addr().String()
}

const room = "0123456789abcdef0123456789abcdef"

func join(t *testing.T, addr, role string) (net.Conn, chan Reply) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	WriteJSON(c, Hello{Room: room, Role: role})
	ch := make(chan Reply, 1)
	go func() {
		var r Reply
		ReadJSON(c, &r)
		ch <- r
	}()
	return c, ch
}

func TestPairAndPipe(t *testing.T) {
	s := &Server{}
	addr := start(t, s)
	a, ra := join(t, addr, "send")
	time.Sleep(150 * time.Millisecond) // a is waiting
	b, rb := join(t, addr, "recv")
	if r := <-ra; !r.OK {
		t.Fatalf("sender: %+v", r)
	}
	if r := <-rb; !r.OK {
		t.Fatalf("receiver: %+v", r)
	}
	a.Write([]byte("ping"))
	buf := make([]byte, 4)
	io.ReadFull(b, buf)
	b.Write([]byte("pong"))
	io.ReadFull(a, buf[:4])
	if string(buf) != "pong" {
		t.Fatalf("got %q", buf)
	}
	a.Close()
	if _, err := b.Read(buf); err == nil {
		t.Fatal("close was not propagated")
	}
}

func TestSameRoleRejectedAndAbandonedRoomFreed(t *testing.T) {
	s := &Server{}
	addr := start(t, s)
	a, _ := join(t, addr, "send")
	time.Sleep(150 * time.Millisecond)
	_, r2 := join(t, addr, "send")
	if r := <-r2; !strings.Contains(r.Error, "already has") {
		t.Fatalf("second sender: %+v", r)
	}
	a.Close() // the waiting sender gives up
	time.Sleep(300 * time.Millisecond)
	_, r3 := join(t, addr, "send")
	select {
	case r := <-r3:
		t.Fatalf("room should be free and the new sender waiting, got %+v", r)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBadHelloAndTimeout(t *testing.T) {
	s := &Server{WaitTimeout: 200 * time.Millisecond}
	addr := start(t, s)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	WriteJSON(c, Hello{Room: "../../etc", Role: "send"})
	var r Reply
	ReadJSON(c, &r)
	if r.Error == "" {
		t.Fatal("bad room accepted")
	}
	_, rw := join(t, addr, "recv")
	select {
	case r := <-rw:
		if !strings.Contains(r.Error, "in time") {
			t.Fatalf("got %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting client never timed out")
	}
}
