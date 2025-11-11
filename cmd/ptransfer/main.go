// Command ptransfer sends files and folders between two computers using a
// short code phrase.
//
//	ptransfer relay   [-addr :9009]
//	ptransfer send    [-relay host:9009] [-code ...] [-no-direct] PATH...
//	ptransfer receive [-relay host:9009] [-out DIR] [-overwrite] [-no-direct] CODE
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/AbdeldjalilChougui/ptransfer/relay"
	"github.com/AbdeldjalilChougui/ptransfer/transfer"
)

const defaultRelay = "127.0.0.1:9009"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	switch os.Args[1] {
	case "relay":
		err = runRelay(ctx, os.Args[2:])
	case "send":
		err = runSend(ctx, os.Args[2:])
	case "receive", "recv":
		err = runReceive(ctx, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "\ninterrupted; run the same command again to resume")
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "\nerror:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  ptransfer relay   [-addr 127.0.0.1:9009]
  ptransfer send    [-relay host:port] [-code CODE] [-no-direct] PATH...
  ptransfer receive [-relay host:port] [-out DIR] [-overwrite] [-no-direct] CODE

The relay address can also come from $PTRANSFER_RELAY.`)
	os.Exit(2)
}

func relayFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("PTRANSFER_RELAY")
	if def == "" {
		def = defaultRelay
	}
	return fs.String("relay", def, "relay address")
}

func runRelay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	addr := fs.String("addr", defaultRelay, "listen address")
	fs.Parse(args)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	s := &relay.Server{}
	go func() { <-ctx.Done(); s.Close() }()
	log.Printf("relay listening on %s", ln.Addr())
	return s.Serve(ln)
}

func runSend(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	rel := relayFlag(fs)
	codeFlag := fs.String("code", "", "use this code instead of a random one")
	noDirect := fs.Bool("no-direct", false, "always go through the relay")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("send: name at least one file or folder")
	}
	bar := newBar("sending")
	res, err := transfer.Send(ctx, fs.Args(), transfer.Options{
		Relay: *rel, Code: *codeFlag, Direct: !*noDirect,
		OnCode: func(c string) {
			fmt.Fprintf(os.Stderr, "Code: %s\nOn the other computer run:\n  ptransfer receive -relay %s %s\n", c, *rel, c)
		},
		Progress: bar.update,
	})
	bar.finish()
	if err != nil {
		return err
	}
	report(res)
	return nil
}

func runReceive(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	rel := relayFlag(fs)
	out := fs.String("out", ".", "directory to save into")
	overwrite := fs.Bool("overwrite", false, "replace existing files that differ")
	noDirect := fs.Bool("no-direct", false, "always go through the relay")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("receive: give the code")
	}
	bar := newBar("receiving")
	res, err := transfer.Receive(ctx, strings.Join(fs.Args(), "-"), transfer.Options{
		Relay: *rel, OutDir: *out, Overwrite: *overwrite, Direct: !*noDirect, Progress: bar.update,
	})
	bar.finish()
	if err != nil {
		return err
	}
	report(res)
	return nil
}

func report(res transfer.Result) {
	via := "relay"
	if res.Direct {
		via = "direct connection"
	}
	fmt.Fprintf(os.Stderr, "%d file(s), %s transferred, %s resumed, via %s\n",
		res.Files, human(res.Bytes), human(res.Resumed), via)
}

// bar is a single-line progress bar on stderr, redrawn at most 10x/s.
type bar struct {
	label string
	start time.Time
	mu    sync.Mutex
	last  time.Time
	p     transfer.Progress
	drawn bool
}

func newBar(label string) *bar { return &bar{label: label, start: time.Now()} }

func (b *bar) update(p transfer.Progress) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.p = p
	if time.Since(b.last) < 100*time.Millisecond && p.Done < p.Total {
		return
	}
	b.last = time.Now()
	b.draw()
}

func (b *bar) draw() {
	const width = 30
	frac := 1.0
	if b.p.Total > 0 {
		frac = float64(b.p.Done) / float64(b.p.Total)
	}
	n := int(frac * width)
	rate := float64(b.p.Done) / max(time.Since(b.start).Seconds(), 0.001)
	fmt.Fprintf(os.Stderr, "\r%s [%s%s] %5.1f%% %s/%s %s/s ", b.label,
		strings.Repeat("#", n), strings.Repeat(".", width-n), 100*frac, human(b.p.Done), human(b.p.Total), human(int64(rate)))
	b.drawn = true
}

func (b *bar) finish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.drawn {
		b.draw()
		fmt.Fprintln(os.Stderr)
	}
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
