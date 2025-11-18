# ptransfer

[![Go Reference](https://pkg.go.dev/badge/github.com/AbdeldjalilChougui/ptransfer.svg)](https://pkg.go.dev/github.com/AbdeldjalilChougui/ptransfer)

Send files and folders between two computers with a short code phrase,
in the style of [croc](https://github.com/schollz/croc) and Magic
Wormhole. The sender gets a code like `4821-lamp-gold-lake`, the receiver
types it, and the files arrive encrypted end to end, through a relay or
directly over the LAN when possible.

## Who it's for

People who want to move a file between their own machines (or to a
friend) without accounts, cloud storage or setting up SSH, and who would
like to run their own relay. It's also a compact, readable example of how
a PAKE-based transfer tool is put together.

## Install

Prebuilt binaries for Linux, macOS and Windows (amd64 and arm64) are on the
[releases page](https://github.com/AbdeldjalilChougui/ptransfer/releases/latest).
Each archive contains the `ptransfer` binary, the README and the license; `checksums.txt`
has the SHA-256 sums. For example, on Linux amd64:

```sh
curl -LO https://github.com/AbdeldjalilChougui/ptransfer/releases/download/v0.1.0/ptransfer_0.1.0_linux_amd64.tar.gz
tar xzf ptransfer_0.1.0_linux_amd64.tar.gz
```

Or build from source with Go:

```sh
go install github.com/AbdeldjalilChougui/ptransfer/cmd/ptransfer@latest
```

## Quick start

```sh
go build -o ptransfer ./cmd/ptransfer

# somewhere both machines can reach (a VPS, or one of the two machines)
./ptransfer relay -addr 0.0.0.0:9009

# machine A
./ptransfer send -relay relay.example.org:9009 holiday-photos/ notes.pdf
#   Code: 4821-lamp-gold-lake

# machine B
./ptransfer receive -relay relay.example.org:9009 -out ~/Downloads 4821-lamp-gold-lake
```

`PTRANSFER_RELAY` sets the default relay. If a transfer is interrupted
(Ctrl-C, network drop), run it again with a new code: files that already
arrived are skipped and partial files resume where they stopped.

## How it works

```
sender                         relay                         receiver
  │ hello{room=H(4821), send}    │   hello{room=H(4821), recv}   │
  │─────────────────────────────►│◄──────────────────────────────│
  │◄──────────── ok ─────────────┤────────────── ok ────────────►│
  │              (from here the relay is a dumb pipe)            │
  │ PAKE (schollz/pake/v3, P-256), password = whole code         │
  │◄────────────────────────────────────────────────────────────►│
  │ key confirmation (HMAC), wrong code → both sides stop        │
  │ AES-256-GCM from now on, key = HKDF(PAKE secret)             │
  │ "direct?" + LAN addresses ─────────────────────────────────► │
  │◄═══════ receiver dials, proves the key with an encrypted ping│
  │ offer: paths, sizes, modes, SHA-256 ──────────────────────►  │
  │◄─ accept: per file, resume offset + hash of the partial data │
  │ data chunks (256 KiB) ───────────────────────────────────►   │
  │                     receiver: write *.ptpart, verify SHA-256,│
  │                     then rename into place                   │
  │◄──────────────────────────────── done ───────────────────────│
```

- **Code phrase**: a number plus three words from a 256-word list. The
  number only picks the relay room (the relay sees a hash of it). The
  whole phrase is the PAKE password, so the relay can't decrypt anything,
  and someone guessing the code gets one try per session.
- **Crypto comes from vetted code**: the PAKE is
  [`github.com/schollz/pake/v3`](https://github.com/schollz/pake) (the one
  croc uses) with participant identities bound into the key; the rest is
  Go's standard `crypto/hkdf`, `crypto/hmac` and AES-GCM. Nothing is
  hand-rolled beyond the framing. Nonces are a direction tag plus a
  counter, so a modified, dropped, reordered, replayed or reflected frame
  fails authentication.
- **Direct connection**: the sender listens on a random port and
  advertises its private LAN addresses over the encrypted channel. If the
  receiver can connect and the encrypted ping/pong works, the data moves
  over that connection; otherwise it stays on the relay.
- **Resume**: the receiver reports how much of each `.ptpart` file it has
  and its SHA-256; the sender only resumes if that matches the start of
  its own file. Every finished file is verified against the sender's
  SHA-256 before it gets its real name.
- **Safety on receive**: paths are checked (no absolute paths, `..`,
  backslashes or NULs) and must stay inside the output directory; existing
  different files are not replaced without `-overwrite`.

## Tests

```sh
go test -race ./...
```

- `code`: generation, normalisation (case, spaces), shared rooms with
  different passwords, rejection of malformed codes.
- `secure`: both sides derive the same key; a wrong code fails on both
  sides with `ErrWrongCode`; flipped bits, dropped frames and reflected
  frames are rejected; a malformed PAKE message doesn't crash the process.
- `relay`: pairing and piping, a second sender for the same room is
  refused, an abandoned room is freed, bad hellos, wait timeouts.
- `transfer`, **end to end through a local relay** on 127.0.0.1:
  - a folder with nested directories, an empty file and binary files
    arrives byte for byte with its file modes, and progress reaches 100 %;
  - the direct connection is used when reachable (one advertised address
    is dead on purpose) and the relay then carries almost nothing;
  - a **wrong code** stops both sides and writes nothing;
  - a **tampering proxy** that flips one bit in the middle of the stream is
    detected (`ErrTampered`) and no unverified file is put in place;
  - resume from a partial file sends only the rest; a partial file that
    doesn't match is discarded; re-sending a file the receiver already has
    transfers nothing;
  - existing files are protected unless `Overwrite` is set;
  - path validation rejects traversal attempts.

## Status and limitations

Early but working. Use it for your own files.

- The code has about 37 bits of entropy. That's plenty against online
  guessing (one guess per session, and the sender notices failures), but
  don't reuse codes.
- The sender hashes every file before the offer, so very large folders
  take a moment to start.
- Direct connections need the receiver to reach the sender's private
  address (same LAN, no client isolation). There's no NAT traversal (STUN,
  hole punching) and IPv6 link-local addresses aren't advertised. During a
  transfer with direct mode on, the sender listens on all interfaces on a
  random port.
- The relay has no authentication, rate limiting or bandwidth caps. Put
  it behind a firewall or add limits before exposing it widely.
- Only regular files are sent: symlinks, empty directories, ownership and
  timestamps are not preserved (permission bits are).
- One sender and one receiver per code; no multicast, no pausing.
- This hasn't been audited. The design is close to croc's, but treat it
  as a personal project.

## License

MIT. See [LICENSE](LICENSE).
