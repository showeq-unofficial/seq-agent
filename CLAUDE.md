Standalone capture forwarder for the ShowEQ daemon. Own git repo (NOT part of the `showeq-decoder-rs` cargo workspace). Direction + rationale live in the parent `../PIE_IN_THE_SKY.md`.

What it is: a deliberately dumb pipe — open a pcap device (or read a `.pcap`), apply a BPF filter, ship timestamped raw frames over TCP. No decode, no state, no protocol knowledge, so it never needs updating on patch day. Two frontends to the same frame stream: live device and `--input file.pcap` replay.

Connection direction: **the agent listens (`--listen`, default `0.0.0.0:9099`); the daemon dials in.** The agent is zero-config about topology — you point the daemon at the agent, not the other way round — so a fleet of agents all run the same argless command and the daemon owns the wiring. Data still flows agent→daemon; only who opens the TCP socket flipped. One daemon at a time; the live device is served on-demand (see below). Multi-daemon fan-out is still future work.

Filter handshake (ported from scry's `Scry.Agent`): **the daemon tells the agent what to capture.** On a live device the agent is an on-demand tap — it opens the capture *when a daemon connects*, using the BPF filter that daemon names in a `ClientHello` (SEQC magic, daemon→agent, sent before the agent's `Hello`), and closes it on disconnect. If no ClientHello arrives within `HELLO_TIMEOUT` (2 s, matches scry) the agent falls back to its own `--filter` default. `seq-sink --filter <BPF>` sends the ClientHello; no `--filter` sends none. `--input` file replay is a "fixed source" — it ignores the ClientHello and replays the whole file (the agent's own `--filter`, if set, still narrows it), so round-trips stay byte-faithful. Consequence vs. the old always-on ring: the live agent no longer captures before a daemon connects (it can't know the filter yet), so there's no cross-reconnect buffering.

Deliberate choices (don't "modernize" without reason):
- **std threads, no tokio.** A single-connection linear capture→ring→send pipe needs no async runtime; `pcap` is blocking anyway. Keeps the static binary tiny (the router/UDM deploy goal). Revisit only if the agent grows multi-daemon fan-out or a control channel.
- **`opt-level=z` + LTO + strip + panic=abort** in release — smallest binary is the point.

Layout:
- `src/proto.rs` — the SEQA wire format (the spec IS this file). `ClientHello` (daemon→agent filter request) + `Hello` + pcap-shaped frame records, all little-endian. Pcap-shaped on purpose so `seq-sink --write-pcap` round-trips with no transformation. Codec round-trip tests live here.
- `src/bin/seq-agent.rs` — the forwarder (needs `pcap`/libpcap). Per-session: capture thread fills the ring, sender thread writes the `Hello` + drains it; `read_client_hello` (loopback-tested) resolves the filter.
- `src/bin/seq-sink.rs` — pure-std test consumer; dials the agent, optionally sends a `--filter` ClientHello, parses SEQA, prints stats, optionally rebuilds a `.pcap`. Seed of the eventual daemon-side reader.

Ring semantics (per session): `--input` (file) = lossless backpressure (faithful replay); live device = bounded drop-oldest (never stalls the NIC). The capture thread fills the ring; the sender drains it to the socket and closes the ring on daemon disconnect (which stops the capture). `seq-sink` (the consumer) is the side that dials with backoff — start either process first.

Build: `(cd /home/rschultz/src/showeq/seq-agent && cargo build --release)`. Needs `libpcap.so` (libpcap0.8-dev) to link.

Live capture needs `cap_net_raw`: `sudo setcap cap_net_raw+ep target/release/seq-agent` (file/replay input needs no privileges).

Round-trip verify (no privileges, no live traffic — either order works):
```
seq-agent --input fixture.pcap --listen 127.0.0.1:9099      # listens, parks until a consumer dials in
seq-sink  --connect 127.0.0.1:9099 --write-pcap /tmp/out.pcap
# then: cmp fixture.pcap /tmp/out.pcap  is byte-identical
```

Capture data (`*.pcap`/`*.vpk`) is gitignored — never commit session bytes.

Cross-build (static musl for routers): `Dockerfile.musl` cross-builds a minimal static `libpcap.a` (base `messense/rust-musl-cross`, needs flex+bison), then links it — `pcap` link-binds via `#[link(name="pcap")]`, honors `LIBPCAP_LIBDIR`+`LIBPCAP_VER`; providing only the `.a` + musl static-CRT gives a fully static binary (~709 KB aarch64, verified). Parameterized by `RUST_MUSL_CROSS_TAG`+`TARGET`. Run `sudo bash scripts/build-aarch64.sh [target tag]` → `dist/`. **docker needs sudo here** (user not in `docker` group). CI (`.github/workflows/ci.yml`): fast native fmt/clippy/test/build gate on push+PR; a `windows` job builds `seq-agent.exe` against the Npcap SDK (link-binds `wpcap`; `LIBPCAP_VER` skips the runtime version-probe since the runner has no Npcap; `LIB` += SDK `Lib\x64`); heavy 3-arch musl matrix (aarch64/armv7/x86_64) on tags+dispatch. All artifacts attached to the GitHub Release on tags. Code is Windows-clean as-is (`pcap` uses `libc::timeval` on all platforms).

Close gracefully on the all-delivered path: a connecting consumer (the daemon) opens with a `ClientHello` (SEQC) naming its filter, but **file-replay mode never reads it**, so `send_session` MUST `graceful_close` (half-close write, then drain the peer's unread bytes) before dropping the socket. Closing a TCP socket with unread data sends RST not FIN, and the RST discards frames still buffered for a SLOW consumer (a decoding showeq-daemon lost 507/1048 frames until this landed) — a fast consumer that drains before the RST arrives masks the bug, so a tiny fixture won't catch it (needs a large transfer + a slow reader). Device mode is immune (it already reads the ClientHello via `read_client_hello`).

Not yet built (later increments): actual UDM run, AF_PACKET fast path, extracting `proto` into a crate the daemon-side reader shares.
