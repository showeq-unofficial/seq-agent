Standalone capture forwarder for the ShowEQ daemon. Own git repo (NOT part of the `showeq-decoder-rs` cargo workspace). Direction + rationale live in the parent `../PIE_IN_THE_SKY.md`.

What it is: a deliberately dumb pipe — open a pcap device (or read a `.pcap`), apply a BPF filter, ship timestamped raw frames over TCP. No decode, no state, no protocol knowledge, so it never needs updating on patch day. Two frontends to the same frame stream: live device and `--input file.pcap` replay.

Deliberate choices (don't "modernize" without reason):
- **std threads, no tokio.** A single-connection linear capture→ring→send pipe needs no async runtime; `pcap` is blocking anyway. Keeps the static binary tiny (the router/UDM deploy goal). Revisit only if the agent grows multi-daemon fan-out or a control channel.
- **`opt-level=z` + LTO + strip + panic=abort** in release — smallest binary is the point.

Layout:
- `src/proto.rs` — the SEQA wire format (the spec IS this file). Hello + pcap-shaped frame records, all little-endian. Pcap-shaped on purpose so `seq-sink --write-pcap` round-trips with no transformation.
- `src/bin/seq-agent.rs` — the forwarder (needs `pcap`/libpcap).
- `src/bin/seq-sink.rs` — pure-std test consumer; parses SEQA, prints stats, optionally rebuilds a `.pcap`. Seed of the eventual daemon-side reader.

Ring semantics: `--input` (file) = lossless backpressure (faithful replay); live device = bounded drop-oldest (never stalls the NIC). Sender reconnects with backoff and buffers into the ring while the consumer is away.

Build: `(cd /home/rschultz/src/showeq/seq-agent && cargo build --release)`. Needs `libpcap.so` (libpcap0.8-dev) to link.

Live capture needs `cap_net_raw`: `sudo setcap cap_net_raw+ep target/release/seq-agent` (file/replay input needs no privileges).

Round-trip verify (no privileges, no live traffic):
```
seq-sink --listen 127.0.0.1:9099 --write-pcap /tmp/out.pcap   # start first
seq-agent --input fixture.pcap --to 127.0.0.1:9099
# then: tcpdump -r /tmp/out.pcap  should match the fixture
```

Capture data (`*.pcap`/`*.vpk`) is gitignored — never commit session bytes.

Cross-build (static musl for routers): `Dockerfile.musl` cross-builds a minimal static `libpcap.a` (base `messense/rust-musl-cross`, needs flex+bison), then links it — `pcap` link-binds via `#[link(name="pcap")]`, honors `LIBPCAP_LIBDIR`+`LIBPCAP_VER`; providing only the `.a` + musl static-CRT gives a fully static binary (~709 KB aarch64, verified). Parameterized by `RUST_MUSL_CROSS_TAG`+`TARGET`. Run `sudo bash scripts/build-aarch64.sh [target tag]` → `dist/`. **docker needs sudo here** (user not in `docker` group). CI (`.github/workflows/ci.yml`): fast native fmt/clippy/test/build gate on push+PR; heavy 3-arch musl matrix (aarch64/armv7/x86_64) on tags+dispatch, artifacts attached to the GitHub Release.

Not yet built (later increments): actual UDM run, AF_PACKET fast path, Windows/Npcap CI, extracting `proto` into a crate the daemon-side reader shares.
