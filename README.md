# seq-agent

A minimal EverQuest packet-capture **forwarder** for the ShowEQ daemon.

`seq-agent` opens a capture device (or replays a `.pcap`), applies a BPF filter,
and streams timestamped raw frames over TCP. It does **no decoding** — no opcode
knowledge, no game state — so it never needs updating on patch day. Run it at a
router vantage point (sees every box's traffic) or on the game host itself; the
daemon treats an agent connection, in-process pcap, and `.pcap`/`.vpk` replay as
three frontends to the same frame stream.

**The agent listens; the daemon dials in and says what to capture.** `seq-agent`
binds a port (`--listen`, default `0.0.0.0:9099`) and waits — it needs no idea
where the daemon lives or what traffic to grab. When a daemon connects it sends a
hello naming the BPF filter, and the (dumb) live agent opens its capture then and
there — an on-demand tap: capture starts on connect and stops on disconnect. If
the daemon names no filter, the agent falls back to its own `--filter` default.
You point the daemon at the agent, so a fleet of agents all run the same argless
command and the daemon owns the topology. (Data still flows agent→daemon.)

A `.pcap` replay (`--input`) is a fixed source: it ignores the daemon's filter
and replays the file faithfully.

Deliberately built on std threads (no async runtime) so the release binary stays
tiny — the goal is a static musl build that runs on a UDM / travel router.

## Build

```sh
cargo build --release
```

Requires `libpcap` (`libpcap0.8-dev` on Debian/Ubuntu). Two binaries drop in
`target/release/`: `seq-agent` (forwarder) and `seq-sink` (test consumer).

To capture from a live device without root:

```sh
sudo setcap cap_net_raw+ep target/release/seq-agent
```

Reading from a `.pcap` file needs no privileges.

## Usage

```sh
# tap a live device and wait for a daemon (listens on 0.0.0.0:9099).
# no filter here — the connecting daemon chooses it (see below)
seq-agent -i eth0

# -f sets the FALLBACK filter, used only if the daemon's hello omits one
seq-agent -i eth0 -f 'udp' --listen 0.0.0.0:9099

# or serve a capture file through the same pipe (ignores the daemon's filter)
seq-agent --input capture.pcap --listen 127.0.0.1:9099

seq-agent --list-devices        # list capture devices
seq-agent --help
```

The daemon (`seq-sink` here) connects to the agent and names the filter it wants
the agent to capture with:

```sh
seq-sink --connect <agent-host>:9099 --filter 'udp and portrange 9000-9010'
```

## Try it end to end (no privileges needed)

```sh
# terminal 1 — the agent listens and parks until a consumer dials in
seq-agent --input some.pcap --listen 127.0.0.1:9099

# terminal 2 — the consumer connects and drives the drain
#   (start either terminal first — the consumer retries until the agent is up)
seq-sink --connect 127.0.0.1:9099 --write-pcap /tmp/out.pcap

# out.pcap now reconstructs the input frame-for-frame:
cmp some.pcap /tmp/out.pcap && echo "byte-identical"
```

## Cross-build a static binary for a router (aarch64 / armv7 / x86_64)

The target build is a **fully static musl** binary (libpcap + libc baked in, no
runtime dependencies) — drop it on the box and run. libpcap is cross-built inside
Docker via [`Dockerfile.musl`](Dockerfile.musl):

```sh
# aarch64 (UDM, Pi, GL.iNet arm64) — outputs dist/seq-agent-aarch64-unknown-linux-musl
sudo bash scripts/build-aarch64.sh

# other arches:
sudo bash scripts/build-aarch64.sh armv7-unknown-linux-musleabihf armv7-musleabihf
sudo bash scripts/build-aarch64.sh x86_64-unknown-linux-musl       x86_64-musl
```

CI builds all three on tags (`v*`) and attaches them to the GitHub Release; it
also builds on manual dispatch. Deploy to a router (running as root avoids
`setcap`), pointing `--device` at the LAN bridge for whole-network vantage. The
agent listens; your dev box then connects the daemon to the router's LAN IP:

```sh
scp dist/seq-agent-aarch64-unknown-linux-musl root@<udm-ip>:/tmp/seq-agent
ssh root@<udm-ip> '/tmp/seq-agent --device br0 --no-promisc --listen 0.0.0.0:9099'

# on the dev box — the daemon picks the filter:
seq-sink --connect <udm-ip>:9099 --filter 'udp'   # (the real daemon connects the same way)
```

> The agent's listen port streams raw captured frames with no auth — bind it to
> a trusted LAN interface, not a public one.

## Windows

`seq-agent` runs on Windows via [Npcap](https://npcap.com) (the `pcap` crate
uses the same API and BPF compiler as libpcap). CI builds `seq-agent.exe` on
every push and attaches it to tagged releases. The exe is **not** self-contained
— it loads `wpcap.dll` at runtime, so:

- **To run it:** install [Npcap](https://npcap.com/#download) (Wireshark's driver;
  during install, leave *"Restrict Npcap driver's access to Administrators only"*
  unchecked if you want non-admin capture). It can also capture loopback.
- **To build it yourself:** install the [Npcap SDK](https://npcap.com/#download)
  and add its `Lib\x64` folder to your `LIB` environment variable, then
  `cargo build --release --bin seq-agent`.

On a switched network a Windows host sees only its own traffic, so the natural
place for a Windows agent is *on the EQ game box itself* — each box runs an agent
that listens, and the daemon connects out to each box, no router/mirror
involvement. (That does put a capture process + driver on the game machine, a
conscious trade-off vs. ShowEQ's classic off-box posture.)

## SEQA wire protocol

TCP, little-endian, pcap-shaped so a stream converts to/from a `.pcap` file with
no transformation. Full spec: [`src/proto.rs`](src/proto.rs).

| Message | Direction | Fields |
|---------|-----------|--------|
| **ClientHello** (once, optional) | daemon → agent | `magic "SEQC"` · `version u8` · `flags u8` · `filt_len u16` · `filter [u8]` |
| **Hello** (once) | agent → daemon | `magic "SEQA"` · `version u8` · `flags u8` · `link_type i32` · `snaplen u32` · `filt_len u16` · `filter [u8]` |
| **Frame** (repeated) | agent → daemon | `ts_micros u64` · `caplen u32` · `origlen u32` · `data [caplen]` |

The daemon opens with a `ClientHello` naming the BPF filter it wants; the agent
applies it (or its `--filter` default), then replies with `Hello` (the link type
+ the filter actually used) and streams `Frame`s.
