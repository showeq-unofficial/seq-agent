# seq-agent

A minimal EverQuest packet-capture **forwarder** for the ShowEQ daemon.

`seq-agent` opens a capture device (or replays a `.pcap`), applies a BPF filter,
and streams timestamped raw frames over TCP to a consumer. It does **no
decoding** — no opcode knowledge, no game state — so it never needs updating on
patch day. Run it at a router vantage point (sees every box's traffic) or on the
game host itself; the daemon treats an agent connection, in-process pcap, and
`.pcap`/`.vpk` replay as three frontends to the same frame stream.

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
# forward live UDP traffic to a consumer
seq-agent --to 10.0.0.5:9099 -i eth0 -f 'udp'

# or replay a capture file through the same pipe
seq-agent --to 127.0.0.1:9099 --input capture.pcap

seq-agent --list-devices        # list capture devices
seq-agent --help
```

## Try it end to end (no privileges needed)

```sh
# terminal 1 — start the consumer first
seq-sink --listen 127.0.0.1:9099 --write-pcap /tmp/out.pcap

# terminal 2 — replay a pcap through the agent
seq-agent --input some.pcap --to 127.0.0.1:9099

# out.pcap now reconstructs the input frame-for-frame:
tcpdump -r /tmp/out.pcap
```

## SEQA wire protocol

TCP, little-endian, pcap-shaped so a stream converts to/from a `.pcap` file with
no transformation. Full spec: [`src/proto.rs`](src/proto.rs).

| Message | Fields |
|---------|--------|
| **Hello** (once) | `magic "SEQA"` · `version u8` · `flags u8` · `link_type i32` · `snaplen u32` · `filt_len u16` · `filter [u8]` |
| **Frame** (repeated) | `ts_micros u64` · `caplen u32` · `origlen u32` · `data [caplen]` |
