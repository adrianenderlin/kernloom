# Kernloom Shield + Kernloom IQ

Kernloom consists of two parts:

- **Kernloom Shield** (`klshield`) — the **XDP/eBPF data plane** (ingress enforcement + telemetry)
- **Kernloom IQ** (`kliq`) — the **userspace brain** (severity scoring + progressive enforcement)

Official docs:
- https://kernloom.com/kernloom-iq/
- https://kernloom.com/kernloom-shield/
- https://kernloom.com/kernloom-iq/

---

## Repo layout

```text
.
├── iq/
│   └── cmd/kliq/kliq.go              # Kernloom IQ CLI
├── shield/
│   ├── bpf/
│   │   ├── xdp_kernloom_shield.bpf.c # XDP program (Shield)
│   │   └── include/vmlinux.h
│   └── cmd/klshield/klshield.go      # Kernloom Shield CLI
└── pkg/version/version.go            # shared version helper
```

---

## What it does

### Shield (XDP ingress pipeline)
Typical packet flow:

1. **Allowlist** (CIDR, LPM trie) *(optional)*
2. **Denylist** (single IP, hash map)
3. **Rate limit** (per-source token bucket; global config + per-IP overrides)
4. PASS / DROP

Telemetry includes:
- per-CPU totals
- per-source stats (IPv4 + IPv6)
- port/packet-length histograms
- optional ringbuf events (sampled) for drop reasons / scan hints

### IQ (controller)
Every tick, IQ:
- reads per-source deltas from Shield telemetry (IPv4 + IPv6)
- computes severity (PPS + SYN/s + scan rate + DropRL/s)
- runs a per-IP FSM: `OBSERVE → RATE_SOFT → RATE_HARD → BLOCK`
- writes enforcement decisions back into Shield policy maps:
  - RL overrides (soft/hard)
  - deny entries (block)

---

## Build

### Prerequisites
- Linux with bpffs available at `/sys/fs/bpf`
- Tools: `clang`, `llvm`, `bpftool`, `iproute2`
- Go toolchain (matching your `go.mod`)

Mount bpffs if needed:
```bash
sudo mount -t bpf bpf /sys/fs/bpf || true
```

### Build the BPF object (Shield)
Use the provided Makefile:

```bash
make -C shield/bpf
```

This typically produces:
```text
shield/bpf/out/xdp_kernloom_shield.bpf.o
```

If you prefer manual build (example):
```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -c shield/bpf/xdp_kernloom_shield.bpf.c \
  -o shield/bpf/out/xdp_kernloom_shield.bpf.o
```

### Build the CLIs
From repo root:

```bash
mkdir -p bin
go build -o bin/klshield ./shield/cmd/klshield
go build -o bin/kliq    ./iq/cmd/kliq
```

### Prepare env
```bash
sudo mkdir -p /etc/kernloom/iq
sudo touch /etc/kernloom/iq/whitelist.txt
sudo chmod 644 /etc/kernloom/iq/whitelist.txt
```

Example content whitelist.txt
```text
# internal monitoring
203.0.113.7

# office NAT
198.51.100.0/24

# IPv6 test host
2001:db8::1
```

```bash
sudo mkdir -p /var/lib/kernloom/iq
sudo echo "[]" > /var/lib/kernloom/iq/feedback.json
sudo chmod 600 /var/lib/kernloom/iq/feedback.json
```

Example content feedback.json
```text
[
  {"target":"203.0.113.7","action":"forgive","ttl":"24h","notes":"partner NAT"},
  {"target":"198.51.100.0/24","action":"whitelist","ttl":"72h"},
  {"target":"2001:db8::1","action":"forgive","ttl":"6h"}
]
```

Recommended permissions
```text
/etc/kernloom/iq/whitelist.txt   root:root 644
/var/lib/kernloom/iq/feedback.json root:root 600
```

If kliq runs as non-root service user (recommended)
```bash
sudo chown kernloom:kernloom /var/lib/kernloom/iq/feedback.json
```

---

## Quick start

### 1) Attach Shield to an interface
```bash
sudo ./bin/klshield attach-xdp -iface eth0 -obj shield/bpf/out/xdp_kernloom_shield.bpf.o -force
```

Check it’s running:
```bash
sudo ./bin/klshield stats
sudo ./bin/klshield top-src -n 20 -by pkts
```

### 2) Add a minimal policy

**Allowlist mode (recommended for public edges)**
```bash
sudo ./bin/klshield add-allow-cidr 203.0.113.0/24
sudo ./bin/klshield add-allow-cidr 2001:db8:abcd::/48
sudo ./bin/klshield enforce-allow on
```

**Deny a single IP**
```bash
sudo ./bin/klshield add-deny-ip 203.0.113.55
sudo ./bin/klshield add-deny-ip 2001:db8::dead:beef
```

**Rate limit (global)**
```bash
sudo ./bin/klshield rl-set -rate 1200 -burst 2400
```

### 3) Run IQ
Start in observe mode first:
```bash
sudo ./bin/kliq -profile ziti-controller -interval 1s -dry-run=true
```

Enable enforcement:
```bash
sudo ./bin/kliq -profile ziti-controller -interval 1s -dry-run=false
```

---

## Whitelist and feedback (IQ)

### Whitelist file
Default (can be changed via flags):
```text
/etc/kernloom/iq/whitelist.txt
```

Format: one entry per line — **IPv4, IPv6, IPv4 CIDR, or IPv6 CIDR**.

Example:
```text
# exact IPv4
203.0.113.7
# CIDR IPv4
198.51.100.0/24

# exact IPv6
2001:db8::1
# CIDR IPv6
2001:db8:abcd::/48
```

### Feedback file (temporary exemptions)
Default:
```text
/var/lib/kernloom/iq/feedback.json
```

Example:
```json
[
  {"target":"203.0.113.7","action":"forgive","ttl":"24h","notes":"partner NAT"},
  {"target":"198.51.100.0/24","action":"whitelist","until":"2026-03-01T12:00:00+01:00"},
  {"target":"2001:db8::1","action":"forgive","ttl":"6h","notes":"v6 test"},
  {"target":"2001:db8:abcd::/48","action":"whitelist","ttl":"72h"}
]
```

---

## CLI reference

### klshield
```text
klshield (XDP only)

Commands:
  attach-xdp   -iface eth0 [-obj shield/bpf/xdp_kernloom_shield.bpf.o] [-force]
  detach-xdp

  add-allow-cidr  <cidr>
  list-allow
  add-deny-ip     <ip>
  del-deny-ip     <ip>
  list-deny

  enforce-allow   on|off
  set-sampling    <mask>     (0 disables, 1 => ~1/2, 3 => ~1/4, 1023 => ~1/1024)

  rl-set          -rate <pps> -burst <n>
  rl-set-ip       -rate <pps> -burst <n> <ip>
  rl-unset-ip     <ip>
  list-rl

  stats
  top-src         [-n 20] [-by pkts|bytes|drops|droprl]
  events
```

### kliq
`kliq` is primarily flag-driven (see source in `iq/cmd/kliq/kliq.go`). Operational highlights:
- `-dry-run=true` → observe only (no map writes)
- `-dry-run=false` → enforces via Shield policy maps (IPv4 + IPv6)
- `-profile` → selects initial behavior template
- `-state-file` → persists autotune state (atomic write + integrity hash)
- `-whitelist` / `-feedback-file` → exemptions (IPv4 + IPv6 supported)
- `-bootstrap` → bootstrapping behaviour (makes it more easy to start)

https://kernloom.com/kernloom-iq/

---

## Troubleshooting

### bpffs / pinned objects
Verify bpffs:
```bash
mount | grep /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
```

See what Shield pinned:
```bash
sudo ls -la /sys/fs/bpf | grep -i kernloom || true
sudo ls -la /sys/fs/bpf | grep -i xdp || true
```

### Driver XDP vs Generic XDP
If attach in driver mode fails on your NIC/driver, Shield may fall back to generic mode (implementation dependent). Check your `klshield` output.

---

## License

See:
- `LICENSE` (repo root)
- `shield/LICENSE` and `iq/LICENSE`
- Additional texts under `LICENSES/`
