// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Adrian Enderlin
// Kernloom Shield XDP (ingress):
//   Allow (CIDR v4+v6, LPM) -> Deny (single IP v4+v6, HASH) -> RateLimit (per-src token bucket) -> PASS/DROP
// Telemetry:
//   - totals (per-cpu)
//   - per-source v4/v6 stats (LRU)
//   - port histogram (0..1023) + packet length histogram
//   - optional ringbuf events (sampled)
//
// Build:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/klshield.bpf.c -o bpf/klshield.bpf.o
//
// NOTE:
//   Map *names* are intentionally kept as xdp_* for userspace compatibility.
//   Userspace pins them under /sys/fs/bpf/kernloom_*.

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#define NSEC_PER_SEC 1000000000ULL

/* TCP flag bitmask (classic) */
#define TCP_F_FIN 0x01
#define TCP_F_SYN 0x02
#define TCP_F_RST 0x04
#define TCP_F_PSH 0x08
#define TCP_F_ACK 0x10
#define TCP_F_URG 0x20
#define TCP_F_ECE 0x40
#define TCP_F_CWR 0x80

/* Event reasons */
#define EV_DROP_ALLOW 1
#define EV_DROP_DENY  2
#define EV_DROP_RL    3
#define EV_SCAN_HINT  4

char _license[] SEC("license") = "Dual BSD/GPL";

/* ==================== Telemetry: totals (per-cpu) ==================== */
struct xdp_totals_t {
    __u64 pkts;
    __u64 bytes;

    __u64 pass;

    __u64 drop_allow;   // enforce_allow drop
    __u64 drop_deny;    // denylist drop
    __u64 drop_rl;      // rate-limit drop

    __u64 v4;
    __u64 v6;

    __u64 tcp;
    __u64 udp;
    __u64 icmp;

    __u64 syn;
    __u64 synack;
    __u64 rst;
    __u64 ack;          // any ACK (includes SYN+ACK too)

    __u64 ipv4_frags;   // fragmented IPv4 (evasion-ish)
    __u64 dport_changes;
    __u64 new_sources;  // count of newly created per-source entries

    __u64 allow_hits;   // allowlist positive matches (when enforce enabled)
    __u64 deny_hits;    // denylist matches
    __u64 rl_hits;      // rate limiter active and checked
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_totals_t);
} xdp_totals SEC(".maps");

/* ==================== Telemetry: per-source v4 (bounded) ==================== */
struct xdp_src_stats_v4_t {
    __u64 pkts;
    __u64 bytes;

    __u64 tcp;
    __u64 udp;
    __u64 icmp;

    __u64 syn;
    __u64 synack;
    __u64 rst;
    __u64 ack;

    __u64 pass;
    __u64 drop_allow;
    __u64 drop_deny;
    __u64 drop_rl;

    __u64 first_seen_ns;
    __u64 last_seen_ns;

    __u16 last_sport;     // network order ok
    __u16 last_dport;     // network order ok
    __u64 dport_changes;

    __u8  last_ttl;
    __u8  last_tcp_flags; // bitmask
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);                   // IPv4 saddr (as loaded from packet)
    __type(value, struct xdp_src_stats_v4_t);
} xdp_src4_stats SEC(".maps");

/* ==================== Telemetry: per-source v6 (bounded) ==================== */
struct src6_key { __u8 ip[16]; };

struct xdp_src_stats_v6_t {
    __u64 pkts;
    __u64 bytes;

    __u64 tcp;
    __u64 udp;
    __u64 icmp;

    __u64 syn;
    __u64 synack;
    __u64 rst;
    __u64 ack;

    __u64 pass;
    __u64 drop_allow;
    __u64 drop_deny;
    __u64 drop_rl;

    __u64 first_seen_ns;
    __u64 last_seen_ns;

    __u16 last_sport;
    __u16 last_dport;
    __u64 dport_changes;

    __u8  last_hlim;
    __u8  last_tcp_flags;
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct src6_key);
    __type(value, struct xdp_src_stats_v6_t);
} xdp_src6_stats SEC(".maps");

/* ==================== Allow/Deny maps ==================== */
struct lpm_key_v4 {
    __u32 prefixlen;
    __u8  data[4];
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} xdp_allow_lpm SEC(".maps");

/* v4 deny key as bytes (endianness-safe userspace) */
struct key4_bytes { __u8 ip[4]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct key4_bytes);
    __type(value, __u8);
} xdp_deny_hash SEC(".maps");

struct lpm_key_v6 {
    __u32 prefixlen;
    __u8  data[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key_v6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} xdp_allow6_lpm SEC(".maps");

struct key6_bytes { __u8 ip[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct key6_bytes);
    __type(value, __u8);
} xdp_deny6_hash SEC(".maps");

/* ==================== Config ==================== */
struct xdp_cfg_t {
    __u32 enforce_allow;      // 0/1
    __u32 event_sample_mask;  // e.g. 1023 => 1/1024, 0 disables
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_cfg_t);
} xdp_cfg SEC(".maps");

/* ==================== Rate limiting (XDP) ==================== */
struct rl_cfg_t {
    __u64 rate_pps;
    __u64 burst;
};

struct rl_state_t {
    __u64 last_ns;
    __u64 tokens;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rl_cfg_t);
} xdp_rl_cfg SEC(".maps");

/* per-ip overrides */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct key4_bytes);
    __type(value, struct rl_cfg_t);
} xdp_rl_policy4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct src6_key);
    __type(value, struct rl_cfg_t);
} xdp_rl_policy6 SEC(".maps");

/* states */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);              // IPv4 saddr (as loaded from packet)
    __type(value, struct rl_state_t);
} xdp_rl_state4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct src6_key);
    __type(value, struct rl_state_t);
} xdp_rl_state6 SEC(".maps");

/* ==================== Histograms ==================== */
struct port_hist_v {
    __u64 pkts;
    __u64 bytes;
    __u64 drops;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct port_hist_v);
} xdp_port_hist SEC(".maps");

struct len_hist_v { __u64 pkts; __u64 bytes; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct len_hist_v);
} xdp_len_hist SEC(".maps");

/* ==================== Optional ringbuf events ==================== */
struct xdp_event_t {
    __u64 ts_ns;
    __u32 reason;
    __u8  ipver;      // 4/6
    __u8  l4proto;    // TCP/UDP/ICMP...
    __u16 dport;      // network order ok
    __u32 saddr_v4;   // raw u32 as in packet load
    __u8  saddr_v6[16];
    __u32 pkt_len;
    __u32 aux;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4MB
} xdp_events SEC(".maps");

/* ==================== Helpers ==================== */
static __always_inline struct xdp_totals_t *totals_get(void) {
    __u32 k = 0;
    return bpf_map_lookup_elem(&xdp_totals, &k);
}

static __always_inline void totals_add_basic(struct xdp_totals_t *t, __u64 len) {
    if (!t) return;
    t->pkts++;
    t->bytes += len;
}

/* VLAN/QinQ-aware Ethernet parser */
static __always_inline int parse_eth(void *data, void *data_end, __u16 *proto, __u64 *off)
{
    if (data + sizeof(struct ethhdr) > data_end) return -1;
    struct ethhdr *eth = data;
    *proto = bpf_ntohs(eth->h_proto);
    *off   = sizeof(*eth);

#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (*proto == 0x8100 || *proto == 0x88a8) {
            if (data + *off + sizeof(struct vlan_hdr) > data_end) return -1;
            struct vlan_hdr *vh = data + *off;
            *proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
            *off  += sizeof(*vh);
        }
    }
    return 0;
}

/* Allow/Deny lookups */
static __always_inline bool in_allow_v4(__be32 saddr)
{
    struct lpm_key_v4 k = { .prefixlen = 32 };
    __builtin_memcpy(k.data, &saddr, 4);
    return bpf_map_lookup_elem(&xdp_allow_lpm, &k) != NULL;
}

static __always_inline bool in_deny_v4(__be32 saddr)
{
    struct key4_bytes k = {};
    __builtin_memcpy(k.ip, &saddr, 4);
    return bpf_map_lookup_elem(&xdp_deny_hash, &k) != NULL;
}

static __always_inline bool in_allow_v6(const __u8 *saddr16)
{
    struct lpm_key_v6 k = { .prefixlen = 128 };
    __builtin_memcpy(k.data, saddr16, 16);
    return bpf_map_lookup_elem(&xdp_allow6_lpm, &k) != NULL;
}

static __always_inline bool in_deny_v6(const __u8 *saddr16)
{
    struct key6_bytes k = {};
    __builtin_memcpy(k.ip, saddr16, 16);
    return bpf_map_lookup_elem(&xdp_deny6_hash, &k) != NULL;
}

/* Hist updates */
static __always_inline void hist_len_add(__u64 pkt_len)
{
    __u32 bin = 15;
    if (pkt_len < 64) bin = 0;
    else if (pkt_len < 128) bin = 1;
    else if (pkt_len < 256) bin = 2;
    else if (pkt_len < 512) bin = 3;
    else if (pkt_len < 1024) bin = 4;
    else if (pkt_len < 1518) bin = 5;
    else if (pkt_len < 2048) bin = 6;
    else if (pkt_len < 4096) bin = 7;
    else if (pkt_len < 8192) bin = 8;

    struct len_hist_v *v = bpf_map_lookup_elem(&xdp_len_hist, &bin);
    if (v) { v->pkts++; v->bytes += pkt_len; }
}

static __always_inline void hist_port_add(__u16 dport_net, __u64 pkt_len, bool dropped)
{
    if (!dport_net) return;
    __u32 p = (__u32)bpf_ntohs(dport_net);
    if (p >= 1024) return;
    struct port_hist_v *v = bpf_map_lookup_elem(&xdp_port_hist, &p);
    if (!v) return;
    v->pkts++;
    v->bytes += pkt_len;
    if (dropped) v->drops++;
}

/* Rate limiting selection */
static __always_inline const struct rl_cfg_t *select_rl_v4(__be32 saddr)
{
    __u32 idx = 0;
    const struct rl_cfg_t *def = bpf_map_lookup_elem(&xdp_rl_cfg, &idx);
    const struct rl_cfg_t *use = (def && def->rate_pps && def->burst) ? def : NULL;

    struct key4_bytes k4 = {};
    __builtin_memcpy(k4.ip, &saddr, 4);
    struct rl_cfg_t *ovr = bpf_map_lookup_elem(&xdp_rl_policy4, &k4);
    if (ovr && ovr->rate_pps && ovr->burst) use = ovr;

    return use;
}

static __always_inline const struct rl_cfg_t *select_rl_v6(const __u8 *saddr16)
{
    __u32 idx = 0;
    const struct rl_cfg_t *def = bpf_map_lookup_elem(&xdp_rl_cfg, &idx);
    const struct rl_cfg_t *use = (def && def->rate_pps && def->burst) ? def : NULL;

    struct src6_key k6 = {};
    __builtin_memcpy(k6.ip, saddr16, 16);
    struct rl_cfg_t *ovr = bpf_map_lookup_elem(&xdp_rl_policy6, &k6);
    if (ovr && ovr->rate_pps && ovr->burst) use = ovr;

    return use;
}

/* Token bucket update (overflow-safe refill shortcut) */
static __always_inline bool tb_allow_and_update(struct rl_state_t *st,
                                                const struct rl_cfg_t *cfg,
                                                __u64 now)
{
    if (!cfg || cfg->rate_pps == 0 || cfg->burst == 0)
        return true;

    if (!st) return true;

    __u64 tokens = st->tokens;
    __u64 delta  = now - st->last_ns;

    if (tokens < cfg->burst) {
        __u64 missing = cfg->burst - tokens;
        __u64 need_ns = (missing * NSEC_PER_SEC + cfg->rate_pps - 1) / cfg->rate_pps;

        if (delta >= need_ns) {
            tokens = cfg->burst;
        } else {
            __u64 add = (delta * cfg->rate_pps) / NSEC_PER_SEC;
            tokens += add;
            if (tokens > cfg->burst) tokens = cfg->burst;
        }
    }

    if (tokens == 0) {
        st->last_ns = now;
        st->tokens  = 0;
        return false;
    }

    st->last_ns = now;
    st->tokens  = tokens - 1;
    return true;
}

/* Optional event emission */
static __always_inline void maybe_emit_event_v4(__u32 reason, __u32 sample_mask,
                                                __u32 saddr, __u8 l4proto, __u16 dport,
                                                __u32 pkt_len, __u32 aux)
{
    if (sample_mask == 0) return;
    if ((bpf_get_prandom_u32() & sample_mask) != 0) return;

    struct xdp_event_t *e = bpf_ringbuf_reserve(&xdp_events, sizeof(*e), 0);
    if (!e) return;

    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->reason = reason;
    e->ipver = 4;
    e->l4proto = l4proto;
    e->dport = dport;
    e->saddr_v4 = saddr;
    e->pkt_len = pkt_len;
    e->aux = aux;

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void maybe_emit_event_v6(__u32 reason, __u32 sample_mask,
                                                const __u8 *saddr16, __u8 l4proto, __u16 dport,
                                                __u32 pkt_len, __u32 aux)
{
    if (sample_mask == 0) return;
    if ((bpf_get_prandom_u32() & sample_mask) != 0) return;

    struct xdp_event_t *e = bpf_ringbuf_reserve(&xdp_events, sizeof(*e), 0);
    if (!e) return;

    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->reason = reason;
    e->ipver = 6;
    e->l4proto = l4proto;
    e->dport = dport;
    __builtin_memcpy(e->saddr_v6, saddr16, 16);
    e->pkt_len = pkt_len;
    e->aux = aux;

    bpf_ringbuf_submit(e, 0);
}

/* per-source update returns bitmask:
 * bit0: dport changed
 * bit1: new source
 */
static __always_inline int src4_update(__be32 saddr, __u64 len, __u64 now,
                                       bool is_tcp, bool is_udp, bool is_icmp,
                                       bool syn, bool synack, bool rst, bool ack,
                                       __u16 sport, __u16 dport,
                                       __u8 ttl, __u8 tcp_flags,
                                       bool pass, bool drop_allow, bool drop_deny, bool drop_rl)
{
    int ret = 0;
    int changed = 0;

    struct xdp_src_stats_v4_t *st = bpf_map_lookup_elem(&xdp_src4_stats, &saddr);
    if (!st) {
        struct xdp_src_stats_v4_t init = {};
        init.pkts = 1;
        init.bytes = len;
        init.tcp = is_tcp ? 1 : 0;
        init.udp = is_udp ? 1 : 0;
        init.icmp = is_icmp ? 1 : 0;
        init.syn = syn ? 1 : 0;
        init.synack = synack ? 1 : 0;
        init.rst = rst ? 1 : 0;
        init.ack = ack ? 1 : 0;

        init.pass = pass ? 1 : 0;
        init.drop_allow = drop_allow ? 1 : 0;
        init.drop_deny  = drop_deny  ? 1 : 0;
        init.drop_rl    = drop_rl    ? 1 : 0;

        init.first_seen_ns = now;
        init.last_seen_ns  = now;

        init.last_sport = sport;
        init.last_dport = dport;

        init.last_ttl = ttl;
        init.last_tcp_flags = tcp_flags;

        bpf_map_update_elem(&xdp_src4_stats, &saddr, &init, BPF_ANY);
        ret |= 2; // new
        return ret;
    }

    st->pkts++;
    st->bytes += len;

    if (is_tcp) st->tcp++;
    if (is_udp) st->udp++;
    if (is_icmp) st->icmp++;

    if (syn) st->syn++;
    if (synack) st->synack++;
    if (rst) st->rst++;
    if (ack) st->ack++;

    if (pass) st->pass++;
    if (drop_allow) st->drop_allow++;
    if (drop_deny)  st->drop_deny++;
    if (drop_rl)    st->drop_rl++;

    st->last_seen_ns = now;

    if (sport) st->last_sport = sport;
    if (dport && st->last_dport != dport) {
        st->dport_changes++;
        st->last_dport = dport;
        changed = 1;
    }

    if (ttl) st->last_ttl = ttl;
    if (tcp_flags) st->last_tcp_flags = tcp_flags;

    if (changed) ret |= 1;
    return ret;
}

static __always_inline int src6_update(const __u8 *saddr16, __u64 len, __u64 now,
                                       bool is_tcp, bool is_udp, bool is_icmp,
                                       bool syn, bool synack, bool rst, bool ack,
                                       __u16 sport, __u16 dport,
                                       __u8 hlim, __u8 tcp_flags,
                                       bool pass, bool drop_allow, bool drop_deny, bool drop_rl)
{
    int ret = 0;
    int changed = 0;

    struct src6_key k = {};
    __builtin_memcpy(k.ip, saddr16, 16);

    struct xdp_src_stats_v6_t *st = bpf_map_lookup_elem(&xdp_src6_stats, &k);
    if (!st) {
        struct xdp_src_stats_v6_t init = {};
        init.pkts = 1;
        init.bytes = len;

        init.tcp = is_tcp ? 1 : 0;
        init.udp = is_udp ? 1 : 0;
        init.icmp = is_icmp ? 1 : 0;

        init.syn = syn ? 1 : 0;
        init.synack = synack ? 1 : 0;
        init.rst = rst ? 1 : 0;
        init.ack = ack ? 1 : 0;

        init.pass = pass ? 1 : 0;
        init.drop_allow = drop_allow ? 1 : 0;
        init.drop_deny  = drop_deny  ? 1 : 0;
        init.drop_rl    = drop_rl    ? 1 : 0;

        init.first_seen_ns = now;
        init.last_seen_ns  = now;

        init.last_sport = sport;
        init.last_dport = dport;
        init.last_hlim = hlim;
        init.last_tcp_flags = tcp_flags;

        bpf_map_update_elem(&xdp_src6_stats, &k, &init, BPF_ANY);
        ret |= 2;
        return ret;
    }

    st->pkts++;
    st->bytes += len;

    if (is_tcp) st->tcp++;
    if (is_udp) st->udp++;
    if (is_icmp) st->icmp++;

    if (syn) st->syn++;
    if (synack) st->synack++;
    if (rst) st->rst++;
    if (ack) st->ack++;

    if (pass) st->pass++;
    if (drop_allow) st->drop_allow++;
    if (drop_deny)  st->drop_deny++;
    if (drop_rl)    st->drop_rl++;

    st->last_seen_ns = now;

    if (sport) st->last_sport = sport;
    if (dport && st->last_dport != dport) {
        st->dport_changes++;
        st->last_dport = dport;
        changed = 1;
    }

    if (hlim) st->last_hlim = hlim;
    if (tcp_flags) st->last_tcp_flags = tcp_flags;

    if (changed) ret |= 1;
    return ret;
}

/* ==================== XDP program ==================== */
SEC("xdp")
int xdp_klshield(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 pkt_len = (__u64)((long)data_end - (long)data);
    __u64 now = bpf_ktime_get_ns();

    struct xdp_totals_t *t = totals_get();
    totals_add_basic(t, pkt_len);

    /* packet length histogram (always) */
    hist_len_add(pkt_len);

    __u16 proto;
    __u64 off;
    if (parse_eth(data, data_end, &proto, &off) < 0) {
        if (t) t->pass++;
        return XDP_PASS;
    }

    __u32 idx = 0;
    struct xdp_cfg_t *cfg = bpf_map_lookup_elem(&xdp_cfg, &idx);
    __u32 enforce = cfg ? cfg->enforce_allow : 0;
    __u32 sample_mask = cfg ? cfg->event_sample_mask : 0;

    /* ================= IPv4 ================= */
    if (proto == 0x0800) {
        if (data + off + sizeof(struct iphdr) > data_end) {
            if (t) t->pass++;
            return XDP_PASS;
        }
        struct iphdr *iph = data + off;
        if (iph->version != 4) { if (t) t->pass++; return XDP_PASS; }

        __u64 ihl_bytes = (__u64)iph->ihl * 4;
        if (ihl_bytes < sizeof(struct iphdr)) { if (t) t->pass++; return XDP_PASS; }
        if (data + off + ihl_bytes > data_end) { if (t) t->pass++; return XDP_PASS; }

        if (t) t->v4++;

        __be32 saddr = iph->saddr;

        /* fragmentation metric */
        __u16 fo = bpf_ntohs(iph->frag_off);
        bool is_frag = ((fo & 0x1FFF) != 0) || ((fo & 0x2000) != 0);
        if (is_frag && t) t->ipv4_frags++;

        bool is_tcp=false, is_udp=false, is_icmp=false;
        bool syn=false, synack=false, rst=false, ack=false;
        __u16 dport = 0, sport = 0;
        __u8 tcp_flags = 0;

        __u64 l4off = off + ihl_bytes;

        __u8 l4proto = iph->protocol;
        if (l4proto == IPPROTO_TCP) {
            is_tcp = true;
            if (t) t->tcp++;
            if (data + l4off + sizeof(struct tcphdr) <= data_end) {
                struct tcphdr *th = data + l4off;
                dport = th->dest;
                sport = th->source;

                if (th->fin) tcp_flags |= TCP_F_FIN;
                if (th->syn) tcp_flags |= TCP_F_SYN;
                if (th->rst) tcp_flags |= TCP_F_RST;
                if (th->psh) tcp_flags |= TCP_F_PSH;
                if (th->ack) tcp_flags |= TCP_F_ACK;
                if (th->urg) tcp_flags |= TCP_F_URG;
                if (th->ece) tcp_flags |= TCP_F_ECE;
                if (th->cwr) tcp_flags |= TCP_F_CWR;

                syn = th->syn;
                rst = th->rst;
                ack = th->ack;
                synack = th->syn && th->ack;

                if (t && syn) t->syn++;
                if (t && synack) t->synack++;
                if (t && rst) t->rst++;
                if (t && ack) t->ack++;
            }
        } else if (l4proto == IPPROTO_UDP) {
            is_udp = true;
            if (t) t->udp++;
            if (data + l4off + sizeof(struct udphdr) <= data_end) {
                struct udphdr *uh = data + l4off;
                dport = uh->dest;
                sport = uh->source;
            }
        } else if (l4proto == IPPROTO_ICMP) {
            is_icmp = true;
            if (t) t->icmp++;
        }

        /* allow/deny */
        bool drop_allow=false, drop_deny=false, drop_rl=false;

        if (enforce) {
            if (!in_allow_v4(saddr)) drop_allow = true;
            else if (t) t->allow_hits++;
        }

        if (!drop_allow) {
            if (in_deny_v4(saddr)) {
                drop_deny = true;
                if (t) t->deny_hits++;
            }
        }

        /* rate limit (only if not already dropped) */
        if (!drop_allow && !drop_deny) {
            const struct rl_cfg_t *use = select_rl_v4(saddr);
            if (use) {
                if (t) t->rl_hits++;
                struct rl_state_t *st = bpf_map_lookup_elem(&xdp_rl_state4, &saddr);
                if (!st) {
                    /* init consumes token for this first packet */
                    __u64 init_tokens = (use->burst > 0) ? (use->burst - 1) : 0;
                    struct rl_state_t init = { .last_ns = now, .tokens = init_tokens };
                    bpf_map_update_elem(&xdp_rl_state4, &saddr, &init, BPF_ANY);
                } else {
                    if (!tb_allow_and_update(st, use, now))
                        drop_rl = true;
                }
            }
        }

        int action = (drop_allow || drop_deny || drop_rl) ? XDP_DROP : XDP_PASS;

        if (t) {
            if (action == XDP_PASS) t->pass++;
            else if (drop_allow)    t->drop_allow++;
            else if (drop_deny)     t->drop_deny++;
            else                    t->drop_rl++;
        }

        /* port histogram */
        hist_port_add(dport, pkt_len, action == XDP_DROP);

        /* per-source + scan hint */
        int upd = src4_update(saddr, pkt_len, now,
                              is_tcp, is_udp, is_icmp,
                              syn, synack, rst, ack,
                              sport, dport,
                              iph->ttl, tcp_flags,
                              action == XDP_PASS,
                              drop_allow, drop_deny, drop_rl);

        if ((upd & 2) && t) t->new_sources++;
        if ((upd & 1) && t) {
            t->dport_changes++;
            maybe_emit_event_v4(EV_SCAN_HINT, sample_mask, (__u32)saddr, l4proto, dport, (__u32)pkt_len, 1);
        }

        if (drop_allow)
            maybe_emit_event_v4(EV_DROP_ALLOW, sample_mask, (__u32)saddr, l4proto, dport, (__u32)pkt_len, 0);
        else if (drop_deny)
            maybe_emit_event_v4(EV_DROP_DENY, sample_mask, (__u32)saddr, l4proto, dport, (__u32)pkt_len, 0);
        else if (drop_rl)
            maybe_emit_event_v4(EV_DROP_RL, sample_mask, (__u32)saddr, l4proto, dport, (__u32)pkt_len, 0);

        return action;
    }

    /* ================= IPv6 ================= */
    if (proto == 0x86DD) {
        if (data + off + sizeof(struct ipv6hdr) > data_end) {
            if (t) t->pass++;
            return XDP_PASS;
        }
        struct ipv6hdr *ip6 = data + off;
        if (ip6->version != 6) { if (t) t->pass++; return XDP_PASS; }

        if (t) t->v6++;

        __u8 saddr6[16];
        __builtin_memcpy(saddr6, &ip6->saddr, 16);

        /* MVP: L4 parse only if no ext headers (best effort) */
        bool is_tcp=false, is_udp=false, is_icmp=false;
        bool syn=false, synack=false, rst=false, ack=false;
        __u16 dport = 0, sport = 0;
        __u8 tcp_flags = 0;

        __u64 l4off = off + sizeof(struct ipv6hdr);
        __u8 nh = ip6->nexthdr;

        if (nh == IPPROTO_TCP) {
            is_tcp = true;
            if (t) t->tcp++;
            if (data + l4off + sizeof(struct tcphdr) <= data_end) {
                struct tcphdr *th = data + l4off;
                dport = th->dest;
                sport = th->source;

                if (th->fin) tcp_flags |= TCP_F_FIN;
                if (th->syn) tcp_flags |= TCP_F_SYN;
                if (th->rst) tcp_flags |= TCP_F_RST;
                if (th->psh) tcp_flags |= TCP_F_PSH;
                if (th->ack) tcp_flags |= TCP_F_ACK;
                if (th->urg) tcp_flags |= TCP_F_URG;
                if (th->ece) tcp_flags |= TCP_F_ECE;
                if (th->cwr) tcp_flags |= TCP_F_CWR;

                syn = th->syn;
                rst = th->rst;
                ack = th->ack;
                synack = th->syn && th->ack;

                if (t && syn) t->syn++;
                if (t && synack) t->synack++;
                if (t && rst) t->rst++;
                if (t && ack) t->ack++;
            }
        } else if (nh == IPPROTO_UDP) {
            is_udp = true;
            if (t) t->udp++;
            if (data + l4off + sizeof(struct udphdr) <= data_end) {
                struct udphdr *uh = data + l4off;
                dport = uh->dest;
                sport = uh->source;
            }
        } else if (nh == IPPROTO_ICMPV6) {
            is_icmp = true;
            if (t) t->icmp++;
        }

        bool drop_allow=false, drop_deny=false, drop_rl=false;

        if (enforce) {
            if (!in_allow_v6(saddr6)) drop_allow = true;
            else if (t) t->allow_hits++;
        }

        if (!drop_allow) {
            if (in_deny_v6(saddr6)) {
                drop_deny = true;
                if (t) t->deny_hits++;
            }
        }

        if (!drop_allow && !drop_deny) {
            const struct rl_cfg_t *use = select_rl_v6(saddr6);
            if (use) {
                if (t) t->rl_hits++;
                struct src6_key k6 = {};
                __builtin_memcpy(k6.ip, saddr6, 16);

                struct rl_state_t *st6 = bpf_map_lookup_elem(&xdp_rl_state6, &k6);
                if (!st6) {
                    __u64 init_tokens = (use->burst > 0) ? (use->burst - 1) : 0;
                    struct rl_state_t init = { .last_ns = now, .tokens = init_tokens };
                    bpf_map_update_elem(&xdp_rl_state6, &k6, &init, BPF_ANY);
                } else {
                    if (!tb_allow_and_update(st6, use, now))
                        drop_rl = true;
                }
            }
        }

        int action = (drop_allow || drop_deny || drop_rl) ? XDP_DROP : XDP_PASS;

        if (t) {
            if (action == XDP_PASS) t->pass++;
            else if (drop_allow)    t->drop_allow++;
            else if (drop_deny)     t->drop_deny++;
            else                    t->drop_rl++;
        }

        hist_port_add(dport, pkt_len, action == XDP_DROP);

        int upd = src6_update(saddr6, pkt_len, now,
                              is_tcp, is_udp, is_icmp,
                              syn, synack, rst, ack,
                              sport, dport,
                              ip6->hop_limit, tcp_flags,
                              action == XDP_PASS,
                              drop_allow, drop_deny, drop_rl);

        if ((upd & 2) && t) t->new_sources++;
        if ((upd & 1) && t) {
            t->dport_changes++;
            maybe_emit_event_v6(EV_SCAN_HINT, sample_mask, saddr6, nh, dport, (__u32)pkt_len, 1);
        }

        if (drop_allow)
            maybe_emit_event_v6(EV_DROP_ALLOW, sample_mask, saddr6, nh, dport, (__u32)pkt_len, 0);
        else if (drop_deny)
            maybe_emit_event_v6(EV_DROP_DENY, sample_mask, saddr6, nh, dport, (__u32)pkt_len, 0);
        else if (drop_rl)
            maybe_emit_event_v6(EV_DROP_RL, sample_mask, saddr6, nh, dport, (__u32)pkt_len, 0);

        return action;
    }

    if (t) t->pass++;
    return XDP_PASS;
}
