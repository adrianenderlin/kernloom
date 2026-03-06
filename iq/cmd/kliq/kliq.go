// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

/*
Kernloom IQ (kliq) — controller for Kernloom Shield (XDP) with:
- Progressive enforcement: OBSERVE -> SOFT -> HARD -> BLOCK
- Anti-flap: up/down streaks + minimum hold
- Non-compliance: if DropRL/s stays > 0 while in HARD -> go BLOCK faster
- Autotune: learn trig-pps/trig-syn/trig-scan using Median+MAD (robust)
- Anti-poisoning: learn only during "clean ticks" (incl optional total drop-ratio gating)
- Persistence: versioned state.json with atomic writes; load on startup
- Whitelist: exclude specific IPs/CIDRs from enforcement (and optionally from learning)
- Feedback: temporary exemptions (forgive/whitelist) + optional CIDR de-enforcement scan

Pinned maps (defaults, from Kernloom Shield):
  Telemetry:
    /sys/fs/bpf/kernloom_src4_stats     (key=[4]byte  => IPv4)
    /sys/fs/bpf/kernloom_src6_stats     (key=src6Key  => IPv6)
    /sys/fs/bpf/kernloom_totals         (per-cpu array, optional for learn gating)
  Enforcement:
    /sys/fs/bpf/kernloom_deny4_hash     (key=[4]byte, value=u8)
    /sys/fs/bpf/kernloom_deny6_hash     (key=key6Bytes, value=u8)
    /sys/fs/bpf/kernloom_rl_policy4     (key=[4]byte, value={u64 rate_pps, u64 burst})
    /sys/fs/bpf/kernloom_rl_policy6     (key=src6Key, value={u64 rate_pps, u64 burst})

NOTE:
  The upstream documentation may state "IPv4 only". This build wires IPv6 into the same flow:
  - reads src6 telemetry
  - applies per-IP RL and deny entries for IPv6
  - supports IPv6 in whitelist + feedback inputs
*/

const (
	// Telemetry
	mapPinSrc4   = "/sys/fs/bpf/kernloom_src4_stats"
	mapPinSrc6   = "/sys/fs/bpf/kernloom_src6_stats"
	mapPinTotals = "/sys/fs/bpf/kernloom_totals"

	// Enforcement
	mapPinDeny4     = "/sys/fs/bpf/kernloom_deny4_hash"
	mapPinDeny6     = "/sys/fs/bpf/kernloom_deny6_hash"
	mapPinRLPolicy4 = "/sys/fs/bpf/kernloom_rl_policy4"
	mapPinRLPolicy6 = "/sys/fs/bpf/kernloom_rl_policy6"
)

/* ---------------- Types (must match Shield C layouts) ---------------- */

// MUST match Shield per-source v4 stats layout + explicit padding.
type xdpSrcStatsV4 struct {
	Pkts  uint64
	Bytes uint64

	Tcp  uint64
	Udp  uint64
	Icmp uint64

	Syn    uint64
	Synack uint64
	Rst    uint64
	Ack    uint64

	Pass      uint64
	DropAllow uint64
	DropDeny  uint64
	DropRL    uint64

	FirstSeenNs uint64
	LastSeenNs  uint64

	LastSport uint16
	LastDport uint16
	Pad0      [4]byte

	DportChanges uint64

	LastTTL      uint8
	LastTCPFlags uint8
	Pad1         [2]byte
	Pad2         [4]byte
}

// MUST match Shield per-source v6 stats layout (xdp_src_stats_v6_t).
type xdpSrcStatsV6 struct {
	Pkts  uint64
	Bytes uint64

	Tcp  uint64
	Udp  uint64
	Icmp uint64

	Syn    uint64
	Synack uint64
	Rst    uint64
	Ack    uint64

	Pass      uint64
	DropAllow uint64
	DropDeny  uint64
	DropRL    uint64

	FirstSeenNs uint64
	LastSeenNs  uint64

	LastSport uint16
	LastDport uint16
	Pad0      [4]byte

	DportChanges uint64

	LastHLIM     uint8
	LastTCPFlags uint8
	Pad1         [2]byte
	Pad2         [4]byte // tail padding (struct align 8)
}

// Totals: MUST match Shield layout for xdp_totals_t.
type xdpTotals struct {
	Pkts       uint64
	Bytes      uint64
	Pass       uint64
	DropAllow  uint64
	DropDeny   uint64
	DropRL     uint64
	V4         uint64
	V6         uint64
	TCP        uint64
	UDP        uint64
	ICMP       uint64
	SYN        uint64
	SYNACK     uint64
	RST        uint64
	ACK        uint64
	IPv4Frags  uint64
	DportChg   uint64
	NewSources uint64
	AllowHits  uint64
	DenyHits   uint64
	RLHits     uint64
}

// RL policy value for Shield.
type rlCfg struct {
	RatePPS uint64
	Burst   uint64
}

// Keys
type src6Key struct{ IP [16]byte }
type key6Bytes struct{ IP [16]byte }

// ---- FSM levels ----
type Level int

const (
	LObserve Level = iota
	LSoft
	LHard
	LBlock
)

func (l Level) String() string {
	switch l {
	case LObserve:
		return "OBSERVE"
	case LSoft:
		return "RATE_SOFT"
	case LHard:
		return "RATE_HARD"
	case LBlock:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

type ipState struct {
	Level         Level
	Strikes       int
	ExpiresAt     time.Time
	CooldownUntil time.Time
	LastTrigger   time.Time

	HighSevSince     time.Time
	LastSeenWallTime time.Time

	UpStreak   int
	DownStreak int

	NonCompTicks int
}

// ---- prev snapshots for deltas ----
type prevV4 struct {
	Pkts, Bytes, Syn, Scan, DropRL uint64
	LastWall                       time.Time
}

type prevV6 struct {
	Pkts, Bytes, Syn, Scan, DropRL uint64
	LastWall                       time.Time
}

type metrics struct {
	IPVer uint8
	IP4   [4]byte
	IP6   [16]byte

	PPS        float64
	Bps        float64
	SynRate    float64
	ScanRate   float64
	DropRLRate float64
	Severity   float64
}

func (m metrics) ipString() string {
	if m.IPVer == 6 {
		return net.IP(m.IP6[:]).String()
	}
	return net.IPv4(m.IP4[0], m.IP4[1], m.IP4[2], m.IP4[3]).String()
}

/* ---------------- Whitelist ---------------- */

type whitelist struct {
	exact4 map[[4]byte]struct{}
	exact6 map[[16]byte]struct{}
	cidrs4 []*net.IPNet
	cidrs6 []*net.IPNet

	path      string
	modTime   time.Time
	lastCheck time.Time
}

func newWhitelist(path string) *whitelist {
	return &whitelist{
		exact4: make(map[[4]byte]struct{}),
		exact6: make(map[[16]byte]struct{}),
		cidrs4: make([]*net.IPNet, 0, 64),
		cidrs6: make([]*net.IPNet, 0, 64),
		path:   path,
	}
}

func (w *whitelist) matchV4(ip4 [4]byte) bool {
	if _, ok := w.exact4[ip4]; ok {
		return true
	}
	if len(w.cidrs4) == 0 {
		return false
	}
	ip := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
	for _, n := range w.cidrs4 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (w *whitelist) matchV6(ip6 [16]byte) bool {
	if _, ok := w.exact6[ip6]; ok {
		return true
	}
	if len(w.cidrs6) == 0 {
		return false
	}
	ip := net.IP(ip6[:])
	for _, n := range w.cidrs6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseWhitelistLine(line string) (family int, isCIDR bool, ip4 [4]byte, ip6 [16]byte, n *net.IPNet, ok bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return 0, false, ip4, ip6, nil, false
	}
	// strip inline comments
	if i := strings.Index(s, "#"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return 0, false, ip4, ip6, nil, false
	}

	// CIDR?
	if strings.Contains(s, "/") {
		_, nn, err := net.ParseCIDR(s)
		if err != nil || nn == nil {
			return 0, false, ip4, ip6, nil, false
		}
		if nn.IP.To4() != nil {
			return 4, true, ip4, ip6, nn, true
		}
		// v6
		ip16 := nn.IP.To16()
		if ip16 == nil {
			return 0, false, ip4, ip6, nil, false
		}
		return 6, true, ip4, ip6, nn, true
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return 0, false, ip4, ip6, nil, false
	}
	if v4 := ip.To4(); v4 != nil {
		copy(ip4[:], v4[:4])
		return 4, false, ip4, ip6, nil, true
	}
	v6p := ip.To16()
	if v6p == nil {
		return 0, false, ip4, ip6, nil, false
	}
	copy(ip6[:], v6p[:16])
	return 6, false, ip4, ip6, nil, true
}

func (w *whitelist) load() error {
	if w.path == "" {
		return nil
	}
	raw, err := os.ReadFile(w.path)
	if err != nil {
		return err
	}

	ex4 := make(map[[4]byte]struct{}, 256)
	ex6 := make(map[[16]byte]struct{}, 256)
	cidrs4 := make([]*net.IPNet, 0, 64)
	cidrs6 := make([]*net.IPNet, 0, 64)

	lines := strings.Split(string(raw), "\n")
	for _, ln := range lines {
		fam, isCIDR, ip4, ip6, n, ok := parseWhitelistLine(ln)
		if !ok {
			continue
		}
		if isCIDR {
			if fam == 4 {
				cidrs4 = append(cidrs4, n)
			} else if fam == 6 {
				cidrs6 = append(cidrs6, n)
			}
			continue
		}
		if fam == 4 {
			ex4[ip4] = struct{}{}
		} else if fam == 6 {
			ex6[ip6] = struct{}{}
		}
	}

	w.exact4 = ex4
	w.exact6 = ex6
	w.cidrs4 = cidrs4
	w.cidrs6 = cidrs6
	return nil
}

func (w *whitelist) maybeReload(every time.Duration) {
	if w.path == "" || every <= 0 {
		return
	}
	now := time.Now()
	if !w.lastCheck.IsZero() && now.Sub(w.lastCheck) < every {
		return
	}
	w.lastCheck = now

	fi, err := os.Stat(w.path)
	if err != nil {
		return
	}
	if fi.ModTime().Equal(w.modTime) {
		return
	}
	if err := w.load(); err == nil {
		w.modTime = fi.ModTime()
		log.Printf("Whitelist reloaded: %s entries4=%d cidrs4=%d entries6=%d cidrs6=%d", w.path, len(w.exact4), len(w.cidrs4), len(w.exact6), len(w.cidrs6))
	}
}

/* ---------------- Feedback / Forgive ---------------- */

type fbCIDR struct {
	net   *net.IPNet
	until time.Time
	fam   int // 4 or 6
}

type feedbackManager struct {
	path      string
	modTime   time.Time
	lastCheck time.Time

	exact4 map[[4]byte]time.Time
	exact6 map[[16]byte]time.Time
	cidrs4 []fbCIDR
	cidrs6 []fbCIDR

	lastCIDRApply time.Time
}

type feedbackEntry struct {
	Target string `json:"target"`
	Action string `json:"action"` // forgive|whitelist
	TTL    string `json:"ttl,omitempty"`
	Until  string `json:"until,omitempty"` // RFC3339
	Notes  string `json:"notes,omitempty"`
}

func newFeedbackManager(path string) *feedbackManager {
	return &feedbackManager{
		path:   path,
		exact4: make(map[[4]byte]time.Time, 64),
		exact6: make(map[[16]byte]time.Time, 64),
		cidrs4: make([]fbCIDR, 0, 32),
		cidrs6: make([]fbCIDR, 0, 32),
	}
}

func parseFBTarget(s string) (family int, isCIDR bool, ip4 [4]byte, ip6 [16]byte, n *net.IPNet, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false, ip4, ip6, nil, false
	}
	if strings.Contains(s, "/") {
		_, nn, err := net.ParseCIDR(s)
		if err != nil || nn == nil {
			return 0, false, ip4, ip6, nil, false
		}
		if nn.IP.To4() != nil {
			return 4, true, ip4, ip6, nn, true
		}
		ip16 := nn.IP.To16()
		if ip16 == nil {
			return 0, false, ip4, ip6, nil, false
		}
		return 6, true, ip4, ip6, nn, true
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return 0, false, ip4, ip6, nil, false
	}
	if v4 := ip.To4(); v4 != nil {
		copy(ip4[:], v4[:4])
		return 4, false, ip4, ip6, nil, true
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return 0, false, ip4, ip6, nil, false
	}
	copy(ip6[:], ip16[:16])
	return 6, false, ip4, ip6, nil, true
}

func (fm *feedbackManager) load(now time.Time) error {
	if fm.path == "" {
		return nil
	}
	raw, err := os.ReadFile(fm.path)
	if err != nil {
		return err
	}

	var entries []feedbackEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}

	ex4 := make(map[[4]byte]time.Time, 256)
	ex6 := make(map[[16]byte]time.Time, 256)
	cidrs4 := make([]fbCIDR, 0, 64)
	cidrs6 := make([]fbCIDR, 0, 64)

	for _, e := range entries {
		target := strings.TrimSpace(e.Target)
		if target == "" {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(e.Action))
		if action == "" {
			action = "forgive"
		}
		if action != "forgive" && action != "whitelist" {
			continue
		}

		var until time.Time
		if e.Until != "" {
			if t, err := time.Parse(time.RFC3339, e.Until); err == nil {
				until = t
			}
		}
		if until.IsZero() {
			ttl := 24 * time.Hour
			if e.TTL != "" {
				if d, err := time.ParseDuration(e.TTL); err == nil && d > 0 {
					ttl = d
				}
			}
			until = now.Add(ttl)
		}

		fam, isCIDR, ip4, ip6, n, ok := parseFBTarget(target)
		if !ok {
			continue
		}
		if isCIDR {
			if fam == 4 {
				cidrs4 = append(cidrs4, fbCIDR{net: n, until: until, fam: 4})
			} else if fam == 6 {
				cidrs6 = append(cidrs6, fbCIDR{net: n, until: until, fam: 6})
			}
			continue
		}
		if fam == 4 {
			ex4[ip4] = until
		} else if fam == 6 {
			ex6[ip6] = until
		}
	}

	fm.exact4 = ex4
	fm.exact6 = ex6
	fm.cidrs4 = cidrs4
	fm.cidrs6 = cidrs6
	return nil
}

func (fm *feedbackManager) maybeReload(every time.Duration) {
	if fm.path == "" || every <= 0 {
		return
	}
	now := time.Now()
	if !fm.lastCheck.IsZero() && now.Sub(fm.lastCheck) < every {
		return
	}
	fm.lastCheck = now

	fi, err := os.Stat(fm.path)
	if err != nil {
		return
	}
	if fi.ModTime().Equal(fm.modTime) {
		return
	}
	if err := fm.load(now); err == nil {
		fm.modTime = fi.ModTime()
		log.Printf("Feedback reloaded: %s entries4=%d cidrs4=%d entries6=%d cidrs6=%d", fm.path, len(fm.exact4), len(fm.cidrs4), len(fm.exact6), len(fm.cidrs6))
	}
}

func (fm *feedbackManager) matchV4(ip4 [4]byte) bool {
	if fm.path == "" {
		return false
	}
	now := time.Now()
	if until, ok := fm.exact4[ip4]; ok {
		if now.Before(until) {
			return true
		}
		delete(fm.exact4, ip4)
		return false
	}
	if len(fm.cidrs4) == 0 {
		return false
	}
	ip := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
	keep := fm.cidrs4[:0]
	matched := false
	for _, c := range fm.cidrs4 {
		if now.After(c.until) {
			continue
		}
		keep = append(keep, c)
		if !matched && c.net.Contains(ip) {
			matched = true
		}
	}
	fm.cidrs4 = keep
	return matched
}

func (fm *feedbackManager) matchV6(ip6 [16]byte) bool {
	if fm.path == "" {
		return false
	}
	now := time.Now()
	if until, ok := fm.exact6[ip6]; ok {
		if now.Before(until) {
			return true
		}
		delete(fm.exact6, ip6)
		return false
	}
	if len(fm.cidrs6) == 0 {
		return false
	}
	ip := net.IP(ip6[:])
	keep := fm.cidrs6[:0]
	matched := false
	for _, c := range fm.cidrs6 {
		if now.After(c.until) {
			continue
		}
		keep = append(keep, c)
		if !matched && c.net.Contains(ip) {
			matched = true
		}
	}
	fm.cidrs6 = keep
	return matched
}

// applyV4 best-effort de-enforcement for exact feedback IPs (v4).
func (fm *feedbackManager) applyV4(now time.Time, denyMap4, rlPolicyMap4 *ebpf.Map, state4 map[[4]byte]ipState, dry bool) {
	if fm.path == "" {
		return
	}
	for ip, until := range fm.exact4 {
		if now.After(until) {
			delete(fm.exact4, ip)
			continue
		}
		if dry {
			continue
		}
		if rlPolicyMap4 != nil {
			_ = rlPolicyMap4.Delete(&ip)
		}
		if denyMap4 != nil {
			_ = denyMap4.Delete(&ip)
		}
		if st, ok := state4[ip]; ok {
			if st.Level != LObserve {
				st.Level = LObserve
			}
			st.Strikes = 0
			st.NonCompTicks = 0
			st.UpStreak = 0
			st.DownStreak = 0
			st.HighSevSince = time.Time{}
			st.ExpiresAt = time.Time{}
			state4[ip] = st
		}
	}
}

// applyV6 best-effort de-enforcement for exact feedback IPs (v6).
func (fm *feedbackManager) applyV6(now time.Time, denyMap6, rlPolicyMap6 *ebpf.Map, state6 map[[16]byte]ipState, dry bool) {
	if fm.path == "" {
		return
	}
	for ip, until := range fm.exact6 {
		if now.After(until) {
			delete(fm.exact6, ip)
			continue
		}
		if dry {
			continue
		}
		if rlPolicyMap6 != nil {
			krl := src6Key{IP: ip}
			_ = rlPolicyMap6.Delete(&krl)
		}
		if denyMap6 != nil {
			kd := key6Bytes{IP: ip}
			_ = denyMap6.Delete(&kd)
		}
		if st, ok := state6[ip]; ok {
			if st.Level != LObserve {
				st.Level = LObserve
			}
			st.Strikes = 0
			st.NonCompTicks = 0
			st.UpStreak = 0
			st.DownStreak = 0
			st.HighSevSince = time.Time{}
			st.ExpiresAt = time.Time{}
			state6[ip] = st
		}
	}
}

/* ---------------- Autotune reservoir ---------------- */

type reservoir struct {
	data   []float64
	cap    int
	seen   int
	rnd    *rand.Rand
	seeded bool
}

func newReservoir(capacity int) *reservoir {
	return &reservoir{cap: capacity, data: make([]float64, 0, capacity)}
}

func (r *reservoir) ensureSeed() {
	if r.seeded {
		return
	}
	r.seeded = true
	r.rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func (r *reservoir) Add(x float64) {
	if math.IsNaN(x) || math.IsInf(x, 0) || x < 0 {
		return
	}
	r.ensureSeed()
	r.seen++
	if len(r.data) < r.cap {
		r.data = append(r.data, x)
		return
	}
	j := r.rnd.Intn(r.seen)
	if j < r.cap {
		r.data[j] = x
	}
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := make([]float64, len(xs))
	copy(cp, xs)
	sort.Float64s(cp)
	m := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[m]
	}
	return (cp[m-1] + cp[m]) / 2
}

func mad(xs []float64, m float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	dev := make([]float64, len(xs))
	for i, x := range xs {
		dev[i] = math.Abs(x - m)
	}
	return median(dev)
}

/* ---------------- Persistence (state.json) ---------------- */

type trigState struct {
	TrigPPS  float64 `json:"trig_pps"`
	TrigSyn  float64 `json:"trig_syn"`
	TrigScan float64 `json:"trig_scan"`
}

type tuneMeta struct {
	Method      string  `json:"method"`
	Window      string  `json:"window"`
	K           float64 `json:"k"`
	SigmaFactor float64 `json:"sigma_factor"`
}

type bootstrapInfo struct {
	Enabled   bool      `json:"enabled"`
	StartedAt time.Time `json:"started_at"`
	Window    string    `json:"window,omitempty"`
	Phase     string    `json:"phase,omitempty"`
}

type stateActive struct {
	Profile     string        `json:"profile"`
	Revision    int           `json:"revision"`
	UpdatedAt   time.Time     `json:"updated_at"`
	Trig        trigState     `json:"trig"`
	Tune        tuneMeta      `json:"tune"`
	Bootstrap   bootstrapInfo `json:"bootstrap,omitempty"`
	SampleCount int           `json:"sample_count"`
	CleanRatio  float64       `json:"clean_ratio"`
	Notes       string        `json:"notes,omitempty"`
}

type stateHistory struct {
	Revision    int       `json:"revision"`
	At          time.Time `json:"at"`
	Trig        trigState `json:"trig"`
	MedianPPS   float64   `json:"median_pps"`
	MadPPS      float64   `json:"mad_pps"`
	MedianSyn   float64   `json:"median_syn"`
	MadSyn      float64   `json:"mad_syn"`
	MedianScan  float64   `json:"median_scan"`
	MadScan     float64   `json:"mad_scan"`
	SampleCount int       `json:"sample_count"`
	CleanRatio  float64   `json:"clean_ratio"`
	Notes       string    `json:"notes,omitempty"`
}

type integrity struct {
	SHA256 string `json:"sha256"`
}

type stateFile struct {
	Version   int            `json:"version"`
	Generated time.Time      `json:"generated_at"`
	Active    stateActive    `json:"active"`
	History   []stateHistory `json:"history"`
	Integrity integrity      `json:"integrity"`
}

func computeSHA256NoIntegrity(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeStateAtomic(path string, st *stateFile) error {
	tmp := *st
	tmp.Integrity = integrity{}
	tmp.Generated = time.Now()

	rawNoInt, err := json.MarshalIndent(&tmp, "", "  ")
	if err != nil {
		return err
	}

	st.Integrity = integrity{SHA256: computeSHA256NoIntegrity(rawNoInt)}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	bakPath := path + ".bak"

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if _, err := os.Stat(path); err == nil {
		_ = os.Rename(path, bakPath)
	}

	return os.Rename(tmpPath, path)
}

func loadState(path string, maxAge time.Duration) (*stateFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var st stateFile
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}

	tmp := st
	tmp.Integrity = integrity{}
	rawNoInt, _ := json.MarshalIndent(&tmp, "", "  ")
	want := computeSHA256NoIntegrity(rawNoInt)
	if st.Integrity.SHA256 != "" && st.Integrity.SHA256 != want {
		return nil, fmt.Errorf("state integrity mismatch")
	}

	if maxAge > 0 && !st.Active.UpdatedAt.IsZero() {
		if time.Since(st.Active.UpdatedAt) > maxAge {
			return nil, fmt.Errorf("state too old (%s)", time.Since(st.Active.UpdatedAt).String())
		}
	}
	return &st, nil
}

/* ---------------- Profiles ---------------- */

type profile struct {
	Name string

	TrigPPS  float64
	TrigSyn  float64
	TrigScan float64

	WPPS   float64
	WSyn   float64
	WScan  float64
	SevCap float64

	SoftAt  int
	HardAt  int
	BlockAt int

	SoftRate  uint64
	SoftBurst uint64
	SoftTTL   time.Duration

	HardRate  uint64
	HardBurst uint64
	HardTTL   time.Duration

	BlockTTL time.Duration
	Cooldown time.Duration

	BlockMinSev float64
	BlockMinDur time.Duration

	UpNeed      int
	DownNeed    int
	MinHoldSoft time.Duration
	MinHoldHard time.Duration

	NonCompAt    int
	NonCompDrop  float64
	NonCompSev   float64
	NonCompReset float64
}

func profileByName(name string) profile {
	n := strings.ToLower(strings.TrimSpace(name))

	// Backward-compatible aliases
	switch n {
	case "router":
		n = "ziti-router"
	case "controller", "ziri-controller":
		n = "ziti-controller"
	case "internal":
		n = "internal-app"
	}

	switch n {

	// =========================
	// OpenZiti Profiles
	// =========================

	case "ziti-router":
		// High throughput / many data packets, NAT-friendly. Block only if sustained.
		return profile{
			Name:    "ziti-router",
			TrigPPS: 8000, TrigSyn: 200, TrigScan: 30,
			WPPS: 0.60, WSyn: 0.25, WScan: 0.15, SevCap: 3.0,
			SoftAt: 2, HardAt: 5, BlockAt: 12,
			SoftRate: 3000, SoftBurst: 6000, SoftTTL: 30 * time.Second,
			HardRate: 800, HardBurst: 1600, HardTTL: 2 * time.Minute,
			BlockTTL: 10 * time.Minute, Cooldown: 8 * time.Second,
			BlockMinSev: 3.0, BlockMinDur: 60 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 20 * time.Second, MinHoldHard: 45 * time.Second,
			NonCompAt: 20, NonCompDrop: 20, NonCompSev: 2.5, NonCompReset: 0.30,
		}

	case "ziti-controller":
		// Public enrolment/API surface. More SYN-sensitive, cautious blocking.
		return profile{
			Name:    "ziti-controller",
			TrigPPS: 80, TrigSyn: 20, TrigScan: 5,
			WPPS: 0.35, WSyn: 0.40, WScan: 0.25, SevCap: 3.0,
			SoftAt: 1, HardAt: 3, BlockAt: 9,
			SoftRate: 20, SoftBurst: 40, SoftTTL: 60 * time.Second,
			HardRate: 5, HardBurst: 10, HardTTL: 10 * time.Minute,
			BlockTTL: 30 * time.Minute, Cooldown: 5 * time.Second,
			BlockMinSev: 2.0, BlockMinDur: 15 * time.Second,
			UpNeed: 2, DownNeed: 6, MinHoldSoft: 15 * time.Second, MinHoldHard: 30 * time.Second,
			NonCompAt: 8, NonCompDrop: 1.0, NonCompSev: 1.5, NonCompReset: 0.30,
		}

	// -------------------------
	// Bootstrap variants (safe start)
	// -------------------------

	case "ziti-router-bootstrap":
		// Start tolerant (high trig-*), prefer rate-limit, avoid blocks early.
		return profile{
			Name:    "ziti-router-bootstrap",
			TrigPPS: 25000, TrigSyn: 600, TrigScan: 120,
			WPPS: 0.60, WSyn: 0.25, WScan: 0.15, SevCap: 3.0,
			SoftAt: 3, HardAt: 8, BlockAt: 999, // avoid blocking during bootstrap
			SoftRate: 6000, SoftBurst: 12000, SoftTTL: 45 * time.Second,
			HardRate: 1500, HardBurst: 3000, HardTTL: 3 * time.Minute,
			BlockTTL: 10 * time.Minute, Cooldown: 10 * time.Second,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 3, DownNeed: 10, MinHoldSoft: 30 * time.Second, MinHoldHard: 60 * time.Second,
			NonCompAt: 40, NonCompDrop: 50, NonCompSev: 2.5, NonCompReset: 0.30,
		}

	case "ziti-controller-bootstrap":
		// Start tolerant to avoid FPs during onboarding. Rate-limit earlier, block disabled by default.
		return profile{
			Name:    "ziti-controller-bootstrap",
			TrigPPS: 400, TrigSyn: 120, TrigScan: 30,
			WPPS: 0.35, WSyn: 0.45, WScan: 0.20, SevCap: 3.0,
			SoftAt: 2, HardAt: 6, BlockAt: 999,
			SoftRate: 60, SoftBurst: 120, SoftTTL: 90 * time.Second,
			HardRate: 20, HardBurst: 40, HardTTL: 10 * time.Minute,
			BlockTTL: 30 * time.Minute, Cooldown: 8 * time.Second,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 3, DownNeed: 8, MinHoldSoft: 30 * time.Second, MinHoldHard: 60 * time.Second,
			NonCompAt: 12, NonCompDrop: 2.0, NonCompSev: 1.5, NonCompReset: 0.30,
		}

	// =========================
	// Generic Public-Facing
	// =========================

	case "public-web":
		// Public website (HTTP/HTTPS). Mostly PPS + SYN. Port-scan less relevant.
		return profile{
			Name:    "public-web",
			TrigPPS: 1200, TrigSyn: 250, TrigScan: 20,
			WPPS: 0.55, WSyn: 0.30, WScan: 0.15, SevCap: 3.0,
			SoftAt: 2, HardAt: 5, BlockAt: 12,
			SoftRate: 500, SoftBurst: 1500, SoftTTL: 60 * time.Second,
			HardRate: 120, HardBurst: 300, HardTTL: 10 * time.Minute,
			BlockTTL: 10 * time.Minute, Cooldown: 10 * time.Second,
			BlockMinSev: 2.8, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 20 * time.Second, MinHoldHard: 45 * time.Second,
			NonCompAt: 15, NonCompDrop: 10, NonCompSev: 2.0, NonCompReset: 0.30,
		}

	case "public-api":
		// Public JSON/API endpoint: bursty, higher PPS.
		return profile{
			Name:    "public-api",
			TrigPPS: 2500, TrigSyn: 500, TrigScan: 30,
			WPPS: 0.55, WSyn: 0.30, WScan: 0.15, SevCap: 3.0,
			SoftAt: 2, HardAt: 4, BlockAt: 10,
			SoftRate: 1000, SoftBurst: 2500, SoftTTL: 60 * time.Second,
			HardRate: 300, HardBurst: 600, HardTTL: 10 * time.Minute,
			BlockTTL: 15 * time.Minute, Cooldown: 10 * time.Second,
			BlockMinSev: 2.8, BlockMinDur: 25 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 20 * time.Second, MinHoldHard: 45 * time.Second,
			NonCompAt: 12, NonCompDrop: 15, NonCompSev: 2.0, NonCompReset: 0.30,
		}

	case "idp":
		// Identity Provider / Auth endpoints: SYN-sensitive, protect against auth abuse. NAT-friendly gating.
		return profile{
			Name:    "idp",
			TrigPPS: 350, TrigSyn: 180, TrigScan: 10,
			WPPS: 0.30, WSyn: 0.55, WScan: 0.15, SevCap: 3.0,
			SoftAt: 1, HardAt: 3, BlockAt: 8,
			SoftRate: 50, SoftBurst: 100, SoftTTL: 2 * time.Minute,
			HardRate: 10, HardBurst: 20, HardTTL: 15 * time.Minute,
			BlockTTL: 30 * time.Minute, Cooldown: 8 * time.Second,
			BlockMinSev: 2.5, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 8, MinHoldSoft: 30 * time.Second, MinHoldHard: 60 * time.Second,
			NonCompAt: 10, NonCompDrop: 1.0, NonCompSev: 1.8, NonCompReset: 0.30,
		}

	// =========================
	// Generic Internal / East-West
	// =========================

	case "internal-app":
		// Internal app: scanning/lateral movement more relevant; avoid blocking by default.
		return profile{
			Name:    "internal-app",
			TrigPPS: 800, TrigSyn: 150, TrigScan: 8,
			WPPS: 0.25, WSyn: 0.20, WScan: 0.55, SevCap: 3.0,
			SoftAt: 3, HardAt: 6, BlockAt: 999,
			SoftRate: 200, SoftBurst: 400, SoftTTL: 3 * time.Minute,
			HardRate: 50, HardBurst: 100, HardTTL: 15 * time.Minute,
			BlockTTL: 10 * time.Minute, Cooldown: 15 * time.Second,
			BlockMinSev: 0, BlockMinDur: 0,
			UpNeed: 2, DownNeed: 10, MinHoldSoft: 45 * time.Second, MinHoldHard: 2 * time.Minute,
			NonCompAt: 999, NonCompDrop: 999, NonCompSev: 999, NonCompReset: 0.30,
		}

	case "ssh-bastion":
		// Protect SSH/bastion: low normal PPS, suspicious SYN/scan. Blocking ok but gated.
		return profile{
			Name:    "ssh-bastion",
			TrigPPS: 60, TrigSyn: 25, TrigScan: 5,
			WPPS: 0.30, WSyn: 0.55, WScan: 0.15, SevCap: 3.0,
			SoftAt: 1, HardAt: 2, BlockAt: 6,
			SoftRate: 5, SoftBurst: 10, SoftTTL: 5 * time.Minute,
			HardRate: 1, HardBurst: 3, HardTTL: 30 * time.Minute,
			BlockTTL: 60 * time.Minute, Cooldown: 20 * time.Second,
			BlockMinSev: 2.0, BlockMinDur: 30 * time.Second,
			UpNeed: 2, DownNeed: 10, MinHoldSoft: 60 * time.Second, MinHoldHard: 5 * time.Minute,
			NonCompAt: 6, NonCompDrop: 0.5, NonCompSev: 1.5, NonCompReset: 0.30,
		}

	default:
		return profileByName("ziti-controller")
	}
}

/* ---------------- misc helpers ---------------- */

func openPinnedMap(path string) (*ebpf.Map, error) { return ebpf.LoadPinnedMap(path, nil) }

func ip4String(k [4]byte) string  { return net.IPv4(k[0], k[1], k[2], k[3]).String() }
func ip6String(k [16]byte) string { return net.IP(k[:]).String() }

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func calcSeverity(pps, synps, scanps float64, trigPPS, trigSyn, trigScan float64, wPPS, wSyn, wScan float64, cap float64) float64 {
	nPPS := 0.0
	if trigPPS > 0 {
		nPPS = minf(pps/trigPPS, cap)
	}
	nSyn := 0.0
	if trigSyn > 0 {
		nSyn = minf(synps/trigSyn, cap)
	}
	nScan := 0.0
	if trigScan > 0 {
		nScan = minf(scanps/trigScan, cap)
	}
	return wPPS*nPPS + wSyn*nSyn + wScan*nScan
}

func capChange(old, target, maxRel float64) float64 {
	if maxRel <= 0 {
		return target
	}
	lo := old * (1 - maxRel)
	hi := old * (1 + maxRel)
	if target < lo {
		return lo
	}
	if target > hi {
		return hi
	}
	return target
}

// capChangeDir applies different relative caps depending on direction.
// - If target > old: maxUp is used.
// - If target < old: maxDown is used.
func capChangeDir(old, target, maxUp, maxDown float64) float64 {
	if target >= old {
		return capChange(old, target, maxUp)
	}
	return capChange(old, target, maxDown)
}

type bootstrapPolicy struct {
	Active  bool
	Phase   string
	Every   time.Duration
	K       float64
	MaxUp   float64
	MaxDown float64
	Alpha   float64
}

func bootstrapEffective(now time.Time, info bootstrapInfo, window, p1End, p2End time.Duration,
	every1, every2, every3 time.Duration,
	kStart, kFinal float64,
	maxUp1, maxDown1, maxUp2, maxDown2, maxUp3, maxDown3 float64,
	alpha1, alpha2, alpha3 float64,
	steadyEvery time.Duration, steadyK, steadyUp, steadyDown, steadyAlpha float64,
) bootstrapPolicy {
	if !info.Enabled || info.StartedAt.IsZero() || window <= 0 {
		return bootstrapPolicy{Active: false, Phase: "steady", Every: steadyEvery, K: steadyK, MaxUp: steadyUp, MaxDown: steadyDown, Alpha: steadyAlpha}
	}
	age := now.Sub(info.StartedAt)
	if age < 0 {
		age = 0
	}
	progress := float64(age) / float64(window)
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	k := kStart + (kFinal-kStart)*progress

	if age < p1End {
		return bootstrapPolicy{Active: true, Phase: "bootstrap-1", Every: every1, K: k, MaxUp: maxUp1, MaxDown: maxDown1, Alpha: alpha1}
	}
	if age < p2End {
		return bootstrapPolicy{Active: true, Phase: "bootstrap-2", Every: every2, K: k, MaxUp: maxUp2, MaxDown: maxDown2, Alpha: alpha2}
	}
	if age < window {
		return bootstrapPolicy{Active: true, Phase: "bootstrap-3", Every: every3, K: k, MaxUp: maxUp3, MaxDown: maxDown3, Alpha: alpha3}
	}
	return bootstrapPolicy{Active: false, Phase: "steady", Every: steadyEvery, K: steadyK, MaxUp: steadyUp, MaxDown: steadyDown, Alpha: steadyAlpha}
}

/* ---------------- totals helper (optional) ---------------- */

func readTotalsSum(m *ebpf.Map) (xdpTotals, error) {
	var out xdpTotals
	if m == nil {
		return out, fmt.Errorf("nil totals map")
	}
	var k uint32 = 0
	var perCPU []xdpTotals
	if err := m.Lookup(&k, &perCPU); err != nil {
		return out, err
	}
	for _, v := range perCPU {
		out.Pkts += v.Pkts
		out.Pass += v.Pass
		out.DropAllow += v.DropAllow
		out.DropDeny += v.DropDeny
		out.DropRL += v.DropRL
	}
	return out, nil
}

/* ---------------- FSM transition (enforcement) ---------------- */

func transitionV4(ip [4]byte, st ipState, target Level, now time.Time, cooldown time.Duration, dry bool,
	denyMap4, rlPolicyMap4 *ebpf.Map,
	softRate, softBurst uint64, softTTL time.Duration,
	hardRate, hardBurst uint64, hardTTL time.Duration,
	blockTTL time.Duration,
) ipState {

	if !dry {
		switch target {
		case LObserve:
			if rlPolicyMap4 != nil {
				_ = rlPolicyMap4.Delete(&ip)
			}
			if denyMap4 != nil {
				_ = denyMap4.Delete(&ip)
			}
		case LSoft:
			if denyMap4 != nil {
				_ = denyMap4.Delete(&ip)
			}
			if rlPolicyMap4 != nil {
				val := rlCfg{RatePPS: softRate, Burst: softBurst}
				_ = rlPolicyMap4.Update(&ip, &val, ebpf.UpdateAny)
			}
		case LHard:
			if denyMap4 != nil {
				_ = denyMap4.Delete(&ip)
			}
			if rlPolicyMap4 != nil {
				val := rlCfg{RatePPS: hardRate, Burst: hardBurst}
				_ = rlPolicyMap4.Update(&ip, &val, ebpf.UpdateAny)
			}
		case LBlock:
			if rlPolicyMap4 != nil {
				_ = rlPolicyMap4.Delete(&ip)
			}
			if denyMap4 != nil {
				v := uint8(1)
				_ = denyMap4.Update(&ip, &v, ebpf.UpdateAny)
			}
		}
	}

	st.Level = target
	st.CooldownUntil = now.Add(cooldown)
	switch target {
	case LObserve:
		st.ExpiresAt = time.Time{}
	case LSoft:
		st.ExpiresAt = now.Add(softTTL)
	case LHard:
		st.ExpiresAt = now.Add(hardTTL)
	case LBlock:
		st.ExpiresAt = now.Add(blockTTL)
	}
	return st
}

func transitionV6(ip [16]byte, st ipState, target Level, now time.Time, cooldown time.Duration, dry bool,
	denyMap6, rlPolicyMap6 *ebpf.Map,
	softRate, softBurst uint64, softTTL time.Duration,
	hardRate, hardBurst uint64, hardTTL time.Duration,
	blockTTL time.Duration,
) ipState {

	if !dry {
		krl := src6Key{IP: ip}
		kd := key6Bytes{IP: ip}

		switch target {
		case LObserve:
			if rlPolicyMap6 != nil {
				_ = rlPolicyMap6.Delete(&krl)
			}
			if denyMap6 != nil {
				_ = denyMap6.Delete(&kd)
			}
		case LSoft:
			if denyMap6 != nil {
				_ = denyMap6.Delete(&kd)
			}
			if rlPolicyMap6 != nil {
				val := rlCfg{RatePPS: softRate, Burst: softBurst}
				_ = rlPolicyMap6.Update(&krl, &val, ebpf.UpdateAny)
			}
		case LHard:
			if denyMap6 != nil {
				_ = denyMap6.Delete(&kd)
			}
			if rlPolicyMap6 != nil {
				val := rlCfg{RatePPS: hardRate, Burst: hardBurst}
				_ = rlPolicyMap6.Update(&krl, &val, ebpf.UpdateAny)
			}
		case LBlock:
			if rlPolicyMap6 != nil {
				_ = rlPolicyMap6.Delete(&krl)
			}
			if denyMap6 != nil {
				v := uint8(1)
				_ = denyMap6.Update(&kd, &v, ebpf.UpdateAny)
			}
		}
	}

	st.Level = target
	st.CooldownUntil = now.Add(cooldown)
	switch target {
	case LObserve:
		st.ExpiresAt = time.Time{}
	case LSoft:
		st.ExpiresAt = now.Add(softTTL)
	case LHard:
		st.ExpiresAt = now.Add(hardTTL)
	case LBlock:
		st.ExpiresAt = now.Add(blockTTL)
	}
	return st
}

/* ---------------- Utility ---------------- */

func minInt(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

/* ---------------- Feedback CIDR de-enforcement ---------------- */

// applyCIDRsIfDue best-effort de-enforcement for CIDR feedback entries (v4 + v6).
// WARNING: iterating large maps can be expensive. Use a reasonable interval and a maxDeletes cap.
func (fm *feedbackManager) applyCIDRsIfDue(
	now time.Time,
	denyMap4, rlPolicyMap4 *ebpf.Map, state4 map[[4]byte]ipState,
	denyMap6, rlPolicyMap6 *ebpf.Map, state6 map[[16]byte]ipState,
	dry bool, every time.Duration, maxDeletes int,
) {
	if fm.path == "" || dry || every <= 0 || maxDeletes <= 0 {
		return
	}
	if (denyMap4 == nil && rlPolicyMap4 == nil) && (denyMap6 == nil && rlPolicyMap6 == nil) {
		return
	}
	if len(fm.cidrs4) == 0 && len(fm.cidrs6) == 0 {
		return
	}
	if !fm.lastCIDRApply.IsZero() && now.Sub(fm.lastCIDRApply) < every {
		return
	}
	fm.lastCIDRApply = now

	// Build active lists and drop expired.
	active4 := make([]*net.IPNet, 0, len(fm.cidrs4))
	keep4 := fm.cidrs4[:0]
	for _, c := range fm.cidrs4 {
		if now.After(c.until) {
			continue
		}
		keep4 = append(keep4, c)
		active4 = append(active4, c.net)
	}
	fm.cidrs4 = keep4

	active6 := make([]*net.IPNet, 0, len(fm.cidrs6))
	keep6 := fm.cidrs6[:0]
	for _, c := range fm.cidrs6 {
		if now.After(c.until) {
			continue
		}
		keep6 = append(keep6, c)
		active6 = append(active6, c.net)
	}
	fm.cidrs6 = keep6

	matchAny4 := func(ip4 [4]byte) bool {
		if len(active4) == 0 {
			return false
		}
		ip := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
		for _, n := range active4 {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	matchAny6 := func(ip6 [16]byte) bool {
		if len(active6) == 0 {
			return false
		}
		ip := net.IP(ip6[:])
		for _, n := range active6 {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}

	// v4 delete from RL policy map (value rlCfg)
	deleteRL4 := func(m *ebpf.Map, budget *int) int {
		if m == nil || *budget <= 0 || len(active4) == 0 {
			return 0
		}
		delKeys := make([][4]byte, 0, 1024)
		it := m.Iterate()
		var k [4]byte
		var v rlCfg
		for it.Next(&k, &v) {
			if !matchAny4(k) {
				continue
			}
			delKeys = append(delKeys, k)
			if len(delKeys) >= 1024 || len(delKeys) >= *budget {
				break
			}
		}
		nDel := 0
		for _, kk := range delKeys {
			if *budget <= 0 {
				break
			}
			_ = m.Delete(&kk)
			nDel++
			*budget--
			if st, ok := state4[kk]; ok {
				st.Level = LObserve
				st.Strikes = 0
				st.NonCompTicks = 0
				st.UpStreak = 0
				st.DownStreak = 0
				st.HighSevSince = time.Time{}
				st.ExpiresAt = time.Time{}
				st.CooldownUntil = time.Time{}
				state4[kk] = st
			}
		}
		if nDel > 0 {
			log.Printf("Feedback CIDR de-enforce: rl_policy4 deleted=%d (budget_left=%d)", nDel, *budget)
		}
		return nDel
	}

	// v4 delete from deny map (value u8)
	deleteDeny4 := func(m *ebpf.Map, budget *int) int {
		if m == nil || *budget <= 0 || len(active4) == 0 {
			return 0
		}
		delKeys := make([][4]byte, 0, 1024)
		it := m.Iterate()
		var k [4]byte
		var v uint8
		for it.Next(&k, &v) {
			if !matchAny4(k) {
				continue
			}
			delKeys = append(delKeys, k)
			if len(delKeys) >= 1024 || len(delKeys) >= *budget {
				break
			}
		}
		nDel := 0
		for _, kk := range delKeys {
			if *budget <= 0 {
				break
			}
			_ = m.Delete(&kk)
			nDel++
			*budget--
			if st, ok := state4[kk]; ok {
				st.Level = LObserve
				st.Strikes = 0
				st.NonCompTicks = 0
				st.UpStreak = 0
				st.DownStreak = 0
				st.HighSevSince = time.Time{}
				st.ExpiresAt = time.Time{}
				st.CooldownUntil = time.Time{}
				state4[kk] = st
			}
		}
		if nDel > 0 {
			log.Printf("Feedback CIDR de-enforce: deny4 deleted=%d (budget_left=%d)", nDel, *budget)
		}
		return nDel
	}

	// v6 delete from RL policy map (key src6Key, value rlCfg)
	deleteRL6 := func(m *ebpf.Map, budget *int) int {
		if m == nil || *budget <= 0 || len(active6) == 0 {
			return 0
		}
		delKeys := make([][16]byte, 0, 512)
		it := m.Iterate()
		var k src6Key
		var v rlCfg
		for it.Next(&k, &v) {
			ip := k.IP
			if !matchAny6(ip) {
				continue
			}
			delKeys = append(delKeys, ip)
			if len(delKeys) >= 512 || len(delKeys) >= *budget {
				break
			}
		}
		nDel := 0
		for _, ip := range delKeys {
			if *budget <= 0 {
				break
			}
			kk := src6Key{IP: ip}
			_ = m.Delete(&kk)
			nDel++
			*budget--
			if st, ok := state6[ip]; ok {
				st.Level = LObserve
				st.Strikes = 0
				st.NonCompTicks = 0
				st.UpStreak = 0
				st.DownStreak = 0
				st.HighSevSince = time.Time{}
				st.ExpiresAt = time.Time{}
				st.CooldownUntil = time.Time{}
				state6[ip] = st
			}
		}
		if nDel > 0 {
			log.Printf("Feedback CIDR de-enforce: rl_policy6 deleted=%d (budget_left=%d)", nDel, *budget)
		}
		return nDel
	}

	// v6 delete from deny map (key key6Bytes, value u8)
	deleteDeny6 := func(m *ebpf.Map, budget *int) int {
		if m == nil || *budget <= 0 || len(active6) == 0 {
			return 0
		}
		delKeys := make([][16]byte, 0, 512)
		it := m.Iterate()
		var k key6Bytes
		var v uint8
		for it.Next(&k, &v) {
			ip := k.IP
			if !matchAny6(ip) {
				continue
			}
			delKeys = append(delKeys, ip)
			if len(delKeys) >= 512 || len(delKeys) >= *budget {
				break
			}
		}
		nDel := 0
		for _, ip := range delKeys {
			if *budget <= 0 {
				break
			}
			kk := key6Bytes{IP: ip}
			_ = m.Delete(&kk)
			nDel++
			*budget--
			if st, ok := state6[ip]; ok {
				st.Level = LObserve
				st.Strikes = 0
				st.NonCompTicks = 0
				st.UpStreak = 0
				st.DownStreak = 0
				st.HighSevSince = time.Time{}
				st.ExpiresAt = time.Time{}
				st.CooldownUntil = time.Time{}
				state6[ip] = st
			}
		}
		if nDel > 0 {
			log.Printf("Feedback CIDR de-enforce: deny6 deleted=%d (budget_left=%d)", nDel, *budget)
		}
		return nDel
	}

	budget := maxDeletes
	_ = deleteRL4(rlPolicyMap4, &budget)
	_ = deleteDeny4(denyMap4, &budget)
	_ = deleteRL6(rlPolicyMap6, &budget)
	_ = deleteDeny6(denyMap6, &budget)
}

/* ---------------- Main ---------------- */

func main() {
	interval := flag.Duration("interval", 1*time.Second, "poll interval")
	topN := flag.Int("top", 200, "top N sources by severity")
	minPPS := flag.Float64("min-pps", 10, "ignore sources below this PPS")
	minSev := flag.Float64("min-sev", 0.0, "include candidates with severity >= min-sev")

	// Profiles + persistence
	profileName := flag.String("profile", "controller", "initial profile name (aliases apply)")
	statePath := flag.String("state-file", "/var/lib/kernloom/iq/state.json", "path to persisted state file")
	maxStateAge := flag.Duration("max-state-age", 14*24*time.Hour, "ignore persisted state older than this (0 disables)")
	historyKeep := flag.Int("state-history", 30, "keep last N history entries")

	// Whitelist
	whitelistPath := flag.String("whitelist", "/etc/kernloom/iq/whitelist.txt", "whitelist file (IPv4/IPv6/CIDR), one per line; empty disables")
	whitelistReload := flag.Duration("whitelist-reload", 10*time.Second, "reload whitelist if file changed (0 disables)")
	whitelistLearn := flag.Bool("whitelist-learn", false, "if true, whitelisted IPs may contribute to learning; default false")

	// Feedback / Forgive (temporary exemptions)
	feedbackPath := flag.String("feedback-file", "/var/lib/kernloom/iq/feedback.json", "feedback file (JSON array) for temporary forgive/whitelist entries; empty disables")
	feedbackReload := flag.Duration("feedback-reload", 10*time.Second, "reload feedback file if changed (0 disables)")
	feedbackLearn := flag.Bool("feedback-learn", false, "if true, feedback-exempt IPs may contribute to learning; default false")

	feedbackCIDRDeenforce := flag.Bool("feedback-deenforce-cidr", true, "if true, CIDR feedback entries will actively de-enforce existing deny/rl map entries by scanning maps periodically (best effort)")
	feedbackCIDREvery := flag.Duration("feedback-cidr-every", 30*time.Second, "how often to scan maps to de-enforce CIDR feedback entries (0 disables)")
	feedbackCIDRMax := flag.Int("feedback-cidr-max", 5000, "max number of entries to delete per CIDR de-enforce scan (bounds cost)")

	// Bootstrapping (self-tuning ramp-down schedule)
	bootstrap := flag.Bool("bootstrap", true, "enable bootstrap autotune schedule (frequent early, slower later)")
	bootstrapWindow := flag.Duration("bootstrap-window", 14*24*time.Hour, "bootstrap duration (suggest 14d)")
	bootstrapP1End := flag.Duration("bootstrap-phase1-end", 48*time.Hour, "end of phase1 since bootstrap start")
	bootstrapP2End := flag.Duration("bootstrap-phase2-end", 5*24*time.Hour, "end of phase2 since bootstrap start")
	bootstrapEvery1 := flag.Duration("bootstrap-every1", 1*time.Hour, "autotune interval during phase1")
	bootstrapEvery2 := flag.Duration("bootstrap-every2", 6*time.Hour, "autotune interval during phase2")
	bootstrapEvery3 := flag.Duration("bootstrap-every3", 24*time.Hour, "autotune interval during phase3 (until bootstrap-window)")
	steadyEvery := flag.Duration("steady-every", 84*time.Hour, "autotune interval after bootstrap (e.g. 84h ~ 2x/week)")

	bootstrapKStart := flag.Float64("bootstrap-k-start", 4.0, "bootstrap starting k (higher => fewer false positives)")
	bootstrapKFinal := flag.Float64("bootstrap-k-final", 3.5, "bootstrap final k at end of bootstrap-window")

	bootstrapMaxUp1 := flag.Float64("bootstrap-max-up1", 0.10, "phase1 max relative increase per update")
	bootstrapMaxDown1 := flag.Float64("bootstrap-max-down1", 0.02, "phase1 max relative decrease per update")
	bootstrapMaxUp2 := flag.Float64("bootstrap-max-up2", 0.08, "phase2 max relative increase per update")
	bootstrapMaxDown2 := flag.Float64("bootstrap-max-down2", 0.03, "phase2 max relative decrease per update")
	bootstrapMaxUp3 := flag.Float64("bootstrap-max-up3", 0.05, "phase3 max relative increase per update")
	bootstrapMaxDown3 := flag.Float64("bootstrap-max-down3", 0.05, "phase3 max relative decrease per update")

	bootstrapAlpha1 := flag.Float64("bootstrap-alpha1", 0.10, "phase1 smoothing alpha")
	bootstrapAlpha2 := flag.Float64("bootstrap-alpha2", 0.15, "phase2 smoothing alpha")
	bootstrapAlpha3 := flag.Float64("bootstrap-alpha3", 0.20, "phase3 smoothing alpha")

	// Autotune
	autoTune := flag.Bool("autotune", true, "enable autotune of trig-* using median+MAD")
	autoEvery := flag.Duration("autotune-every", 24*time.Hour, "how often to write new trig-* state")
	autoMinSamples := flag.Int("autotune-min-samples", 5000, "minimum samples per feature before tuning")
	autoK := flag.Float64("autotune-k", 3.5, "k for trig = median + k*mad (k=3.5 ~ p99)")
	autoMaxChange := flag.Float64("autotune-max-change", 0.05, "max relative change per update (e.g. 0.05 => ±5%)")

	autoMaxUp := flag.Float64("autotune-max-change-up", 0, "max relative increase per update (0 => use autotune-max-change)")
	autoMaxDown := flag.Float64("autotune-max-change-down", 0, "max relative decrease per update (0 => use autotune-max-change)")

	autoAlpha := flag.Float64("autotune-alpha", 0.2, "smoothing alpha (0 disables)")
	autoFloorPPS := flag.Float64("autotune-floor-pps", 100, "minimum trig-pps")
	autoFloorSyn := flag.Float64("autotune-floor-syn", 50, "minimum trig-syn")
	autoFloorScan := flag.Float64("autotune-floor-scan", 20, "minimum trig-scan")

	// Anti-poisoning "clean ticks"
	learnSevGT := flag.Float64("learn-sev-gt", 1.0, "tick is 'dirty' if sev>=learn-sev-gt fraction is too high")
	learnFracGT := flag.Float64("learn-frac-gt", 0.005, "max fraction of sources with sev>=learn-sev-gt to consider tick 'clean'")
	learnMaxSev := flag.Float64("learn-max-sev", 0.8, "only add samples from sources with severity <= this")
	learnSkipIfBlocks := flag.Bool("learn-skip-if-blocks", true, "if any IP is in BLOCK, skip learning for this tick")

	// Optional: learn gating from totals drop ratio (extra anti-poison)
	learnMaxDropRatio := flag.Float64("learn-max-drop-ratio", 0.02, "skip learning if total_drop/(total_pass+total_drop) exceeds this (0 disables)")

	// Severity params (trig-* may be tuned; weights static)
	trigPPS := flag.Float64("trig-pps", 0, "PPS trigger threshold (0 => from profile/state)")
	trigSyn := flag.Float64("trig-syn", 0, "SYN/s trigger threshold (0 => from profile/state)")
	trigScan := flag.Float64("trig-scan", 0, "scan/s trigger threshold (0 => from profile/state)")
	wPPS := flag.Float64("w-pps", 0, "weight for PPS (0 => from profile)")
	wSyn := flag.Float64("w-syn", 0, "weight for SYN/s (0 => from profile)")
	wScan := flag.Float64("w-scan", 0, "weight for scan/s (0 => from profile)")
	sevCap := flag.Float64("sev-cap", 0, "cap for normalized metrics (0 => from profile)")

	// Strikes mapping
	sevStep1 := flag.Float64("sev-step1", 1.0, "severity >= step1 -> add delta1 strikes")
	sevStep2 := flag.Float64("sev-step2", 2.0, "severity >= step2 -> add delta2 strikes")
	sevStep3 := flag.Float64("sev-step3", 3.0, "severity >= step3 -> add delta3 strikes")
	sevDelta1 := flag.Int("sev-delta1", 1, "strike delta at step1")
	sevDelta2 := flag.Int("sev-delta2", 2, "strike delta at step2")
	sevDelta3 := flag.Int("sev-delta3", 3, "strike delta at step3")
	sevDecayBelow := flag.Float64("sev-decay-below", 0.25, "if severity < this, strikes may decay")

	// Thresholds (strikes)
	softAt := flag.Int("soft-at", 0, "strikes >= soft-at -> SOFT (0 => from profile)")
	hardAt := flag.Int("hard-at", 0, "strikes >= hard-at -> HARD (0 => from profile)")
	blockAt := flag.Int("block-at", 0, "strikes >= block-at -> BLOCK (0 => from profile)")

	// Enforcement actions
	softRate := flag.Uint64("soft-rate", 0, "soft rate limit pps (0 => from profile)")
	softBurst := flag.Uint64("soft-burst", 0, "soft burst tokens (0 => from profile)")
	softTTL := flag.Duration("soft-ttl", 0, "soft TTL (0 => from profile)")
	hardRate := flag.Uint64("hard-rate", 0, "hard rate limit pps (0 => from profile)")
	hardBurst := flag.Uint64("hard-burst", 0, "hard burst tokens (0 => from profile)")
	hardTTL := flag.Duration("hard-ttl", 0, "hard TTL (0 => from profile)")
	blockTTL := flag.Duration("block-ttl", 0, "block TTL (0 => from profile)")
	cooldown := flag.Duration("cooldown", 0, "min time between level changes (0 => from profile)")

	// Block gating
	blockMinSev := flag.Float64("block-min-sev", math.NaN(), "only allow BLOCK if severity >= this (NaN => from profile, 0 disables)")
	blockMinDur := flag.Duration("block-min-dur", -1, "require sev>=block-min-sev for at least this duration (-1 => from profile, 0 disables)")

	// Anti-flap
	upNeed := flag.Int("up-need", 0, "require N consecutive high ticks before escalating (0 => from profile)")
	downNeed := flag.Int("down-need", 0, "require N consecutive low ticks before de-escalation/decay (0 => from profile)")
	minHoldSoft := flag.Duration("min-hold-soft", 0, "minimum time in SOFT before stepping down (0 => from profile)")
	minHoldHard := flag.Duration("min-hold-hard", 0, "minimum time in HARD before stepping down (0 => from profile)")

	// Non-compliance
	nonCompAt := flag.Int("noncomp-at", 0, "if NonCompTicks reaches this while in HARD -> BLOCK faster (0 => from profile)")
	nonCompDrop := flag.Float64("noncomp-drop", 0, "count as non-compliance if DropRL/s >= this (0 => from profile)")
	nonCompSev := flag.Float64("noncomp-sev", 0, "count as non-compliance if severity >= this (0 => from profile)")
	nonCompResetBelow := flag.Float64("noncomp-reset-below", 0, "reset NonCompTicks if severity < this AND DropRL/s==0 (0 => from profile)")

	// Housekeeping
	prevTTL := flag.Duration("prev-ttl", 10*time.Minute, "forget prev entries if not seen (bounds mem)")
	stateTTL := flag.Duration("state-ttl", 60*time.Minute, "forget OBSERVE-only state if not seen for this long")
	dryRun := flag.Bool("dry-run", true, "if true: no enforcement, only logs")

	flag.Parse()

	p := profileByName(*profileName)

	// Fill missing from profile
	if *trigPPS == 0 {
		*trigPPS = p.TrigPPS
	}
	if *trigSyn == 0 {
		*trigSyn = p.TrigSyn
	}
	if *trigScan == 0 {
		*trigScan = p.TrigScan
	}
	if *wPPS == 0 {
		*wPPS = p.WPPS
	}
	if *wSyn == 0 {
		*wSyn = p.WSyn
	}
	if *wScan == 0 {
		*wScan = p.WScan
	}
	if *sevCap == 0 {
		*sevCap = p.SevCap
	}
	if *softAt == 0 {
		*softAt = p.SoftAt
	}
	if *hardAt == 0 {
		*hardAt = p.HardAt
	}
	if *blockAt == 0 {
		*blockAt = p.BlockAt
	}
	if *softRate == 0 {
		*softRate = p.SoftRate
	}
	if *softBurst == 0 {
		*softBurst = p.SoftBurst
	}
	if *softTTL == 0 {
		*softTTL = p.SoftTTL
	}
	if *hardRate == 0 {
		*hardRate = p.HardRate
	}
	if *hardBurst == 0 {
		*hardBurst = p.HardBurst
	}
	if *hardTTL == 0 {
		*hardTTL = p.HardTTL
	}
	if *blockTTL == 0 {
		*blockTTL = p.BlockTTL
	}
	if *cooldown == 0 {
		*cooldown = p.Cooldown
	}
	if math.IsNaN(*blockMinSev) {
		*blockMinSev = p.BlockMinSev
	}
	if *blockMinDur < 0 {
		*blockMinDur = p.BlockMinDur
	}
	if *upNeed == 0 {
		*upNeed = p.UpNeed
	}
	if *downNeed == 0 {
		*downNeed = p.DownNeed
	}
	if *minHoldSoft == 0 {
		*minHoldSoft = p.MinHoldSoft
	}
	if *minHoldHard == 0 {
		*minHoldHard = p.MinHoldHard
	}
	if *nonCompAt == 0 {
		*nonCompAt = p.NonCompAt
	}
	if *nonCompDrop == 0 {
		*nonCompDrop = p.NonCompDrop
	}
	if *nonCompSev == 0 {
		*nonCompSev = p.NonCompSev
	}
	if *nonCompResetBelow == 0 {
		*nonCompResetBelow = p.NonCompReset
	}

	// Load persisted state (override trig-*)
	var stFile *stateFile
	if *statePath != "" {
		if st, err := loadState(*statePath, *maxStateAge); err == nil {
			stFile = st
			if st.Active.Trig.TrigPPS > 0 {
				*trigPPS = st.Active.Trig.TrigPPS
			}
			if st.Active.Trig.TrigSyn > 0 {
				*trigSyn = st.Active.Trig.TrigSyn
			}
			if st.Active.Trig.TrigScan > 0 {
				*trigScan = st.Active.Trig.TrigScan
			}
			log.Printf("Loaded state: profile=%s rev=%d updated=%s trig{pps=%.1f syn=%.1f scan=%.1f}",
				st.Active.Profile, st.Active.Revision, st.Active.UpdatedAt.Format(time.RFC3339),
				*trigPPS, *trigSyn, *trigScan)
		} else {
			log.Printf("No usable state loaded (%s): %v", *statePath, err)
		}
	}

	// Bootstrap start time (persisted in state) so schedule survives reboot.
	var bs bootstrapInfo
	if *bootstrap {
		if stFile != nil {
			bs = stFile.Active.Bootstrap
		}
		bs.Enabled = true
		if bs.StartedAt.IsZero() {
			bs.StartedAt = time.Now()
			bs.Window = bootstrapWindow.String()
			bs.Phase = "bootstrap-1"

			// Persist bootstrap metadata immediately (best-effort).
			if *statePath != "" {
				if stFile == nil {
					stFile = &stateFile{Version: 2}
					stFile.Active = stateActive{
						Profile:     p.Name,
						Revision:    0,
						UpdatedAt:   time.Time{},
						Trig:        trigState{TrigPPS: *trigPPS, TrigSyn: *trigSyn, TrigScan: *trigScan},
						Tune:        tuneMeta{Method: "median_mad", Window: "reservoir", K: *autoK, SigmaFactor: 1.4826},
						Bootstrap:   bs,
						SampleCount: 0,
						CleanRatio:  1.0,
						Notes:       "bootstrap initialized",
					}
					stFile.History = []stateHistory{}
				} else {
					stFile.Active.Bootstrap = bs
				}
				_ = writeStateAtomic(*statePath, stFile)
			}
		}
	}

	// Whitelist + Feedback
	wl := newWhitelist(*whitelistPath)
	fb := newFeedbackManager(*feedbackPath)

	if *whitelistPath != "" {
		if err := wl.load(); err == nil {
			if fi, err := os.Stat(*whitelistPath); err == nil {
				wl.modTime = fi.ModTime()
			}
			log.Printf("Whitelist loaded: %s entries4=%d cidrs4=%d entries6=%d cidrs6=%d",
				*whitelistPath, len(wl.exact4), len(wl.cidrs4), len(wl.exact6), len(wl.cidrs6))
		} else {
			log.Printf("Whitelist not loaded (%s): %v", *whitelistPath, err)
		}
	}

	if *feedbackPath != "" {
		if err := fb.load(time.Now()); err == nil {
			if fi, err := os.Stat(*feedbackPath); err == nil {
				fb.modTime = fi.ModTime()
			}
			log.Printf("Feedback loaded: %s entries4=%d cidrs4=%d entries6=%d cidrs6=%d",
				*feedbackPath, len(fb.exact4), len(fb.cidrs4), len(fb.exact6), len(fb.cidrs6))
		} else {
			log.Printf("Feedback not loaded (%s): %v", *feedbackPath, err)
		}
	}

	// Open telemetry maps (v4 required; v6 optional but expected)
	srcMap4, err := openPinnedMap(mapPinSrc4)
	if err != nil {
		log.Fatalf("open %s: %v", mapPinSrc4, err)
	}
	defer srcMap4.Close()

	var srcMap6 *ebpf.Map
	if m6, err := openPinnedMap(mapPinSrc6); err == nil {
		srcMap6 = m6
		defer srcMap6.Close()
	} else {
		log.Printf("IPv6 telemetry map not available (optional): open %s: %v", mapPinSrc6, err)
	}

	// Enforcement maps
	var deny4, rl4 *ebpf.Map
	var deny6, rl6 *ebpf.Map
	if !*dryRun {
		deny4, err = openPinnedMap(mapPinDeny4)
		if err != nil {
			log.Fatalf("open %s: %v", mapPinDeny4, err)
		}
		defer deny4.Close()

		rl4, err = openPinnedMap(mapPinRLPolicy4)
		if err != nil {
			log.Fatalf("open %s: %v", mapPinRLPolicy4, err)
		}
		defer rl4.Close()

		if m6, err := openPinnedMap(mapPinDeny6); err == nil {
			deny6 = m6
			defer deny6.Close()
		} else {
			log.Printf("IPv6 deny map not available (optional): open %s: %v", mapPinDeny6, err)
		}
		if m6, err := openPinnedMap(mapPinRLPolicy6); err == nil {
			rl6 = m6
			defer rl6.Close()
		} else {
			log.Printf("IPv6 rl policy map not available (optional): open %s: %v", mapPinRLPolicy6, err)
		}
	}

	// totals map is optional even in dry-run
	var totalsMap *ebpf.Map
	if tm, err := openPinnedMap(mapPinTotals); err == nil {
		totalsMap = tm
		defer totalsMap.Close()
	} else {
		log.Printf("Totals map not available (optional): %v", err)
	}

	prev4 := make(map[[4]byte]prevV4, 64_000)
	prev6 := make(map[[16]byte]prevV6, 64_000)
	state4 := make(map[[4]byte]ipState, 64_000)
	state6 := make(map[[16]byte]ipState, 64_000)

	resPPS := newReservoir(50_000)
	resSyn := newReservoir(50_000)
	resScan := newReservoir(50_000)

	lastTune := time.Now()
	if stFile != nil && !stFile.Active.UpdatedAt.IsZero() {
		lastTune = stFile.Active.UpdatedAt
	}
	totalLearnTicks := 0
	cleanLearnTicks := 0

	// totals prev for drop-ratio gating
	var prevTotals xdpTotals
	var prevTotalsWall time.Time
	if totalsMap != nil {
		if t, err := readTotalsSum(totalsMap); err == nil {
			prevTotals = t
			prevTotalsWall = time.Now()
		}
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	log.Printf("Kernloom IQ started profile=%s interval=%s dry_run=%v top=%d trig{pps=%.1f syn=%.1f scan=%.1f} weights{pps=%.2f syn=%.2f scan=%.2f} cap=%.1f (ipv6=%v)",
		p.Name, interval.String(), *dryRun, *topN, *trigPPS, *trigSyn, *trigScan, *wPPS, *wSyn, *wScan, *sevCap, srcMap6 != nil)

	for range ticker.C {
		nowWall := time.Now()

		wl.maybeReload(*whitelistReload)
		fb.maybeReload(*feedbackReload)

		// Apply exact feedback de-enforcement (best effort)
		fb.applyV4(nowWall, deny4, rl4, state4, *dryRun)
		fb.applyV6(nowWall, deny6, rl6, state6, *dryRun)

		// Optional CIDR de-enforcement scan
		if *feedbackCIDRDeenforce {
			fb.applyCIDRsIfDue(nowWall, deny4, rl4, state4, deny6, rl6, state6, *dryRun, *feedbackCIDREvery, *feedbackCIDRMax)
		}

		// Optional totals drop ratio gating: compute drop ratio over last interval
		dropRatio := 0.0
		if totalsMap != nil && !prevTotalsWall.IsZero() {
			if t, err := readTotalsSum(totalsMap); err == nil {
				sec := nowWall.Sub(prevTotalsWall).Seconds()
				if sec > 0 {
					dPass := float64(t.Pass - prevTotals.Pass)
					dDrop := float64((t.DropAllow + t.DropDeny + t.DropRL) - (prevTotals.DropAllow + prevTotals.DropDeny + prevTotals.DropRL))
					den := dPass + dDrop
					if den > 0 {
						dropRatio = dDrop / den
					}
				}
				prevTotals = t
				prevTotalsWall = nowWall
			}
		}

		cands := make([]metrics, 0, 4096)

		seenForLearn := 0
		highSevCount := 0

		// ----- Iterate v4 sources -----
		it4 := srcMap4.Iterate()
		var k4 [4]byte
		var v4 xdpSrcStatsV4

		for it4.Next(&k4, &v4) {
			pv, ok := prev4[k4]
			if !ok {
				prev4[k4] = prevV4{Pkts: v4.Pkts, Bytes: v4.Bytes, Syn: v4.Syn, Scan: v4.DportChanges, DropRL: v4.DropRL, LastWall: nowWall}
				continue
			}

			sec := nowWall.Sub(pv.LastWall).Seconds()
			if sec <= 0 {
				sec = interval.Seconds()
				if sec <= 0 {
					sec = 1
				}
			}

			dPkts := v4.Pkts - pv.Pkts
			dBytes := v4.Bytes - pv.Bytes
			dSyn := v4.Syn - pv.Syn
			dScan := v4.DportChanges - pv.Scan
			dDropRL := v4.DropRL - pv.DropRL

			pps := float64(dPkts) / sec
			bps := float64(dBytes) / sec
			synRate := float64(dSyn) / sec
			scanRate := float64(dScan) / sec
			dropRLRate := float64(dDropRL) / sec

			sev := calcSeverity(pps, synRate, scanRate, *trigPPS, *trigSyn, *trigScan, *wPPS, *wSyn, *wScan, *sevCap)

			// clean tick accounting (only if activity)
			if dPkts > 0 || dSyn > 0 || dScan > 0 {
				seenForLearn++
				if sev >= *learnSevGT {
					highSevCount++
				}
			}

			if pps < *minPPS && sev < *minSev && dropRLRate == 0 {
				prev4[k4] = prevV4{Pkts: v4.Pkts, Bytes: v4.Bytes, Syn: v4.Syn, Scan: v4.DportChanges, DropRL: v4.DropRL, LastWall: nowWall}
				continue
			}

			cands = append(cands, metrics{
				IPVer:      4,
				IP4:        k4,
				PPS:        pps,
				Bps:        bps,
				SynRate:    synRate,
				ScanRate:   scanRate,
				DropRLRate: dropRLRate,
				Severity:   sev,
			})

			prev4[k4] = prevV4{Pkts: v4.Pkts, Bytes: v4.Bytes, Syn: v4.Syn, Scan: v4.DportChanges, DropRL: v4.DropRL, LastWall: nowWall}
		}
		if err := it4.Err(); err != nil {
			log.Printf("iterate src4 map err: %v", err)
			continue
		}

		// ----- Iterate v6 sources -----
		if srcMap6 != nil {
			it6 := srcMap6.Iterate()
			var k6 src6Key
			var v6 xdpSrcStatsV6

			for it6.Next(&k6, &v6) {
				ip6 := k6.IP
				pv, ok := prev6[ip6]
				if !ok {
					prev6[ip6] = prevV6{Pkts: v6.Pkts, Bytes: v6.Bytes, Syn: v6.Syn, Scan: v6.DportChanges, DropRL: v6.DropRL, LastWall: nowWall}
					continue
				}

				sec := nowWall.Sub(pv.LastWall).Seconds()
				if sec <= 0 {
					sec = interval.Seconds()
					if sec <= 0 {
						sec = 1
					}
				}

				dPkts := v6.Pkts - pv.Pkts
				dBytes := v6.Bytes - pv.Bytes
				dSyn := v6.Syn - pv.Syn
				dScan := v6.DportChanges - pv.Scan
				dDropRL := v6.DropRL - pv.DropRL

				pps := float64(dPkts) / sec
				bps := float64(dBytes) / sec
				synRate := float64(dSyn) / sec
				scanRate := float64(dScan) / sec
				dropRLRate := float64(dDropRL) / sec

				sev := calcSeverity(pps, synRate, scanRate, *trigPPS, *trigSyn, *trigScan, *wPPS, *wSyn, *wScan, *sevCap)

				// clean tick accounting (only if activity)
				if dPkts > 0 || dSyn > 0 || dScan > 0 {
					seenForLearn++
					if sev >= *learnSevGT {
						highSevCount++
					}
				}

				if pps < *minPPS && sev < *minSev && dropRLRate == 0 {
					prev6[ip6] = prevV6{Pkts: v6.Pkts, Bytes: v6.Bytes, Syn: v6.Syn, Scan: v6.DportChanges, DropRL: v6.DropRL, LastWall: nowWall}
					continue
				}

				cands = append(cands, metrics{
					IPVer:      6,
					IP6:        ip6,
					PPS:        pps,
					Bps:        bps,
					SynRate:    synRate,
					ScanRate:   scanRate,
					DropRLRate: dropRLRate,
					Severity:   sev,
				})

				prev6[ip6] = prevV6{Pkts: v6.Pkts, Bytes: v6.Bytes, Syn: v6.Syn, Scan: v6.DportChanges, DropRL: v6.DropRL, LastWall: nowWall}
			}

			if err := it6.Err(); err != nil {
				log.Printf("iterate src6 map err: %v", err)
			}
		}

		sort.Slice(cands, func(i, j int) bool {
			if cands[i].Severity == cands[j].Severity {
				return cands[i].PPS > cands[j].PPS
			}
			return cands[i].Severity > cands[j].Severity
		})
		if *topN < len(cands) {
			cands = cands[:*topN]
		}

		// blocks active?
		blocksActive := 0
		for _, st := range state4 {
			if st.Level == LBlock {
				blocksActive++
			}
		}
		for _, st := range state6 {
			if st.Level == LBlock {
				blocksActive++
			}
		}

		// Clean tick decision
		totalLearnTicks++
		clean := true
		if *learnSkipIfBlocks && blocksActive > 0 {
			clean = false
		}
		if seenForLearn > 0 {
			frac := float64(highSevCount) / float64(seenForLearn)
			if frac > *learnFracGT {
				clean = false
			}
		}
		if *learnMaxDropRatio > 0 && dropRatio > *learnMaxDropRatio {
			clean = false
		}
		if clean {
			cleanLearnTicks++
		}

		for _, m := range cands {
			// Separate v4/v6 flows but keep identical decision logic.
			if m.IPVer == 4 {
				ip := m.IP4

				wlHit := wl.matchV4(ip)
				fbHit := fb.matchV4(ip)
				isWL := wlHit || fbHit

				st := state4[ip]
				st.LastSeenWallTime = nowWall

				// Exempt sources: ensure no enforcement and don't accumulate strikes.
				if isWL {
					if st.Level != LObserve {
						st = transitionV4(ip, st, LObserve, nowWall, *cooldown, *dryRun, deny4, rl4,
							*softRate, *softBurst, *softTTL,
							*hardRate, *hardBurst, *hardTTL,
							*blockTTL)
					}
					st.Strikes = 0
					st.NonCompTicks = 0
					st.UpStreak = 0
					st.DownStreak = 0
					st.HighSevSince = time.Time{}
					state4[ip] = st

					if *autoTune && clean && st.Level == LObserve && m.Severity <= *learnMaxSev && m.DropRLRate == 0 {
						if (wlHit && *whitelistLearn) || (fbHit && *feedbackLearn) {
							resPPS.Add(m.PPS)
							resSyn.Add(m.SynRate)
							resScan.Add(m.ScanRate)
						}
					}
					continue
				}

				// high severity sustain tracking for block gate
				if *blockMinSev > 0 && m.Severity >= *blockMinSev {
					if st.HighSevSince.IsZero() {
						st.HighSevSince = nowWall
					}
				} else {
					st.HighSevSince = time.Time{}
				}

				// Anti-flap streaks
				highTick := (m.Severity >= *sevStep1) || (*nonCompDrop > 0 && m.DropRLRate >= *nonCompDrop)
				lowTick := (m.Severity < *sevDecayBelow) && (m.DropRLRate == 0)

				if highTick {
					st.UpStreak++
					st.DownStreak = 0
				} else if lowTick {
					st.DownStreak++
					st.UpStreak = 0
				} else {
					if st.UpStreak > 0 {
						st.UpStreak--
					}
					if st.DownStreak > 0 {
						st.DownStreak--
					}
				}

				// strikes update
				strikeDelta := 0
				switch {
				case m.Severity >= *sevStep3:
					strikeDelta = *sevDelta3
				case m.Severity >= *sevStep2:
					strikeDelta = *sevDelta2
				case m.Severity >= *sevStep1:
					strikeDelta = *sevDelta1
				}
				if strikeDelta > 0 {
					st.Strikes += strikeDelta
					st.LastTrigger = nowWall
				} else if st.Strikes > 0 && lowTick && st.DownStreak >= *downNeed {
					st.Strikes--
				}

				// Non-compliance (only while RL active)
				if st.Level >= LSoft && *nonCompAt > 0 {
					if (*nonCompDrop > 0 && m.DropRLRate >= *nonCompDrop) || (*nonCompSev > 0 && m.Severity >= *nonCompSev) {
						st.NonCompTicks++
					} else if m.Severity < *nonCompResetBelow && m.DropRLRate == 0 {
						st.NonCompTicks = 0
					}
				} else {
					st.NonCompTicks = 0
				}

				// TTL stepdown needs quiet streak + min hold
				if st.Level == LSoft && !st.ExpiresAt.IsZero() && nowWall.After(st.ExpiresAt) &&
					st.DownStreak >= *downNeed && nowWall.Sub(st.LastTrigger) >= *minHoldSoft &&
					nowWall.After(st.CooldownUntil) {
					st = transitionV4(ip, st, LObserve, nowWall, *cooldown, *dryRun, deny4, rl4,
						*softRate, *softBurst, *softTTL,
						*hardRate, *hardBurst, *hardTTL,
						*blockTTL)
				}
				if st.Level == LHard && !st.ExpiresAt.IsZero() && nowWall.After(st.ExpiresAt) &&
					st.DownStreak >= *downNeed && nowWall.Sub(st.LastTrigger) >= *minHoldHard &&
					nowWall.After(st.CooldownUntil) {
					st = transitionV4(ip, st, LSoft, nowWall, *cooldown, *dryRun, deny4, rl4,
						*softRate, *softBurst, *softTTL,
						*hardRate, *hardBurst, *hardTTL,
						*blockTTL)
				}

				// Determine target
				target := st.Level
				if st.Level == LHard && *nonCompAt > 0 && st.NonCompTicks >= *nonCompAt {
					target = LBlock
				} else {
					if st.Strikes >= *blockAt {
						target = LBlock
					} else if st.Strikes >= *hardAt {
						target = LHard
					} else if st.Strikes >= *softAt {
						target = LSoft
					} else {
						target = LObserve
					}
					if target > st.Level && st.UpStreak < *upNeed {
						target = st.Level
					}
				}

				// Block gating
				if target == LBlock && *blockMinSev > 0 {
					ok := true
					if st.HighSevSince.IsZero() {
						ok = false
					} else if *blockMinDur > 0 && nowWall.Sub(st.HighSevSince) < *blockMinDur {
						ok = false
					}
					if !ok {
						target = LHard // clamp
					}
				}

				// Apply transition (cooldown)
				if target != st.Level && nowWall.After(st.CooldownUntil) {
					prevLevel := st.Level
					st = transitionV4(ip, st, target, nowWall, *cooldown, *dryRun, deny4, rl4,
						*softRate, *softBurst, *softTTL,
						*hardRate, *hardBurst, *hardTTL,
						*blockTTL)

					log.Printf("STATE %s v4 %s->%s strikes=%d up=%d down=%d noncomp=%d sev=%.2f pps=%.0f syn=%.0f scan=%.0f dropRL/s=%.1f",
						ip4String(ip), prevLevel.String(), st.Level.String(),
						st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks,
						m.Severity, m.PPS, m.SynRate, m.ScanRate, m.DropRLRate)
				}

				state4[ip] = st

				// Learning samples
				if *autoTune && clean {
					if st.Level == LObserve && m.Severity <= *learnMaxSev && m.DropRLRate == 0 {
						resPPS.Add(m.PPS)
						resSyn.Add(m.SynRate)
						resScan.Add(m.ScanRate)
					}
				}

				continue
			}

			// ---------------- IPv6 candidate ----------------
			ip := m.IP6

			wlHit := wl.matchV6(ip)
			fbHit := fb.matchV6(ip)
			isWL := wlHit || fbHit

			st := state6[ip]
			st.LastSeenWallTime = nowWall

			// Exempt sources
			if isWL {
				if st.Level != LObserve {
					st = transitionV6(ip, st, LObserve, nowWall, *cooldown, *dryRun, deny6, rl6,
						*softRate, *softBurst, *softTTL,
						*hardRate, *hardBurst, *hardTTL,
						*blockTTL)
				}
				st.Strikes = 0
				st.NonCompTicks = 0
				st.UpStreak = 0
				st.DownStreak = 0
				st.HighSevSince = time.Time{}
				state6[ip] = st

				if *autoTune && clean && st.Level == LObserve && m.Severity <= *learnMaxSev && m.DropRLRate == 0 {
					if (wlHit && *whitelistLearn) || (fbHit && *feedbackLearn) {
						resPPS.Add(m.PPS)
						resSyn.Add(m.SynRate)
						resScan.Add(m.ScanRate)
					}
				}
				continue
			}

			// high severity sustain tracking for block gate
			if *blockMinSev > 0 && m.Severity >= *blockMinSev {
				if st.HighSevSince.IsZero() {
					st.HighSevSince = nowWall
				}
			} else {
				st.HighSevSince = time.Time{}
			}

			// Anti-flap streaks
			highTick := (m.Severity >= *sevStep1) || (*nonCompDrop > 0 && m.DropRLRate >= *nonCompDrop)
			lowTick := (m.Severity < *sevDecayBelow) && (m.DropRLRate == 0)

			if highTick {
				st.UpStreak++
				st.DownStreak = 0
			} else if lowTick {
				st.DownStreak++
				st.UpStreak = 0
			} else {
				if st.UpStreak > 0 {
					st.UpStreak--
				}
				if st.DownStreak > 0 {
					st.DownStreak--
				}
			}

			// strikes update
			strikeDelta := 0
			switch {
			case m.Severity >= *sevStep3:
				strikeDelta = *sevDelta3
			case m.Severity >= *sevStep2:
				strikeDelta = *sevDelta2
			case m.Severity >= *sevStep1:
				strikeDelta = *sevDelta1
			}
			if strikeDelta > 0 {
				st.Strikes += strikeDelta
				st.LastTrigger = nowWall
			} else if st.Strikes > 0 && lowTick && st.DownStreak >= *downNeed {
				st.Strikes--
			}

			// Non-compliance (only while RL active)
			if st.Level >= LSoft && *nonCompAt > 0 {
				if (*nonCompDrop > 0 && m.DropRLRate >= *nonCompDrop) || (*nonCompSev > 0 && m.Severity >= *nonCompSev) {
					st.NonCompTicks++
				} else if m.Severity < *nonCompResetBelow && m.DropRLRate == 0 {
					st.NonCompTicks = 0
				}
			} else {
				st.NonCompTicks = 0
			}

			// TTL stepdown needs quiet streak + min hold
			if st.Level == LSoft && !st.ExpiresAt.IsZero() && nowWall.After(st.ExpiresAt) &&
				st.DownStreak >= *downNeed && nowWall.Sub(st.LastTrigger) >= *minHoldSoft &&
				nowWall.After(st.CooldownUntil) {
				st = transitionV6(ip, st, LObserve, nowWall, *cooldown, *dryRun, deny6, rl6,
					*softRate, *softBurst, *softTTL,
					*hardRate, *hardBurst, *hardTTL,
					*blockTTL)
			}
			if st.Level == LHard && !st.ExpiresAt.IsZero() && nowWall.After(st.ExpiresAt) &&
				st.DownStreak >= *downNeed && nowWall.Sub(st.LastTrigger) >= *minHoldHard &&
				nowWall.After(st.CooldownUntil) {
				st = transitionV6(ip, st, LSoft, nowWall, *cooldown, *dryRun, deny6, rl6,
					*softRate, *softBurst, *softTTL,
					*hardRate, *hardBurst, *hardTTL,
					*blockTTL)
			}

			// Determine target
			target := st.Level
			if st.Level == LHard && *nonCompAt > 0 && st.NonCompTicks >= *nonCompAt {
				target = LBlock
			} else {
				if st.Strikes >= *blockAt {
					target = LBlock
				} else if st.Strikes >= *hardAt {
					target = LHard
				} else if st.Strikes >= *softAt {
					target = LSoft
				} else {
					target = LObserve
				}
				if target > st.Level && st.UpStreak < *upNeed {
					target = st.Level
				}
			}

			// Block gating
			if target == LBlock && *blockMinSev > 0 {
				ok := true
				if st.HighSevSince.IsZero() {
					ok = false
				} else if *blockMinDur > 0 && nowWall.Sub(st.HighSevSince) < *blockMinDur {
					ok = false
				}
				if !ok {
					target = LHard // clamp
				}
			}

			// Apply transition (cooldown)
			if target != st.Level && nowWall.After(st.CooldownUntil) {
				prevLevel := st.Level
				st = transitionV6(ip, st, target, nowWall, *cooldown, *dryRun, deny6, rl6,
					*softRate, *softBurst, *softTTL,
					*hardRate, *hardBurst, *hardTTL,
					*blockTTL)

				log.Printf("STATE %s v6 %s->%s strikes=%d up=%d down=%d noncomp=%d sev=%.2f pps=%.0f syn=%.0f scan=%.0f dropRL/s=%.1f",
					ip6String(ip), prevLevel.String(), st.Level.String(),
					st.Strikes, st.UpStreak, st.DownStreak, st.NonCompTicks,
					m.Severity, m.PPS, m.SynRate, m.ScanRate, m.DropRLRate)
			}

			state6[ip] = st

			// Learning samples
			if *autoTune && clean {
				if st.Level == LObserve && m.Severity <= *learnMaxSev && m.DropRLRate == 0 {
					resPPS.Add(m.PPS)
					resSyn.Add(m.SynRate)
					resScan.Add(m.ScanRate)
				}
			}
		}

		// housekeeping: bound memory
		for ip, pv := range prev4 {
			if nowWall.Sub(pv.LastWall) > *prevTTL {
				delete(prev4, ip)
			}
		}
		for ip, pv := range prev6 {
			if nowWall.Sub(pv.LastWall) > *prevTTL {
				delete(prev6, ip)
			}
		}
		for ip, st := range state4 {
			if st.Level == LObserve && st.Strikes == 0 && !st.LastSeenWallTime.IsZero() && nowWall.Sub(st.LastSeenWallTime) > *stateTTL {
				delete(state4, ip)
			}
		}
		for ip, st := range state6 {
			if st.Level == LObserve && st.Strikes == 0 && !st.LastSeenWallTime.IsZero() && nowWall.Sub(st.LastSeenWallTime) > *stateTTL {
				delete(state6, ip)
			}
		}

		// Autotune schedule
		steadyK := *autoK
		steadyEveryEff := *autoEvery
		if *bootstrap {
			steadyEveryEff = *steadyEvery
		}
		steadyUp := *autoMaxChange
		steadyDown := *autoMaxChange
		if *autoMaxUp > 0 {
			steadyUp = *autoMaxUp
		}
		if *autoMaxDown > 0 {
			steadyDown = *autoMaxDown
		}
		steadyAlpha := *autoAlpha

		pol := bootstrapEffective(nowWall, bs, *bootstrapWindow, *bootstrapP1End, *bootstrapP2End,
			*bootstrapEvery1, *bootstrapEvery2, *bootstrapEvery3,
			*bootstrapKStart, *bootstrapKFinal,
			*bootstrapMaxUp1, *bootstrapMaxDown1, *bootstrapMaxUp2, *bootstrapMaxDown2, *bootstrapMaxUp3, *bootstrapMaxDown3,
			*bootstrapAlpha1, *bootstrapAlpha2, *bootstrapAlpha3,
			steadyEveryEff, steadyK, steadyUp, steadyDown, steadyAlpha)

		if *autoTune && pol.Every > 0 && time.Since(lastTune) >= pol.Every {
			n := minInt(len(resPPS.data), len(resSyn.data), len(resScan.data))
			cleanRatio := 0.0
			if totalLearnTicks > 0 {
				cleanRatio = float64(cleanLearnTicks) / float64(totalLearnTicks)
			}

			if n < *autoMinSamples {
				log.Printf("AUTOTUNE skipped: not enough samples (have=%d need=%d) cleanRatio=%.4f", n, *autoMinSamples, cleanRatio)
				lastTune = time.Now()
				continue
			}

			mPPS := median(resPPS.data)
			mdPPS := mad(resPPS.data, mPPS)
			mSyn := median(resSyn.data)
			mdSyn := mad(resSyn.data, mSyn)
			mScan := median(resScan.data)
			mdScan := mad(resScan.data, mScan)

			// target trig = max(floor, median + k*mad)
			targetPPS := math.Max(*autoFloorPPS, mPPS+(pol.K)*mdPPS)
			targetSyn := math.Max(*autoFloorSyn, mSyn+(pol.K)*mdSyn)
			targetScan := math.Max(*autoFloorScan, mScan+(pol.K)*mdScan)

			// change cap
			targetPPS = capChangeDir(*trigPPS, targetPPS, pol.MaxUp, pol.MaxDown)
			targetSyn = capChangeDir(*trigSyn, targetSyn, pol.MaxUp, pol.MaxDown)
			targetScan = capChangeDir(*trigScan, targetScan, pol.MaxUp, pol.MaxDown)

			// smoothing
			if pol.Alpha > 0 && pol.Alpha < 1 {
				targetPPS = (*trigPPS)*(1-pol.Alpha) + targetPPS*(pol.Alpha)
				targetSyn = (*trigSyn)*(1-pol.Alpha) + targetSyn*(pol.Alpha)
				targetScan = (*trigScan)*(1-pol.Alpha) + targetScan*(pol.Alpha)
			}

			oldPPS, oldSyn, oldScan := *trigPPS, *trigSyn, *trigScan
			*trigPPS, *trigSyn, *trigScan = targetPPS, targetSyn, targetScan
			lastTune = time.Now()

			log.Printf("AUTOTUNE applied: trig_pps %.1f->%.1f trig_syn %.1f->%.1f trig_scan %.1f->%.1f (median+MAD k=%.2f) samples=%d cleanRatio=%.4f clean=%v dropRatio=%.4f phase=%s",
				oldPPS, *trigPPS, oldSyn, *trigSyn, oldScan, *trigScan, pol.K, n, cleanRatio, clean, dropRatio, pol.Phase)

			// persist
			if *statePath != "" {
				st := stFile
				if st == nil {
					st = &stateFile{Version: 1}
				}

				rev := st.Active.Revision + 1
				entry := stateHistory{
					Revision: rev,
					At:       time.Now(),
					Trig: trigState{
						TrigPPS:  *trigPPS,
						TrigSyn:  *trigSyn,
						TrigScan: *trigScan,
					},
					MedianPPS:   mPPS,
					MadPPS:      mdPPS,
					MedianSyn:   mSyn,
					MadSyn:      mdSyn,
					MedianScan:  mScan,
					MadScan:     mdScan,
					SampleCount: n,
					CleanRatio:  cleanRatio,
					Notes:       fmt.Sprintf("autotune median+mad dropRatio=%.4f phase=%s", dropRatio, pol.Phase),
				}

				st.History = append(st.History, entry)
				if len(st.History) > *historyKeep && *historyKeep > 0 {
					st.History = st.History[len(st.History)-*historyKeep:]
				}

				st.Active = stateActive{
					Profile:   p.Name,
					Revision:  rev,
					UpdatedAt: time.Now(),
					Trig: trigState{
						TrigPPS:  *trigPPS,
						TrigSyn:  *trigSyn,
						TrigScan: *trigScan,
					},
					Tune: tuneMeta{
						Method:      "median_mad",
						Window:      "reservoir",
						K:           pol.K,
						SigmaFactor: 1.4826,
					},
					Bootstrap:   bs,
					SampleCount: n,
					CleanRatio:  cleanRatio,
					Notes:       "autotune",
				}

				if err := writeStateAtomic(*statePath, st); err != nil {
					log.Printf("AUTOTUNE state write failed: %v", err)
				} else {
					stFile = st
					log.Printf("AUTOTUNE state saved: %s (rev=%d)", *statePath, rev)
				}
			}
		}

		if len(cands) > 0 {
			top := cands[0]
			topWL := false
			if top.IPVer == 4 {
				topWL = wl.matchV4(top.IP4)
			} else {
				topWL = wl.matchV6(top.IP6)
			}
			fmt.Printf("TOP %-39s ipver=%d sev=%.2f pps=%.0f syn=%.0f scan=%.0f dropRL/s=%.1f trig{pps=%.0f syn=%.0f scan=%.0f} clean=%v dropRatio=%.4f wl=%v phase=%s\n",
				top.ipString(), top.IPVer, top.Severity, top.PPS, top.SynRate, top.ScanRate, top.DropRLRate,
				*trigPPS, *trigSyn, *trigScan, clean, dropRatio, topWL, pol.Phase)
		}
	}
}
