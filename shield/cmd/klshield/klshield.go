// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	// pinned link (per Kernloom docs)
	pinXdpLink = "/sys/fs/bpf/kernloom_shield_xdp_link"

	// pinned maps (per Kernloom docs)
	pinTotals    = "/sys/fs/bpf/kernloom_totals"
	pinSrc4Stats = "/sys/fs/bpf/kernloom_src4_stats"
	pinSrc6Stats = "/sys/fs/bpf/kernloom_src6_stats"

	pinAllow4LPM = "/sys/fs/bpf/kernloom_allow4_lpm"
	pinDeny4Hash = "/sys/fs/bpf/kernloom_deny4_hash"
	pinAllow6LPM = "/sys/fs/bpf/kernloom_allow6_lpm"
	pinDeny6Hash = "/sys/fs/bpf/kernloom_deny6_hash"

	pinCfg = "/sys/fs/bpf/kernloom_cfg"

	pinRLCfg     = "/sys/fs/bpf/kernloom_rl_cfg"
	pinRLPolicy4 = "/sys/fs/bpf/kernloom_rl_policy4"
	pinRLPolicy6 = "/sys/fs/bpf/kernloom_rl_policy6"

	pinEvents = "/sys/fs/bpf/kernloom_events"
)

/* ---------------- Types ---------------- */

type xdpCfg struct {
	EnforceAllow    uint32
	EventSampleMask uint32
}

type rlCfg struct {
	RatePPS uint64
	Burst   uint64
}

type lpmKey4 struct {
	Prefixlen uint32
	Data      [4]byte
}
type lpmKey6 struct {
	Prefixlen uint32
	Data      [16]byte
}

type key4Bytes struct{ IP [4]byte }
type key6Bytes struct{ IP [16]byte }
type src6Key struct{ IP [16]byte }

// MUST match Shield C layout for xdp_src_stats_v4_t (including explicit padding).
type src4Stats struct {
	Pkts  uint64
	Bytes uint64

	TCP  uint64
	UDP  uint64
	ICMP uint64

	SYN    uint64
	SYNACK uint64
	RST    uint64
	ACK    uint64

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

// Totals: MUST match Shield C layout for xdp_totals_t.
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

type xdpEvent struct {
	TsNs    uint64
	Reason  uint32
	IPVer   uint8
	L4Proto uint8
	Dport   uint16
	SaddrV4 [4]byte
	SaddrV6 [16]byte
	PktLen  uint32
	Aux     uint32
}

type bpfObjects struct {
	// Program: support both symbol names during transition:
	// - new: xdp_klshield
	// - old: xdp_netguard
	XdpProgram *ebpf.Program

	XdpTotals    *ebpf.Map
	XdpSrc4Stats *ebpf.Map
	XdpSrc6Stats *ebpf.Map

	XdpAllowLpm  *ebpf.Map
	XdpDenyHash4 *ebpf.Map
	XdpAllow6Lpm *ebpf.Map
	XdpDenyHash6 *ebpf.Map
	XdpCfg       *ebpf.Map

	XdpRLCfg     *ebpf.Map
	XdpRLPolicy4 *ebpf.Map
	XdpRLPolicy6 *ebpf.Map

	XdpEventsRing *ebpf.Map

	coll *ebpf.Collection
}

func (o *bpfObjects) Close() {
	if o != nil && o.coll != nil {
		o.coll.Close()
		o.coll = nil
	}
}

/* ---------------- Helpers ---------------- */

func must(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", msg, err)
		os.Exit(1)
	}
}
func mustIf(cond bool, msg string) {
	if cond {
		must(errors.New("invalid"), msg)
	}
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func openPinnedMap(path string) (*ebpf.Map, error) { return ebpf.LoadPinnedMap(path, nil) }

func tryOpenPinnedMap(path string) (*ebpf.Map, bool) {
	m, err := openPinnedMap(path)
	if err != nil {
		return nil, false
	}
	return m, true
}

func pinIfMissing(m *ebpf.Map, path string) error {
	if exists(path) {
		return nil
	}
	return m.Pin(path)
}

/*
BPF uses bpf_ktime_get_ns() for timestamps => monotonic since boot.

To print wall-clock:
- approximate boot time via /proc/uptime
- wall = boot + monotonic_ns
*/
func approxBootTime() time.Time {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Now()
	}
	var upSec float64
	_, _ = fmt.Sscanf(string(b), "%f", &upSec)
	return time.Now().Add(-time.Duration(upSec * float64(time.Second)))
}

func initCfgDefaults() {
	m, err := openPinnedMap(pinCfg)
	if err != nil {
		return
	}
	defer m.Close()

	var k uint32 = 0
	var cur xdpCfg
	_ = m.Lookup(&k, &cur)

	// Reasonable default: 1/1024 sampling (mask=1023). User can set to 1 or 3 for more.
	if cur.EventSampleMask == 0 {
		cur.EventSampleMask = 1023
		_ = m.Update(&k, &cur, ebpf.UpdateAny)
	}
}

func loadBPFWithReplacements(objPath string) (*bpfObjects, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, err
	}

	// Reuse pinned maps if they exist.
	repl := map[string]*ebpf.Map{}
	for name, pin := range map[string]string{
		"xdp_totals":     pinTotals,
		"xdp_src4_stats": pinSrc4Stats,
		"xdp_src6_stats": pinSrc6Stats,

		"xdp_allow_lpm":  pinAllow4LPM,
		"xdp_deny_hash":  pinDeny4Hash,
		"xdp_allow6_lpm": pinAllow6LPM,
		"xdp_deny6_hash": pinDeny6Hash,

		"xdp_cfg": pinCfg,

		"xdp_rl_cfg":     pinRLCfg,
		"xdp_rl_policy4": pinRLPolicy4,
		"xdp_rl_policy6": pinRLPolicy6,

		"xdp_events": pinEvents,
	} {
		if m, ok := tryOpenPinnedMap(pin); ok {
			repl[name] = m
		}
	}

	opts := ebpf.CollectionOptions{MapReplacements: repl}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, err
	}

	getMap := func(name string) (*ebpf.Map, error) {
		m := coll.Maps[name]
		if m == nil {
			return nil, fmt.Errorf("missing map in object: %s", name)
		}
		return m, nil
	}

	// Program name: prefer new, fallback to old.
	var prog *ebpf.Program
	if p := coll.Programs["xdp_klshield"]; p != nil {
		prog = p
	} else if p := coll.Programs["xdp_netguard"]; p != nil {
		prog = p
	} else {
		coll.Close()
		return nil, fmt.Errorf("missing xdp program: expected xdp_klshield (new) or xdp_netguard (old)")
	}

	objs := &bpfObjects{XdpProgram: prog, coll: coll}
	var err2 error

	if objs.XdpTotals, err2 = getMap("xdp_totals"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpSrc4Stats, err2 = getMap("xdp_src4_stats"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpSrc6Stats, err2 = getMap("xdp_src6_stats"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpAllowLpm, err2 = getMap("xdp_allow_lpm"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpDenyHash4, err2 = getMap("xdp_deny_hash"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpAllow6Lpm, err2 = getMap("xdp_allow6_lpm"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpDenyHash6, err2 = getMap("xdp_deny6_hash"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpCfg, err2 = getMap("xdp_cfg"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpRLCfg, err2 = getMap("xdp_rl_cfg"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpRLPolicy4, err2 = getMap("xdp_rl_policy4"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpRLPolicy6, err2 = getMap("xdp_rl_policy6"); err2 != nil {
		objs.Close()
		return nil, err2
	}
	if objs.XdpEventsRing, err2 = getMap("xdp_events"); err2 != nil {
		objs.Close()
		return nil, err2
	}

	// Pin maps (names per docs) if missing.
	if err := pinIfMissing(objs.XdpTotals, pinTotals); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpSrc4Stats, pinSrc4Stats); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpSrc6Stats, pinSrc6Stats); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpAllowLpm, pinAllow4LPM); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpDenyHash4, pinDeny4Hash); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpAllow6Lpm, pinAllow6LPM); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpDenyHash6, pinDeny6Hash); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpCfg, pinCfg); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpRLCfg, pinRLCfg); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpRLPolicy4, pinRLPolicy4); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpRLPolicy6, pinRLPolicy6); err != nil {
		objs.Close()
		return nil, err
	}
	if err := pinIfMissing(objs.XdpEventsRing, pinEvents); err != nil {
		objs.Close()
		return nil, err
	}

	initCfgDefaults()
	return objs, nil
}

func ifaceIndex(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

func execCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

/* ---------------- XDP Attach/Detach ---------------- */

func attachXDP(iface, obj string, force bool) {
	if force {
		_ = execCommand("ip", "link", "set", "dev", iface, "xdp", "off")
		_ = os.Remove(pinXdpLink)
	}

	objs, err := loadBPFWithReplacements(obj)
	must(err, "load BPF")
	defer objs.Close()

	if exists(pinXdpLink) {
		fmt.Printf("XDP link already pinned at %s (detach first)\n", pinXdpLink)
		return
	}

	idx, err := ifaceIndex(iface)
	must(err, "get iface index")

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgram,
		Interface: idx,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		lnk, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpProgram,
			Interface: idx,
			Flags:     link.XDPGenericMode,
		})
		must(err, "attach xdp (driver+generic failed)")
	}

	must(lnk.Pin(pinXdpLink), "pin xdp link")
	fmt.Printf("Attached Kernloom Shield XDP to %s (link pinned at %s)\n", iface, pinXdpLink)
}

func detachXDP() {
	lnk, err := link.LoadPinnedLink(pinXdpLink, nil)
	if err != nil {
		fmt.Printf("No pinned XDP link found at %s\n", pinXdpLink)
		return
	}
	_ = os.Remove(pinXdpLink)
	_ = lnk.Close()
	fmt.Println("Detached Kernloom Shield XDP (closed pinned link).")
}

/* ---------------- Allow/Deny management ---------------- */

func addAllowCIDR(cidr string) {
	_, ipnet, err := net.ParseCIDR(cidr)
	must(err, "parse cidr")
	ones, _ := ipnet.Mask.Size()

	ip := ipnet.IP
	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinAllow4LPM)
		must(err, "open allow4 lpm")
		defer m.Close()

		var k lpmKey4
		k.Prefixlen = uint32(ones)
		copy(k.Data[:], ip4[:])
		var v uint8 = 1
		must(m.Update(&k, &v, ebpf.UpdateAny), "update allow4")
		fmt.Printf("allow4 add: %s\n", cidr)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "cidr ip")
	m, err := openPinnedMap(pinAllow6LPM)
	must(err, "open allow6 lpm")
	defer m.Close()

	var k lpmKey6
	k.Prefixlen = uint32(ones)
	copy(k.Data[:], ip16[:])
	var v uint8 = 1
	must(m.Update(&k, &v, ebpf.UpdateAny), "update allow6")
	fmt.Printf("allow6 add: %s\n", cidr)
}

func listAllow() {
	// v4
	if m, err := openPinnedMap(pinAllow4LPM); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k lpmKey4
		var v uint8
		fmt.Println("Allow v4:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IPv4(k.Data[0], k.Data[1], k.Data[2], k.Data[3])
			fmt.Printf("  %s/%d\n", ip.String(), k.Prefixlen)
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate allow v4 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("Allow v4: cannot open %s: %v\n", pinAllow4LPM, err)
	}

	// v6
	if m, err := openPinnedMap(pinAllow6LPM); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k lpmKey6
		var v uint8
		fmt.Println("Allow v6:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IP(k.Data[:])
			fmt.Printf("  %s/%d\n", ip.String(), k.Prefixlen)
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate allow v6 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("Allow v6: cannot open %s: %v\n", pinAllow6LPM, err)
	}
}

func addDenyIP(ipStr string) {
	ip := net.ParseIP(ipStr)
	mustIf(ip == nil, "parse ip")

	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinDeny4Hash)
		must(err, "open deny4")
		defer m.Close()
		var k key4Bytes
		copy(k.IP[:], ip4[:])
		var v uint8 = 1
		must(m.Update(&k, &v, ebpf.UpdateAny), "update deny4")
		fmt.Printf("deny4 add: %s\n", ipStr)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "parse ip16")
	m, err := openPinnedMap(pinDeny6Hash)
	must(err, "open deny6")
	defer m.Close()
	var k key6Bytes
	copy(k.IP[:], ip16[:])
	var v uint8 = 1
	must(m.Update(&k, &v, ebpf.UpdateAny), "update deny6")
	fmt.Printf("deny6 add: %s\n", ipStr)
}

func delDenyIP(ipStr string) {
	ip := net.ParseIP(ipStr)
	mustIf(ip == nil, "parse ip")

	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinDeny4Hash)
		must(err, "open deny4")
		defer m.Close()
		var k key4Bytes
		copy(k.IP[:], ip4[:])
		must(m.Delete(&k), "delete deny4")
		fmt.Printf("deny4 removed: %s\n", ipStr)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "parse ip16")
	m, err := openPinnedMap(pinDeny6Hash)
	must(err, "open deny6")
	defer m.Close()
	var k key6Bytes
	copy(k.IP[:], ip16[:])
	must(m.Delete(&k), "delete deny6")
	fmt.Printf("deny6 removed: %s\n", ipStr)
}

func listDeny() {
	// v4
	if m, err := openPinnedMap(pinDeny4Hash); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k key4Bytes
		var v uint8
		fmt.Println("Deny v4:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IPv4(k.IP[0], k.IP[1], k.IP[2], k.IP[3])
			fmt.Printf("  %s\n", ip.String())
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate deny v4 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("Deny v4: cannot open %s: %v\n", pinDeny4Hash, err)
	}

	// v6
	if m, err := openPinnedMap(pinDeny6Hash); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k key6Bytes
		var v uint8
		fmt.Println("Deny v6:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IP(k.IP[:])
			fmt.Printf("  %s\n", ip.String())
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate deny v6 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	}
}

/* ---------------- Runtime cfg ---------------- */

func enforceAllow(on bool) {
	m, err := openPinnedMap(pinCfg)
	must(err, "open kernloom_cfg")
	defer m.Close()

	var k uint32 = 0
	var cur xdpCfg
	_ = m.Lookup(&k, &cur)
	if on {
		cur.EnforceAllow = 1
	} else {
		cur.EnforceAllow = 0
	}
	if cur.EventSampleMask == 0 {
		cur.EventSampleMask = 1023
	}
	must(m.Update(&k, &cur, ebpf.UpdateAny), "update cfg")
	fmt.Printf("enforce_allow=%v, event_sample_mask=%d\n", on, cur.EventSampleMask)
}

func setEventSampling(mask uint32) {
	m, err := openPinnedMap(pinCfg)
	must(err, "open kernloom_cfg")
	defer m.Close()

	var k uint32 = 0
	var cur xdpCfg
	_ = m.Lookup(&k, &cur)
	cur.EventSampleMask = mask
	must(m.Update(&k, &cur, ebpf.UpdateAny), "update cfg sampling")
	fmt.Printf("event_sample_mask=%d (0 disables events)\n", mask)
}

/* ---------------- Rate limiting ---------------- */

func rlSet(rate, burst uint64) {
	m, err := openPinnedMap(pinRLCfg)
	must(err, "open kernloom_rl_cfg")
	defer m.Close()

	var k uint32 = 0
	val := rlCfg{RatePPS: rate, Burst: burst}
	must(m.Update(&k, &val, ebpf.UpdateAny), "update rl cfg")
	fmt.Printf("rl cfg: rate=%d pps, burst=%d\n", rate, burst)
}

func rlSetIP(ipStr string, rate, burst uint64) {
	ip := net.ParseIP(ipStr)
	mustIf(ip == nil, "parse ip")

	val := rlCfg{RatePPS: rate, Burst: burst}

	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinRLPolicy4)
		must(err, "open rl policy4")
		defer m.Close()
		var k key4Bytes
		copy(k.IP[:], ip4[:])
		must(m.Update(&k, &val, ebpf.UpdateAny), "update rl policy4")
		fmt.Printf("rl ip v4: %s rate=%d burst=%d\n", ipStr, rate, burst)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "parse ip16")
	m, err := openPinnedMap(pinRLPolicy6)
	must(err, "open rl policy6")
	defer m.Close()
	var k src6Key
	copy(k.IP[:], ip16[:])
	must(m.Update(&k, &val, ebpf.UpdateAny), "update rl policy6")
	fmt.Printf("rl ip v6: %s rate=%d burst=%d\n", ipStr, rate, burst)
}

func rlUnsetIP(ipStr string) {
	ip := net.ParseIP(ipStr)
	mustIf(ip == nil, "parse ip")

	if ip4 := ip.To4(); ip4 != nil {
		m, err := openPinnedMap(pinRLPolicy4)
		must(err, "open rl policy4")
		defer m.Close()
		var k key4Bytes
		copy(k.IP[:], ip4[:])
		must(m.Delete(&k), "delete rl policy4")
		fmt.Printf("rl ip v4 removed: %s\n", ipStr)
		return
	}

	ip16 := ip.To16()
	mustIf(ip16 == nil, "parse ip16")
	m, err := openPinnedMap(pinRLPolicy6)
	must(err, "open rl policy6")
	defer m.Close()
	var k src6Key
	copy(k.IP[:], ip16[:])
	must(m.Delete(&k), "delete rl policy6")
	fmt.Printf("rl ip v6 removed: %s\n", ipStr)
}

func listRL() {
	// global cfg
	if m, err := openPinnedMap(pinRLCfg); err == nil {
		defer m.Close()
		var k uint32 = 0
		var v rlCfg
		if err := m.Lookup(&k, &v); err == nil {
			fmt.Printf("RL global: rate=%d pps burst=%d\n", v.RatePPS, v.Burst)
		} else {
			fmt.Printf("RL global: lookup err: %v\n", err)
		}
	} else {
		fmt.Printf("RL global: cannot open %s: %v\n", pinRLCfg, err)
	}

	// v4 overrides
	if m, err := openPinnedMap(pinRLPolicy4); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k key4Bytes
		var v rlCfg
		fmt.Println("RL overrides v4:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IPv4(k.IP[0], k.IP[1], k.IP[2], k.IP[3])
			fmt.Printf("  %s rate=%d burst=%d\n", ip.String(), v.RatePPS, v.Burst)
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate rl v4 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("RL overrides v4: cannot open %s: %v\n", pinRLPolicy4, err)
	}

	// v6 overrides
	if m, err := openPinnedMap(pinRLPolicy6); err == nil {
		defer m.Close()
		it := m.Iterate()
		var k src6Key
		var v rlCfg
		fmt.Println("RL overrides v6:")
		n := 0
		for it.Next(&k, &v) {
			ip := net.IP(k.IP[:])
			fmt.Printf("  %s rate=%d burst=%d\n", ip.String(), v.RatePPS, v.Burst)
			n++
		}
		if err := it.Err(); err != nil {
			fmt.Printf("iterate rl v6 error: %v\n", err)
		}
		if n == 0 {
			fmt.Println("  (none)")
		}
	} else {
		fmt.Printf("RL overrides v6: cannot open %s: %v\n", pinRLPolicy6, err)
	}
}

/* ---------------- Stats ---------------- */

func sumPerCPU(vals []xdpTotals) xdpTotals {
	var out xdpTotals
	for _, v := range vals {
		out.Pkts += v.Pkts
		out.Bytes += v.Bytes
		out.Pass += v.Pass
		out.DropAllow += v.DropAllow
		out.DropDeny += v.DropDeny
		out.DropRL += v.DropRL
		out.V4 += v.V4
		out.V6 += v.V6
		out.TCP += v.TCP
		out.UDP += v.UDP
		out.ICMP += v.ICMP
		out.SYN += v.SYN
		out.SYNACK += v.SYNACK
		out.RST += v.RST
		out.ACK += v.ACK
		out.IPv4Frags += v.IPv4Frags
		out.DportChg += v.DportChg
		out.NewSources += v.NewSources
		out.AllowHits += v.AllowHits
		out.DenyHits += v.DenyHits
		out.RLHits += v.RLHits
	}
	return out
}

func readTotals() xdpTotals {
	m, err := openPinnedMap(pinTotals)
	must(err, "open totals")
	defer m.Close()

	var k uint32 = 0
	var perCPU []xdpTotals
	must(m.Lookup(&k, &perCPU), "lookup totals per-cpu")

	return sumPerCPU(perCPU)
}

func stats() {
	t := readTotals()
	fmt.Println("=== XDP Totals ===")
	fmt.Printf("pkts=%d bytes=%d pass=%d drop_allow=%d drop_deny=%d drop_rl=%d\n",
		t.Pkts, t.Bytes, t.Pass, t.DropAllow, t.DropDeny, t.DropRL)
	fmt.Printf("v4=%d v6=%d tcp=%d udp=%d icmp=%d syn=%d synack=%d ack=%d rst=%d\n",
		t.V4, t.V6, t.TCP, t.UDP, t.ICMP, t.SYN, t.SYNACK, t.ACK, t.RST)
	fmt.Printf("ipv4_frags=%d dport_changes=%d new_sources=%d allow_hits=%d deny_hits=%d rl_hits=%d\n",
		t.IPv4Frags, t.DportChg, t.NewSources, t.AllowHits, t.DenyHits, t.RLHits)
}

/* ---------------- Top Sources (v4) ---------------- */

type topEntry struct {
	IP        string
	Pkts      uint64
	Bytes     uint64
	DropAllow uint64
	DropDeny  uint64
	DropRL    uint64
	LastNs    uint64
	FirstNs   uint64
}

func topSrc(n int, by string) {
	m, err := openPinnedMap(pinSrc4Stats)
	must(err, "open src4 stats")
	defer m.Close()

	boot := approxBootTime()

	it := m.Iterate()
	var k [4]byte
	var v src4Stats

	out := make([]topEntry, 0, n)

	for it.Next(&k, &v) {
		ip := net.IPv4(k[0], k[1], k[2], k[3]).String()
		out = append(out, topEntry{
			IP:        ip,
			Pkts:      v.Pkts,
			Bytes:     v.Bytes,
			DropAllow: v.DropAllow,
			DropDeny:  v.DropDeny,
			DropRL:    v.DropRL,
			LastNs:    v.LastSeenNs,
			FirstNs:   v.FirstSeenNs,
		})
	}
	if err := it.Err(); err != nil {
		fmt.Printf("iterate src4 error: %v\n", err)
	}

	sort.Slice(out, func(i, j int) bool {
		switch by {
		case "bytes":
			return out[i].Bytes > out[j].Bytes
		case "droprl":
			return out[i].DropRL > out[j].DropRL
		case "drops":
			return (out[i].DropAllow + out[i].DropDeny + out[i].DropRL) > (out[j].DropAllow + out[j].DropDeny + out[j].DropRL)
		default:
			return out[i].Pkts > out[j].Pkts
		}
	})

	if n > len(out) {
		n = len(out)
	}

	fmt.Printf("=== Top %d src4 by %s ===\n", n, by)
	for i := 0; i < n; i++ {
		e := out[i]
		last := boot.Add(time.Duration(e.LastNs)).Format(time.RFC3339Nano)
		first := boot.Add(time.Duration(e.FirstNs)).Format(time.RFC3339Nano)
		fmt.Printf("%2d) %-15s pkts=%d bytes=%d drop_allow=%d drop_deny=%d drop_rl=%d last=%s first=%s\n",
			i+1, e.IP, e.Pkts, e.Bytes, e.DropAllow, e.DropDeny, e.DropRL, last, first)
	}
}

/* ---------------- Events ---------------- */

func events() {
	m, err := openPinnedMap(pinEvents)
	must(err, "open kernloom_events ringbuf")
	defer m.Close()

	rd, err := ringbuf.NewReader(m)
	must(err, "ringbuf reader")
	defer rd.Close()

	boot := approxBootTime()

	fmt.Println("Listening for events (Ctrl+C to stop) ...")
	fmt.Println("Tip: increase event rate with:  sudo ./klshield set-sampling 1")
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		buf := rec.RawSample
		if len(buf) < 44 {
			continue
		}

		var e xdpEvent
		e.TsNs = binary.LittleEndian.Uint64(buf[0:8])
		e.Reason = binary.LittleEndian.Uint32(buf[8:12])
		e.IPVer = buf[12]
		e.L4Proto = buf[13]
		e.Dport = binary.BigEndian.Uint16(buf[14:16])
		copy(e.SaddrV4[:], buf[16:20])
		copy(e.SaddrV6[:], buf[20:36])
		e.PktLen = binary.LittleEndian.Uint32(buf[36:40])
		e.Aux = binary.LittleEndian.Uint32(buf[40:44])

		when := boot.Add(time.Duration(e.TsNs)).Format(time.RFC3339Nano)
		reason := map[uint32]string{1: "DROP_ALLOW", 2: "DROP_DENY", 3: "DROP_RL", 4: "SCAN_HINT"}[e.Reason]

		var src string
		if e.IPVer == 4 {
			src = net.IPv4(e.SaddrV4[0], e.SaddrV4[1], e.SaddrV4[2], e.SaddrV4[3]).String()
		} else {
			src = net.IP(e.SaddrV6[:]).String()
		}

		fmt.Printf("%s %s ipver=%d proto=%d src=%s dport=%d len=%d aux=%d\n",
			when, reason, e.IPVer, e.L4Proto, src, e.Dport, e.PktLen, e.Aux)
	}
}

/* ---------------- CLI ---------------- */

func usage() {
	fmt.Print(`klshield (Kernloom Shield, XDP only)

Commands:
  attach-xdp   -iface eth0 [-obj bpf/klshield.bpf.o] [-force]
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
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "attach-xdp":
		fs := flag.NewFlagSet("attach-xdp", flag.ExitOnError)
		iface := fs.String("iface", "eth0", "interface")
		obj := fs.String("obj", "bpf/klshield.bpf.o", "bpf object path")
		force := fs.Bool("force", false, "detach any existing XDP program from iface before attach (WARNING)")
		_ = fs.Parse(os.Args[2:])
		args := fs.Args()
		if len(args) >= 1 {
			*iface = args[0]
		}
		attachXDP(*iface, *obj, *force)

	case "detach-xdp":
		detachXDP()

	case "add-allow-cidr":
		if len(os.Args) < 3 {
			must(errors.New("missing cidr"), "add-allow-cidr")
		}
		addAllowCIDR(os.Args[2])

	case "list-allow":
		listAllow()

	case "add-deny-ip":
		if len(os.Args) < 3 {
			must(errors.New("missing ip"), "add-deny-ip")
		}
		addDenyIP(os.Args[2])

	case "del-deny-ip":
		if len(os.Args) < 3 {
			must(errors.New("missing ip"), "del-deny-ip")
		}
		delDenyIP(os.Args[2])

	case "list-deny":
		listDeny()

	case "enforce-allow":
		if len(os.Args) < 3 {
			must(errors.New("missing on|off"), "enforce-allow")
		}
		on := strings.ToLower(os.Args[2]) == "on"
		enforceAllow(on)

	case "set-sampling":
		if len(os.Args) < 3 {
			must(errors.New("missing mask"), "set-sampling")
		}
		var mask uint32
		_, err := fmt.Sscanf(os.Args[2], "%d", &mask)
		must(err, "parse mask")
		setEventSampling(mask)

	case "rl-set":
		fs := flag.NewFlagSet("rl-set", flag.ExitOnError)
		rate := fs.Uint64("rate", 0, "tokens/sec (pps)")
		burst := fs.Uint64("burst", 0, "max tokens")
		_ = fs.Parse(os.Args[2:])
		rlSet(*rate, *burst)

	case "rl-set-ip":
		fs := flag.NewFlagSet("rl-set-ip", flag.ExitOnError)
		rate := fs.Uint64("rate", 0, "tokens/sec (pps)")
		burst := fs.Uint64("burst", 0, "max tokens")
		_ = fs.Parse(os.Args[2:])
		args := fs.Args()
		if len(args) < 1 {
			must(errors.New("missing ip"), "rl-set-ip")
		}
		rlSetIP(args[0], *rate, *burst)

	case "rl-unset-ip":
		if len(os.Args) < 3 {
			must(errors.New("missing ip"), "rl-unset-ip")
		}
		rlUnsetIP(os.Args[2])

	case "list-rl":
		listRL()

	case "stats":
		stats()

	case "top-src":
		fs := flag.NewFlagSet("top-src", flag.ExitOnError)
		n := fs.Int("n", 20, "top N")
		by := fs.String("by", "pkts", "pkts|bytes|drops|droprl")
		_ = fs.Parse(os.Args[2:])
		topSrc(*n, *by)

	case "events":
		events()

	default:
		usage()
		os.Exit(1)
	}
}
