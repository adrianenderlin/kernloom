# Contributing to Kernloom

Thanks for your interest in contributing to Kernloom.

Kernloom currently consists of two main parts:

- **Kernloom Shield (`klshield`)** — the XDP/eBPF data plane
- **Kernloom IQ (`kliq`)** — the userspace control plane / decision engine

This document explains how to propose changes safely and in a way that is easy to review.

---

## Scope

Contributions are welcome for:

- bug fixes
- documentation improvements
- test improvements
- performance improvements
- CLI UX improvements
- telemetry improvements
- IPv4 / IPv6 handling
- rate-limit and enforcement logic
- packaging and release workflow improvements

Please keep changes focused. Small, well-scoped pull requests are much easier to review than large rewrites.

---

## Before you start

For larger changes, open an issue first and describe:

- the problem
- why the current behavior is insufficient
- the proposed approach
- compatibility or migration impact
- performance or safety considerations

This is especially important for changes touching:

- eBPF/XDP packet-path logic
- map layout / pinned map compatibility
- userspace ↔ BPF interfaces
- telemetry formats
- enforcement state machines
- public CLI flags or output formats
- licensing boundaries between modules

---

## Development principles

When contributing to Kernloom, prefer the following:

- **Safety over cleverness** in packet-path code
- **Predictable behavior** over implicit magic
- **Readable control logic** over dense heuristics
- **Backward awareness** when changing map formats or CLI behavior
- **Small reviewable commits** with clear intent
- **Operational realism**: assume production traffic, NAT, IPv4 and IPv6, and noisy edge environments

---

## Local build

From the repository root:

```bash
make -C shield/bpf
mkdir -p bin
go build -o bin/klshield ./shield/cmd/klshield
go build -o bin/kliq ./iq/cmd/kliq
```

Typical prerequisites include:

- Linux
- `clang`
- `llvm`
- `bpftool`
- `iproute2`
- Go toolchain
- bpffs mounted at `/sys/fs/bpf`

Example:

```bash
sudo mount -t bpf bpf /sys/fs/bpf || true
```

---

## Coding expectations

### Go

- Keep functions small and explicit
- Return actionable error messages
- Avoid hidden side effects in CLI commands
- Keep flag names stable unless there is a strong reason to change them
- Prefer compatibility-preserving changes where possible

### C / eBPF

- Keep hot-path logic minimal
- Be conservative with complexity in XDP code
- Comment non-obvious verifier-sensitive logic
- Avoid unnecessary branching and state expansion
- Document map purpose, key/value shape, and compatibility impact

### Documentation

- Update docs together with behavior changes
- Keep examples copy-pasteable
- Prefer concrete operational wording over marketing language
- Call out security or compatibility impact explicitly

---

## Commit style

Use clear commit messages.

Good examples:

- `shield: fix IPv6 deny-map lookup`
- `iq: reduce block escalation on NAT-heavy sources`
- `docs: clarify whitelist and feedback file permissions`
- `release: add version metadata to binaries`

Try to keep unrelated changes out of the same commit.

---

## Signed-off-by / DCO

For all non-trivial contributions, please sign off your commits:

```bash
git commit -s -m "shield: fix IPv6 deny-map lookup"
```

This adds a `Signed-off-by:` line and confirms that you have the right to submit the contribution under the repository's license model.

Maintainers may require signed-off commits before merging.

---

## Pull requests

Please include in your PR:

- what changed
- why it changed
- risk / compatibility notes
- how it was tested
- whether docs were updated

Useful additions where relevant:

- benchmark notes
- packet-path reasoning
- example commands
- before/after behavior
- sample output for CLI changes

If your change affects enforcement or telemetry, mention the expected effect on:

- false positives
- NAT-heavy clients
- IPv6
- memory usage / map pressure
- packet-path latency

---

## Testing guidance

At minimum, contributors should do the most relevant subset of the following:

### General

- build `shield/bpf`
- build `klshield`
- build `kliq`
- verify that changed commands still parse and run

### Shield-related changes

- attach XDP successfully
- inspect stats output
- validate allow/deny behavior
- validate rate-limit behavior
- verify pinned map behavior if affected
- check both IPv4 and IPv6 if relevant

### IQ-related changes

- verify telemetry ingestion still works
- verify severity scoring behavior
- verify FSM transitions
- verify whitelist / feedback handling
- verify action writes back to Shield maps correctly

### Docs-only changes

- verify paths, commands, filenames, and flags actually match the current repo

---

## Backward compatibility

Please explicitly call out if your change affects:

- pinned map compatibility
- object file paths
- CLI flags
- output formats intended for scripting
- config file locations
- default enforcement behavior

Breaking changes should be clearly justified.

---

## Licensing

By contributing, you agree that your contribution may be distributed under the licenses used in this repository.

At the time of writing, this repository uses a multi-license layout. Contributors must preserve existing license boundaries and headers where applicable.

In particular, review carefully before moving code between components with different license requirements.

---

## What maintainers may reject

A contribution may be declined if it:

- increases packet-path complexity without clear benefit
- weakens security or operational predictability
- changes CLI behavior without documentation
- mixes unrelated refactors with functional changes
- introduces unclear licensing status
- lacks enough context to review safely

---

## Questions

If you are unsure, open an issue and describe the intended change before investing heavily in implementation.

Thanks for helping improve Kernloom.
