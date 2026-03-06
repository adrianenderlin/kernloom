## Summary

Describe the change in a few sentences.

## Why this change

What problem does this solve?

## Scope

- [ ] Shield / eBPF dataplane
- [ ] IQ / userspace controller
- [ ] CLI / UX
- [ ] Docs
- [ ] Build / release
- [ ] Other

## Risk / compatibility notes

Describe any impact on:

- CLI flags or output
- pinned maps
- default behavior
- IPv4 / IPv6 behavior
- NAT-heavy environments
- performance / latency

## Testing

What did you test?

- [ ] `make -C shield/bpf`
- [ ] `go build -o bin/klshield ./shield/cmd/klshield`
- [ ] `go build -o bin/kliq ./iq/cmd/kliq`
- [ ] Relevant commands run successfully
- [ ] Docs/examples updated if needed

Additional notes:

## Checklist

- [ ] The change is scoped and reviewable
- [ ] Commit messages are clear
- [ ] Commits are signed off where appropriate (`git commit -s`)
- [ ] Documentation was updated when behavior changed
- [ ] I considered compatibility and operational impact
