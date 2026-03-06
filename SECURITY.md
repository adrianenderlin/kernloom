# Security Policy

## Supported scope

Security reports are especially relevant for:

- `shield/bpf/` (XDP/eBPF program)
- `shield/cmd/klshield/`
- `iq/cmd/kliq/`
- shared interfaces between userspace and pinned BPF maps
- build and release artifacts
- documentation that could cause unsafe deployment or exposure

---

## Reporting a vulnerability

Please **do not** open a public GitHub issue for suspected vulnerabilities.

Instead, use one of the following private channels:

1. **GitHub private vulnerability reporting / security advisory**, if enabled for this repository.
2. If that is not available, contact the maintainer through a private channel and include enough detail for reproduction and assessment.

Please include where possible:

- affected component
- affected version / commit
- environment
- reproduction steps
- proof of concept or packet sequence if relevant
- impact assessment
- suggested fix, if known

---

## What to report

Please report issues such as:

- bypass of deny / allow / rate-limit enforcement
- verifier-safe but logically unsafe packet-path behavior
- map corruption or unsafe state assumptions
- privilege or boundary issues in CLI tooling
- unsafe defaults
- exposure of sensitive operational data
- release or packaging problems affecting trust or integrity

Operational bugs that are not security-sensitive should normally go through regular issues.

---

## Coordinated disclosure

Kernloom follows a coordinated disclosure approach:

- the maintainer reviews the report privately
- impact and scope are assessed
- a fix is prepared where feasible
- disclosure happens after mitigation is available, or once risk is sufficiently understood

Please avoid public disclosure before the maintainer has had a reasonable chance to investigate and address the problem.

---

## Response expectations

Best effort will be made to:

- acknowledge receipt
- assess severity and scope
- confirm whether the report is valid
- communicate whether a fix or mitigation is planned

No specific SLA is guaranteed.

---

## Safe harbor

Good-faith security research intended to improve the project is welcome.

Please:

- avoid harming third-party systems or data
- avoid service disruption beyond what is necessary to demonstrate the issue
- avoid public disclosure before coordination
- avoid accessing data that is not yours except to the minimal extent required to demonstrate impact

