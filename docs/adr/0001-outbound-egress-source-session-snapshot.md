# ADR: Architecture Decision Record

- ADR ID: 0001
- Title: Outbound egress source snapshot in session metadata
- Status: Canary
- Date: 2026-05-10

## Context
- `XrayR` structured access log needs a best-effort local outbound socket tuple for abuse/DMCA correlation.
- Existing `session.Outbound.Conn` is explicitly optional and can be nil for proxy, mux and tunnel paths.
- Mux creates the physical outbound socket in a worker context that is detached from the logical request context, so `XrayR` cannot reliably recover the source tuple only in its dispatcher.

## Problem
- Logical VPN sessions need to observe the local endpoint of the physical outbound socket without changing routing behavior.
- For mux, one physical connection can carry multiple logical sessions, so the physical source tuple must be copied from the worker back into logical `session.Outbound` metadata.

## Decision
- Add a thread-safe egress source snapshot to `session.Outbound`.
- Capture successful outbound dial local endpoint in `app/proxyman/outbound.Handler.Dial`.
- Propagate the captured source tuple to all outbound metadata entries in the current context, so nested proxy/dialer paths can update the outer logical outbound too.
- For mux, store the physical worker egress source and copy it into logical sessions dispatched through that worker.
- Keep `Conn` as-is and treat it only as a fallback for consumers that still use it.

## Ownership and Scope
- Owner repo: `Xray-core`
- Downstream consumers:
  - `XrayR` access log enrichment.
- Нужен ли отдельный org-wide ADR:
  - Нет для canary; нужен, если egress source snapshot станет обязательным org-wide observability contract для нескольких продуктов.

## Alternatives considered
- Read `session.Outbound.Conn.LocalAddr()` in `XrayR`.
- Add conntrack/eBPF sidecar and join socket tuples with access logs outside xray-core.
- Disable mux on edge nodes for observability.

## Consequences
- Плюсы:
  - Consumers get one metadata source for ordinary, nested and mux outbound paths.
  - Routing behavior and wire protocols are unchanged.
- Компромиссы:
  - For mux, multiple logical sessions can share the same physical source tuple.
  - The tuple is still local to the xray-core network namespace and may not equal final public tuple after NAT, tunnel or another proxy.

## Risks
- Technical:
  - Consumers may overinterpret mux shared physical ports as one-to-one user attribution.
- Operational:
  - Requires downstream `XrayR` to depend on this forked xray-core build during canary.
- Product:
  - No user-facing product behavior changes.
- Security/Privacy:
  - Adds socket metadata only; no payload logging.

## Mitigations
- Now:
  - Expose this as best-effort source tuple metadata, not as guaranteed public NAT tuple.
  - Canary only on `planck` before any wider rollout.
- Later:
  - If public tuple accuracy is required for NAT/tunnel cases, design separate conntrack/eBPF observability.

## Rollout plan
- Publish fork commit.
- Bump `XrayR` to this xray-core revision.
- Build `XrayR` image only through CI.
- Deploy only to `planck` and verify `egress_src_ip` / `egress_src_port` in access log and ClickHouse.

## Status notes
- 2026-05-10: Proposed for `planck` canary.
- Что может supersede это решение:
  - Org-wide edge observability contract with conntrack/eBPF-backed public tuple attribution.
