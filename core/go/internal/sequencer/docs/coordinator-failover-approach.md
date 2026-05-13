# Coordinator Failover: Design Approach

This document captures the design of the inactivity-based ring-step failover mechanism that was partially implemented and then removed from the sequencer in order to document the approach before the implementation is resumed.

This was an iteration on the algorithm described in https://github.com/LFDT-Paladin/paladin/blob/1f47aa52ec4ec89c64fa9901b62ab0850ccef294/doc-site/docs/architecture/distributed_sequencer.md. When this work is resumed, there will need to be careful comparison with this document, to understand if the departures can be explained based on the reality of actual implementation, or whether in fact they provided solutions to the unanswered questions below.

---

## Overview

In `COORDINATOR_ENDORSER` mode, the active coordinator for a contract is determined deterministically by hashing the current block range epoch against the sorted endorser pool. If that coordinator node is unreachable, the originator currently redelegates to the same node on each inactive-grace interval — a nudge, but not a recovery.

Failover means allowing the originator to **walk the endorser pool ring** when the current coordinator is unresponsive, selecting successive candidates until a responsive one is found. This ensures transactions can continue to make progress even if the designated coordinator node has gone offline.

---

## Algorithm Design

### Key data carried by the originator

| Field | Purpose |
|---|---|
| `preferredActiveCoordinator` | The coordinator chosen by `SelectCoordinatorNode` at `failoverOffset = 0` — i.e. the node that should be coordinating under normal conditions for this epoch. |
| `currentActiveCoordinator` | The node the originator is currently delegating to. Under normal conditions this equals `preferredActiveCoordinator`. During failover these differ. |
| `failoverOffset` | An integer counter, starting at 0, representing how many steps around the pool ring the originator has taken. 0 means the preferred node; 1 means the next node in lex-sorted order; and so on. |
| `needsFailoverOffsetReset` | Set to `true` when a new block range epoch begins, so that `action_SelectActiveCoordinator` resets the offset to 0 before computing the new coordinator. |

### `SelectCoordinatorNode` with a failover offset

The selection function is extended to accept a `failoverOffset int` in addition to the pool, block height, and block range. The offset shifts the result by `failoverOffset` positions around the pool ring:

```
p = hash(effectiveBlockNumber) % n          // preferred slot
s = (p + failoverOffset) % n                // current slot after stepping
preferred = pool[p]
current   = pool[s]
```

The function returns both `(preferred, current string)`.

### Ring stepping on inactive grace

When the originator is in `Sending` and `guard_InactiveGracePeriodExceeded` fires on a heartbeat interval:

1. `action_IncrementFailoverOffset` — adds 1 to `failoverOffset`.
2. `action_SelectActiveCoordinator` — calls `SelectCoordinatorNode` with the new offset and updates both `preferred` (unchanged) and `current` (now the next pool member).
3. `action_SendDelegationRequest` — delegates to the new `currentActiveCoordinator`.

The originator also notifies its local coordinator of the coordinator change via an `ActiveCoordinatorUnavailable` event (see below), so that the coordinator's view stays aligned.

This stepping is **only active in `COORDINATOR_ENDORSER` mode** — the step is a no-op for `COORDINATOR_SENDER` and `COORDINATOR_STATIC` where no pool exists.

### Epoch reset

When a new block-range epoch begins, `action_SelectActiveCoordinator` resets `failoverOffset` to 0 and recomputes both `preferred` and `current` from scratch for the new epoch's pool slot. Any failover walk from the previous epoch is discarded.

### Preferred recovery

If the originator is on a fallback coordinator (`failoverOffset > 0`) and receives a heartbeat from the **preferred** coordinator showing it is `Active`, the originator realigns immediately:

- `currentActiveCoordinator` is reset to `preferredActiveCoordinator`.
- `failoverOffset` is reset to 0.
- `needsRedelegate` is set so that all in-flight transactions are redelegated to the preferred coordinator in the same cycle.

This recovery does not wait for a flush from the fallback — the preferred coordinator returning to Active is not an epoch handover.

### `ActiveCoordinatorUnavailableEvent`

An originator-to-coordinator event carrying the new `currentActiveCoordinator` string. When the originator steps to a new candidate it queues this event to the local coordinator, allowing the coordinator to update its own `currentActiveCoordinator` field without having to infer the step change from an absence of heartbeats. A coordinator cannot distinguish between idleness vs unavailability as the reason for a lack of heartbeats, whereas an originator in sending state knows that the current preferred coordinator must not be idle.

The local coordinator ignores this event if it believes it is itself the preferred coordinator — that case should not arise in practice since the local coordinator should never be unavailable to an originatior.

### Coordinator state machine interactions

The coordinator state machine has additional transitions driven by failover:

- **`Idle → Active`** (via `validator_IsHeartbeatFromActiveWhenWeArePreferred`): when the preferred coordinator receives a heartbeat from a fallback that is currently `Active`, the preferred knows it should take back coordination. It transitions from `Idle` to `Elect` (or directly to `Active`), following the normal epoch-handover path.
- **`Active → Flush/Closing`** (via `validator_IsHeartbeatFromPreferredActiveCoordinator`): when a fallback coordinator in `Active` receives a heartbeat from the preferred showing it is `Active`, the fallback yields and begins flushing.
- **`*`** (via `Event_ActiveCoordinatorUnavailable`): received from the originator, updates `currentActiveCoordinator` in any state.

The coordinator also carries `preferredActiveCoordinator` to distinguish between its preferred identity and the current active identity, which may differ during failover.

---

## What Was Implemented and Then Removed

The following types, fields, and functions were introduced to implement this design and have since been removed. They are listed here as pointers to where the implementation should be re-introduced.

### `common/selection.go`

- `SelectCoordinatorNode` signature extended with `failoverOffset int` parameter and returning `(preferred, current string)` instead of a single `string`.

### `coordinator/coordinator.go`

- `preferredActiveCoordinator string` field on the `coordinator` struct.

### `coordinator/events.go`

- `ActiveCoordinatorUnavailableEvent` struct with fields `NewCurrentActiveCoordinator string`.
- `Event_ActiveCoordinatorUnavailable` event type constant.

### `coordinator/inactive.go`

- `validator_IsHeartbeatFromPreferredActiveCoordinator` — returns true when the heartbeat is from the preferred coordinator and shows it is `Active`. Used to trigger the preferred coordinator awakening flow.
- `validator_IsHeartbeatFromActiveWhenWeArePreferred` — returns true when the local node is the preferred coordinator and the heartbeat is from a different node showing `Active` state. Used to wake the preferred from `Idle`.
- Realignment branch in `action_HeartbeatReceived` — when `currentActiveCoordinator != preferredActiveCoordinator` and a heartbeat arrives from the preferred showing `Active`, resets `currentActiveCoordinator` to `preferredActiveCoordinator`.

### `coordinator/selection.go`

- `action_CurrentActiveCoordinatorUnavailable` — handles `ActiveCoordinatorUnavailableEvent` by updating the coordinator's `currentActiveCoordinator` to the value carried in the event.

### `coordinator/state_machine.go`

- `Event_ActiveCoordinatorUnavailable` handlers in `Idle`, `Observing`, `Flush`, and `Closing` states.
- `Idle → Elect` transition via `validator_IsHeartbeatFromActiveWhenWeArePreferred` (preferred awakening on fallback active).
- `Active → Flush/Closing` transition via `validator_IsHeartbeatFromPreferredActiveCoordinator` (yield when preferred returns).
- `guard_IsPreferredActiveCoordinator` used in the `Observing → Elect` transition (replaced by `guard_IsCurrentActiveCoordinator` after removal).

### `coordinator/state_transition_guards.go`

- `guard_IsPreferredActiveCoordinator` — returns true if the local node's name equals `coordinator.preferredActiveCoordinator`.

### `originator/originator.go`

- `preferredActiveCoordinator string` field.
- `failoverOffset int` field.
- `needsFailoverOffsetReset bool` field.
- `queueActiveCoordinatorUnavailable func(ctx context.Context, newCurrent string)` field — closure injected at construction time that queues an `ActiveCoordinatorUnavailableEvent` to the local coordinator.

### `originator/originating.go`

- `action_IncrementFailoverOffset` — increments `failoverOffset` by 1 if in `COORDINATOR_ENDORSER` mode; no-op otherwise.
- `guard_PreferredAndCurrentDiffer` — returns true when `preferredActiveCoordinator != currentActiveCoordinator`.
- `action_ResetCurrentToPreferred` — resets `currentActiveCoordinator` to `preferredActiveCoordinator`, clears `failoverOffset` to 0, and resets `heartbeatIntervalsSinceLastReceive`.
- `action_SelectActiveCoordinator` — contained the failover logic: reset `failoverOffset` on epoch change, pass the offset to `SelectCoordinatorNode`, set both `preferred` and `current`, and call `queueActiveCoordinatorUnavailable` if the current coordinator changed.
- `action_UpdateBlockHeight` — set `needsFailoverOffsetReset = true` when crossing an epoch boundary.

### `originator/state_machine.go`

- In `State_Sending`, `Event_HeartbeatInterval`: `action_IncrementFailoverOffset` action rule; a separate `guard_InactiveGracePeriodExceeded → action_SelectActiveCoordinator` rule (so selection runs after the offset increment before delegation).
- In `State_Idle`, `State_Observing`, and `State_Sending`, `Event_HeartbeatReceived`: three-step preferred-recovery rules combining `validator_IsHeartbeatFromPreferredActiveCoordinator`, `guard_PreferredAndCurrentDiffer`, and `action_ResetCurrentToPreferred`.

### `sequencer/sequencer_lifecycle.go`

- `queueActiveCoordinatorUnavailable` closure definition and the argument passed to `originator.NewOriginator`.

---

## Problems to Solve

* When a preferred active coordinator becomes available again and the failover coordinator yields to it, how can a flush and handover of state locks be managed?
* In the case of such a flush, what happens if a block range epoch boundary is crossed and we have a new preferred coordinator?
* Consider a scenario where we've lost two nodes - preferred and first failover - so the remaining nodes start using the second failover. If the first failover node becomes available again, while the preferred is still unavailable, it will start coordinating its own transactions. How should the other nodes using the second failover coordinator handle this?
