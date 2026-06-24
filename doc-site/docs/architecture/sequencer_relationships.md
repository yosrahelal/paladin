# Sequencer Component Relationships

The distributed sequencer is composed of four main components. Each private contract address gets its own **Sequencer**, which owns one **Originator** and one **Coordinator** instance.

```mermaid
sequenceDiagram
    participant Caller as Transaction manager
    participant SM as Sequencer Manager
    participant S as Sequencer
    participant O as Originator
    participant C as Coordinator

    Note over SM,S: Lifecycle

    Caller->>SM: HandleNewTx(tx)
    SM->>S: LoadSequencer(contractAddr)
    S-->>SM: sequencer (created or retrieved)
    SM->>O: QueueEvent(TransactionCreatedEvent)

    Note over O: State: Idle → Sending

    Note over O,C: Delegation (via network transport)

    O->>C: SendDelegationRequest(txID, blockHeight)
    C-->>O: DelegationResponse (accepted)

    Note over C: State: Idle → Active

    Note over C,O: Assembly

    C->>O: SendAssembleRequest(txID)
    O->>C: SendAssembleResponse(txID, assembledTx)

    Note over C: State: Assembling → Endorsing → Dispatching

    Note over SM,C: Confirmation

    C->>SM: HandlePublicTXSubmission(txID)
    SM-->>C: (nonce assigned)
    C->>SM: PrivateTransactionsConfirmed(completions)
    SM->>O: QueueEvent(ConfirmedSuccessEvent)

    Note over S,O: Heartbeat (every ~500ms)

    loop Heartbeat
        S->>O: QueueEvent(HeartbeatIntervalEvent)
        S->>C: QueueEvent(HeartbeatIntervalEvent)
    end
```
