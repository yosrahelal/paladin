# Private Transaction Manager

The responsibility of this package is to co-ordinate all inflight private paladin transactions through integration across nodes to assemble and endorse transactions and ultimately to handover to a PublicTransactionManger for submitting to the base ledger.

There are 4 primary component in this package:
 - **Transaction Manager** This is a singleton per paladin node and is the main entry point into this package that is exposed to other components
 - **Sequencer** There is, at most, one sequencer per private smart contract and it is responsible for managing the threading model and error handling related to the coordination of various transactions.
 - **Transaction Flow** There is one transaction flow for every in flight transaction and is responsible for tracking the current status of that transaction and deciding what action(s) need to be performed next for each transaction and to track and retry outstanding asynchronous actions.
 - **Graph** There is one graph per sequencer and it keep track of dependencies between transactions and analyzes which transaction(s) are ready for dispatch at any given point in time as a function of those dependencies and the respective endorsement status of each transaction.
  
In addition to these primary components, there are some utility components in this package:
 - **EndorsementGatherer**  provides integration with the domain manager to endorse transactions. This may be transaction that are being coordinated by a Sequencer in the local address space or may be in response to a transport message received from a sequencer on a remote node.
 - **TransportWriter** provides integration with the transport manager to send messages, encapsulates the nuances of how the various data structures are serialized and provides a well defined interface for each of the message types that we expect to be sent by private transaction manager
 - **TransportReceiver** provides integration with the transport manager to receive messages and route them to the relevant functions on the private transaction manger ( which then distributes them to the relevant Sequencer).
 - **Publisher** provides a well defined interface for in-memory events that are input to the event loop for a sequencer.  


To understand the protocol and threading model implemented in here, the most logical place to start is code inspection of:
 - Sequencer's `handleEvent` function in [sequencer_event_loop.go](./sequencer_event_loop.go)
 - TransactionFlow's `Action` function in [transaction_flow_actions.go](./transaction_flow_actions.go) 

To understand the persistence model of the private transaction manager in more detail, see the [syncpoints](./syncpoints/) package and the references to it from this package.