The following qualifiers can be used in queries to the state store:

- `available` - states that have been confirmed by a blockchain transaction, and not yet been spent in a subsequent transaction
- `unconfirmed` - states where no transaction has yet been processed from the blockchain to confirm the state
- `confirmed` - states that have not been marked spent as a result of indexing a blockchain transaction
- `spent` - states that have not been marked spent as a result of indexing a blockchain transaction
- `all` - all states stored in this node, regardless of status
- `[uuid]` - any other value is parsed as the UUID, and if there is an in-memory domain context active for that UUID the query is executed within that domain context