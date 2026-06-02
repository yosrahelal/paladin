CREATE TABLE private_state_completion (
    "contract"              TEXT    NOT NULL,
    "transaction_id"        TEXT    NOT NULL,
    "block_number"          INTEGER NOT NULL,
    "next_missing_state"    TEXT    NOT NULL,
    PRIMARY KEY ("contract", "transaction_id")
);
CREATE INDEX psci_next_missing_state ON private_state_completion ("next_missing_state");
