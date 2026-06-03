CREATE TABLE private_state_completion (
    "contract"          TEXT    NOT NULL,
    "missing_state_id"  TEXT    NOT NULL,
    "block_number"      INTEGER NOT NULL,
    PRIMARY KEY ("missing_state_id")
);
CREATE INDEX psci_contract_block ON private_state_completion ("contract", "block_number");
