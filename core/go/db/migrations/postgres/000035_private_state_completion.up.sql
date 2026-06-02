BEGIN;

CREATE TABLE private_state_completion (
    "contract"              VARCHAR NOT NULL,
    "transaction_id"        VARCHAR NOT NULL,
    "block_number"          BIGINT  NOT NULL,
    "next_missing_state"    VARCHAR NOT NULL,
    PRIMARY KEY ("contract", "transaction_id")
);
CREATE INDEX psci_next_missing_state ON private_state_completion ("next_missing_state");

COMMIT;
