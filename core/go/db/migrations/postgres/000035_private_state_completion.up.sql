BEGIN;

CREATE TABLE private_state_completion (
    "contract"         VARCHAR NOT NULL,
    "missing_state_id" VARCHAR NOT NULL,
    "block_number"     BIGINT  NOT NULL,
    PRIMARY KEY ("missing_state_id")
);
CREATE INDEX psci_contract_block ON private_state_completion ("contract", "block_number");

COMMIT;
