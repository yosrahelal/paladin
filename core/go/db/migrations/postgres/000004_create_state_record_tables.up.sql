BEGIN;

CREATE TABLE state_confirms (
    "domain_name" TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    "transaction" UUID    NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_confirm_transaction ON state_confirms("transaction");

CREATE TABLE state_spends (
    "domain_name" TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    "transaction" UUID    NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_spend_transaction ON state_spends("transaction");

CREATE TABLE state_nullifiers (
    "domain_name" TEXT    NOT NULL,
    "id"          TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    PRIMARY KEY ("domain_name", "id")
);
CREATE UNIQUE INDEX state_nullifiers_state ON state_nullifiers("domain_name", "state");

COMMIT;