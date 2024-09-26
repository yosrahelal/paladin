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

CREATE TABLE state_locks (
    "domain_name" TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    "transaction" UUID    NOT NULL,
    "creating"    BOOLEAN NOT NULL,
    "spending"    BOOLEAN NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_lock_transaction ON state_locks("transaction");

CREATE TABLE state_nullifiers (
    "domain_name" TEXT    NOT NULL,
    "nullifier"   TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    PRIMARY KEY ("domain_name", "nullifier")
);
CREATE UNIQUE INDEX state_nullifiers_state ON state_nullifiers("domain_name", "state");

COMMIT;