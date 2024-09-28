CREATE TABLE state_confirms (
    "domain_name" VARCHAR NOT NULL,
    "state"       VARCHAR NOT NULL,
    "transaction" UUID    NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_confirm_transaction ON state_confirms("transaction");

CREATE TABLE state_spends (
    "domain_name" VARCHAR NOT NULL,
    "state"       VARCHAR NOT NULL,
    "transaction" UUID    NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_spend_transaction ON state_spends("transaction");

CREATE TABLE state_locks (
    "domain_name" VARCHAR NOT NULL,
    "state"       VARCHAR NOT NULL,
    "transaction" UUID    NOT NULL,
    "creating"    BOOLEAN NOT NULL,
    "spending"    BOOLEAN NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_lock_transaction ON state_locks("transaction");

CREATE TABLE state_nullifiers (
    "domain_name" VARCHAR NOT NULL,
    "nullifier"   VARCHAR NOT NULL,
    "state"       VARCHAR NOT NULL,
    PRIMARY KEY ("domain_name", "nullifier")
);
CREATE UNIQUE INDEX state_nullifiers_state ON state_nullifiers("domain_name", "state");
