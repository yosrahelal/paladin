BEGIN;

CREATE TABLE state_confirm_records (
    "domain_name" TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    "transaction" UUID    NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_confirm_records_transaction ON state_confirm_records("transaction");

CREATE TABLE state_spend_records (
    "domain_name" TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    "transaction" UUID    NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_spend_records_transaction ON state_spend_records("transaction");

CREATE TABLE state_read_records (
    "domain_name" TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    "transaction" UUID    NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_read_records_transaction ON state_read_records("transaction");

CREATE TABLE state_info_records (
    "domain_name" TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    "transaction" UUID    NOT NULL,
    PRIMARY KEY ("domain_name", "state")
);
CREATE INDEX state_info_records_transaction ON state_info_records("transaction");

CREATE TABLE state_nullifiers (
    "domain_name" TEXT    NOT NULL,
    "id"          TEXT    NOT NULL,
    "state"       TEXT    NOT NULL,
    PRIMARY KEY ("domain_name", "id")
);
CREATE UNIQUE INDEX state_nullifiers_state ON state_nullifiers("domain_name", "state");

COMMIT;